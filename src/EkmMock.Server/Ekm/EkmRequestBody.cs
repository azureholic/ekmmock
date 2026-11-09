using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;

namespace EkmMock.Server.Ekm;

/// <summary>
/// One EKM request body: read into a rented buffer (spec 4.1: at most 16 KiB, chunked or Content-Length) and parsed with
/// <see cref="Utf8JsonReader"/> (spec 4.3: unknown fields ignored). The <c>value</c> field, which holds a plaintext DEK for
/// wrap, is never turned into a <see cref="string"/>; it stays a UTF-8 slice of the rented buffer, and <see cref="Dispose"/>
/// zeroes everything with <see cref="CryptographicOperations.ZeroMemory"/> before the buffers go back to the pool.
/// </summary>
internal sealed class EkmRequestBody : IDisposable
{
    public const int MaxBodyBytes = 16 * 1024;

    private static ReadOnlySpan<byte> Utf8Bom => [0xEF, 0xBB, 0xBF];

    private byte[]? _buffer;
    private int _length;
    private int _valueStart = -1;
    private int _valueLength;
    private byte[]? _unescapedValue;
    private int _unescapedLength;

    private EkmRequestBody(byte[] buffer, int length)
    {
        _buffer = buffer;
        _length = length;
    }

    /// <summary>True when <c>request_context</c> was present as a JSON object (spec 4.3: required).</summary>
    public bool HasRequestContext { get; private set; }

    public string? RequestId { get; private set; }

    public string? CorrelationId { get; private set; }

    public string? PoolName { get; private set; }

    /// <summary>The <c>alg</c> string, null if absent or JSON null.</summary>
    public string? Algorithm { get; private set; }

    /// <summary><c>alg</c> was present but not a string or null (wrap/unwrap answer InvalidRequest; other operations ignore it).</summary>
    public bool HasInvalidAlgorithm { get; private set; }

    /// <summary><c>value</c> was present but not a string or null (wrap/unwrap answer InvalidRequest; other operations ignore it).</summary>
    public bool HasInvalidValue { get; private set; }

    public bool HasValue => _valueStart >= 0 || _unescapedValue is not null;

    /// <summary>Raw bytes of the base64url text in <c>value</c>. Valid until <see cref="Dispose"/>.</summary>
    public ReadOnlySpan<byte> ValueUtf8
        => _unescapedValue is not null
            ? _unescapedValue.AsSpan(0, _unescapedLength)
            : _buffer is not null && _valueStart >= 0 ? _buffer.AsSpan(_valueStart, _valueLength) : [];

    /// <summary>Size of the request body in bytes.</summary>
    public int Length => _length;

    /// <summary>Reads and parses the body. Throws <see cref="EkmProtocolException"/> (InvalidRequest) when it is too large or not an acceptable JSON object.</summary>
    public static async ValueTask<EkmRequestBody> ReadAsync(HttpRequest request, int maxBytes, CancellationToken cancellationToken)
    {
        if (request.ContentLength > maxBytes)
        {
            throw TooLarge();
        }

        var buffer = ArrayPool<byte>.Shared.Rent(maxBytes + 1);
        var total = 0;
        try
        {
            while (true)
            {
                var read = await request.Body.ReadAsync(buffer.AsMemory(total, maxBytes + 1 - total), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > maxBytes)
                {
                    throw TooLarge();
                }
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, total));
            ArrayPool<byte>.Shared.Return(buffer);
            throw;
        }

        var body = new EkmRequestBody(buffer, total);
        try
        {
            body.Parse();
        }
        catch
        {
            body.Dispose();
            throw;
        }

        return body;
    }

    public void Dispose()
    {
        if (_buffer is not null)
        {
            CryptographicOperations.ZeroMemory(_buffer.AsSpan(0, _length));
            ArrayPool<byte>.Shared.Return(_buffer);
            _buffer = null;
        }

        ReleaseUnescaped();
    }

    private static EkmProtocolException TooLarge()
        => new(ProxyErrorCode.InvalidRequest, "The request body is larger than 16 KiB");

    private static EkmProtocolException NotJson()
        => new(ProxyErrorCode.InvalidRequest, "The request body is not a valid JSON object");

    private void Parse()
    {
        try
        {
            var whole = _buffer.AsSpan(0, _length);
            var offset = whole.StartsWith(Utf8Bom) ? Utf8Bom.Length : 0;

            // Utf8JsonReader only validates UTF-8 where it transcodes, so skipped fields would let garbage through.
            if (!System.Text.Unicode.Utf8.IsValid(whole[offset..]))
            {
                throw NotJson();
            }

            var reader = new Utf8JsonReader(whole[offset..], new JsonReaderOptions { MaxDepth = 32 });

            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                throw NotJson();
            }

            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                // Here the token is always a property name.
                if (reader.ValueTextEquals("request_context"u8))
                {
                    reader.Read();
                    ReadRequestContext(ref reader);
                }
                else if (reader.ValueTextEquals("alg"u8))
                {
                    reader.Read();
                    HasInvalidAlgorithm = false;
                    switch (reader.TokenType)
                    {
                        case JsonTokenType.String:
                            Algorithm = reader.GetString();
                            break;
                        case JsonTokenType.Null:
                            Algorithm = null;
                            break;
                        default:
                            // Only wrap/unwrap care; info and metadata ignore it like any other unknown field.
                            Algorithm = null;
                            HasInvalidAlgorithm = true;
                            reader.Skip();
                            break;
                    }
                }
                else if (reader.ValueTextEquals("value"u8))
                {
                    reader.Read();
                    ReadValue(ref reader, offset);
                }
                else
                {
                    reader.Read();
                    reader.Skip();
                }
            }

            // The reader stops at the root's closing brace; anything but whitespace after it is an error.
            if (reader.TokenType != JsonTokenType.EndObject || reader.Read())
            {
                throw NotJson();
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            // Never echo the parser's message: it can quote request content.
            throw NotJson();
        }
    }

    private void ReadRequestContext(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            reader.Skip();
            HasRequestContext = false;
            return;
        }

        HasRequestContext = true;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if (reader.ValueTextEquals("request_id"u8))
            {
                reader.Read();
                RequestId = ReadOptionalString(ref reader);
            }
            else if (reader.ValueTextEquals("correlation_id"u8))
            {
                reader.Read();
                CorrelationId = ReadOptionalString(ref reader);
            }
            else if (reader.ValueTextEquals("pool_name"u8))
            {
                reader.Read();
                PoolName = ReadOptionalString(ref reader);
            }
            else
            {
                reader.Read();
                reader.Skip();
            }
        }
    }

    // Lenient on purpose: these three fields are only for correlation, so a non-string is ignored rather than rejected.
    private static string? ReadOptionalString(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            reader.Skip();
            return null;
        }

        var text = reader.GetString();
        return text is { Length: > EkmRequestContext.MaxContextFieldLength }
            ? text[..EkmRequestContext.MaxContextFieldLength]
            : text;
    }

    private void ReadValue(ref Utf8JsonReader reader, int offset)
    {
        ReleaseUnescaped();
        _valueStart = -1;
        _valueLength = 0;
        HasInvalidValue = false;

        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                return;

            case JsonTokenType.String:
                if (reader.HasValueSequence)
                {
                    throw NotJson(); // cannot happen for a single span; defensive
                }

                if (reader.ValueIsEscaped)
                {
                    // Escapes inside base64url text are legal JSON (for example \u002D). Decode into a private rented buffer.
                    _unescapedValue = ArrayPool<byte>.Shared.Rent(Math.Max(1, reader.ValueSpan.Length));
                    _unescapedLength = reader.CopyString(_unescapedValue);
                }
                else
                {
                    // TokenStartIndex points at the opening quote.
                    _valueStart = offset + (int)reader.TokenStartIndex + 1;
                    _valueLength = reader.ValueSpan.Length;
                }

                return;

            default:
                // Only wrap/unwrap care; info and metadata ignore it like any other unknown field.
                HasInvalidValue = true;
                reader.Skip();
                return;
        }
    }

    private void ReleaseUnescaped()
    {
        if (_unescapedValue is not null)
        {
            CryptographicOperations.ZeroMemory(_unescapedValue.AsSpan(0, _unescapedLength));
            ArrayPool<byte>.Shared.Return(_unescapedValue);
            _unescapedValue = null;
            _unescapedLength = 0;
        }
    }
}
