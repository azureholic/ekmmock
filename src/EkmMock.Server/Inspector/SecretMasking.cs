using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Unicode;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;

namespace EkmMock.Server.Inspector;

/// <summary>Where in an exchange a body sits, which decides whether it can carry a plaintext DEK (spec 8.4).</summary>
internal enum BodyPosition
{
    /// <summary>Cannot carry a DEK: every response except the response of unwrapkey. Shown exactly as it is (wrapped values, <c>n</c>, <c>e</c>, ProxyErrors).</summary>
    Plain,

    /// <summary>The request of <c>wrapkey</c> (and of anything unroutable: the operation is unknown, so a DEK is possible): <c>value</c> is the plaintext DEK.</summary>
    SecretRequest,

    /// <summary>The response of <c>unwrapkey</c>: <c>value</c> is the plaintext DEK.</summary>
    SecretResponse,

    /// <summary>The request of <c>unwrapkey</c>: <c>value</c> is ciphertext and is shown as sent. Only a body that is not one complete JSON object is not captured (conservative).</summary>
    CiphertextRequest,

    /// <summary>The request of <c>info</c> or <c>metadata</c>: nothing secret is expected, so it is shown as it is, except that a <c>value</c> field (which should not be there) is masked.</summary>
    NoDekRequest,
}

internal static class BodyPositions
{
    /// <summary>
    /// The secrecy rule per (operation, direction), spec 8.4: the <em>request</em> of wrapkey and the <em>response</em> of unwrapkey carry a plaintext DEK;
    /// the request of unwrapkey and the response of wrapkey carry ciphertext, which is not secret. An unroutable request (operation unknown) is treated
    /// like a wrap request: a client may have sent a DEK to a wrong path, and the inspector must not be the place where it shows up.
    /// </summary>
    public static BodyPosition For(EkmOperation? operation, bool isRequest)
        => isRequest
            ? operation switch
            {
                EkmOperation.UnwrapKey => BodyPosition.CiphertextRequest,
                EkmOperation.Info or EkmOperation.Metadata => BodyPosition.NoDekRequest,
                _ => BodyPosition.SecretRequest, // wrapkey, and unroutable
            }
            : operation is EkmOperation.UnwrapKey ? BodyPosition.SecretResponse : BodyPosition.Plain;
}

/// <summary>The fingerprint of spec 8.4: the first 12 hex characters of the SHA-256 of the raw (decoded) bytes.</summary>
internal static class SecretFingerprint
{
    public const int HexLength = 12;

    public static string Compute(ReadOnlySpan<byte> raw)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(raw, hash);
        return Convert.ToHexStringLower(hash[..(HexLength / 2)]);
    }

    /// <summary>The display text, for example <c>32 bytes · fp 3f9a1c07b2e4</c>.</summary>
    public static string Display(int bytes, string fingerprint) => $"{bytes} bytes · fp {fingerprint}";

    /// <summary>What an undecodable value in a secret position becomes: its length only, never a fingerprint of data that is not a valid encoding.</summary>
    public static string DisplayInvalid(int chars) => $"value (invalid, {chars} chars)";
}

/// <summary>
/// Redacts captured bodies (spec 8.4). The rules, in short:
/// <list type="bullet">
/// <item>On a <see cref="BodyPosition.Plain"/> position (every response but an unwrap response) the body is shown as it is. An unwrap request (<see cref="BodyPosition.CiphertextRequest"/>) is shown as sent, but a body that is not one complete JSON object is not captured; an info/metadata request (<see cref="BodyPosition.NoDekRequest"/>) is shown as it is except for a stray <c>value</c>.</item>
/// <item>On a secret position the masked text is <em>built from the parsed JSON</em>, not by searching the original text: every <c>value</c> string is replaced by
/// its masked form (length and fingerprint), a <c>value</c> that is not valid base64url by <c>value (invalid, N chars)</c>, and every top-level property that is not
/// on a short allow-list (<c>request_context</c>, an <c>alg</c> that is a supported algorithm name; for a response <c>code</c> and <c>message</c>) by its length. That covers
/// a DEK sent under a wrong field name or in the <c>alg</c> field.</item>
/// <item>A body on a secret position that is not one complete JSON object (bad JSON, bad UTF-8, a scalar or array root, larger than 16 KiB) is not captured at all:
/// only its size and a note are stored, because it cannot be masked reliably.</item>
/// </list>
/// The original bytes are never turned into a string on a secret position, so no copy of a DEK survives in the captured text.
/// </summary>
internal static class BodyRedactor
{
    public const int MaxCaptureBytes = 16 * 1024;

    private const int MaxFieldNameLength = 40;

    private static ReadOnlySpan<byte> Utf8Bom => [0xEF, 0xBB, 0xBF];

    public static CapturedBody Redact(ReadOnlySpan<byte> bytes, long totalSize, bool truncated, BodyPosition position, bool revealable)
    {
        if (bytes.IsEmpty && totalSize == 0)
        {
            return CapturedBody.Empty;
        }

        if (position == BodyPosition.Plain)
        {
            return Verbatim(bytes, totalSize, truncated);
        }

        if (truncated)
        {
            // A truncated NoDekRequest is the one exception: it carries nothing secret by position, so the part that was read is shown.
            return position == BodyPosition.NoDekRequest
                ? Verbatim(bytes, totalSize, truncated)
                : NotCaptured(totalSize, truncated, "Body larger than 16 KiB not captured: it cannot be masked reliably.");
        }

        var side = position is BodyPosition.SecretResponse ? "response" : "request";
        var fields = new List<MaskedField>(2);
        if (TryMask(bytes, side, position, revealable, fields, out var text))
        {
            return new CapturedBody { SizeBytes = totalSize, Text = text, MaskedFields = fields };
        }

        // An info/metadata request that is not JSON is exactly what one wants to see when Managed HSM sends something unexpected.
        return position == BodyPosition.NoDekRequest
            ? Verbatim(bytes, totalSize, truncated)
            : NotCaptured(totalSize, truncated, "Unparseable body not captured: it cannot be masked reliably.");
    }

    private static CapturedBody Verbatim(ReadOnlySpan<byte> bytes, long totalSize, bool truncated)
    {
        var span = bytes.StartsWith(Utf8Bom) ? bytes[Utf8Bom.Length..] : bytes;
        return new CapturedBody { SizeBytes = totalSize, Truncated = truncated, Text = Encoding.UTF8.GetString(span) };
    }

    private static CapturedBody NotCaptured(long totalSize, bool truncated, string note)
        => new() { SizeBytes = totalSize, Truncated = truncated, Captured = false, Note = note };

    private enum Mode
    {
        Show,
        ShowIfSupportedAlgorithm,
        MaskValue,
        MaskGeneric,
    }

    private static bool TryMask(ReadOnlySpan<byte> bytes, string side, BodyPosition position, bool revealable, List<MaskedField> fields, out string text)
    {
        text = string.Empty;
        var offset = bytes.StartsWith(Utf8Bom) ? Utf8Bom.Length : 0;
        var body = bytes[offset..];
        if (!Utf8.IsValid(body))
        {
            return false;
        }

        var builder = new StringBuilder(body.Length + 64);
        var copied = 0;
        try
        {
            var reader = new Utf8JsonReader(body, new JsonReaderOptions { MaxDepth = 32 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return false;
            }

            var rootEnded = false;
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject && reader.CurrentDepth == 0)
                {
                    rootEnded = true;
                    break;
                }

                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    continue;
                }

                var depth = reader.CurrentDepth;
                var name = reader.GetString() ?? string.Empty;
                var mode = Decide(name, depth, position);
                if (mode == Mode.Show)
                {
                    continue;
                }

                reader.Read(); // the value
                var start = (int)reader.TokenStartIndex;
                var token = reader.TokenType;
                if (token is JsonTokenType.StartObject or JsonTokenType.StartArray)
                {
                    reader.Skip();
                }

                if (token == JsonTokenType.Null)
                {
                    continue;
                }

                if (mode == Mode.ShowIfSupportedAlgorithm && token == JsonTokenType.String && IsSupportedAlgorithmName(ref reader))
                {
                    continue;
                }

                var end = (int)reader.BytesConsumed;
                var label = Label(side, name);
                var topLevelValue = depth == 1 && name == "value";
                string display;
                if (token == JsonTokenType.String)
                {
                    display = MaskString(ref reader, mode != Mode.MaskGeneric && mode != Mode.ShowIfSupportedAlgorithm, label, revealable && topLevelValue, fields);
                }
                else
                {
                    display = mode == Mode.MaskValue ? "value (invalid, not a string)" : "(masked)";
                    fields.Add(new MaskedField(label, display, null, null, false));
                }

                builder.Append(Encoding.UTF8.GetString(body[copied..start]));
                builder.Append('"').Append(display).Append('"');
                copied = end;
            }

            // A complete root object and nothing but whitespace after it (anything else throws or means a truncated document).
            if (!rootEnded || reader.Read())
            {
                return false;
            }
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        builder.Append(Encoding.UTF8.GetString(body[copied..]));
        text = builder.ToString();
        return true;
    }

    // Compared as bytes on purpose: the text of an alg field that is not an algorithm name can be a DEK, and must never become a string here.
    private static bool IsSupportedAlgorithmName(ref Utf8JsonReader reader)
        => reader.ValueTextEquals("A256KW"u8)
        || reader.ValueTextEquals("A256KWP"u8)
        || reader.ValueTextEquals("RSA-OAEP-256"u8)
        || reader.ValueTextEquals("RSA-OAEP"u8);

    private static Mode Decide(string name, int depth, BodyPosition position)
    {
        // An unwrap request is ciphertext: everything is shown as sent (the body is only checked to be one complete JSON object).
        if (position == BodyPosition.CiphertextRequest)
        {
            return Mode.Show;
        }

        if (name.Equals("value", StringComparison.OrdinalIgnoreCase))
        {
            return Mode.MaskValue;
        }

        // info and metadata requests: no DEK is expected anywhere, so only a stray "value" is masked.
        if (position == BodyPosition.NoDekRequest || depth > 1)
        {
            return Mode.Show; // (depth > 1: inside an allow-listed subtree such as request_context)
        }

        if (position == BodyPosition.SecretRequest)
        {
            return name switch
            {
                "request_context" => Mode.Show,
                "alg" => Mode.ShowIfSupportedAlgorithm,
                _ => Mode.MaskGeneric,
            };
        }

        return name is "code" or "message" ? Mode.Show : Mode.MaskGeneric;
    }

    private static string Label(string side, string name)
        => $"{side}.{(name.Length > MaxFieldNameLength ? name[..MaxFieldNameLength] : name)}";

    // The reader sits on a string token. Escaped strings (legal JSON, for example \u002D inside base64url) are unescaped into a private buffer first.
    private static string MaskString(ref Utf8JsonReader reader, bool asValue, string label, bool revealable, List<MaskedField> fields)
    {
        byte[]? unescaped = null;
        byte[]? decoded = null;
        var innerLength = 0;
        try
        {
            ReadOnlySpan<byte> inner;
            if (reader.ValueIsEscaped)
            {
                unescaped = ArrayPool<byte>.Shared.Rent(Math.Max(1, reader.ValueSpan.Length));
                innerLength = reader.CopyString(unescaped);
                inner = unescaped.AsSpan(0, innerLength);
            }
            else
            {
                inner = reader.ValueSpan;
                innerLength = inner.Length;
            }

            var chars = Encoding.UTF8.GetCharCount(inner);
            if (!asValue)
            {
                var generic = $"(masked, {chars} chars)";
                fields.Add(new MaskedField(label, generic, null, null, false));
                return generic;
            }

            decoded = ArrayPool<byte>.Shared.Rent(Math.Max(1, Base64UrlCodec.MaxDecodedLength(inner.Length)));
            if (Base64UrlCodec.TryDecode(inner, decoded, out var length))
            {
                var fingerprint = SecretFingerprint.Compute(decoded.AsSpan(0, length));
                var display = SecretFingerprint.Display(length, fingerprint);
                fields.Add(new MaskedField(label, display, length, fingerprint, revealable));
                return display;
            }

            var invalid = SecretFingerprint.DisplayInvalid(chars);
            fields.Add(new MaskedField(label, invalid, null, null, false));
            return invalid;
        }
        finally
        {
            if (decoded is not null)
            {
                CryptographicOperations.ZeroMemory(decoded);
                ArrayPool<byte>.Shared.Return(decoded);
            }

            if (unescaped is not null)
            {
                CryptographicOperations.ZeroMemory(unescaped.AsSpan(0, innerLength));
                ArrayPool<byte>.Shared.Return(unescaped);
            }
        }
    }

    /// <summary>
    /// Reads <c>request_id</c>, <c>correlation_id</c> and <c>pool_name</c> from a complete request body that the dispatcher never parsed (a request rejected
    /// before the body was read, for example a 401), so that rejected requests can still be found by <c>correlation_id</c>. Lenient: anything unexpected is null.
    /// </summary>
    public static (string? RequestId, string? CorrelationId, string? PoolName) ExtractRequestContext(ReadOnlySpan<byte> bytes)
    {
        string? requestId = null;
        string? correlationId = null;
        string? poolName = null;
        try
        {
            var span = bytes.StartsWith(Utf8Bom) ? bytes[Utf8Bom.Length..] : bytes;
            var reader = new Utf8JsonReader(span, new JsonReaderOptions { MaxDepth = 32 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return default;
            }

            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                if (reader.ValueTextEquals("request_context"u8))
                {
                    reader.Read();
                    if (reader.TokenType != JsonTokenType.StartObject)
                    {
                        reader.Skip();
                        continue;
                    }

                    while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
                    {
                        if (reader.ValueTextEquals("request_id"u8))
                        {
                            reader.Read();
                            requestId = ReadBoundedString(ref reader);
                        }
                        else if (reader.ValueTextEquals("correlation_id"u8))
                        {
                            reader.Read();
                            correlationId = ReadBoundedString(ref reader);
                        }
                        else if (reader.ValueTextEquals("pool_name"u8))
                        {
                            reader.Read();
                            poolName = ReadBoundedString(ref reader);
                        }
                        else
                        {
                            reader.Read();
                            reader.Skip();
                        }
                    }
                }
                else
                {
                    reader.Read();
                    reader.Skip();
                }
            }
        }
        catch (JsonException)
        {
            // Not a body we can read the context from.
        }
        catch (InvalidOperationException)
        {
        }

        return (requestId, correlationId, poolName);
    }

    private static string? ReadBoundedString(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            reader.Skip();
            return null;
        }

        var text = reader.GetString();
        return text is { Length: > EkmRequestContext.MaxContextFieldLength } ? text[..EkmRequestContext.MaxContextFieldLength] : text;
    }
}

/// <summary>The fields that can be revealed (spec 8.4). Only the two plaintext DEK positions exist.</summary>
internal static class RevealFields
{
    public const string RequestValue = "request.value";

    public const string ResponseValue = "response.value";

    public static bool IsKnown(string? field) => field is RequestValue or ResponseValue;
}

/// <summary>
/// The raw bodies of one exchange, kept in memory only and only while reveal is allowed (spec 8.4): the complete request body (for reveal of a wrap DEK and for
/// replay) and the complete response body of an unwrap (for reveal of the unwrapped DEK). Never persisted, never exported: it is not part of <see cref="ExchangeRecord"/>.
/// It lives in the ring buffer slot of its exchange and is zeroed when that slot is evicted or cleared (or when the capture queue drops it).
/// </summary>
internal sealed class RetainedSecrets
{
    private readonly object _gate = new();
    private byte[]? _request;
    private byte[]? _response;

    public RetainedSecrets(byte[]? requestBody, byte[]? responseBody)
    {
        _request = requestBody;
        _response = responseBody;
    }

    public bool HasRequestBody
    {
        get
        {
            lock (_gate)
            {
                return _request is not null;
            }
        }
    }

    public bool IsEmpty
    {
        get
        {
            lock (_gate)
            {
                return _request is null && _response is null;
            }
        }
    }

    /// <summary>A copy of the raw request body (the caller zeroes it), or null when it was not retained or has been evicted.</summary>
    public byte[]? CopyRequestBody()
    {
        lock (_gate)
        {
            return _request?.ToArray();
        }
    }

    /// <summary>The raw text of the top-level <c>value</c> string of the requested body, or null when it is not available.</summary>
    public string? ReadValue(string field)
    {
        lock (_gate)
        {
            var body = field switch
            {
                RevealFields.RequestValue => _request,
                RevealFields.ResponseValue => _response,
                _ => null,
            };
            return body is null ? null : ReadTopLevelValue(body);
        }
    }

    public void Zero()
    {
        lock (_gate)
        {
            if (_request is not null)
            {
                CryptographicOperations.ZeroMemory(_request);
                _request = null;
            }

            if (_response is not null)
            {
                CryptographicOperations.ZeroMemory(_response);
                _response = null;
            }
        }
    }

    private static string? ReadTopLevelValue(byte[] body)
    {
        try
        {
            var span = body.AsSpan();
            if (span.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
            {
                span = span[3..];
            }

            var reader = new Utf8JsonReader(span, new JsonReaderOptions { MaxDepth = 32 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return null;
            }

            string? value = null;
            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                if (reader.CurrentDepth == 1 && reader.ValueTextEquals("value"u8))
                {
                    reader.Read();
                    value = reader.TokenType == JsonTokenType.String ? reader.GetString() : null;
                }
                else
                {
                    reader.Read();
                    reader.Skip();
                }
            }

            return value;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
