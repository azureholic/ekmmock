using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;

namespace EkmMock.Server.WebConsole;

internal enum PlaygroundMode
{
    /// <summary>Calls the engine in-process. Not captured as EKM traffic.</summary>
    Direct,

    /// <summary>A real HTTPS request to the EKM endpoint with the console test client certificate; it appears in Live traffic.</summary>
    ViaEkm,
}

/// <summary>Where a playground operation goes: mode, namespace, key and the wire name of the algorithm.</summary>
internal sealed record PlaygroundTarget(PlaygroundMode Mode, string Namespace, string Key, string Algorithm);

/// <summary>
/// The outcome of one playground operation. <see cref="WrappedValue"/> is ciphertext (not secret); <see cref="SecretValue"/> is a plaintext DEK and is zeroed when the
/// result is disposed. Only lengths and fingerprints are shown by default (spec 8.4).
/// </summary>
internal sealed class PlaygroundResult : IDisposable
{
    public required PlaygroundTarget Target { get; init; }

    public required string Operation { get; init; }

    public bool Ok { get; init; }

    /// <summary>The HTTP status of the EKM answer (via-EKM mode only).</summary>
    public int? HttpStatus { get; init; }

    public string? ErrorCode { get; init; }

    public string? Message { get; init; }

    /// <summary>The namespace does not trust the console test CA: the page offers the audited one-click fix.</summary>
    public bool NeedsTestClientTrust { get; init; }

    public byte[]? WrappedValue { get; init; }

    public byte[]? SecretValue { get; init; }

    public int? InputBytes { get; init; }

    public string? InputFingerprint { get; init; }

    public int? ResultBytes { get; init; }

    public string? ResultFingerprint { get; init; }

    /// <summary>On an unwrap that follows a wrap: true when the fingerprint of the unwrapped DEK equals the one that was wrapped.</summary>
    public bool? RoundTripMatches { get; init; }

    public string? RequestId { get; init; }

    public string? CorrelationId { get; init; }

    /// <summary>The exchange in Live traffic (via-EKM mode), once the capture has stored it.</summary>
    public long? ExchangeId { get; init; }

    public double ElapsedMs { get; init; }

    public void Dispose()
    {
        if (SecretValue is { } secret)
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}

/// <summary>How the DEK of a wrap is given: typed as hex, typed as base64url, or generated.</summary>
internal enum DekInputKind
{
    Hex,
    Base64Url,
    Random,
}

internal static class PlaygroundInput
{
    public const int MaxBytes = 4096;

    /// <summary>
    /// Parses a DEK (or a wrapped value) into a new buffer the caller zeroes. Hex may contain whitespace; base64url is strict (padded or not, no <c>+</c> or <c>/</c>), as on
    /// the wire. The text is never echoed in an error.
    /// </summary>
    public static byte[] Parse(DekInputKind kind, string? text, int randomBytes = 32)
    {
        switch (kind)
        {
            case DekInputKind.Random:
                if (randomBytes is < 1 or > MaxBytes)
                {
                    throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, $"The random length must be between 1 and {MaxBytes} bytes.");
                }

                return RandomNumberGenerator.GetBytes(randomBytes);

            case DekInputKind.Hex:
            {
                var compact = new string((text ?? string.Empty).Where(static c => !char.IsWhiteSpace(c)).ToArray());
                if (compact.Length == 0 || compact.Length % 2 != 0 || compact.Length > MaxBytes * 2 || !compact.All(Uri.IsHexDigit))
                {
                    throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "Enter the value as hexadecimal characters (an even number of 0-9 and a-f).");
                }

                return Convert.FromHexString(compact);
            }

            default:
            {
                var trimmed = (text ?? string.Empty).Trim();
                var utf8 = Encoding.ASCII.GetBytes(trimmed);
                var buffer = new byte[Base64UrlCodec.MaxDecodedLength(Math.Max(utf8.Length, 4)) + 4];
                try
                {
                    if (utf8.Length == 0 || !Base64UrlCodec.TryDecode(utf8, buffer, out var written) || written > MaxBytes)
                    {
                        throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "Enter the value as base64url (letters, digits, '-' and '_'; no '+' or '/').");
                    }

                    return buffer[..written];
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(utf8);
                    CryptographicOperations.ZeroMemory(buffer);
                }
            }
        }
    }

    /// <summary>The wrap algorithms that are valid for a key type (spec 4.10).</summary>
    public static IReadOnlyList<WrapAlgorithm> AlgorithmsFor(KeyType type)
        => type == KeyType.Oct ? [WrapAlgorithm.A256KWP, WrapAlgorithm.A256KW] : [WrapAlgorithm.RsaOaep256, WrapAlgorithm.RsaOaep];
}

/// <summary>
/// The crypto playground (spec 8.5.8). <b>Direct</b> calls the engine in-process; <b>via EKM</b> sends a real mutual-TLS request through <see cref="EkmSelfClient"/>, so it
/// is captured like any other call. Secrets: the DEK passed in is owned (and zeroed) by the caller; request and response buffers created here are zeroed; results show
/// length and fingerprint only, and the plaintext of an unwrap is revealed solely through <see cref="Reveal"/> (gate and audit, same rules as the inspector).
/// </summary>
internal sealed class PlaygroundService
{
    public const string PoolName = "ekmmock-playground";

    private readonly ICryptoBackend _backend;
    private readonly IKeyManager _keys;
    private readonly NamespaceStore _namespaces;
    private readonly NamespaceAdminService _namespaceAdmin;
    private readonly EkmSelfClient _client;
    private readonly IInspectorQuery _inspector;
    private readonly AuditRecorder _audit;

    public PlaygroundService(
        ICryptoBackend backend,
        IKeyManager keys,
        NamespaceStore namespaces,
        NamespaceAdminService namespaceAdmin,
        EkmSelfClient client,
        IInspectorQuery inspector,
        AuditRecorder audit)
    {
        _backend = backend;
        _keys = keys;
        _namespaces = namespaces;
        _namespaceAdmin = namespaceAdmin;
        _client = client;
        _inspector = inspector;
        _audit = audit;
    }

    /// <summary>Whether the plaintext result of an unwrap may be shown on request (<c>EKMMOCK_INSPECTOR_ALLOW_REVEAL=true</c> and <c>Inspector:SecretDisplay=Reveal</c>).</summary>
    public bool RevealAllowed => _inspector.Status().RevealAllowed;

    public Task<PlaygroundResult> WrapAsync(string actor, PlaygroundTarget target, ReadOnlyMemory<byte> dek, CancellationToken cancellationToken = default)
        => RunAsync(actor, target, "wrap", dek, expectedBytes: null, expectedFingerprint: null, cancellationToken);

    /// <summary>Unwraps a value. When <paramref name="expectedFingerprint"/> is given (the fingerprint of the DEK that was wrapped), the result says whether they are equal.</summary>
    public Task<PlaygroundResult> UnwrapAsync(string actor, PlaygroundTarget target, ReadOnlyMemory<byte> wrapped, int? expectedBytes = null, string? expectedFingerprint = null, CancellationToken cancellationToken = default)
        => RunAsync(actor, target, "unwrap", wrapped, expectedBytes, expectedFingerprint, cancellationToken);

    /// <summary>
    /// Returns the plaintext DEK of an unwrap result as base64url and hex, only when the reveal gate is open. The audit entry is written first; if that fails nothing is
    /// returned. A refused attempt is audited too.
    /// </summary>
    public (string Base64Url, string Hex) Reveal(string actor, PlaygroundResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var target = $"key:{result.Target.Namespace}/{result.Target.Key}";
        if (!RevealAllowed)
        {
            _audit.Record(actor, AuditActions.PlaygroundRevealDenied, target, "reveal is not allowed on this instance");
            throw new ConsoleActionException(ConsoleErrorCode.Forbidden, "Reveal is not allowed: start the process with EKMMOCK_INSPECTOR_ALLOW_REVEAL=true and set Inspector:SecretDisplay=Reveal.");
        }

        if (result.SecretValue is not { } secret)
        {
            throw new ConsoleActionException(ConsoleErrorCode.Conflict, "This result holds no plaintext DEK.");
        }

        _audit.Record(actor, AuditActions.PlaygroundReveal, target, $"{secret.Length} bytes");
        return (Base64Url.EncodeToString(secret), Convert.ToHexStringLower(secret));
    }

    // ---- internals ----

    private async Task<PlaygroundResult> RunAsync(string actor, PlaygroundTarget target, string operation, ReadOnlyMemory<byte> input, int? expectedBytes, string? expectedFingerprint, CancellationToken cancellationToken)
    {
        if (!WrapAlgorithms.TryParse(target.Algorithm, out var algorithm))
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "Choose one of A256KW, A256KWP, RSA-OAEP-256 or RSA-OAEP.");
        }

        var definition = _namespaces.Get(target.Namespace) ?? throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Namespace not found.");
        var info = _keys.Get(new KeyRef(target.Namespace, target.Key)) ?? throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Key not found.");
        if (info.Type != algorithm.RequiredKeyType())
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, $"{target.Algorithm} cannot be used with a {(info.Type == KeyType.Oct ? "AES" : "RSA")} key.");
        }

        var result = target.Mode == PlaygroundMode.Direct
            ? RunDirect(target, algorithm, operation, input.Span, expectedBytes, expectedFingerprint)
            : await RunViaEkmAsync(definition, target, algorithm, operation, input, expectedBytes, expectedFingerprint, cancellationToken).ConfigureAwait(false);

        // Running an operation bumps the key's usage counters, so it is audited like a state change: who used which key, how, and with what outcome (never the data).
        _audit.Record(
            actor,
            operation == "wrap" ? AuditActions.PlaygroundWrap : AuditActions.PlaygroundUnwrap,
            $"key:{target.Namespace}/{target.Key}",
            $"mode={(target.Mode == PlaygroundMode.Direct ? "direct" : "ekm")} alg={target.Algorithm} {(result.Ok ? "ok" : "failed:" + (result.ErrorCode ?? "error"))}");
        return result;
    }

    private PlaygroundResult RunDirect(PlaygroundTarget target, WrapAlgorithm algorithm, string operation, ReadOnlySpan<byte> input, int? expectedBytes, string? expectedFingerprint)
    {
        var key = new KeyRef(target.Namespace, target.Key);
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        try
        {
            if (operation == "wrap")
            {
                var wrapped = _backend.Wrap(key, algorithm, input);
                return Success(target, operation, started, wrapped: wrapped, secret: null, inputBytes: input.Length, inputFingerprint: SecretFingerprint.Compute(input), expectedBytes, expectedFingerprint, status: null, requestId: null, correlationId: null, exchangeId: null);
            }

            var dek = _backend.Unwrap(key, algorithm, input);
            return Success(target, operation, started, wrapped: null, secret: dek, inputBytes: input.Length, inputFingerprint: null, expectedBytes, expectedFingerprint, status: null, requestId: null, correlationId: null, exchangeId: null);
        }
        catch (EkmEngineException exception)
        {
            return Failure(target, operation, started, null, exception.Code, exception.Message, needsTrust: false, requestId: null, correlationId: null, exchangeId: null, input.Length, operation == "wrap" ? SecretFingerprint.Compute(input) : null);
        }
    }

    private async Task<PlaygroundResult> RunViaEkmAsync(NamespaceDefinition definition, PlaygroundTarget target, WrapAlgorithm algorithm, string operation, ReadOnlyMemory<byte> input, int? expectedBytes, string? expectedFingerprint, CancellationToken cancellationToken)
    {
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        var inputFingerprint = operation == "wrap" ? SecretFingerprint.Compute(input.Span) : null;
        if (!_namespaceAdmin.TrustsConsoleTestClient(definition.Name))
        {
            return Failure(
                target, operation, started, null, "TestClientNotTrusted",
                $"Namespace '{definition.Name}' does not trust the console test client (CN {ConsoleTestIdentity.CommonName}). Trust the test CA in this namespace first.",
                needsTrust: true, requestId: null, correlationId: null, exchangeId: null, input.Length, inputFingerprint);
        }

        var requestId = Guid.NewGuid().ToString();
        var correlationId = Guid.NewGuid().ToString();
        var path = (definition.Prefix.Length == 0 ? string.Empty : "/" + definition.Prefix) + $"/{target.Key}/{(operation == "wrap" ? "wrapkey" : "unwrapkey")}?api-version={EkmApi.SupportedApiVersion}";

        var body = new ArrayBufferWriter<byte>(256 + Base64Url.GetEncodedLength(input.Length));
        var encoded = new byte[Base64Url.GetEncodedLength(input.Length)];
        SelfResponse? response = null;
        try
        {
            Base64Url.EncodeToUtf8(input.Span, encoded, out _, out var encodedLength);
            using (var writer = new Utf8JsonWriter(body))
            {
                writer.WriteStartObject();
                writer.WriteStartObject("request_context");
                writer.WriteString("request_id", requestId);
                writer.WriteString("correlation_id", correlationId);
                writer.WriteString("pool_name", PoolName);
                writer.WriteEndObject();
                writer.WriteString("alg", target.Algorithm);
                writer.WriteString("value"u8, encoded.AsSpan(0, encodedLength));
                writer.WriteEndObject();
            }

            response = await _client.SendAsync("POST", path, "application/json", body.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
            body.Clear();
        }

        var exchangeId = await FindExchangeAsync(correlationId, cancellationToken).ConfigureAwait(false);
        try
        {
            if (response.Status == StatusCodes.Status200OK)
            {
                var value = ReadValue(response.Body, out var parsed);
                if (!parsed || value is null)
                {
                    return Failure(target, operation, started, response.Status, "InvalidResponse", "The EKM endpoint answered 200 without a readable value.", needsTrust: false, requestId, correlationId, exchangeId, input.Length, inputFingerprint);
                }

                return operation == "wrap"
                    ? Success(target, operation, started, wrapped: value, secret: null, inputBytes: input.Length, inputFingerprint, expectedBytes, expectedFingerprint, response.Status, requestId, correlationId, exchangeId)
                    : Success(target, operation, started, wrapped: null, secret: value, inputBytes: input.Length, inputFingerprint: null, expectedBytes, expectedFingerprint, response.Status, requestId, correlationId, exchangeId);
            }

            var (code, message) = ReadError(response.Body);
            var needsTrust = response.Status == StatusCodes.Status401Unauthorized;
            return Failure(
                target, operation, started, response.Status, code ?? "Error",
                needsTrust ? "The EKM endpoint answered 401 Unauthenticated: the namespace does not trust the console test client. Trust the test CA in this namespace." : message ?? "The EKM endpoint refused the request.",
                needsTrust, requestId, correlationId, exchangeId, input.Length, inputFingerprint);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(response.Body);
        }
    }

    private PlaygroundResult Success(
        PlaygroundTarget target,
        string operation,
        long started,
        byte[]? wrapped,
        byte[]? secret,
        int inputBytes,
        string? inputFingerprint,
        int? expectedBytes,
        string? expectedFingerprint,
        int? status,
        string? requestId,
        string? correlationId,
        long? exchangeId)
    {
        var resultBytes = secret ?? wrapped;
        var fingerprint = secret is null ? null : SecretFingerprint.Compute(secret);
        bool? matches = secret is not null && expectedFingerprint is not null ? string.Equals(fingerprint, expectedFingerprint, StringComparison.Ordinal) && secret.Length == expectedBytes : null;
        return new PlaygroundResult
        {
            Target = target,
            Operation = operation,
            Ok = true,
            HttpStatus = status,
            WrappedValue = wrapped,
            SecretValue = secret,
            InputBytes = inputBytes,
            InputFingerprint = inputFingerprint,
            ResultBytes = resultBytes?.Length,
            ResultFingerprint = fingerprint,
            RoundTripMatches = matches,
            RequestId = requestId,
            CorrelationId = correlationId,
            ExchangeId = exchangeId,
            ElapsedMs = System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds,
        };
    }

    private static PlaygroundResult Failure(
        PlaygroundTarget target,
        string operation,
        long started,
        int? status,
        string code,
        string message,
        bool needsTrust,
        string? requestId,
        string? correlationId,
        long? exchangeId,
        int inputBytes,
        string? inputFingerprint)
        => new()
        {
            Target = target,
            Operation = operation,
            Ok = false,
            HttpStatus = status,
            ErrorCode = code,
            Message = message,
            NeedsTestClientTrust = needsTrust,
            InputBytes = inputBytes,
            InputFingerprint = inputFingerprint,
            RequestId = requestId,
            CorrelationId = correlationId,
            ExchangeId = exchangeId,
            ElapsedMs = System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds,
        };

    // The capture stores the exchange asynchronously (spec 8.3), so look for it by its fresh correlation id for a moment. Never blocks the result: no exchange id is fine.
    private async Task<long?> FindExchangeAsync(string correlationId, CancellationToken cancellationToken)
    {
        var deadline = System.Diagnostics.Stopwatch.GetTimestamp();
        var filter = new ExchangeFilter { Text = correlationId };
        var paging = new ExchangePaging { Limit = 1 };
        while (System.Diagnostics.Stopwatch.GetElapsedTime(deadline) < TimeSpan.FromSeconds(3))
        {
            var page = _inspector.Query(filter, paging);
            if (page.Items.Count > 0)
            {
                return page.Items[0].Id;
            }

            await Task.Delay(25, cancellationToken).ConfigureAwait(false);
        }

        return null;
    }

    // Reads the "value" property of an answer without ever turning the DEK into a string.
    private static byte[]? ReadValue(byte[] body, out bool parsed)
    {
        parsed = false;
        var decoded = new byte[Base64UrlCodec.MaxDecodedLength(Math.Max(body.Length, 4)) + 4];
        try
        {
            var reader = new Utf8JsonReader(body);
            var depth = 0;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                    case JsonTokenType.StartArray:
                        depth++;
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.EndArray:
                        depth--;
                        break;
                    case JsonTokenType.PropertyName when depth == 1 && reader.ValueTextEquals("value"u8):
                        if (!reader.Read() || reader.TokenType != JsonTokenType.String || reader.ValueIsEscaped || reader.HasValueSequence)
                        {
                            return null;
                        }

                        if (!Base64UrlCodec.TryDecode(reader.ValueSpan, decoded, out var written))
                        {
                            return null;
                        }

                        parsed = true;
                        return decoded[..written];
                }
            }

            return null;
        }
        catch (JsonException)
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    private static (string? Code, string? Message) ReadError(byte[] body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return (null, null);
            }

            var code = document.RootElement.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
            var message = document.RootElement.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() : null;
            return (Bound(code), Bound(message));
        }
        catch (JsonException)
        {
            return (null, null);
        }
    }

    private static string? Bound(string? value) => value is null ? null : value.Length <= 200 ? value : value[..200];
}
