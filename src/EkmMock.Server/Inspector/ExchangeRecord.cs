using System.Text.Json;
using System.Text.Json.Serialization;
using EkmMock.Server.Tls;

namespace EkmMock.Server.Inspector;

/// <summary>
/// One HTTP exchange on the EKM endpoint as the inspector shows it (spec 8.1), in the groups of the spec table. It is immutable and
/// <b>masked by construction</b>: bodies are already redacted (spec 8.4), so a record can be shown, exported, written to JSONL and sent to
/// every console without another check. Raw secrets never live here; they live in <see cref="RetainedSecrets"/> beside the ring buffer slot,
/// and only when reveal is allowed.
/// </summary>
internal sealed record ExchangeRecord
{
    /// <summary>Discriminator for JSONL files, which hold exchanges and connection events side by side.</summary>
    public string Type => "exchange";

    public required ExchangeIdentity Identity { get; init; }

    /// <summary>Null when the exchange did not arrive over a captured TLS connection (the in-process test host).</summary>
    public TlsFacts? Tls { get; init; }

    public required ClientCertFacts ClientCertificate { get; init; }

    public required RequestFacts Request { get; init; }

    public required EkmContextFacts Context { get; init; }

    public required ResponseFacts Response { get; init; }

    public required TimingFacts Timing { get; init; }

    /// <summary>The key the call touched (type, size, usage after the call); null when no key was involved or found.</summary>
    public KeyFacts? Key { get; init; }

    /// <summary>The fault that fired on this exchange (spec 10.2); null when none did.</summary>
    public FaultFacts? Faults { get; init; }

    [JsonIgnore]
    public long Id => Identity.ExchangeId;

    [JsonIgnore]
    public string? Operation => Request.Operation;

    [JsonIgnore]
    public int Status => Response.Status;

    [JsonIgnore]
    public bool IsError => Response.Status >= 400;

    [JsonIgnore]
    public DateTimeOffset ReceivedAtUtc => Identity.ReceivedAtUtc;
}

/// <summary><see cref="ConnectionId"/> is null only in the in-process test host, which has no connections.</summary>
internal sealed record ExchangeIdentity(long ExchangeId, string? ConnectionId, DateTimeOffset ReceivedAtUtc, string? RemoteEndPoint);

internal sealed record TlsFacts(
    string? Protocol,
    string? CipherSuite,
    string? Alpn,
    string? Sni,
    bool? Resumed,
    double? HandshakeMs,
    int RequestNumberOnConnection)
{
    /// <summary>True for the first exchange of a connection: only that one carries the handshake time.</summary>
    [JsonIgnore]
    public bool NewConnection => RequestNumberOnConnection == 1;
}

/// <summary>The client certificate group (spec 8.1). <see cref="AuthEvaluated"/> is false when the exchange was rejected before the Auth stage (for example an unroutable path).</summary>
internal sealed record ClientCertFacts
{
    public bool Present { get; init; }

    public string? Subject { get; init; }

    public string? Issuer { get; init; }

    public string? Serial { get; init; }

    public string? ThumbprintSha256 { get; init; }

    public DateTimeOffset? NotBeforeUtc { get; init; }

    public DateTimeOffset? NotAfterUtc { get; init; }

    public string? CommonName { get; init; }

    public bool AuthEvaluated { get; init; }

    /// <summary>The chain status flags of the chain built against the namespace's own roots, or <c>NoError</c>.</summary>
    public string? ChainResult { get; init; }

    public bool? CommonNameAllowed { get; init; }

    public bool? NamespaceMatched { get; init; }

    /// <summary>Internal reason of a rejection (never on the wire; the client only sees 401).</summary>
    public string? AuthFailure { get; init; }
}

internal sealed record HeaderEntry(string Name, string Value);

internal sealed record RequestFacts
{
    public required string Method { get; init; }

    public string? HttpVersion { get; init; }

    /// <summary>The request target exactly as received (path and query, not decoded), bounded.</summary>
    public string? RawTarget { get; init; }

    /// <summary>The configured prefix of the matched namespace (empty for <c>_default</c>); null when the path matched none.</summary>
    public string? Prefix { get; init; }

    public string? Namespace { get; init; }

    public string? Key { get; init; }

    /// <summary>info, metadata, wrapkey or unwrapkey; null for an unroutable path.</summary>
    public string? Operation { get; init; }

    public string? ApiVersion { get; init; }

    public IReadOnlyList<HeaderEntry> Headers { get; init; } = [];

    public required CapturedBody Body { get; init; }
}

internal sealed record EkmContextFacts(string? RequestId, string? CorrelationId, string? PoolName, string? Algorithm);

internal sealed record ResponseFacts
{
    public required int Status { get; init; }

    /// <summary>The ProxyError <c>code</c> of a failed exchange.</summary>
    public string? Code { get; init; }

    public IReadOnlyList<HeaderEntry> Headers { get; init; } = [];

    public required CapturedBody Body { get; init; }

    /// <summary>True when the client went away before the response could be written (a client timeout, a blackholed request that the client gave up on).</summary>
    public bool ClientAborted { get; init; }

    /// <summary>True when a fault rule aborted the connection without any response (spec 10.2 "close connection"). The status is then 499, "no response".</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool ClosedByServer { get; init; }
}

internal sealed record TimingFacts
{
    /// <summary>Total server time of the exchange (the Exchange middleware, i.e. without the inspector itself).</summary>
    public required double TotalMs { get; init; }

    public double AuthMs { get; init; }

    public double CryptoMs { get; init; }

    /// <summary>Delay injected by a fault rule (spec 10.2); zero when none fired.</summary>
    public double InjectedDelayMs { get; init; }

    /// <summary>Server time before the crypto stage that is neither authorization nor injected delay (reading the request, routing, scheduling); see DECISIONS.md "M7: Limits".</summary>
    public double QueueWaitMs { get; init; }

    public required BudgetStatus Budget { get; init; }
}

internal sealed record KeyFacts(string Type, int Size, string State, long WrapCount, long UnwrapCount);

/// <summary>
/// The fault rule that fired on an exchange (spec 8.1 "Faults", spec 10.2): its id, the kind and its parameters in words (for example <c>delay 300 ms</c>, <c>error 503 (50 %)</c>),
/// and the operator's description. All of it comes from the rule, never from the request.
/// </summary>
internal sealed record FaultFacts(string Rule, string? Kind = null, string? Summary = null, string? Description = null)
{
    /// <summary>What the badge says: <c>delay 300 ms</c> when the kind is known, otherwise the rule id.</summary>
    [JsonIgnore]
    public string Label => Summary ?? Rule;
}

/// <summary>
/// A captured body, already redacted. <see cref="Text"/> is the raw text with every secret replaced by its masked form
/// (<c>32 bytes · fp 3f9a1c07b2e4</c>); <see cref="PrettyJson"/> is derived from it on demand. A body that could not be made safe is not captured at all
/// (<see cref="Captured"/> false, only the size and a note).
/// </summary>
internal sealed class CapturedBody
{
    private string? _pretty;
    private bool _prettyComputed;

    public static CapturedBody Empty { get; } = new() { SizeBytes = 0 };

    /// <summary>The size of the body on the wire (the declared or observed length, which can exceed the captured 16 KiB).</summary>
    public required long SizeBytes { get; init; }

    /// <summary>More than 16 KiB: <see cref="Text"/> covers only the first 16 KiB.</summary>
    public bool Truncated { get; init; }

    /// <summary>False when the body was deliberately not stored (an unparseable body on a position that can carry a DEK).</summary>
    public bool Captured { get; init; } = true;

    public string? Text { get; init; }

    public string? Note { get; init; }

    public IReadOnlyList<MaskedField> MaskedFields { get; init; } = [];

    /// <summary>The text as indented JSON when it is complete valid JSON, otherwise null.</summary>
    [JsonIgnore]
    public string? PrettyJson
    {
        get
        {
            if (!_prettyComputed)
            {
                _pretty = Captured && !Truncated ? TryIndent(Text) : null;
                _prettyComputed = true;
            }

            return _pretty;
        }
    }

    private static string? TryIndent(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(text);
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
            {
                document.RootElement.WriteTo(writer);
            }

            return System.Text.Encoding.UTF8.GetString(stream.GetBuffer(), 0, (int)stream.Length);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>
/// A value the inspector masked (spec 8.4). <see cref="Display"/> is what replaced it in the text. A fingerprint exists only for a value that
/// decoded as base64url; an undecodable value gets its length only.
/// </summary>
internal sealed record MaskedField(string Field, string Display, int? Bytes, string? Fingerprint, bool Revealable);

/// <summary>A connection event for the console, JSONL and the live feed (spec 8.2): the flat <c>ConnectionEvent</c> without .NET-specific types.</summary>
internal sealed record ConnectionEventRecord
{
    public string Type => "connection";

    public long Sequence { get; init; }

    public required string ConnectionId { get; init; }

    /// <summary>opened, handshake_succeeded, handshake_failed or closed.</summary>
    public required string Kind { get; init; }

    public required DateTimeOffset AtUtc { get; init; }

    public string? RemoteEndPoint { get; init; }

    public int LocalPort { get; init; }

    public string? TlsProtocol { get; init; }

    public string? CipherSuite { get; init; }

    public string? Alpn { get; init; }

    public string? Sni { get; init; }

    public bool? Resumed { get; init; }

    public double? HandshakeMs { get; init; }

    public ClientCertificateSummary? ClientCertificate { get; init; }

    /// <summary>The snake_case reason label of a failed handshake (also the metric label).</summary>
    public string? FailureReason { get; init; }

    public string? FailureDescription { get; init; }

    public string? FailureDetail { get; init; }

    public double? DurationMs { get; init; }

    public long? RequestCount { get; init; }
}

/// <summary>A connection that is open right now, for the Connections tab (spec 8.5).</summary>
internal sealed record OpenConnectionInfo(
    string ConnectionId,
    string? RemoteEndPoint,
    DateTimeOffset OpenedAtUtc,
    double AgeMs,
    long RequestCount,
    bool HandshakeCompleted,
    string? TlsProtocol,
    string? CipherSuite,
    string? Alpn,
    string? Sni,
    string? ClientCertificateSubject);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    WriteIndented = false)]
[JsonSerializable(typeof(ExchangeRecord))]
[JsonSerializable(typeof(ConnectionEventRecord))]
[JsonSerializable(typeof(AuditEntry))]
internal sealed partial class InspectorJsonContext : JsonSerializerContext
{
}
