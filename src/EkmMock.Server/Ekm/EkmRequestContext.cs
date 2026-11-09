using EkmMock.Crypto;

namespace EkmMock.Server.Ekm;

/// <summary>
/// Everything known about one EKM exchange, created by the first middleware and stored as an <see cref="HttpContext"/>
/// feature (<see cref="EkmRequestContextExtensions.GetEkmContext"/>). The log line is built from it, and the inspector (M4),
/// faults (M7) and limits (M7) read and extend it. It never holds <c>value</c>, bodies or headers.
/// </summary>
internal sealed class EkmRequestContext
{
    /// <summary>Longest request_id / correlation_id / pool_name kept (they are client supplied).</summary>
    public const int MaxContextFieldLength = 256;

    public EkmRequestContext(long exchangeId, string connectionId, DateTimeOffset receivedAtUtc, long startTimestamp)
    {
        ExchangeId = exchangeId;
        ConnectionId = connectionId;
        ReceivedAtUtc = receivedAtUtc;
        StartTimestamp = startTimestamp;
    }

    /// <summary>Sequential per process, starting at 1.</summary>
    public long ExchangeId { get; }

    public string ConnectionId { get; }

    public DateTimeOffset ReceivedAtUtc { get; }

    /// <summary><see cref="System.Diagnostics.Stopwatch.GetTimestamp"/> at the start of the exchange.</summary>
    public long StartTimestamp { get; }

    /// <summary>Set by the routing middleware; null while the path is unresolved (unknown prefix or operation).</summary>
    public EkmRoute? Route { get; set; }

    public string? NamespaceName => Route?.Namespace.Name;

    public EkmOperation? Operation => Route?.Operation;

    public string? KeyName => Route?.KeyName;

    /// <summary>The <c>api-version</c> query value once it has been validated.</summary>
    public string? ApiVersion { get; set; }

    // From request_context (spec 4.3); null when absent or the body was not parsed.
    public string? RequestId { get; set; }

    public string? CorrelationId { get; set; }

    public string? PoolName { get; set; }

    /// <summary>The <c>alg</c> of a wrap/unwrap request when it is a supported name, otherwise the literal <c>unsupported</c> (client text is never logged).</summary>
    public string? Algorithm { get; set; }

    public int RequestBodyBytes { get; set; }

    public int StatusCode { get; set; }

    /// <summary>The ProxyError <c>code</c> of a failed exchange, null on success.</summary>
    public string? ErrorCode { get; set; }

    /// <summary>Time spent inside <see cref="ICryptoBackend"/> (synchronous crypto only).</summary>
    public TimeSpan CryptoElapsed { get; set; }

    public TimeSpan Duration { get; set; }

    /// <summary>Time spent in the Auth stage (certificate chain build and CN check); zero when Auth did not run.</summary>
    public TimeSpan AuthElapsed { get; set; }

    /// <summary>Delay injected by a fault rule before the crypto call (spec 10.2), as measured; zero when no delay rule fired.</summary>
    public TimeSpan InjectedDelay { get; set; }

    /// <summary>
    /// "Queue wait" (spec 8.1): the server time between the start of the request and the start of the crypto stage that is neither authorization nor injected delay, i.e. the
    /// time spent reading the request, routing and waiting to be scheduled. EkmMock has no queue (over the concurrency limit is an immediate 429), see DECISIONS.md "M7: Limits".
    /// </summary>
    public TimeSpan QueueWait { get; set; }

    /// <summary>The fault that fired on this exchange (M7), i.e. that actually acted on it; null when none did. See <see cref="Faults.FaultDecisions.Fire"/>.</summary>
    public Faults.FaultDecision? Fault { get; set; }

    /// <summary>
    /// The fault chosen by the Faults stage that acts later (blackhole in the Limits slot, delay and key-disabled right before the crypto call). It becomes <see cref="Fault"/>
    /// only when the stage that carries it out is reached: a request that Auth or the validation rejects first is not delayed, not held, and not flagged.
    /// </summary>
    public Faults.FaultDecision? PendingFault { get; set; }

    /// <summary>Id of the fault rule that fired on this exchange (M7); null when none did.</summary>
    public string? FaultRule => Fault?.Rule.Id;

    /// <summary>The internal deadline (spec 10.1) together with <c>RequestAborted</c>; default (never cancelled) when the Limits stage did not run.</summary>
    public CancellationToken DeadlineToken { get; set; }

    /// <summary>True when the request was refused because the internal deadline passed before the crypto call could start (counted as budget exceeded).</summary>
    public bool DeadlineExceeded { get; set; }

    /// <summary><see cref="System.Diagnostics.Stopwatch.GetTimestamp"/> at the moment the crypto call returned; 0 when there was none.</summary>
    public long CryptoEndTimestamp { get; set; }

    /// <summary>True when a fault rule aborted the connection without a response (close-connection, or a blackhole that reached its hold cap).</summary>
    public bool ClosedByFault { get; set; }

    /// <summary>True once a handler asked the crypto engine about the key (so the inspector may read the key's type, size and usage counters).</summary>
    public bool EngineCalled { get; set; }

    /// <summary>1 for the first exchange on its connection, 2 for the next one, and so on; 0 when the exchange has no captured connection.</summary>
    public int RequestNumberOnConnection { get; set; }

    /// <summary>Type name (never the message) of an unexpected exception, for the log.</summary>
    public string? UnexpectedExceptionType { get; set; }

    /// <summary>True when the client went away before a response could be written.</summary>
    public bool ClientAborted { get; set; }

    /// <summary>The outcome of the Auth stage (client certificate facts, chain result, CN allowed, namespace matched); null until Auth ran.</summary>
    public EkmAuthResult? Authentication { get; set; }

    /// <summary>
    /// The single common name of the client certificate the TLS handshake accepted, read when a fault answers <em>before</em> Auth (spec 7: Faults come first), so that the log and
    /// the inspector can still say who called. It is display text only: authorization for the namespace has not been evaluated. Null otherwise.
    /// </summary>
    public string? PresentedCommonName { get; set; }

    /// <summary>The caller's common name for the log and the inspector: the authorized one when Auth ran, else the one the handshake presented (faults before Auth).</summary>
    public string? ClientCommonName => Authentication?.CommonName ?? PresentedCommonName;

    /// <summary>The connection this exchange arrived on (TLS facts, handshake time), or null when there is none (in-process test host).</summary>
    public Connections.ConnectionState? Connection { get; set; }
}

internal static class EkmRequestContextExtensions
{
    public static EkmRequestContext GetEkmContext(this HttpContext httpContext)
        => httpContext.Features.Get<EkmRequestContext>()
            ?? throw new InvalidOperationException("The EKM exchange middleware has not run for this request.");

    public static EkmRequestContext? TryGetEkmContext(this HttpContext httpContext)
        => httpContext.Features.Get<EkmRequestContext>();
}
