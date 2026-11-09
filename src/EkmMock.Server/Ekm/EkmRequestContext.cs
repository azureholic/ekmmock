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

    /// <summary>Type name (never the message) of an unexpected exception, for the log.</summary>
    public string? UnexpectedExceptionType { get; set; }

    /// <summary>True when the client went away before a response could be written.</summary>
    public bool ClientAborted { get; set; }
}

internal static class EkmRequestContextExtensions
{
    public static EkmRequestContext GetEkmContext(this HttpContext httpContext)
        => httpContext.Features.Get<EkmRequestContext>()
            ?? throw new InvalidOperationException("The EKM exchange middleware has not run for this request.");

    public static EkmRequestContext? TryGetEkmContext(this HttpContext httpContext)
        => httpContext.Features.Get<EkmRequestContext>();
}
