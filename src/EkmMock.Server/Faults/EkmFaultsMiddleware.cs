using EkmMock.Server.Ekm;

namespace EkmMock.Server.Faults;

/// <summary>
/// The Faults stage of the EKM pipeline (spec 7: <c>Route → Faults → Auth → Limits</c>). It evaluates the rules once for the routed request, records the winning rule on the
/// exchange (so the log line, the inspector and the badge in Live traffic show it) and carries out the faults that need no concurrency slot and no request body:
/// <list type="bullet">
/// <item><b>HSM offline</b> and <b>error rate</b> answer immediately (503 HsmUnavailable; 429 TooManyRequests, 500 InternalError or 503 HsmUnavailable).</item>
/// <item><b>Close connection</b> aborts the connection without a response.</item>
/// <item><b>Delay</b>, <b>key disabled</b> and <b>blackhole</b> are carried by <see cref="EkmRequestContext.Fault"/> and acted on later: the blackhole inside the Limits slot,
/// the delay and the key-disabled answer in the dispatcher right before the crypto call.</item>
/// </list>
/// Faults exist only on the EKM branch of the pipeline, so they can never touch the console, <c>/healthz</c>, <c>/readyz</c> or <c>/metrics</c>.
/// </summary>
internal sealed class EkmFaultsMiddleware
{
    private const int MaxCommonNameLength = 128;

    private readonly RequestDelegate _next;
    private readonly FaultRuleStore _rules;

    public EkmFaultsMiddleware(RequestDelegate next, FaultRuleStore rules)
    {
        _next = next;
        _rules = rules;
    }

    public Task InvokeAsync(HttpContext context)
    {
        var exchange = context.GetEkmContext();
        var route = exchange.Route ?? throw new EkmProtocolException(ProxyErrorCode.NotFound);

        if (_rules.Resolve(route) is not { } decision)
        {
            return _next(context);
        }

        switch (decision.Kind)
        {
            case FaultKind.HsmOffline:
                Act(context, exchange, decision);
                throw new EkmProtocolException(ProxyErrorCode.HsmUnavailable);

            case FaultKind.Error:
                Act(context, exchange, decision);
                throw new EkmProtocolException(ErrorCodeOf(decision.StatusCode));

            case FaultKind.CloseConnection:
                Act(context, exchange, decision);
                exchange.ClosedByFault = true;
                context.Abort();
                return Task.CompletedTask;

            default:
                // Delay, key disabled and blackhole act later, if the request gets that far (see EkmRequestContext.PendingFault).
                exchange.PendingFault = decision;
                return _next(context);
        }
    }

    // The faults that answer here do so before Auth, so the log and the inspector would not know who called: read the name of the certificate the handshake accepted (display only).
    private static void Act(HttpContext context, EkmRequestContext exchange, FaultDecision decision)
    {
        exchange.Fire(decision);
        if (context.Connection.ClientCertificate is { } presented
            && Tls.CommonNameReader.TryGetSingleCommonName(presented.SubjectName, out var commonName))
        {
            exchange.PresentedCommonName = commonName is { Length: > MaxCommonNameLength } ? commonName[..MaxCommonNameLength] : commonName;
        }
    }

    /// <summary>The ProxyError code of the three injectable statuses (spec 4.4); the rule validation admits no other.</summary>
    internal static ProxyErrorCode ErrorCodeOf(int status) => status switch
    {
        StatusCodes.Status429TooManyRequests => ProxyErrorCode.TooManyRequests,
        StatusCodes.Status503ServiceUnavailable => ProxyErrorCode.HsmUnavailable,
        _ => ProxyErrorCode.InternalError,
    };
}
