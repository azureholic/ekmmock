using System.Collections;
using System.Diagnostics;
using EkmMock.Server.Connections;
using EkmMock.Server.Hosting;

namespace EkmMock.Server.Ekm;

/// <summary>
/// First middleware of the EKM pipeline. It creates the <see cref="EkmRequestContext"/>, is the global safety net (whatever
/// is thrown below becomes a ProxyError through <see cref="ProxyErrors.Map"/>, so no non-ProxyError body can escape),
/// and writes the one structured log line per request (spec 9). The inspector's RequestCapture (M4) goes in front of it.
/// </summary>
internal sealed class EkmExchangeMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ExchangeCounter _counter;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Connections.ConnectionRegistry _connections;

    public EkmExchangeMiddleware(RequestDelegate next, ExchangeCounter counter, TimeProvider time, ILoggerFactory loggerFactory, Connections.ConnectionRegistry connections)
    {
        _next = next;
        _counter = counter;
        _time = time;
        _logger = loggerFactory.CreateLogger("EkmMock.Exchange");
        _connections = connections;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var exchange = new EkmRequestContext(_counter.Next(), context.Connection.Id, _time.GetUtcNow(), Stopwatch.GetTimestamp());
        context.Features.Set(exchange);
        exchange.Connection = _connections.TryGet(context.Connection.Id);
        exchange.Connection?.RequestStarted();
        try
        {
            await _next(context).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            // The client went away; there is nobody to answer. Not an error of ours.
            exchange.ClientAborted = true;
        }
        catch (Exception exception)
        {
            await WriteErrorAsync(context, exchange, exception).ConfigureAwait(false);
        }
        finally
        {
            exchange.Duration = Stopwatch.GetElapsedTime(exchange.StartTimestamp);
            exchange.StatusCode = exchange.ClientAborted ? 499 : context.Response.StatusCode;
            EkmExchangeLog.Write(_logger, exchange);
        }
    }

    private static async Task WriteErrorAsync(HttpContext context, EkmRequestContext exchange, Exception exception)
    {
        var mapped = ProxyErrors.Map(exception, exchange.Operation);
        exchange.ErrorCode = mapped.Code.ToString();
        exchange.UnexpectedExceptionType = mapped.UnexpectedExceptionType;

        if (context.Response.HasStarted)
        {
            // Too late for a ProxyError; do not leave a half written body behind.
            context.Abort();
            return;
        }

        try
        {
            await EkmResponse.WriteErrorAsync(context, mapped).ConfigureAwait(false);
        }
        catch (Exception) when (context.RequestAborted.IsCancellationRequested)
        {
            exchange.ClientAborted = true;
        }
    }
}

/// <summary>Resolves the namespace, operation and key from the path (spec 4.2). Everything unroutable is 404 NotFound.</summary>
internal sealed class EkmRouteMiddleware
{
    private readonly RequestDelegate _next;
    private readonly EkmMock.Crypto.NamespaceStore _namespaces;

    public EkmRouteMiddleware(RequestDelegate next, EkmMock.Crypto.NamespaceStore namespaces)
    {
        _next = next;
        _namespaces = namespaces;
    }

    public Task InvokeAsync(HttpContext context)
    {
        var exchange = context.GetEkmContext();
        exchange.Route = EkmRouter.TryRoute(_namespaces, context.Request.Path.Value)
            ?? throw new EkmProtocolException(ProxyErrorCode.NotFound);
        return _next(context);
    }
}

/// <summary>
/// The EKM request pipeline in the order of spec section 7. The connection-level stages (ConnectionCapture, TLS) are Kestrel connection
/// middleware on the EKM listener (<c>EkmKestrelSetup</c>); everything here is HTTP middleware that runs only on the EKM port.
/// </summary>
internal static class EkmPipeline
{
    /// <summary>
    /// Wires the port separation of spec 5.4: the EKM pipeline runs <em>only</em> for connections that arrived on an EKM listener port
    /// (<see cref="IEkmPortPolicy"/>, decided by <c>HttpContext.Connection.LocalPort</c>, never by Host header). Every other port gets a
    /// plain <c>404</c> for everything, so EKM routes cannot be reached through the console listener. The console pipeline (M5) replaces that
    /// 404 branch; on the EKM port anything that is not an EKM route is answered with the EKM-style ProxyError <c>404</c>.
    /// </summary>
    public static IApplicationBuilder UseEkmPipeline(this IApplicationBuilder app)
    {
        var ports = app.ApplicationServices.GetRequiredService<IEkmPortPolicy>();

        app.UseWhen(context => ports.IsEkmPort(context.Connection.LocalPort), branch =>
        {
            // [M4] RequestCapture goes before the exchange middleware: it must see rejected requests too.
            branch.UseMiddleware<EkmExchangeMiddleware>();

            // Routing is resolved early because faults (per namespace/key/op) and auth (per namespace) both need it.
            branch.UseMiddleware<EkmRouteMiddleware>();

            // [M7] Faults slot in before Auth; [M7] Limits after it.
            branch.UseMiddleware<EkmAuthMiddleware>();

            branch.Run(static context => context.RequestServices.GetRequiredService<EkmDispatcher>().InvokeAsync(context));
        });

        // Reached only by requests that did not arrive on an EKM port.
        app.Run(static context =>
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return Task.CompletedTask;
        });

        return app;
    }
}

/// <summary>
/// The structured request log line (spec 9) with the fields that exist at this milestone. It is built from fixed fields only:
/// never <c>value</c>, <c>n</c>, <c>e</c>, bodies or headers. <c>client_cn</c> and <c>injected_delay_ms</c> arrive with M3/M7.
/// </summary>
internal static class EkmExchangeLog
{
    public static void Write(ILogger logger, EkmRequestContext exchange)
    {
        var level = exchange.UnexpectedExceptionType is null ? LogLevel.Information : LogLevel.Error;
        if (!logger.IsEnabled(level))
        {
            return;
        }

        logger.Log(level, new EventId(1, "EkmExchange"), new ExchangeLogState(exchange), null, static (state, _) => state.ToString());
    }

    internal sealed class ExchangeLogState : IReadOnlyList<KeyValuePair<string, object?>>
    {
        private readonly KeyValuePair<string, object?>[] _fields;

        public ExchangeLogState(EkmRequestContext e)
        {
            _fields =
            [
                new("exchange_id", e.ExchangeId),
                new("request_id", e.RequestId),
                new("correlation_id", e.CorrelationId),
                new("pool_name", e.PoolName),
                new("namespace", e.NamespaceName),
                new("op", e.Operation?.WireName()),
                new("key", Truncate(e.KeyName, 80)),
                new("alg", e.Algorithm),
                new("status", e.StatusCode),
                new("error_code", e.ErrorCode),
                new("duration_ms", Math.Round(e.Duration.TotalMilliseconds, 3)),
                new("crypto_ms", Math.Round(e.CryptoElapsed.TotalMilliseconds, 3)),
                new("client_cn", e.Authentication?.CommonName),
                new("auth_failure", e.Authentication is { Succeeded: false } auth ? auth.Failure.ToString() : null),
                new("exception_type", e.UnexpectedExceptionType),
            ];
            Summary = $"EKM {e.Operation?.WireName() ?? "unrouted"} {e.StatusCode} exchange={e.ExchangeId}";
        }

        private string Summary { get; }

        public int Count => _fields.Length;

        public KeyValuePair<string, object?> this[int index] => _fields[index];

        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() => ((IEnumerable<KeyValuePair<string, object?>>)_fields).GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public override string ToString() => Summary;

        private static string? Truncate(string? value, int max) => value is not null && value.Length > max ? value[..max] : value;
    }
}
