using System.Diagnostics;
using EkmMock.Server.Faults;
using EkmMock.Server.Inspector;
using EkmMock.Server.Metrics;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Ekm;

/// <summary>
/// The concurrency limit of spec 10.1 as a counter: <see cref="TryEnter"/> either takes a slot at once or says no, never waits and never blocks a thread (there is no queue:
/// "over the limit, return 429 immediately"). <see cref="Exit"/> must be called exactly once per successful entry (the Limits middleware does so in a <c>finally</c>, so a
/// thrown exception or an aborted connection cannot leak a slot). <see cref="InFlight"/> is the <c>ekmmock_inflight_requests</c> gauge.
/// </summary>
internal sealed class ConcurrencyGate
{
    private int _inFlight;

    public ConcurrencyGate(IOptions<LimitsOptions> options) => Limit = options.Value.MaxConcurrency;

    public ConcurrencyGate(int limit) => Limit = limit;

    public int Limit { get; }

    public int InFlight => Volatile.Read(ref _inFlight);

    /// <summary>
    /// Takes a slot or says no, and never lets <see cref="InFlight"/> exceed <see cref="Limit"/>, not even transiently (a compare-and-swap loop instead of
    /// increment-then-undo), so the <c>ekmmock_inflight_requests</c> gauge can never show more than the limit.
    /// </summary>
    public bool TryEnter()
    {
        int current;
        do
        {
            current = Volatile.Read(ref _inFlight);
            if (current >= Limit)
            {
                return false;
            }
        }
        while (Interlocked.CompareExchange(ref _inFlight, current + 1, current) != current);

        return true;
    }

    public void Exit() => Interlocked.Decrement(ref _inFlight);
}

/// <summary>Options of the fault execution that are not rules.</summary>
internal sealed class FaultOptions
{
    public const string SectionName = "Faults";

    /// <summary>
    /// How long a blackholed request is held at most, in seconds, before the connection is aborted (0 for no cap). A blackhole holds a concurrency slot for as long as it lasts, so
    /// a client that never gives up would otherwise pin the slot until the process stops. Default 600.
    /// </summary>
    public int BlackholeMaxHoldSeconds { get; set; } = 600;
}

/// <summary>
/// The Limits stage of the EKM pipeline (spec 7, 10.1), after Auth: takes a concurrency slot or answers <c>429</c> at once, gives the request its internal deadline (a
/// <see cref="CancellationTokenSource"/> that is disposed with the request), carries out a blackhole fault inside the slot (so that pending blackholes count against the limit,
/// which is the point of the test feature), and counts a request whose deadline was exceeded in <c>ekmmock_budget_exceeded_total</c>.
/// <para>
/// Crypto itself is synchronous and is never cancelled once started; the deadline only guards the way <em>to</em> the crypto call (see <see cref="EkmRequestContextLimits"/>).
/// </para>
/// </summary>
internal sealed class EkmLimitsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ConcurrencyGate _gate;
    private readonly EkmMetrics _metrics;
    private readonly LimitsOptions _limits;
    private readonly FaultOptions _faults;
    private readonly IHostApplicationLifetime _lifetime;

    public EkmLimitsMiddleware(
        RequestDelegate next,
        ConcurrencyGate gate,
        EkmMetrics metrics,
        IOptions<LimitsOptions> limits,
        IOptions<FaultOptions> faults,
        IHostApplicationLifetime lifetime)
    {
        _next = next;
        _gate = gate;
        _metrics = metrics;
        _limits = limits.Value;
        _faults = faults.Value;
        _lifetime = lifetime;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var exchange = context.GetEkmContext();
        if (!_gate.TryEnter())
        {
            throw new EkmProtocolException(ProxyErrorCode.TooManyRequests, "The concurrency limit was reached");
        }

        try
        {
            // The deadline is measured from the start of the exchange, not from here: time spent before this stage (reading headers, authorization) counts.
            var remaining = TimeSpan.FromMilliseconds(_limits.InternalDeadlineMs) - Stopwatch.GetElapsedTime(exchange.StartTimestamp);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            deadline.CancelAfter(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero);
            exchange.DeadlineToken = deadline.Token;

            if (exchange.PendingFault is { Kind: FaultKind.Blackhole } blackhole)
            {
                exchange.Fire(blackhole);
                await BlackholeAsync(context, exchange).ConfigureAwait(false);
                return;
            }

            await _next(context).ConfigureAwait(false);
        }
        finally
        {
            _gate.Exit();
            exchange.DeadlineToken = default; // the source is disposed with this request
            if (exchange.DeadlineExceeded || CryptoEndedAfterDeadline(exchange))
            {
                _metrics.RecordBudgetExceeded(exchange.Operation);
            }
        }
    }

    private bool CryptoEndedAfterDeadline(EkmRequestContext exchange)
        => exchange.CryptoEndTimestamp != 0
            && Stopwatch.GetElapsedTime(exchange.StartTimestamp, exchange.CryptoEndTimestamp) > TimeSpan.FromMilliseconds(_limits.InternalDeadlineMs);

    /// <summary>
    /// Spec 10.2 "Blackhole": the request is accepted and never answered. Nothing blocks a thread: this awaits a task that never completes by itself and is cancelled by the
    /// client going away (the normal end), the hold cap, or the host stopping. When the client goes away the cancellation propagates to the Exchange middleware, which records
    /// the exchange as "no response" (status 499).
    /// </summary>
    private async Task BlackholeAsync(HttpContext context, EkmRequestContext exchange)
    {
        using var hold = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, _lifetime.ApplicationStopping);
        if (_faults.BlackholeMaxHoldSeconds > 0)
        {
            hold.CancelAfter(TimeSpan.FromSeconds(_faults.BlackholeMaxHoldSeconds));
        }

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, hold.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!context.RequestAborted.IsCancellationRequested)
        {
            // The hold cap or the shutdown ended it, not the client: close the connection, the nearest thing to "never answered" that frees the slot.
            exchange.ClosedByFault = true;
            context.Abort();
        }
    }
}

/// <summary>The pre-crypto checkpoint of spec 10.1, called by the dispatcher right before the operation starts.</summary>
internal static class EkmRequestContextLimits
{
    /// <summary>
    /// Records the queue wait and enforces the internal deadline: when the deadline has passed before the crypto call starts the answer is an immediate <c>429</c> (spec 10.1:
    /// "a fast, explicit error beats a vague Azure-side timeout"). Does nothing but record when the Limits stage did not run (the benchmark pipeline).
    /// </summary>
    public static void EnterCryptoStage(this EkmRequestContext exchange, HttpContext context)
    {
        var elapsed = Stopwatch.GetElapsedTime(exchange.StartTimestamp);
        var queueWait = elapsed - exchange.AuthElapsed;
        exchange.QueueWait = queueWait > TimeSpan.Zero ? queueWait : TimeSpan.Zero;
        exchange.ThrowIfDeadlineExceeded(context);
    }

    public static void ThrowIfDeadlineExceeded(this EkmRequestContext exchange, HttpContext context)
    {
        if (exchange.DeadlineToken.IsCancellationRequested && !context.RequestAborted.IsCancellationRequested)
        {
            exchange.DeadlineExceeded = true;
            throw new EkmProtocolException(ProxyErrorCode.TooManyRequests, "The internal deadline was reached before the request could be processed");
        }
    }
}
