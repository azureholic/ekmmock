using EkmMock.Server.Connections;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Inspector;

/// <summary>
/// One consumer of captured traffic: the ring buffer, the dashboard aggregator, the live feed, the JSONL writer and the connection statistics are stages.
/// They run on the consumer threads, never on the request path, and must not throw (a stage that does is isolated from the others).
/// </summary>
internal interface IInspectorStage
{
    void OnExchange(CapturedExchange exchange)
    {
    }

    void OnConnectionEvent(ConnectionEventRecord connectionEvent)
    {
    }

    /// <summary>Called when the queue ran empty: the moment to flush buffered output.</summary>
    void OnIdle()
    {
    }
}

internal static class ConnectionEventRecords
{
    public static ConnectionEventRecord From(ConnectionEvent e) => new()
    {
        Sequence = e.Sequence,
        ConnectionId = e.ConnectionId,
        Kind = e.Kind switch
        {
            ConnectionEventKind.Opened => "opened",
            ConnectionEventKind.HandshakeSucceeded => "handshake_succeeded",
            ConnectionEventKind.HandshakeFailed => "handshake_failed",
            ConnectionEventKind.Closed => "closed",
            _ => "unknown",
        },
        AtUtc = e.AtUtc,
        RemoteEndPoint = e.RemoteEndPoint,
        LocalPort = e.LocalPort,
        TlsProtocol = e.TlsProtocol,
        CipherSuite = e.CipherSuite,
        Alpn = e.Alpn,
        Sni = e.Sni,
        Resumed = e.Resumed,
        HandshakeMs = e.HandshakeTime is { } handshake ? Math.Round(handshake.TotalMilliseconds, 3) : null,
        ClientCertificate = e.ClientCertificate,
        FailureReason = e.FailureReason is { } reason ? HandshakeFailureReasons.Label(reason) : null,
        FailureDescription = e.FailureReason is { } described ? HandshakeFailureReasons.Describe(described) : null,
        FailureDetail = e.FailureDetail,
        DurationMs = e.Duration is { } duration ? Math.Round(duration.TotalMilliseconds, 3) : null,
        RequestCount = e.RequestCount,
    };
}

/// <summary>
/// The bounded hand-over between the request path and the consumer (spec 8.3). The request path only calls <see cref="Enqueue"/>, which never blocks and
/// never awaits: when the queue is full the <em>oldest</em> record is dropped, its raw secrets (if any) are zeroed, and the drop is counted
/// (<c>ekmmock_inspector_dropped_total</c>).
/// </summary>
internal sealed class InspectorPipeline
{
    private readonly BoundedDropOldestQueue<CapturedExchange> _queue;

    public InspectorPipeline(IOptions<InspectorOptions> options, EkmMetrics metrics)
    {
        _queue = new BoundedDropOldestQueue<CapturedExchange>(
            options.Value.ChannelCapacity,
            dropped =>
            {
                dropped.Secrets?.Zero();
                metrics.RecordInspectorDropped();
            });
    }

    public int Capacity => _queue.Capacity;

    /// <summary>Exchanges dropped because the queue was full.</summary>
    public long Dropped => _queue.Dropped;

    public System.Threading.Channels.ChannelReader<CapturedExchange> Reader => _queue.Reader;

    public bool Enqueue(CapturedExchange exchange) => _queue.TryEnqueue(exchange);

    public void Complete() => _queue.Complete();
}

/// <summary>
/// The single background consumer of the capture queue (spec 8.3). It hands each exchange to the stages in registration order (ring buffer first, so a record
/// is queryable before it is pushed to a console), and tells them when the queue ran empty. At shutdown it drains what is left.
/// </summary>
internal sealed class InspectorConsumer : BackgroundService
{
    private readonly InspectorPipeline _pipeline;
    private readonly IInspectorStage[] _stages;
    private readonly InspectorFeed _feed;
    private readonly ILogger _logger;
    private long _stageFailures;

    public InspectorConsumer(InspectorPipeline pipeline, IEnumerable<IInspectorStage> stages, InspectorFeed feed, ILoggerFactory loggerFactory)
    {
        _pipeline = pipeline;
        _stages = [.. stages];
        _feed = feed;
        _logger = loggerFactory.CreateLogger("EkmMock.Inspector");
    }

    /// <summary>Failures of stages (never of requests) since the process started.</summary>
    public long StageFailures => Interlocked.Read(ref _stageFailures);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var reader = _pipeline.Reader;
        try
        {
            while (await reader.WaitToReadAsync(stoppingToken).ConfigureAwait(false))
            {
                while (reader.TryRead(out var exchange))
                {
                    Process(exchange);
                }

                Idle();
            }
        }
        catch (OperationCanceledException)
        {
            // The host is stopping: drain below.
        }

        while (reader.TryRead(out var remaining))
        {
            Process(remaining);
        }

        Idle();
        _feed.CompleteAll();
    }

    private void Process(CapturedExchange exchange)
    {
        foreach (var stage in _stages)
        {
            try
            {
                stage.OnExchange(exchange);
            }
            catch (Exception exception)
            {
                Failed(stage, exception);
            }
        }
    }

    private void Idle()
    {
        foreach (var stage in _stages)
        {
            try
            {
                stage.OnIdle();
            }
            catch (Exception exception)
            {
                Failed(stage, exception);
            }
        }
    }

    private void Failed(IInspectorStage stage, Exception exception)
    {
        var failures = Interlocked.Increment(ref _stageFailures);
        if (failures is 1 || failures % 1000 == 0)
        {
            _logger.LogWarning("Inspector stage {Stage} failed ({ExceptionType}); {Failures} failure(s) so far.", stage.GetType().Name, exception.GetType().Name, failures);
        }
    }
}
