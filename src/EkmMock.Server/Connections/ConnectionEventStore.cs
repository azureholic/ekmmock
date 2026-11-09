using System.Diagnostics.Metrics;
using System.Collections.Concurrent;

namespace EkmMock.Server.Connections;

/// <summary>
/// Recent connection events in memory (a bounded ring). Fed by <see cref="ConnectionEventPump"/>; M4's inspector pipeline adds its own
/// consumers of the same sink. Reads return immutable copies.
/// </summary>
internal sealed class ConnectionEventStore
{
    private readonly object _gate = new();
    private readonly Queue<ConnectionEvent> _events = new();
    private readonly int _capacity;
    private TaskCompletionSource _changed = NewSignal();

    public ConnectionEventStore(int capacity = 2000)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _capacity = capacity;
    }

    public void Add(ConnectionEvent connectionEvent)
    {
        TaskCompletionSource signal;
        lock (_gate)
        {
            if (_events.Count >= _capacity)
            {
                _events.Dequeue();
            }

            _events.Enqueue(connectionEvent);
            signal = _changed;
            _changed = NewSignal();
        }

        signal.TrySetResult();
    }

    /// <summary>Oldest first.</summary>
    public IReadOnlyList<ConnectionEvent> Snapshot()
    {
        lock (_gate)
        {
            return [.. _events];
        }
    }

    /// <summary>Waits until an event matching <paramref name="predicate"/> is in the store, and returns the first match (or null on timeout).</summary>
    public async Task<ConnectionEvent?> WaitForAsync(Func<ConnectionEvent, bool> predicate, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        while (true)
        {
            Task signal;
            lock (_gate)
            {
                var match = _events.FirstOrDefault(predicate);
                if (match is not null)
                {
                    return match;
                }

                signal = _changed.Task;
            }

            try
            {
                await signal.WaitAsync(cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                lock (_gate)
                {
                    return _events.FirstOrDefault(predicate);
                }
            }
        }
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

/// <summary>Drains the sink into the store. A separate consumer on purpose: the connection path only ever enqueues.</summary>
internal sealed class ConnectionEventPump : BackgroundService
{
    private readonly ConnectionEventSink _sink;
    private readonly ConnectionEventStore _store;

    public ConnectionEventPump(ConnectionEventSink sink, ConnectionEventStore store)
    {
        _sink = sink;
        _store = store;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var connectionEvent in _sink.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                _store.Add(connectionEvent);
            }
        }
        catch (OperationCanceledException)
        {
            // Host is stopping.
        }
    }
}

/// <summary>
/// Metrics of the EKM endpoint that exist at M3. The Prometheus exposition and the remaining instruments arrive with M7;
/// the instrument names follow spec 9. The counts are also kept in memory so tests and the console can read them directly.
/// </summary>
internal sealed class EkmMetrics : IDisposable
{
    public const string MeterName = "EkmMock";
    public const string HandshakeFailuresName = "ekmmock_tls_handshake_failures_total";

    private readonly Meter _meter;
    private readonly Counter<long> _handshakeFailures;
    private readonly ConcurrentDictionary<string, long> _failureCounts = new(StringComparer.Ordinal);

    public EkmMetrics()
    {
        _meter = new Meter(MeterName);
        _handshakeFailures = _meter.CreateCounter<long>(HandshakeFailuresName, description: "TLS handshakes on the EKM endpoint that did not complete, by reason.");
    }

    public void RecordHandshakeFailure(HandshakeFailureReason reason)
    {
        var label = HandshakeFailureReasons.Label(reason);
        _failureCounts.AddOrUpdate(label, 1, static (_, count) => count + 1);
        _handshakeFailures.Add(1, new KeyValuePair<string, object?>("reason", label));
    }

    /// <summary>Total failures per <c>reason</c> label since the process started.</summary>
    public IReadOnlyDictionary<string, long> HandshakeFailureCounts => new Dictionary<string, long>(_failureCounts);

    public long TotalHandshakeFailures => _failureCounts.Values.Sum();

    public void Dispose() => _meter.Dispose();
}
