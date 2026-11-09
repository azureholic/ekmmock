using System.Diagnostics.Metrics;
using System.Collections.Concurrent;
using EkmMock.Server.Inspector;

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

/// <summary>
/// Drains the sink into the store and then hands every event to the inspector stages (live feed, JSONL, connection statistics). A separate consumer on
/// purpose: the connection path only ever enqueues. One stage failing never stops the others or the pump.
/// </summary>
internal sealed class ConnectionEventPump : BackgroundService
{
    private readonly ConnectionEventSink _sink;
    private readonly ConnectionEventStore _store;
    private readonly IInspectorStage[] _stages;

    public ConnectionEventPump(ConnectionEventSink sink, ConnectionEventStore store, IEnumerable<IInspectorStage>? stages = null)
    {
        _sink = sink;
        _store = store;
        _stages = [.. stages ?? []];
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var connectionEvent in _sink.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                _store.Add(connectionEvent);
                if (_stages.Length > 0)
                {
                    var record = ConnectionEventRecords.From(connectionEvent);
                    foreach (var stage in _stages)
                    {
                        try
                        {
                            stage.OnConnectionEvent(record);
                        }
                        catch (Exception)
                        {
                            // A broken stage must not stop the events of the others.
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Host is stopping.
        }
    }
}
