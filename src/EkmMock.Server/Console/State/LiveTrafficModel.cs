using EkmMock.Server.Inspector;

namespace EkmMock.Server.WebConsole;

internal enum LiveRowKind
{
    Exchange,
    Connection,
}

/// <summary>One row of the Live traffic list: an exchange or (inline, spec 8.2) a connection event.</summary>
internal sealed record LiveRow(LiveRowKind Kind, long Id, DateTimeOffset At, ExchangeRecord? Exchange, ConnectionEventRecord? Connection)
{
    /// <summary>A stable key for the row (exchange ids and connection event sequence numbers are different number spaces).</summary>
    public string Key => Kind == LiveRowKind.Exchange ? $"x{Id}" : $"c{Id}";

    public static LiveRow Of(ExchangeRecord exchange) => new(LiveRowKind.Exchange, exchange.Id, exchange.ReceivedAtUtc, exchange, null);

    public static LiveRow Of(ConnectionEventRecord connection) => new(LiveRowKind.Connection, connection.Sequence, connection.AtUtc, null, connection);
}

/// <summary>
/// The state of the Live traffic page, without any UI: the bounded list of rows, the view filter, pause with a bounded pending buffer, "clear view", the
/// connection-events toggle. The page feeds it from the inspector's live feed (<see cref="Apply"/>) and renders <see cref="Snapshot"/>.
/// <para>
/// Design (DECISIONS.md "M5: Live traffic"): the filter is applied when an item arrives, and changing the filter reloads from the inspector's ring buffer, so the cap
/// (<see cref="LiveTrafficOptions.MaxRows"/>) applies to matching rows; <em>pause</em> freezes the list and keeps counting (and buffering, bounded by
/// <see cref="LiveTrafficOptions.MaxPending"/>, dropping the oldest and counting the drops) what arrives; <em>clear</em> is view-only: it empties the list and
/// remembers the newest id/time so that a later reload does not bring the cleared rows back. The ring buffer itself is never touched.
/// </para>
/// Not thread-safe: use it from the component's synchronization context only.
/// </summary>
internal sealed class LiveTrafficModel
{
    private readonly IInspectorQuery _inspector;
    private readonly LiveTrafficOptions _options;
    private readonly List<LiveRow> _rows = [];
    private readonly HashSet<string> _keys = [];
    private readonly List<LiveRow> _pending = [];
    private LiveRow[]? _snapshot;
    private readonly TimeProvider _time;
    private long _maxRowExchangeId;
    private long _maxSeenExchangeId;
    private long? _clearedAfterExchangeId;
    private DateTimeOffset? _clearedAtUtc;
    private long? _frozenBeforeExchangeId;
    private DateTimeOffset? _frozenAtUtc;
    private bool _showConnectionEvents = true;

    public LiveTrafficModel(IInspectorQuery inspector, LiveTrafficOptions options, TimeProvider time)
    {
        _inspector = inspector;
        _options = options;
        _time = time;
    }

    public ExchangeFilter Filter { get; private set; } = new();

    public bool Paused { get; private set; }

    /// <summary>Items that arrived (and match the filter) while the view was paused.</summary>
    public int PendingCount => _pending.Count;

    /// <summary>Pending items lost because the pause buffer was full (oldest first).</summary>
    public long PendingDropped { get; private set; }

    /// <summary>Rows that fell off the end of the list because the UI cap was reached.</summary>
    public long TrimmedRows { get; private set; }

    /// <summary>Incremented on every change that affects what is rendered.</summary>
    public long Version { get; private set; }

    public bool ShowConnectionEvents
    {
        get => _showConnectionEvents;
        set
        {
            if (_showConnectionEvents != value)
            {
                _showConnectionEvents = value;
                Changed();
            }
        }
    }

    public int RowCount => _rows.Count;

    /// <summary>The rows to render, newest first, honouring the connection-events toggle. The array is cached until the next change.</summary>
    public LiveRow[] Snapshot()
    {
        if (_snapshot is null)
        {
            var list = new List<LiveRow>(_rows.Count);
            for (var i = _rows.Count - 1; i >= 0; i--)
            {
                var row = _rows[i];
                if (row.Kind == LiveRowKind.Connection && !_showConnectionEvents)
                {
                    continue;
                }

                list.Add(row);
            }

            _snapshot = [.. list];
        }

        return _snapshot;
    }

    /// <summary>Loads the newest matching rows (and the recent connection events) from the inspector. Called when the page opens and when the filter changes.</summary>
    public void Load()
    {
        _rows.Clear();
        _keys.Clear();
        var limit = Math.Clamp(Math.Min(_options.InitialRows, _options.MaxRows), 0, ExchangePaging.MaxLimit);
        var loaded = new List<LiveRow>();

        if (limit > 0)
        {
            var page = _inspector.Query(
                Filter,
                new ExchangePaging { Limit = limit, BeforeId = _frozenBeforeExchangeId, AfterId = _clearedAfterExchangeId });
            loaded.AddRange(page.Items.Select(LiveRow.Of));

            foreach (var connection in _inspector.ConnectionEvents(null, Math.Min(limit, 200)))
            {
                if ((_clearedAtUtc is { } cleared && connection.AtUtc <= cleared) || (_frozenAtUtc is { } frozen && connection.AtUtc > frozen))
                {
                    continue;
                }

                loaded.Add(LiveRow.Of(connection));
            }
        }

        // Oldest first, so that new rows are simply appended.
        foreach (var row in loaded.OrderBy(static r => r.At).ThenBy(static r => r.Kind).ThenBy(static r => r.Id))
        {
            Add(row);
        }

        TrimToCap();
        foreach (var row in loaded.Where(static r => r.Kind == LiveRowKind.Exchange))
        {
            _maxSeenExchangeId = Math.Max(_maxSeenExchangeId, row.Id);
        }

        Changed();
    }

    /// <summary>Takes one item of the live feed. Returns true when something visible (or the pending count) changed and the page should render.</summary>
    public bool Apply(InspectorFeedItem item)
    {
        LiveRow row;
        switch (item)
        {
            case ExchangeFeedItem exchange:
                _maxSeenExchangeId = Math.Max(_maxSeenExchangeId, exchange.Exchange.Id);
                if (!Filter.Matches(exchange.Exchange))
                {
                    return false;
                }

                row = LiveRow.Of(exchange.Exchange);
                break;
            case ConnectionFeedItem connection:
                row = LiveRow.Of(connection.Event);
                break;
            default:
                return false;
        }

        if (Paused)
        {
            AddPending(row);
            return true;
        }

        if (!Add(row))
        {
            return false;
        }

        TrimToCap();
        Changed();
        return true;
    }

    /// <summary>Freezes the list. What arrives next is counted and buffered.</summary>
    public void Pause()
    {
        if (Paused)
        {
            return;
        }

        Paused = true;
        _frozenBeforeExchangeId = _maxRowExchangeId + 1;
        _frozenAtUtc = _time.GetUtcNow();
        Changed();
    }

    /// <summary>Shows what arrived during the pause (newest rows on top, within the UI cap) and follows the stream again.</summary>
    public void Resume()
    {
        if (!Paused)
        {
            return;
        }

        Paused = false;
        _frozenBeforeExchangeId = null;
        _frozenAtUtc = null;
        foreach (var row in _pending)
        {
            Add(row);
        }

        _pending.Clear();
        TrimToCap();
        Changed();
    }

    /// <summary>Clears the view (view-only: the inspector keeps its history). Pending rows are discarded too.</summary>
    public void Clear()
    {
        _clearedAfterExchangeId = Math.Max(_maxSeenExchangeId, _maxRowExchangeId);
        _clearedAtUtc = _time.GetUtcNow();
        _rows.Clear();
        _keys.Clear();
        _pending.Clear();
        Changed();
    }

    /// <summary>Applies a new filter: the list is reloaded from the inspector's ring buffer under the new filter. Pending rows are dropped (they are in the buffer).</summary>
    public void SetFilter(ExchangeFilter filter)
    {
        Filter = filter;
        _pending.Clear();
        Load();
    }

    private bool Add(LiveRow row)
    {
        if (!_keys.Add(row.Key))
        {
            return false;
        }

        _rows.Add(row);
        if (row.Kind == LiveRowKind.Exchange && row.Id > _maxRowExchangeId)
        {
            _maxRowExchangeId = row.Id;
        }

        return true;
    }

    private void AddPending(LiveRow row)
    {
        _pending.Add(row);
        if (_pending.Count > _options.MaxPending)
        {
            var excess = _pending.Count - _options.MaxPending;
            _pending.RemoveRange(0, excess);
            PendingDropped += excess;
        }
    }

    private void TrimToCap()
    {
        var excess = _rows.Count - _options.MaxRows;
        if (excess <= 0)
        {
            return;
        }

        foreach (var removed in _rows.Take(excess))
        {
            _keys.Remove(removed.Key);
        }

        _rows.RemoveRange(0, excess);
        TrimmedRows += excess;
    }

    private void Changed()
    {
        Version++;
        _snapshot = null;
    }
}
