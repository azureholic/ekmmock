namespace EkmMock.Server.Connections;

/// <summary>
/// Rate limits a log line that an anonymous peer can trigger at will (security review L1): at most <c>maxPerSecond</c> lines per one-second window, and a periodic summary of how many
/// were left out. Nothing is lost for diagnosis: the caller still records every event (connection event, metric counter), only the <em>log line</em> is aggregated.
/// <para>No timer: the summary is handed out with the next call after <c>summaryInterval</c> has passed, so a flood that stops is reported by the next failure or by <see cref="TakeSummary"/>.</para>
/// </summary>
internal sealed class WarningThrottle
{
    private readonly object _gate = new();
    private readonly TimeProvider _time;
    private readonly int _maxPerSecond;
    private readonly TimeSpan _summaryInterval;
    private DateTimeOffset _windowStart;
    private int _inWindow;
    private long _suppressed;
    private DateTimeOffset _lastSummary;

    public WarningThrottle(TimeProvider time, int maxPerSecond = 5, TimeSpan? summaryInterval = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxPerSecond, 1);
        _time = time;
        _maxPerSecond = maxPerSecond;
        _summaryInterval = summaryInterval ?? TimeSpan.FromSeconds(10);
        _windowStart = time.GetUtcNow();
        _lastSummary = _windowStart;
    }

    /// <summary>Asks whether this occurrence may be logged individually. Counts it as suppressed when not.</summary>
    public bool TryAcquire()
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            if (now - _windowStart >= TimeSpan.FromSeconds(1))
            {
                _windowStart = now;
                _inWindow = 0;
            }

            if (_inWindow < _maxPerSecond)
            {
                _inWindow++;
                return true;
            }

            _suppressed++;
            return false;
        }
    }

    /// <summary>
    /// The number of occurrences that were not logged individually since the last summary, once <c>summaryInterval</c> has passed since the previous one; otherwise 0.
    /// Reading it resets the count.
    /// </summary>
    public long TakeSummary()
    {
        lock (_gate)
        {
            if (_suppressed == 0)
            {
                return 0;
            }

            var now = _time.GetUtcNow();
            if (now - _lastSummary < _summaryInterval)
            {
                return 0;
            }

            _lastSummary = now;
            var count = _suppressed;
            _suppressed = 0;
            return count;
        }
    }

    /// <summary>The summary interval, for the message.</summary>
    public TimeSpan SummaryInterval => _summaryInterval;
}
