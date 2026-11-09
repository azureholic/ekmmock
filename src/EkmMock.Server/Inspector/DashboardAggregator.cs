namespace EkmMock.Server.Inspector;

internal sealed record OperationStats(string Operation, long Count, long Errors, long OverBudget, double P50Ms, double P95Ms, double P99Ms, double MaxMs);

/// <summary>Everything the dashboard shows for one time window (spec 8.5: 15 minutes and 1 hour).</summary>
internal sealed record WindowStats(
    int Minutes,
    long Total,
    long Errors,
    long OverBudget,
    double OverBudgetShare,
    IReadOnlyList<OperationStats> Operations,
    IReadOnlyDictionary<string, long> ErrorsByCode);

/// <summary>Requests of one minute by operation, for the requests-per-minute chart.</summary>
internal sealed record RatePoint(DateTimeOffset MinuteStartUtc, IReadOnlyDictionary<string, long> ByOperation);

/// <summary>Latency percentiles of one operation in one minute, for the latency-over-time chart.</summary>
internal sealed record LatencyPoint(DateTimeOffset MinuteStartUtc, string Operation, long Count, double P50Ms, double P95Ms, double P99Ms);

/// <summary>
/// The Managed HSM heartbeat (spec 8.5): the last <c>info</c> call and who made it. <see cref="IsStale"/> is true when it is older than 60 seconds or never seen
/// (the console shows red). A probe that was rejected (401) still proves that Managed HSM reaches the endpoint, so the heartbeat reports the last <c>info</c> of any status
/// and, separately, the last successful one.
/// </summary>
internal sealed record HeartbeatInfo(
    bool EverSeen,
    DateTimeOffset? LastInfoAtUtc,
    string? LastInfoClientCommonName,
    int? LastInfoStatus,
    DateTimeOffset? LastSuccessfulInfoAtUtc,
    double? AgeSeconds,
    bool IsStale);

internal sealed record DashboardSnapshot(
    DateTimeOffset GeneratedAtUtc,
    WindowStats Last15Minutes,
    WindowStats LastHour,
    IReadOnlyList<RatePoint> RequestsPerMinute,
    IReadOnlyList<LatencyPoint> LatencyPerMinute,
    HeartbeatInfo Heartbeat,
    long DroppedCaptures,
    long ExchangesSinceStart);

/// <summary>
/// The dashboard aggregates (spec 8.5), maintained by the consumer (never on the request path) in per-minute buckets covering the last hour, independent of the
/// ring buffer size. Per minute and operation it keeps counts, errors by code, over-budget counts and up to <see cref="InspectorOptions.MaxSamplesPerMinuteAndOperation"/>
/// latency samples (reservoir sampling beyond that, so memory is bounded).
/// <para>
/// Percentile method: <b>nearest rank</b> on the sorted samples, <c>rank = ceil(p/100 · n)</c>, which returns an observed value (the p95 of 1..100 ms is 95 ms). A window covers the
/// current minute and the N−1 minutes before it. The latency is the server time of the exchange (<c>Timing.TotalMs</c>). An unroutable request counts under <c>(unrouted)</c>.
/// </para>
/// </summary>
internal sealed class DashboardAggregator : IInspectorStage
{
    public const string UnroutedLabel = "(unrouted)";
    public static readonly TimeSpan HeartbeatStaleAfter = TimeSpan.FromSeconds(60);

    private const int RetainMinutes = 62;
    private const long TicksPerMinute = TimeSpan.TicksPerMinute;

    private readonly object _gate = new();
    private readonly SortedDictionary<long, Dictionary<string, OperationBucket>> _buckets = [];
    private readonly TimeProvider _time;
    private readonly int _maxSamples;
    private long _total;
    private DateTimeOffset? _lastInfoAt;
    private string? _lastInfoCommonName;
    private int? _lastInfoStatus;
    private DateTimeOffset? _lastSuccessfulInfoAt;

    public DashboardAggregator(Microsoft.Extensions.Options.IOptions<InspectorOptions> options, TimeProvider time)
        : this(time, options.Value.MaxSamplesPerMinuteAndOperation)
    {
    }

    public DashboardAggregator(TimeProvider time, int maxSamplesPerMinuteAndOperation = 4096)
    {
        _time = time;
        _maxSamples = Math.Max(16, maxSamplesPerMinuteAndOperation);
    }

    void IInspectorStage.OnExchange(CapturedExchange exchange) => Add(exchange.Record);

    public void Add(ExchangeRecord record)
    {
        var minute = record.ReceivedAtUtc.UtcTicks / TicksPerMinute;
        var operation = record.Request.Operation ?? UnroutedLabel;
        lock (_gate)
        {
            _total++;
            if (!_buckets.TryGetValue(minute, out var operations))
            {
                operations = new Dictionary<string, OperationBucket>(StringComparer.Ordinal);
                _buckets[minute] = operations;
                while (_buckets.Count > 0 && _buckets.Keys.First() < _buckets.Keys.Last() - RetainMinutes)
                {
                    _buckets.Remove(_buckets.Keys.First());
                }
            }

            if (!operations.TryGetValue(operation, out var bucket))
            {
                bucket = new OperationBucket(_maxSamples);
                operations[operation] = bucket;
            }

            bucket.Add(record);

            if (operation == "info")
            {
                if (_lastInfoAt is null || record.ReceivedAtUtc >= _lastInfoAt)
                {
                    _lastInfoAt = record.ReceivedAtUtc;
                    _lastInfoCommonName = record.ClientCertificate.CommonName;
                    _lastInfoStatus = record.Response.Status;
                }

                if (record.Response.Status is >= 200 and < 300 && (_lastSuccessfulInfoAt is null || record.ReceivedAtUtc >= _lastSuccessfulInfoAt))
                {
                    _lastSuccessfulInfoAt = record.ReceivedAtUtc;
                }
            }
        }
    }

    public DashboardSnapshot Snapshot(long droppedCaptures)
    {
        var now = _time.GetUtcNow();
        var nowMinute = now.UtcTicks / TicksPerMinute;
        lock (_gate)
        {
            return new DashboardSnapshot(
                now,
                Window(15, nowMinute),
                Window(60, nowMinute),
                RatePoints(nowMinute, 60),
                LatencyPoints(nowMinute, 60),
                Heartbeat(now),
                droppedCaptures,
                _total);
        }
    }

    public WindowStats Window(int minutes, DateTimeOffset? at = null)
    {
        var nowMinute = (at ?? _time.GetUtcNow()).UtcTicks / TicksPerMinute;
        lock (_gate)
        {
            return Window(minutes, nowMinute);
        }
    }

    // ---- everything below runs under _gate ----

    private WindowStats Window(int minutes, long nowMinute)
    {
        var merged = new Dictionary<string, MergedOperation>(StringComparer.Ordinal);
        var errorsByCode = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var (minute, operations) in _buckets)
        {
            if (minute > nowMinute - minutes && minute <= nowMinute)
            {
                foreach (var (operation, bucket) in operations)
                {
                    if (!merged.TryGetValue(operation, out var total))
                    {
                        total = new MergedOperation();
                        merged[operation] = total;
                    }

                    total.Merge(bucket);
                    foreach (var (code, count) in bucket.ErrorsByCode)
                    {
                        errorsByCode[code] = errorsByCode.GetValueOrDefault(code) + count;
                    }
                }
            }
        }

        var stats = merged
            .OrderBy(static p => p.Key, StringComparer.Ordinal)
            .Select(static p => p.Value.ToStats(p.Key))
            .ToList();
        var all = stats.Sum(static s => s.Count);
        var errors = stats.Sum(static s => s.Errors);
        var over = stats.Sum(static s => s.OverBudget);
        return new WindowStats(minutes, all, errors, over, all == 0 ? 0 : (double)over / all, stats, errorsByCode);
    }

    private List<RatePoint> RatePoints(long nowMinute, int minutes)
    {
        var points = new List<RatePoint>(minutes);
        for (var minute = nowMinute - minutes + 1; minute <= nowMinute; minute++)
        {
            var byOperation = _buckets.TryGetValue(minute, out var operations)
                ? operations.ToDictionary(static p => p.Key, static p => p.Value.Count, StringComparer.Ordinal)
                : new Dictionary<string, long>();
            points.Add(new RatePoint(MinuteStart(minute), byOperation));
        }

        return points;
    }

    private List<LatencyPoint> LatencyPoints(long nowMinute, int minutes)
    {
        var points = new List<LatencyPoint>();
        for (var minute = nowMinute - minutes + 1; minute <= nowMinute; minute++)
        {
            if (!_buckets.TryGetValue(minute, out var operations))
            {
                continue;
            }

            foreach (var (operation, bucket) in operations.OrderBy(static p => p.Key, StringComparer.Ordinal))
            {
                var sorted = bucket.SortedSamples();
                points.Add(new LatencyPoint(MinuteStart(minute), operation, bucket.Count, Percentiles.NearestRank(sorted, 50), Percentiles.NearestRank(sorted, 95), Percentiles.NearestRank(sorted, 99)));
            }
        }

        return points;
    }

    private HeartbeatInfo Heartbeat(DateTimeOffset now)
    {
        if (_lastInfoAt is not { } last)
        {
            return new HeartbeatInfo(false, null, null, null, null, null, true);
        }

        var age = now - last;
        return new HeartbeatInfo(true, last, _lastInfoCommonName, _lastInfoStatus, _lastSuccessfulInfoAt, Math.Max(0, Math.Round(age.TotalSeconds, 1)), age > HeartbeatStaleAfter);
    }

    private static DateTimeOffset MinuteStart(long minute) => new(minute * TicksPerMinute, TimeSpan.Zero);

    private sealed class OperationBucket
    {
        private readonly int _max;
        private double[] _values = [];
        private int _sampleCount;

        public OperationBucket(int max) => _max = max;

        public long Count { get; private set; }

        public long Errors { get; private set; }

        public long OverBudget { get; private set; }

        public double Max { get; private set; }

        public Dictionary<string, long> ErrorsByCode { get; } = new(StringComparer.Ordinal);

        public void Add(ExchangeRecord record)
        {
            Count++;
            var ms = record.Timing.TotalMs;
            Max = Math.Max(Max, ms);
            if (record.Response.Status >= 400)
            {
                Errors++;
                var code = record.Response.Code ?? $"HTTP {record.Response.Status}";
                ErrorsByCode[code] = ErrorsByCode.GetValueOrDefault(code) + 1;
            }

            if (record.Timing.Budget == BudgetStatus.Red)
            {
                OverBudget++;
            }

            AddSample(ms);
        }

        private void AddSample(double ms)
        {
            if (_sampleCount < _max)
            {
                if (_sampleCount == _values.Length)
                {
                    Array.Resize(ref _values, Math.Min(_max, Math.Max(16, _values.Length * 2)));
                }

                _values[_sampleCount++] = ms;
                return;
            }

            // Reservoir sampling: every observed value has the same chance of being in the sample.
            var j = Random.Shared.NextInt64(Count);
            if (j < _max)
            {
                _values[j] = ms;
            }
        }

        public double[] SortedSamples()
        {
            var copy = _values.AsSpan(0, _sampleCount).ToArray();
            Array.Sort(copy);
            return copy;
        }

        public void CopySamplesTo(List<double> destination) => destination.AddRange(_values.AsSpan(0, _sampleCount));
    }

    private sealed class MergedOperation
    {
        private readonly List<double> _samples = [];
        private long _count;
        private long _errors;
        private long _over;
        private double _max;

        public void Merge(OperationBucket bucket)
        {
            _count += bucket.Count;
            _errors += bucket.Errors;
            _over += bucket.OverBudget;
            _max = Math.Max(_max, bucket.Max);
            bucket.CopySamplesTo(_samples);
        }

        public OperationStats ToStats(string operation)
        {
            var sorted = _samples.ToArray();
            Array.Sort(sorted);
            return new OperationStats(operation, _count, _errors, _over, Percentiles.NearestRank(sorted, 50), Percentiles.NearestRank(sorted, 95), Percentiles.NearestRank(sorted, 99), _max);
        }
    }
}

internal static class Percentiles
{
    /// <summary>Nearest-rank percentile of an ascending sorted array: <c>sorted[ceil(p/100·n) − 1]</c>. Zero for no samples.</summary>
    public static double NearestRank(IReadOnlyList<double> sorted, double percentile)
    {
        if (sorted.Count == 0)
        {
            return 0;
        }

        var rank = (int)Math.Ceiling(percentile / 100.0 * sorted.Count);
        return sorted[Math.Clamp(rank - 1, 0, sorted.Count - 1)];
    }
}
