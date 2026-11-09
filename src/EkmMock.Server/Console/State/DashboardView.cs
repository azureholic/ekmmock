using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole.Charts;

namespace EkmMock.Server.WebConsole;

/// <summary>The dashboard's time windows (spec 8.5: last 15 minutes and last hour).</summary>
internal enum DashboardWindow
{
    Minutes15 = 15,
    Hour1 = 60,
}

/// <summary>What the Dashboard page draws, derived from the inspector's <see cref="DashboardSnapshot"/> for one window. Pure, so the mapping to chart data is testable.</summary>
internal sealed class DashboardView
{
    /// <summary>Stable series order: the four EKM operations first, anything else after them.</summary>
    private static readonly string[] KnownOperations = ["info", "metadata", "wrapkey", "unwrapkey"];

    private DashboardView(
        WindowStats stats,
        IReadOnlyList<StackedColumn> requestsPerMinute,
        IReadOnlyDictionary<string, IReadOnlyList<ChartSeries>> latencyByOperation,
        IReadOnlyDictionary<string, IReadOnlyList<double>> rateByOperation,
        IReadOnlyList<BarDatum> errorsByCode,
        DateTimeOffset windowStart,
        DateTimeOffset windowEnd)
    {
        Stats = stats;
        RequestsPerMinute = requestsPerMinute;
        LatencyByOperation = latencyByOperation;
        RateByOperation = rateByOperation;
        ErrorsByCode = errorsByCode;
        WindowStart = windowStart;
        WindowEnd = windowEnd;
    }

    public WindowStats Stats { get; }

    public IReadOnlyList<StackedColumn> RequestsPerMinute { get; }

    /// <summary>Per operation: the p50, p95 and p99 series over the window (the chart draws the budget line on top).</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<ChartSeries>> LatencyByOperation { get; }

    /// <summary>Per operation: requests in each minute of the window (oldest first), for the sparklines.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<double>> RateByOperation { get; }

    public IReadOnlyList<BarDatum> ErrorsByCode { get; }

    public DateTimeOffset WindowStart { get; }

    public DateTimeOffset WindowEnd { get; }

    public static int SeriesIndex(string operation)
    {
        var known = Array.IndexOf(KnownOperations, operation);
        return known >= 0 ? known : KnownOperations.Length;
    }

    public static DashboardView From(DashboardSnapshot snapshot, DashboardWindow window)
    {
        var minutes = (int)window;
        var stats = window == DashboardWindow.Minutes15 ? snapshot.Last15Minutes : snapshot.LastHour;
        var end = snapshot.GeneratedAtUtc;
        var currentMinute = new DateTimeOffset(end.UtcDateTime.Ticks - (end.UtcDateTime.Ticks % TimeSpan.TicksPerMinute), TimeSpan.Zero);
        var start = currentMinute.AddMinutes(-(minutes - 1));

        var rates = snapshot.RequestsPerMinute.Where(p => p.MinuteStartUtc >= start).OrderBy(static p => p.MinuteStartUtc).ToList();
        var columns = rates
            .Select(p => new StackedColumn(
                p.MinuteStartUtc.UtcDateTime.ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture),
                [.. p.ByOperation.OrderBy(static o => SeriesIndex(o.Key)).ThenBy(static o => o.Key, StringComparer.Ordinal)
                    .Select(o => new ChartSegment(o.Key, SeriesIndex(o.Key), o.Value))]))
            .ToList();

        var operations = stats.Operations.Select(static o => o.Operation)
            .Concat(rates.SelectMany(static r => r.ByOperation.Keys))
            .Concat(snapshot.LatencyPerMinute.Select(static l => l.Operation))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(SeriesIndex)
            .ThenBy(static o => o, StringComparer.Ordinal)
            .ToList();

        var latency = new Dictionary<string, IReadOnlyList<ChartSeries>>(StringComparer.Ordinal);
        var rate = new Dictionary<string, IReadOnlyList<double>>(StringComparer.Ordinal);
        foreach (var operation in operations)
        {
            var points = snapshot.LatencyPerMinute
                .Where(l => l.Operation == operation && l.MinuteStartUtc >= start && l.Count > 0)
                .OrderBy(static l => l.MinuteStartUtc)
                .ToList();
            if (points.Count > 0)
            {
                latency[operation] =
                [
                    new ChartSeries("p50", 0, [.. points.Select(static p => new ChartPoint(p.MinuteStartUtc, p.P50Ms))]),
                    new ChartSeries("p95", 1, [.. points.Select(static p => new ChartPoint(p.MinuteStartUtc, p.P95Ms))]),
                    new ChartSeries("p99", 2, [.. points.Select(static p => new ChartPoint(p.MinuteStartUtc, p.P99Ms))]),
                ];
            }

            rate[operation] = [.. Enumerable.Range(0, minutes)
                .Select(i => start.AddMinutes(i))
                .Select(m => (double)(rates.FirstOrDefault(r => r.MinuteStartUtc == m)?.ByOperation.GetValueOrDefault(operation) ?? 0))];
        }

        var errors = stats.ErrorsByCode.OrderByDescending(static e => e.Value).ThenBy(static e => e.Key, StringComparer.Ordinal)
            .Select(static e => new BarDatum(e.Key, e.Value))
            .ToList();

        return new DashboardView(stats, columns, latency, rate, errors, start, currentMinute.AddMinutes(1));
    }
}
