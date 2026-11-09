using System.Globalization;

namespace EkmMock.Server.WebConsole.Charts;

// The chart components are public Razor components, so their parameter types are public too. They are deliberately plain data: no inspector type crosses this boundary.

/// <summary>One point of a line series.</summary>
public sealed record ChartPoint(DateTimeOffset X, double Y);

/// <summary>A named line. <see cref="Index"/> picks the stroke style (colour and dash pattern) so that series stay distinguishable without colour.</summary>
public sealed record ChartSeries(string Name, int Index, IReadOnlyList<ChartPoint> Points);

/// <summary>One bar of a horizontal bar chart. <see cref="Detail"/> is extra text for the tooltip.</summary>
public sealed record BarDatum(string Label, double Value, string? Detail = null, string? CssClass = null);

/// <summary>A piece of a stacked column (one series' count in one minute).</summary>
public sealed record ChartSegment(string Name, int Index, double Value);

/// <summary>A stacked column (one minute).</summary>
public sealed record StackedColumn(string Label, IReadOnlyList<ChartSegment> Segments);

/// <summary>The latency budget colours as plain data for the components.</summary>
public enum LatencyLevel
{
    Green,
    Amber,
    Red,
}

/// <summary>The geometry of a chart: nice axis maxima and ticks, and the mapping of values to pixels. Pure, so the SVG can be tested without a browser.</summary>
public static class ChartScale
{
    /// <summary>The smallest "nice" number (1, 2, 2.5, 5 times a power of ten) that is at least <paramref name="value"/>.</summary>
    public static double NiceMax(double value)
    {
        if (value <= 0 || double.IsNaN(value) || double.IsInfinity(value))
        {
            return 1;
        }

        var exponent = Math.Floor(Math.Log10(value));
        var scale = Math.Pow(10, exponent);
        foreach (var factor in new[] { 1d, 2d, 2.5d, 5d, 10d })
        {
            var candidate = factor * scale;
            if (candidate >= value * 0.999999)
            {
                return candidate;
            }
        }

        return 10 * scale;
    }

    /// <summary>The y axis maximum: the data (with headroom) and the budget line always fit, so the budget line is always visible.</summary>
    public static double YMax(double dataMax, double? budget)
        => NiceMax(Math.Max(dataMax * 1.05, (budget ?? 0) * 1.1));

    public static IReadOnlyList<double> Ticks(double max, int segments = 4)
        => [.. Enumerable.Range(0, segments + 1).Select(i => max * i / segments)];

    /// <summary>
    /// The axis of a chart of counts: whole numbers only. Up to four, one tick per count (0, 1, 2, ...); above that four equal steps of a "nice" whole size (1, 2, 5, 10, 20, 50, ...),
    /// so the top tick is always at least the largest count.
    /// </summary>
    public static (double Max, IReadOnlyList<double> Ticks) CountAxis(double value)
    {
        var needed = Math.Max(1, Math.Ceiling(value));
        if (needed <= 4)
        {
            return (needed, [.. Enumerable.Range(0, (int)needed + 1).Select(static i => (double)i)]);
        }

        var minimumStep = Math.Ceiling(needed / 4);
        var scale = Math.Pow(10, Math.Floor(Math.Log10(minimumStep)));
        var step = new[] { 1d, 2d, 5d, 10d }.Select(f => f * scale).First(s => s >= minimumStep);
        return (step * 4, [.. Enumerable.Range(0, 5).Select(i => step * i)]);
    }

    public static string Format(double value)
        => value.ToString(Math.Abs(value) >= 10 || Math.Abs(value % 1) < 1e-9 ? "0" : "0.0", CultureInfo.InvariantCulture);

    /// <summary>SVG coordinates are invariant-culture numbers with at most two decimals.</summary>
    public static string Px(double value) => Math.Round(value, 2).ToString("0.##", CultureInfo.InvariantCulture);
}
