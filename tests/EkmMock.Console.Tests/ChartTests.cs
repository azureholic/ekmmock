using System.Globalization;
using EkmMock.Server.WebConsole.Charts;
using EkmMock.Server.WebConsole.Components;

namespace EkmMock.Console.Tests;

/// <summary>The pure-Razor SVG charts (no chart library): axes, the 250 ms budget line, empty states, accessible names, legends that do not rely on colour.</summary>
public sealed class ChartTests : ConsoleTestBase
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);

    private static double Num(string? text) => double.Parse(text!, CultureInfo.InvariantCulture);

    private static ChartSeries Series(string name, int index, params (int Minute, double Value)[] points)
        => new(name, index, [.. points.Select(static p => new ChartPoint(T0.AddMinutes(p.Minute), p.Value))]);

    // ---- the scale ----

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-5, 1)]
    [InlineData(0.8, 1)]
    [InlineData(1, 1)]
    [InlineData(1.1, 2)]
    [InlineData(2.2, 2.5)]
    [InlineData(3, 5)]
    [InlineData(6, 10)]
    [InlineData(99, 100)]
    [InlineData(101, 200)]
    [InlineData(251, 500)]
    [InlineData(2600, 5000)]
    public void NiceMax_RoundsUpToOneTwoTwoPointFiveFiveOrTen(double value, double expected)
        => ChartScale.NiceMax(value).ShouldBe(expected, 1e-9);

    [Fact]
    public void TheYAxis_AlwaysReachesAboveTheBudget_SoTheBudgetLineIsAlwaysVisible()
    {
        ChartScale.YMax(dataMax: 12, budget: 250).ShouldBeGreaterThan(250);
        ChartScale.YMax(dataMax: 900, budget: 250).ShouldBeGreaterThan(900);
        ChartScale.YMax(dataMax: 0, budget: null).ShouldBe(1);
    }

    [Theory]
    [InlineData(0, 1, "0,1")]
    [InlineData(1, 1, "0,1")]
    [InlineData(2, 2, "0,1,2")]
    [InlineData(2.4, 3, "0,1,2,3")]
    [InlineData(4, 4, "0,1,2,3,4")]
    [InlineData(5, 8, "0,2,4,6,8")]
    [InlineData(23, 40, "0,10,20,30,40")]
    [InlineData(100, 200, "0,50,100,150,200")]
    [InlineData(101, 200, "0,50,100,150,200")]
    public void ACountAxis_UsesWholeNumbersOnly_AndReachesTheLargestCount(double largest, double max, string ticks)
    {
        var axis = ChartScale.CountAxis(largest);

        axis.Max.ShouldBe(max);
        string.Join(',', axis.Ticks.Select(static t => t.ToString("0.##", CultureInfo.InvariantCulture))).ShouldBe(ticks);
        axis.Ticks[^1].ShouldBeGreaterThanOrEqualTo(Math.Max(1, Math.Ceiling(largest)));
        axis.Ticks.ShouldAllBe(static t => t % 1 == 0);
    }

    // ---- line chart ----

    [Fact]
    public void ALineChart_WithNoData_ShowsAnEmptyState_AndNoSvg()
    {
        var cut = Render<LineChart>(p => p.Add(static c => c.Title, "wrapkey latency").Add(static c => c.Series, []));

        cut.Find("[data-role='empty']").TextContent.ShouldBe("No data in this window yet.");
        cut.FindAll("svg").ShouldBeEmpty();
        cut.Find("figcaption").TextContent.ShouldBe("wrapkey latency");
    }

    [Fact]
    public void ALineChart_DrawsAxes_Ticks_AndOnePolylinePerSeries()
    {
        var cut = Render<LineChart>(p => p
            .Add(static c => c.Title, "wrapkey latency")
            .Add(static c => c.BudgetLine, 250d)
            .Add(static c => c.Series, [Series("p50", 0, (0, 5), (1, 6), (2, 7)), Series("p95", 1, (0, 9), (1, 12), (2, 14)), Series("p99", 2, (0, 20), (1, 25), (2, 30))]));

        cut.Find("[data-role='y-axis']").ShouldNotBeNull();
        cut.Find("[data-role='x-axis']").ShouldNotBeNull();
        cut.Find("[data-role='y-unit']").TextContent.ShouldBe("ms");
        cut.FindAll("[data-role='y-tick']").Count.ShouldBe(5);
        cut.FindAll("[data-role='x-tick']").Select(static t => t.TextContent).ShouldBe(["12:00", "12:00", "12:01", "12:01", "12:02"]);
        cut.FindAll("polyline.chart-series").Select(static l => l.GetAttribute("data-series")).ShouldBe(["p50", "p95", "p99"]);
        cut.FindAll("polyline.chart-series").ShouldAllBe(static l => l.GetAttribute("points")!.Split(' ').Length == 3);
        cut.FindAll("circle.chart-marker").Count.ShouldBe(3);
    }

    [Fact]
    public void TheBudgetLine_IsDrawnAtTheBudgetValue_OnTheSameScaleAsTheData()
    {
        var cut = Render<LineChart>(p => p
            .Add(static c => c.BudgetLine, 250d)
            .Add(static c => c.Series, [Series("p99", 2, (0, 100), (1, 100))]));

        var budget = cut.Find("[data-role='budget']");
        budget.GetAttribute("data-value").ShouldBe("250");
        var budgetY = Num(budget.GetAttribute("y1"));
        budget.GetAttribute("y2").ShouldBe(budget.GetAttribute("y1"));

        // 100 ms is below the budget, so its y is larger (lower on the screen); the highest tick is above the budget line.
        var seriesY = Num(cut.Find("polyline.chart-series").GetAttribute("points")!.Split(' ')[0].Split(',')[1]);
        seriesY.ShouldBeGreaterThan(budgetY);
        var ticks = cut.FindAll("[data-role='y-tick']").Select(static t => Num(t.TextContent)).ToList();
        ticks.Max().ShouldBeGreaterThan(250);
        cut.Find("[data-role='budget-label']").TextContent.ShouldBe("250 ms budget");

        // The budget y matches its position on the tick scale: a tick with the same value as the budget (250) sits on the line when the axis maximum is 500.
        ticks.ShouldContain(250);
        var tickY = cut.FindAll("[data-role='y-grid']")[ticks.IndexOf(250)].GetAttribute("y1");
        Num(tickY).ShouldBe(budgetY, 0.5);
    }

    [Fact]
    public void WhenTheDataIsOverTheBudget_TheAxisGrowsAndTheLineStaysBelowTheData()
    {
        var cut = Render<LineChart>(p => p
            .Add(static c => c.BudgetLine, 250d)
            .Add(static c => c.Series, [Series("p99", 2, (0, 600), (1, 650))]));

        var budgetY = Num(cut.Find("[data-role='budget']").GetAttribute("y1"));
        var seriesY = Num(cut.Find("polyline.chart-series").GetAttribute("points")!.Split(' ')[0].Split(',')[1]);

        seriesY.ShouldBeLessThan(budgetY, "600 ms is above the budget line");
    }

    [Fact]
    public void TheLegend_NamesEverySeriesAndTheBudget_WithAShapeNotJustAColour()
    {
        var cut = Render<LineChart>(p => p
            .Add(static c => c.BudgetLine, 250d)
            .Add(static c => c.Series, [Series("p50", 0, (0, 5), (1, 6)), Series("p95", 1, (0, 9), (1, 12)), Series("p99", 2, (0, 20), (1, 25))]));

        var legend = cut.FindAll("[data-role='legend'] li").Select(static li => li.TextContent.Trim()).ToList();

        legend.ShouldBe(["p50", "p95", "p99", "250 ms budget"]);
        cut.FindAll("[data-role='legend'] li svg").Count.ShouldBe(4);
        // The strokes differ by class (and by dash pattern in the stylesheet), not only by colour.
        cut.FindAll("polyline.chart-series").Select(static l => l.ClassName).Distinct().Count().ShouldBe(3);
    }

    [Fact]
    public void TheChart_HasAnAccessibleName_WithTheLatestValues()
    {
        var cut = Render<LineChart>(p => p
            .Add(static c => c.Title, "unwrapkey latency")
            .Add(static c => c.Series, [Series("p99", 2, (0, 20), (1, 25))]));

        var svg = cut.Find("svg.chart-svg");
        svg.GetAttribute("role").ShouldBe("img");
        svg.GetAttribute("aria-label").ShouldBe("unwrapkey latency: p99 latest 25");
        svg.QuerySelector("title")!.TextContent.ShouldBe("unwrapkey latency");
    }

    [Fact]
    public void ASingleRepeatedTimestamp_DoesNotDivideByZero()
    {
        var cut = Render<LineChart>(p => p.Add(static c => c.Series, [Series("p50", 0, (0, 5))]));

        cut.FindAll("polyline.chart-series").Count.ShouldBe(1);
        cut.Find("circle.chart-marker").GetAttribute("cx")!.ShouldNotContain("NaN");
    }

    [Fact]
    public void AFixedTimeWindow_PlacesPointsRelativeToIt()
    {
        var cut = Render<LineChart>(p => p
            .Add(static c => c.XMin, T0)
            .Add(static c => c.XMax, T0.AddMinutes(15))
            .Add(static c => c.Series, [Series("p50", 0, (0, 5), (15, 5))]));

        var points = cut.Find("polyline.chart-series").GetAttribute("points")!.Split(' ').Select(static p => Num(p.Split(',')[0])).ToList();
        points[0].ShouldBeLessThan(points[1]);
        cut.FindAll("[data-role='x-tick']").Select(static t => t.TextContent).First().ShouldBe("12:00");
        cut.FindAll("[data-role='x-tick']").Select(static t => t.TextContent).Last().ShouldBe("12:15");
    }

    // ---- stacked columns ----

    private static StackedColumn Column(string label, params (string Op, int Index, double Value)[] segments)
        => new(label, [.. segments.Select(static s => new ChartSegment(s.Op, s.Index, s.Value))]);

    [Fact]
    public void StackedColumns_StackTheSegments_ToTheirCounts_AndNameThemInTheLegend()
    {
        var cut = Render<StackedColumnChart>(p => p.Add(static c => c.Columns,
        [
            Column("12:00", ("info", 0, 3), ("wrapkey", 2, 10)),
            Column("12:01", ("info", 0, 3), ("wrapkey", 2, 20)),
        ]));

        cut.FindAll("g.chart-column").Count.ShouldBe(2);
        var rects = cut.FindAll("rect.chart-bar").ToList();
        rects.Count.ShouldBe(4);
        var wrapHeights = rects.Where(static r => r.GetAttribute("data-series") == "wrapkey").Select(static r => Num(r.GetAttribute("height"))).ToList();
        wrapHeights[1].ShouldBeGreaterThan(wrapHeights[0]); // 20 is taller than 10
        (wrapHeights[1] / wrapHeights[0]).ShouldBe(2, 0.05);
        cut.FindAll("[data-role='legend'] li").Select(static li => li.TextContent.Trim()).ShouldBe(["info", "wrapkey"]);
        cut.Find("g.chart-column title").TextContent.ShouldBe("12:00: info 3, wrapkey 10");
        cut.FindAll("[data-role='y-tick']").Select(static t => Num(t.TextContent)).Max().ShouldBeGreaterThanOrEqualTo(23);
    }

    [Fact]
    public void StackedColumns_WithNoRequests_ShowAnEmptyState()
    {
        var cut = Render<StackedColumnChart>(p => p.Add(static c => c.Columns, [Column("12:00"), Column("12:01", ("info", 0, 0))]));

        cut.Find("[data-role='empty']").TextContent.ShouldBe("No requests in this window yet.");
        cut.FindAll("svg").ShouldBeEmpty();
    }

    [Fact]
    public void StackedColumns_ThinTheXAxisLabels_WhenThereAreManyColumns()
    {
        var columns = Enumerable.Range(0, 60).Select(i => Column($"12:{i:00}", ("info", 0, 1))).ToList();

        var cut = Render<StackedColumnChart>(p => p.Add(static c => c.Columns, columns));

        cut.FindAll("g.chart-column").Count.ShouldBe(60);
        cut.FindAll("[data-role='x-tick']").Count.ShouldBeLessThanOrEqualTo(12);
    }

    // ---- horizontal bars ----

    [Fact]
    public void ErrorBars_ScaleToTheLargest_ShowTheirValueAsText_AndHaveAnEmptyState()
    {
        var cut = Render<HorizontalBarChart>(p => p.Add(static c => c.Bars, [new BarDatum("KeyNotFound", 8), new BarDatum("HTTP 503", 2), new BarDatum("InvalidRequest", 4)]));

        cut.FindAll(".bar-row").Select(static r => r.GetAttribute("data-label")).ShouldBe(["KeyNotFound", "HTTP 503", "InvalidRequest"]);
        cut.FindAll("[data-role='bar-value']").Select(static v => v.TextContent).ShouldBe(["8", "2", "4"]);
        var widths = cut.FindAll("[data-role='bar']").Select(static b => Num(b.GetAttribute("width"))).ToList();
        widths[0].ShouldBe(100, 0.01);
        widths[1].ShouldBe(25, 0.01);
        widths[2].ShouldBe(50, 0.01);

        Render<HorizontalBarChart>(p => p.Add(static c => c.Bars, [])).Find("[data-role='empty']").TextContent.ShouldBe("No errors in this window.");
        Render<HorizontalBarChart>(p => p.Add(static c => c.Bars, [new BarDatum("x", 0)])).FindAll("[data-role='empty']").Count.ShouldBe(1);
    }

    [Fact]
    public void ASmallNonZeroBar_IsStillVisible()
    {
        var cut = Render<HorizontalBarChart>(p => p.Add(static c => c.Bars, [new BarDatum("big", 10_000), new BarDatum("one", 1)]));

        Num(cut.FindAll("[data-role='bar']")[1].GetAttribute("width")).ShouldBeGreaterThanOrEqualTo(2);
    }

    // ---- sparkline ----

    [Fact]
    public void ASparkline_DrawsTheTrend_AndStatesTheLatestValueAsText()
    {
        var cut = Render<Sparkline>(p => p.Add(static c => c.Values, [1d, 4d, 2d, 8d]).Add(static c => c.Label, "wrapkey requests per minute"));

        cut.Find("polyline.sparkline-line").GetAttribute("points")!.Split(' ').Length.ShouldBe(4);
        cut.Find("[data-role='latest']").TextContent.ShouldBe("8");
        cut.Find("[data-chart='sparkline']").GetAttribute("aria-label").ShouldBe("wrapkey requests per minute: latest 8, highest 8");
        Render<Sparkline>().Find("[data-role='latest']").TextContent.ShouldBe("-");
    }
}
