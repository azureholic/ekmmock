using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Components;
using EkmMock.Server.WebConsole.Pages;

namespace EkmMock.Console.Tests;

/// <summary>The Dashboard (spec 8.5.4): rates, percentiles against the 250 ms budget, share over budget, errors by code, the Managed HSM heartbeat and the refresh timer.</summary>
public sealed class DashboardTests : ConsoleTestBase
{
    private DateTimeOffset Now => ManualTime.GetUtcNow();

    private DateTimeOffset Ago(double minutes) => Now.AddMinutes(-minutes);

    private static string Text(AngleSharp.Dom.IElement element) => Dom.Text(element);

    private IRenderedComponent<Dashboard> Open() => Render<Dashboard>();

    private long id;

    private void Add(string op, int status = 200, double ms = 5, double minutesAgo = 1, string? cn = "mhsm.example", string? code = null)
        => InspectorFake.Publish(Rec.Make(++id, op, status, ms, cn: cn, at: Ago(minutesAgo), code: code));

    // ---- content ----

    [Fact]
    public void WithNoTraffic_EverySectionHasAnEmptyState_AndTheHeartbeatIsRed()
    {
        var cut = Open();

        cut.Find("[data-role='total-requests']").TextContent.ShouldBe("0");
        cut.Find("[data-role='latency-empty']").TextContent.ShouldContain("No latency data");
        cut.Find("[data-role='operations'] .chart-empty").TextContent.ShouldContain("No requests");
        cut.Find("[data-role='errors'] [data-role='empty']").TextContent.ShouldBe("No errors in this window.");
        cut.Find("[data-role='heartbeat']").GetAttribute("data-state").ShouldBe("never");
        cut.Find("[data-role='heartbeat']").ClassList.ShouldContain("heartbeat-never");
        Text(cut.Find("[data-role='heartbeat']")).ShouldContain("No info call seen yet");
    }

    [Fact]
    public void TheTotals_CountRequests_Errors_AndTheShareOverTheBudget()
    {
        Add("wrapkey", ms: 10);
        Add("wrapkey", ms: 300);
        Add("unwrapkey", 404, 4, code: "KeyNotFound");
        Add("unwrapkey", 200, 6);

        var cut = Open();

        cut.Find("[data-role='total-requests']").TextContent.ShouldBe("4");
        cut.Find("[data-role='total-errors']").TextContent.ShouldBe("1");
        var share = cut.Find("[data-role='share-over-budget']");
        Text(share).ShouldBe("1 (25.0 %)");
        share.ClassList.ShouldContain("budget-red");
        cut.Find("[data-role='since-start']").TextContent.ShouldBe("4");
    }

    [Fact]
    public void TheShareOverBudget_IsGreen_WhenNothingIsOver()
    {
        Add("wrapkey", ms: 10);

        Open().Find("[data-role='share-over-budget']").ClassList.ShouldContain("budget-green");
    }

    [Fact]
    public void RequestsPerMinute_AreStackedByOperation()
    {
        Add("info", minutesAgo: 3);
        Add("wrapkey", minutesAgo: 3);
        Add("wrapkey", minutesAgo: 3);
        Add("unwrapkey", minutesAgo: 1);

        var cut = Open();
        var chart = cut.Find("[data-chart='stacked-columns']");

        chart.QuerySelectorAll("g.chart-column").Length.ShouldBe(15, "one column per minute of the window, empty minutes included");
        chart.QuerySelectorAll("[data-role='legend'] li").Select(static l => l.TextContent.Trim()).ShouldBe(["info", "wrapkey", "unwrapkey"]);
        chart.QuerySelectorAll("rect[data-series='wrapkey']").Length.ShouldBe(1);
        chart.QuerySelectorAll("rect[data-series='wrapkey']")[0].GetAttribute("data-value").ShouldBe("2");
    }

    [Fact]
    public void Latency_IsDrawnPerOperation_WithP50P95P99_AndTheBudgetLineAt250()
    {
        for (var i = 1; i <= 20; i++)
        {
            Add("wrapkey", ms: i, minutesAgo: 2);
            Add("unwrapkey", ms: i * 2, minutesAgo: 2);
        }

        var cut = Open();
        var charts = cut.FindAll("[data-role='latency-section'] [data-chart='line']");

        charts.Count.ShouldBe(2);
        charts.Select(static c => c.QuerySelector("figcaption")!.TextContent).ShouldBe(["wrapkey latency", "unwrapkey latency"]); // the four EKM operations keep a fixed order
        foreach (var chart in charts)
        {
            chart.QuerySelectorAll("polyline.chart-series").Select(static l => l.GetAttribute("data-series")).ShouldBe(["p50", "p95", "p99"]);
            chart.QuerySelector("[data-role='budget']")!.GetAttribute("data-value").ShouldBe("250");
            chart.QuerySelector("[data-role='budget-label']")!.TextContent.ShouldBe("250 ms budget");
        }
    }

    [Fact]
    public void ThePerOperationTable_ShowsCountsAndPercentiles_FromTheAggregates()
    {
        for (var i = 1; i <= 100; i++)
        {
            Add("wrapkey", ms: i);
        }

        var row = Open().Find("tr[data-operation='wrapkey']");

        var text = Text(row);
        text.ShouldStartWith("wrapkey 100");
        text.ShouldContain("50.0 ms"); // p50 (nearest rank)
        text.ShouldContain("95.0 ms"); // p95
        text.ShouldContain("99.0 ms"); // p99
        text.ShouldContain("100 ms"); // max
        row.QuerySelector("[data-chart='sparkline']").ShouldNotBeNull();
    }

    [Fact]
    public void ErrorsByCode_AreBars_SortedByCount_WithTheirNumbersAsText()
    {
        Add("unwrapkey", 404, code: "KeyNotFound");
        Add("unwrapkey", 404, code: "KeyNotFound");
        Add("unwrapkey", 404, code: "KeyNotFound");
        Add("wrapkey", 403, code: "KeyDisabled");
        Add("wrapkey", 200);

        var bars = Open().Find("[data-role='errors']");

        bars.QuerySelectorAll(".bar-row").Select(static r => r.GetAttribute("data-label")).ShouldBe(["KeyNotFound", "KeyDisabled"]);
        bars.QuerySelectorAll("[data-role='bar-value']").Select(static v => v.TextContent).ShouldBe(["3", "1"]);
    }

    [Fact]
    public void TheWindowSelector_SwitchesBetween15MinutesAndOneHour()
    {
        Add("wrapkey", minutesAgo: 5);
        Add("wrapkey", minutesAgo: 40);
        var cut = Open();
        cut.Find("[data-role='total-requests']").TextContent.ShouldBe("1");
        Text(cut.Find("[data-role='totals']")).ShouldContain("Last 15 minutes");

        cut.Find("[data-role='window'] fluent-option[value='60']").Click();

        cut.Find("[data-role='total-requests']").TextContent.ShouldBe("2");
        Text(cut.Find("[data-role='totals']")).ShouldContain("Last 60 minutes");
        cut.FindAll("[data-chart='stacked-columns'] g.chart-column").Count.ShouldBe(60);
        cut.FindAll("[data-chart='stacked-columns'] rect.chart-bar").Count.ShouldBe(2);
    }

    [Fact]
    public void TheDroppedCaptureCounter_IsShown()
    {
        var cut = Open();

        cut.Find("[data-role='dropped-captures']").TextContent.ShouldBe("0");
    }

    // ---- the heartbeat (spec 8.5: red when the last info call is older than 60 s) ----

    [Fact]
    public void TheHeartbeat_IsGreen_FourteenSecondsAfterAnInfoCall_AndNamesTheClient()
    {
        InspectorFake.Publish(Rec.Make(1, "info", cn: "contoso.managedhsmclient.azure.net", at: Now.AddSeconds(-14)));

        var heartbeat = Open().Find("[data-role='heartbeat']");

        heartbeat.GetAttribute("data-state").ShouldBe("ok");
        heartbeat.ClassList.ShouldContain("heartbeat-ok");
        Text(heartbeat).ShouldContain("Healthy");
        Text(heartbeat).ShouldContain("Last info call 14 s ago from CN contoso.managedhsmclient.azure.net.");
    }

    [Fact]
    public void TheHeartbeat_TurnsRed_PastSixtySeconds_WithoutReQueryingAnything()
    {
        InspectorFake.Publish(Rec.Make(1, "info", cn: "contoso.managedhsmclient.azure.net", at: Now.AddSeconds(-14)));
        var cut = Open();
        var heartbeat = cut.FindComponent<HeartbeatCard>();

        ManualTime.Advance(TimeSpan.FromSeconds(46)); // 60 s: still within the limit
        cut.Find("[data-role='heartbeat']").GetAttribute("data-state").ShouldBe("ok");
        Text(cut.Find("[data-role='heartbeat-detail']")).ShouldContain("1 min 0 s ago");

        ManualTime.Advance(TimeSpan.FromSeconds(2)); // 62 s: stale
        var element = cut.Find("[data-role='heartbeat']");
        element.GetAttribute("data-state").ShouldBe("stale");
        element.ClassList.ShouldContain("heartbeat-stale");
        Text(element).ShouldContain("Stale: no recent probe");
        Text(element).ShouldContain("1 min 2 s ago");
        heartbeat.ShouldNotBeNull();
    }

    [Fact]
    public async Task TheHeartbeat_TicksOncePerSecond_FromAClockTimer_AndTheTimerIsDisposedWithThePage()
    {
        InspectorFake.Publish(Rec.Make(1, "info", at: Now.AddSeconds(-1)));
        var cut = Open();
        var before = cut.FindComponent<HeartbeatCard>().RenderCount;

        ManualTime.Advance(TimeSpan.FromSeconds(3));

        cut.FindComponent<HeartbeatCard>().RenderCount.ShouldBeGreaterThan(before);
        ManualTime.ActiveTimers.ShouldBeGreaterThanOrEqualTo(2); // the heartbeat tick and the dashboard refresh

        await DisposeComponentsAsync();

        ManualTime.ActiveTimers.ShouldBe(0);
    }

    [Fact]
    public void ARejectedInfoProbe_StillCountsAsHeartbeat_AndShowsTheStatus()
    {
        InspectorFake.Publish(Rec.Make(1, "info", 401, cn: "wrong.example", at: Now.AddSeconds(-5), code: "Unauthenticated"));

        var heartbeat = Open().Find("[data-role='heartbeat']");

        heartbeat.GetAttribute("data-state").ShouldBe("ok");
        Text(heartbeat).ShouldContain("(answered 401)");
    }

    // ---- refresh ----

    [Fact]
    public void TheDashboard_RefreshesOnATimer_AndShowsWhenItWasUpdated()
    {
        var cut = Open();
        cut.Find("[data-role='total-requests']").TextContent.ShouldBe("0");
        Text(cut.Find("[data-role='updated']")).ShouldContain("refreshes every 2 s");

        Add("wrapkey");
        cut.Find("[data-role='total-requests']").TextContent.ShouldBe("0"); // not before the timer fires
        ManualTime.Advance(TimeSpan.FromSeconds(2));

        cut.Find("[data-role='total-requests']").TextContent.ShouldBe("1");
        Text(cut.Find("[data-role='updated']")).ShouldContain("12:30:02");
    }

    // ---- the mapping ----

    [Fact]
    public void DashboardView_MapsTheSnapshotToChartData_ForTheChosenWindow()
    {
        Add("wrapkey", minutesAgo: 2, ms: 10);
        Add("wrapkey", minutesAgo: 30, ms: 20);
        Add("info", minutesAgo: 2, ms: 1);
        var snapshot = InspectorFake.Dashboard();

        var fifteen = DashboardView.From(snapshot, DashboardWindow.Minutes15);
        var hour = DashboardView.From(snapshot, DashboardWindow.Hour1);

        fifteen.RequestsPerMinute.Count.ShouldBe(15);
        fifteen.RequestsPerMinute.Count(static c => c.Segments.Count > 0).ShouldBe(1);
        hour.RequestsPerMinute.Count.ShouldBe(60);
        hour.RequestsPerMinute.Count(static c => c.Segments.Count > 0).ShouldBe(2);
        fifteen.RateByOperation["wrapkey"].Count.ShouldBe(15);
        hour.RateByOperation["wrapkey"].Count.ShouldBe(60);
        hour.RateByOperation["wrapkey"].Sum().ShouldBe(2);
        fifteen.LatencyByOperation["wrapkey"][0].Points.Count.ShouldBe(1);
        hour.LatencyByOperation["wrapkey"][0].Points.Count.ShouldBe(2);
        DashboardView.SeriesIndex("info").ShouldBe(0);
        DashboardView.SeriesIndex("unwrapkey").ShouldBe(3);
        DashboardView.SeriesIndex("(unrouted)").ShouldBe(4);
    }
}
