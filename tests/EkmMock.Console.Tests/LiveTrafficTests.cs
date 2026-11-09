using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Components;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.FluentUI.AspNetCore.Components;

namespace EkmMock.Console.Tests;

/// <summary>The Live traffic page (spec 8.5.1): table content, status and budget colours with words, pause/resume, clear, auto-scroll, connection events, filters, the row cap.</summary>
public sealed class LiveTrafficTests : ConsoleTestBase
{
    public LiveTrafficTests()
        : base(realTime: true)
    {
    }

    private IRenderedComponent<LiveTraffic> Open() => Render<LiveTraffic>();

    private static IReadOnlyList<long> RowIds(IRenderedComponent<LiveTraffic> cut)
        => [.. cut.FindAll("[data-row='exchange']").Select(static r => long.Parse(r.GetAttribute("data-exchange-id")!))];

    private static async Task Wait(IRenderedComponent<LiveTraffic> cut, Action assertion) => await cut.WaitForAssertionAsync(assertion, TimeSpan.FromSeconds(5));

    private static string Text(AngleSharp.Dom.IElement element) => Dom.Text(element);

    // ---- content ----

    [Fact]
    public void TheTable_ShowsTheNewestExchangeFirst_WithTheSpecColumns()
    {
        InspectorFake.Publish(Rec.Make(1));
        InspectorFake.Publish(Rec.Make(2));
        InspectorFake.Publish(Rec.Make(3));

        var cut = Open();

        RowIds(cut).ShouldBe([3, 2, 1]);
        var headers = cut.FindAll("[role='columnheader']").Select(static h => h.TextContent.Trim()).ToList();
        headers.ShouldBe(["Time (UTC)", "Op", "Namespace", "Key", "Alg", "Status", "Latency", "Client CN", "correlation_id", "Fault"]);
        cut.Find("[role='table']").GetAttribute("aria-label").ShouldBe("Live traffic");
    }

    [Fact]
    public void ARow_ShowsTime_Op_Namespace_Key_Alg_Status_Latency_Cn_AndAShortCorrelationId()
    {
        InspectorFake.Publish(Rec.Make(7, "unwrapkey", 200, 12.34, "contoso", "my-key", "mhsm.example", "0123456789abcdef-long-correlation-id", alg: "RSA-OAEP-256"));

        var row = Open().Find("[data-row='exchange']");

        row.QuerySelector(".cell-time")!.TextContent.ShouldBe("12:00:00.007");
        row.QuerySelector(".cell-op")!.TextContent.ShouldBe("unwrapkey");
        row.QuerySelector(".cell-ns")!.TextContent.ShouldBe("contoso");
        row.QuerySelector(".cell-key")!.TextContent.ShouldBe("my-key");
        row.QuerySelector(".cell-alg")!.TextContent.ShouldBe("RSA-OAEP-256");
        row.QuerySelector(".cell-cn")!.TextContent.ShouldBe("mhsm.example");
        Text(row.QuerySelector("[data-role='latency']")!).ShouldBe("12.3 ms (fast)");
        var correlation = row.QuerySelector("[data-role='correlation-id']")!;
        correlation.TextContent.ShouldBe("01234567…"); // eight characters
        correlation.GetAttribute("title").ShouldBe("0123456789abcdef-long-correlation-id"); // the whole id on hover
        row.QuerySelector("[data-role='copy']").ShouldNotBeNull();
    }

    [Theory]
    [InlineData(200, "status-ok", "200 OK")]
    [InlineData(400, "status-client", "400 BadRequest")]
    [InlineData(401, "status-client", "401 Unauthenticated")]
    [InlineData(403, "status-client", "403 KeyDisabled")]
    [InlineData(429, "status-client", "429 TooManyRequests")]
    [InlineData(500, "status-server", "500 InternalError")]
    [InlineData(503, "status-server", "503 HsmUnavailable")]
    public void TheStatus_IsColouredAndAlwaysWrittenOutInWords(int status, string css, string text)
    {
        InspectorFake.Publish(Rec.Make(1, status: status, code: status >= 400 ? text[(text.IndexOf(' ') + 1)..] : null));

        var cell = Open().Find("[data-role='status']");

        cell.ClassList.ShouldContain(css);
        cell.TextContent.ShouldBe(text);
    }

    [Theory]
    [InlineData(10, "budget-green", "fast", "green")]
    [InlineData(149.9, "budget-green", "fast", "green")]
    [InlineData(150, "budget-amber", "slow", "amber")]
    [InlineData(250, "budget-amber", "slow", "amber")]
    [InlineData(250.1, "budget-red", "over budget", "red")]
    [InlineData(900, "budget-red", "over budget", "red")]
    public void TheLatency_UsesTheBudgetColour_AndTheWordSaysTheSame(double ms, string css, string word, string data)
    {
        InspectorFake.Publish(Rec.Make(1, ms: ms));

        var cell = Open().Find("[data-role='latency']");

        cell.ClassList.ShouldContain(css);
        cell.GetAttribute("data-budget").ShouldBe(data);
        cell.TextContent.ShouldContain($"({word})");
    }

    [Fact]
    public void AFaultBadge_AppearsOnlyWhenARuleFired()
    {
        InspectorFake.Publish(Rec.Make(1));
        InspectorFake.Publish(Rec.Make(2, fault: new FaultFacts("delay-300")));

        var cut = Open();

        cut.Find("[data-exchange-id='2'] [data-role='fault']").TextContent.ShouldContain("fault: delay-300");
        cut.Find("[data-exchange-id='1'] [data-role='fault']").TextContent.Trim().ShouldBeEmpty();
    }

    [Fact]
    public void ARowWithoutAClientCertificate_SaysSo()
    {
        InspectorFake.Publish(Rec.Make(1, cn: null, status: 401, code: "Unauthenticated"));

        Open().Find(".cell-cn").TextContent.ShouldBe("(no certificate)");
    }

    [Fact]
    public void WithNoTraffic_TheTableSaysSo()
    {
        var cut = Open();

        cut.Find("[data-role='empty']").TextContent.ShouldContain("No traffic yet");
        cut.FindAll("[data-row]").ShouldBeEmpty();
        Text(cut.Find("[data-role='row-count']")).ShouldBe("0 rows");
    }

    // ---- live arrival ----

    [Fact]
    public async Task ANewExchange_AppearsOnTopWithoutReloading()
    {
        InspectorFake.Publish(Rec.Make(1));
        var cut = Open();

        InspectorFake.Publish(Rec.Make(2, "info"));
        InspectorFake.Publish(Rec.Make(3, "metadata"));

        await Wait(cut, () => RowIds(cut).ShouldBe([3, 2, 1]));
    }

    [Fact]
    public async Task ABurstOfExchanges_IsRenderedInBatches_NotOneRenderPerExchange()
    {
        var cut = Open();
        await Task.Delay(100, Xunit.TestContext.Current.CancellationToken);
        var before = cut.RenderCount;

        for (var i = 1; i <= 500; i++)
        {
            InspectorFake.Publish(Rec.Make(i));
        }

        await Wait(cut, () => Text(cut.Find("[data-role='row-count']")).ShouldBe("500 rows"));
        (cut.RenderCount - before).ShouldBeLessThan(60, "500 exchanges must not cause 500 renders");
    }

    // ---- pause, resume, clear, auto-scroll ----

    [Fact]
    public async Task Pause_FreezesTheList_CountsWhatArrives_AndResumeShowsIt()
    {
        InspectorFake.Publish(Rec.Make(1));
        var cut = Open();

        cut.Find("[data-role='pause-resume']").Click();
        cut.Find("[data-role='pause-resume']").TextContent.Trim().ShouldBe("Resume");
        cut.Find("[data-role='state-word']").TextContent.Trim().ShouldBe("Paused");

        InspectorFake.Publish(Rec.Make(2));
        InspectorFake.Publish(Rec.Make(3));

        await Wait(cut, () => Text(cut.Find("[data-role='pending']")).ShouldBe("2 new exchanges are waiting"));
        RowIds(cut).ShouldBe([1]);

        cut.Find("[data-role='pause-resume']").Click();

        RowIds(cut).ShouldBe([3, 2, 1]);
        cut.FindAll("[data-role='pending']").ShouldBeEmpty();
        cut.Find("[data-role='state-word']").TextContent.Trim().ShouldBe("Live");
    }

    [Fact]
    public async Task ThePauseBuffer_IsBounded_AndTheDropsAreCounted()
    {
        using var small = new ConsoleOptionsContext(o => o.LiveTraffic.MaxPending = 10);
        var cut = small.Render<LiveTraffic>();
        cut.Find("[data-role='pause-resume']").Click();

        for (var i = 1; i <= 25; i++)
        {
            small.Inspector.Publish(Rec.Make(i));
        }

        await cut.WaitForAssertionAsync(
            () =>
            {
                Text(cut.Find("[data-role='pending']")).ShouldContain("10 new exchanges are waiting");
                Text(cut.Find("[data-role='pending']")).ShouldContain("(15 older ones were dropped)");
            },
            TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ClearView_EmptiesOnlyTheView_TheInspectorKeepsItsHistory_AndNewRowsStillArrive()
    {
        InspectorFake.Publish(Rec.Make(1));
        InspectorFake.Publish(Rec.Make(2));
        var cut = Open();
        RowIds(cut).Count.ShouldBe(2);

        cut.Find("[data-role='clear']").Click();

        RowIds(cut).ShouldBeEmpty();
        InspectorFake.Count().ShouldBe(2);
        InspectorFake.Publish(Rec.Make(3));
        await Wait(cut, () => RowIds(cut).ShouldBe([3]));

        // A filter reload does not bring the cleared rows back.
        await SetCheckbox(cut, "Only errors", true);
        RowIds(cut).ShouldBeEmpty(); // exchange 3 is a 200: not an error
        await SetCheckbox(cut, "Only errors", false);
        RowIds(cut).ShouldBe([3]);
    }

    [Fact]
    public async Task AutoScroll_ScrollsToTheNewestRow_WhileOn_AndStopsWhenSwitchedOff()
    {
        var cut = Open();
        int Scrolls() => JSInterop.Invocations.Count(static i => i.Identifier == "ekmConsole.scrollToTop");

        InspectorFake.Publish(Rec.Make(1));
        await Wait(cut, () => Scrolls().ShouldBeGreaterThan(0));

        await cut.InvokeAsync(() => cut.FindComponents<FluentSwitch>().First(static s => s.Instance.Label == "Auto-scroll").Instance.ValueChanged.InvokeAsync(false));
        var before = Scrolls();
        InspectorFake.Publish(Rec.Make(2));
        await Wait(cut, () => RowIds(cut).ShouldBe([2, 1]));
        await Task.Delay(100, Xunit.TestContext.Current.CancellationToken);

        Scrolls().ShouldBe(before);
    }

    // ---- connection events inline ----

    [Fact]
    public async Task ConnectionEvents_AppearInline_WithTheFailureReason_AndTheToggleHidesThem()
    {
        var cut = Open();
        InspectorFake.Publish(Rec.Make(1));
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("handshake_failed", failureReason: "client_cert_not_trusted", failureDescription: "The client certificate chain is not trusted"));

        await Wait(cut, () => cut.FindAll("[data-row='connection']").Count.ShouldBe(1));
        var connection = cut.Find("[data-row='connection']");
        connection.TextContent.ShouldContain("TLS handshake failed: The client certificate chain is not trusted");
        connection.ClassList.ShouldContain("connection-failed");
        RowIds(cut).ShouldBe([1]);

        await cut.InvokeAsync(() => cut.FindComponents<FluentSwitch>().First(static s => s.Instance.Label == "Connection events").Instance.ValueChanged.InvokeAsync(false));
        cut.FindAll("[data-row='connection']").ShouldBeEmpty();
        RowIds(cut).ShouldBe([1]);

        await cut.InvokeAsync(() => cut.FindComponents<FluentSwitch>().First(static s => s.Instance.Label == "Connection events").Instance.ValueChanged.InvokeAsync(true));
        cut.FindAll("[data-row='connection']").Count.ShouldBe(1);
    }

    [Fact]
    public void ConnectionEvents_AlreadyKnown_AreShownWhenThePageOpens()
    {
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("opened"));
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("closed"));

        var cut = Open();

        cut.FindAll("[data-row='connection']").Count.ShouldBe(2);
        cut.Markup.ShouldContain("Connection closed after 1.5 s, 3 request(s)");
    }

    // ---- filters (spec 8.5.1) ----

    private static async Task SetText(IRenderedComponent<LiveTraffic> cut, string label, string value)
        => await cut.InvokeAsync(() => cut.FindComponents<FluentTextField>().First(t => t.Instance.Label == label).Instance.ValueChanged.InvokeAsync(value));

    private static async Task SetCheckbox(IRenderedComponent<LiveTraffic> cut, string label, bool value)
        => await cut.InvokeAsync(() => cut.FindComponents<FluentCheckbox>().First(c => c.Instance.Label == label).Instance.ValueChanged.InvokeAsync(value));

    private static void Choose(IRenderedComponent<LiveTraffic> cut, string role, string value)
        => cut.Find($"[data-role='{role}'] fluent-option[value='{value}']").Click();

    private void SeedMixedTraffic()
    {
        InspectorFake.Publish(Rec.Make(1, "info", 200, 3, key: null, ns: "_default", cn: "a.test", correlationId: "corr-aaa", poolName: "pool-a"));
        InspectorFake.Publish(Rec.Make(2, "wrapkey", 200, 20, ns: "_default", key: "k1", cn: "a.test", correlationId: "corr-bbb", poolName: "pool-b"));
        InspectorFake.Publish(Rec.Make(3, "unwrapkey", 404, 5, ns: "contoso", key: "k2", cn: "b.test", correlationId: "corr-ccc", poolName: "pool-c", code: "KeyNotFound"));
        InspectorFake.Publish(Rec.Make(4, "wrapkey", 200, 300, ns: "contoso", key: "k2", cn: "b.test", correlationId: "corr-ddd", poolName: "pool-d"));
        InspectorFake.Publish(Rec.Make(5, "wrapkey", 503, 4, ns: "_default", key: "k1", cn: "a.test", correlationId: "corr-eee", poolName: "pool-e", code: "HsmUnavailable"));
    }

    [Fact]
    public async Task TheCheckboxFilters_OnlyErrors_OnlyOverBudget_HideHealthProbes()
    {
        SeedMixedTraffic();
        var cut = Open();
        RowIds(cut).ShouldBe([5, 4, 3, 2, 1]);

        await SetCheckbox(cut, "Only errors", true);
        RowIds(cut).ShouldBe([5, 3]);
        await SetCheckbox(cut, "Only errors", false);

        await SetCheckbox(cut, "Only over budget", true);
        RowIds(cut).ShouldBe([4]);
        await SetCheckbox(cut, "Only over budget", false);

        await SetCheckbox(cut, "Hide health probes (info)", true);
        RowIds(cut).ShouldBe([5, 4, 3, 2]);
    }

    [Fact]
    public async Task TheTextFilters_Namespace_Key_ClientCn_AndCorrelationOrPoolSearch()
    {
        SeedMixedTraffic();
        var cut = Open();

        await SetText(cut, "Namespace", "contoso");
        RowIds(cut).ShouldBe([4, 3]);
        await SetText(cut, "Namespace", string.Empty);

        await SetText(cut, "Key", "k1");
        RowIds(cut).ShouldBe([5, 2]);
        await SetText(cut, "Key", string.Empty);

        await SetText(cut, "Client CN", "b.test");
        RowIds(cut).ShouldBe([4, 3]);
        await SetText(cut, "Client CN", string.Empty);

        await SetText(cut, "correlation_id / pool_name", "CORR-bb");
        RowIds(cut).ShouldBe([2]);
        await SetText(cut, "correlation_id / pool_name", "pool-e");
        RowIds(cut).ShouldBe([5]);
    }

    [Fact]
    public async Task TheOperationAndStatusClassFilters_AreSelects()
    {
        SeedMixedTraffic();
        var cut = Open();

        Choose(cut, "filter-op", "wrapkey");
        await Wait(cut, () => RowIds(cut).ShouldBe([5, 4, 2]));

        Choose(cut, "filter-status", "5");
        await Wait(cut, () => RowIds(cut).ShouldBe([5]));

        Choose(cut, "filter-op", string.Empty);
        Choose(cut, "filter-status", "4");
        await Wait(cut, () => RowIds(cut).ShouldBe([3]));
    }

    [Fact]
    public async Task Filters_AreCombinedWithAnd_AndResetClearsThemAll()
    {
        SeedMixedTraffic();
        var cut = Open();

        await SetText(cut, "Namespace", "_default");
        await SetCheckbox(cut, "Only errors", true);
        RowIds(cut).ShouldBe([5]);

        cut.Find("[data-role='filter-reset']").Click();

        RowIds(cut).ShouldBe([5, 4, 3, 2, 1]);
        cut.FindComponents<FluentTextField>().First(static t => t.Instance.Label == "Namespace").Instance.Value.ShouldBe(string.Empty);
        cut.FindComponents<FluentCheckbox>().ShouldAllBe(static c => c.Instance.Value == false);
    }

    [Fact]
    public async Task AFilter_AlsoAppliesToWhatArrivesLater()
    {
        var cut = Open();
        await SetCheckbox(cut, "Only errors", true);

        InspectorFake.Publish(Rec.Make(1, status: 200));
        InspectorFake.Publish(Rec.Make(2, status: 500, code: "InternalError"));

        await Wait(cut, () => RowIds(cut).ShouldBe([2]));
    }

    [Fact]
    public async Task AFilter_ReachesBackIntoTheInspectorHistory_BeyondWhatThePageLoadedOnOpen()
    {
        using var small = new ConsoleOptionsContext(o => o.LiveTraffic.InitialRows = 3);
        small.Inspector.Publish(Rec.Make(1, status: 500, code: "InternalError"));
        for (var i = 2; i <= 10; i++)
        {
            small.Inspector.Publish(Rec.Make(i));
        }

        var cut = small.Render<LiveTraffic>();
        cut.FindAll("[data-row='exchange']").Count.ShouldBe(3);

        await cut.InvokeAsync(() => cut.FindComponents<FluentCheckbox>().First(static c => c.Instance.Label == "Only errors").Instance.ValueChanged.InvokeAsync(true));

        cut.FindAll("[data-row='exchange']").Select(static r => r.GetAttribute("data-exchange-id")).ShouldBe(["1"]);
    }

    // ---- the cap ----

    [Fact]
    public async Task TheList_IsCapped_AndSaysHowManyRowsLeftTheView()
    {
        using var small = new ConsoleOptionsContext(o => o.LiveTraffic.MaxRows = 10);
        var cut = small.Render<LiveTraffic>();

        for (var i = 1; i <= 25; i++)
        {
            small.Inspector.Publish(Rec.Make(i));
        }

        await cut.WaitForAssertionAsync(
            () =>
            {
                Text(cut.Find("[data-role='row-count']")).ShouldContain("10 rows");
                Text(cut.Find("[data-role='row-count']")).ShouldContain("15 older rows left this view (cap 10)");
            },
            TimeSpan.FromSeconds(5));
        await cut.WaitForAssertionAsync(() => cut.FindAll("[data-row='exchange']").Select(static r => r.GetAttribute("data-exchange-id")).First().ShouldBe("25"), TimeSpan.FromSeconds(5));
    }

    // ---- the detail panel ----

    [Fact]
    public void ClickingARow_OpensTheDetailPanel_AndCloseHidesIt()
    {
        InspectorFake.Publish(Rec.Make(1));
        InspectorFake.Publish(Rec.Make(2, "unwrapkey"));
        var cut = Open();
        cut.FindAll("[data-role='detail-panel']").ShouldBeEmpty();

        cut.Find("[data-exchange-id='2']").Click();

        cut.Find("[data-role='detail-panel'] [data-role='exchange-detail']").GetAttribute("data-exchange-id").ShouldBe("2");
        cut.Find("[data-exchange-id='2']").GetAttribute("aria-selected").ShouldBe("true");
        cut.Find("[data-role='open-full']").GetAttribute("href").ShouldBe("/exchange/2");

        cut.Find("[data-role='close-detail']").Click();
        cut.FindAll("[data-role='detail-panel']").ShouldBeEmpty();
    }

    [Fact]
    public void ARow_IsKeyboardOperable_EnterOpensTheDetail()
    {
        InspectorFake.Publish(Rec.Make(1));
        var cut = Open();
        var row = cut.Find("[data-exchange-id='1']");
        row.GetAttribute("tabindex").ShouldBe("0");

        row.KeyDown(new KeyboardEventArgs { Key = "Enter" });

        cut.Find("[data-role='detail-panel']").ShouldNotBeNull();
    }

    // ---- lifetime ----

    [Fact]
    public async Task LeavingThePage_UnsubscribesFromTheFeed()
    {
        var cut = Open();
        InspectorFake.Feed.SubscriberCount.ShouldBe(1);

        await DisposeComponentsAsync();

        InspectorFake.Feed.SubscriberCount.ShouldBe(0);
        cut.ShouldNotBeNull();
    }
}

/// <summary>A second, separately configured component context for tests that need other live-traffic limits.</summary>
internal sealed class ConsoleOptionsContext : ConsoleTestBase
{
    public ConsoleOptionsContext(Action<ConsoleOptions> configure)
        : base(realTime: true, configure)
    {
    }

    public FakeInspector Inspector => InspectorFake;
}
