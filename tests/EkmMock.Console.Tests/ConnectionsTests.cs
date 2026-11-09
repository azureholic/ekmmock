using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.FluentUI.AspNetCore.Components;

namespace EkmMock.Console.Tests;

/// <summary>The Connections page (spec 8.2, 8.5.3): events, open connections, requests per connection, resumption rate; live.</summary>
public sealed class ConnectionsTests : ConsoleTestBase
{
    public ConnectionsTests()
        : base(realTime: true)
    {
    }

    private static string Text(AngleSharp.Dom.IElement element) => Dom.Text(element);

    private IRenderedComponent<Connections> Open() => Render<Connections>();

    private OpenConnectionInfo OpenConnection(string id, long requests = 3, string? subject = "CN=mhsm.example")
        => new(id, "203.0.113.5:44000", Rec.Epoch, 65_000, requests, true, "TLS 1.3", "TLS_AES_256_GCM_SHA384", "http/1.1", "ekm.test", subject);

    [Fact]
    public void WithNothingYet_ThePageShowsEmptyStates_AndZeroStatistics()
    {
        var cut = Open();

        cut.Find("[data-role='open-empty']").TextContent.ShouldBe("No open connections.");
        cut.Find("[data-role='events-empty']").TextContent.ShouldBe("No connection events yet.");
        cut.Find("[data-role='opened']").TextContent.ShouldBe("0");
        cut.Find("[data-role='open-now']").TextContent.ShouldBe("0");
        cut.Find("[data-role='resumption-rate']").TextContent.ShouldContain("0.0 %");
    }

    [Fact]
    public void TheEvents_ListOpenedHandshakeFailedAndClosed_NewestFirst_WithTheReasonInWords()
    {
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("opened", "conn-a", Rec.Epoch.AddSeconds(1)));
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("handshake_succeeded", "conn-a", Rec.Epoch.AddSeconds(2)));
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("handshake_failed", "conn-b", Rec.Epoch.AddSeconds(3), "tls_version_not_supported", "The client offered TLS 1.2 only"));
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("closed", "conn-a", Rec.Epoch.AddSeconds(4)));

        var cut = Open();
        var rows = cut.FindAll("[data-role='events-table'] tbody tr");

        rows.Select(static r => r.GetAttribute("data-event-kind")).ShouldBe(["closed", "handshake_failed", "handshake_succeeded", "opened"]);
        var failed = rows[1];
        failed.ClassList.ShouldContain("connection-failed");
        Text(failed).ShouldContain("Handshake FAILED");
        Text(failed).ShouldContain("TLS handshake failed: The client offered TLS 1.2 only");
        Text(rows[0]).ShouldContain("Connection closed after 1.5 s, 3 request(s)");
        Text(rows[2]).ShouldContain("TLS handshake ok (TLS 1.3, TLS_AES_256_GCM_SHA384)");
    }

    [Fact]
    public void TheStatistics_CountTheEvents_AndExplainTheFailureReasons()
    {
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("opened"));
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("handshake_succeeded"));
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("handshake_failed", "conn-2", failureReason: "no_common_cipher_suite"));
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("handshake_failed", "conn-3", failureReason: "no_common_cipher_suite"));
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("closed"));

        var cut = Open();

        cut.Find("[data-role='opened']").TextContent.ShouldBe("1");
        cut.Find("[data-role='handshakes-ok']").TextContent.ShouldBe("1");
        var failed = cut.Find("[data-role='handshakes-failed']");
        failed.TextContent.ShouldBe("2");
        failed.ClassList.ShouldContain("status-server");
        cut.Find("[data-role='closed']").TextContent.ShouldBe("1");
        cut.Find("[data-role='avg-requests']").TextContent.ShouldBe("3.0");
        Text(cut.Find("[data-role='failure-reasons']")).ShouldBe("no_common_cipher_suite : 2");
        Text(cut.Find("[data-role='resumption-rate']")).ShouldContain("resumption is switched off on purpose");
    }

    [Fact]
    public async Task FailuresOnly_FiltersTheEventList()
    {
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("opened"));
        InspectorFake.Publish(InspectorFake.NewConnectionEvent("handshake_failed", "conn-2", failureReason: "client_closed"));
        var cut = Open();
        cut.FindAll("[data-role='events-table'] tbody tr").Count.ShouldBe(2);

        await cut.InvokeAsync(() => cut.FindComponent<FluentSwitch>().Instance.ValueChanged.InvokeAsync(true));

        cut.FindAll("[data-role='events-table'] tbody tr").Select(static r => r.GetAttribute("data-event-kind")).ShouldBe(["handshake_failed"]);
    }

    [Fact]
    public void OpenConnections_ShowTheirTlsFacts_ClientCertificate_AndRequestCount()
    {
        InspectorFake.Open = [OpenConnection("conn-a", requests: 17), OpenConnection("conn-b", requests: 2, subject: null)];

        var cut = Open();
        var text = Text(cut.Find("[data-role='open-connections']"));

        cut.Find("[data-role='open-now']").TextContent.ShouldBe("2");
        text.ShouldContain("Open connections (2)");
        text.ShouldContain("203.0.113.5:44000");
        text.ShouldContain("17");
        text.ShouldContain("TLS 1.3");
        text.ShouldContain("TLS_AES_256_GCM_SHA384");
        text.ShouldContain("http/1.1");
        text.ShouldContain("ekm.test");
        text.ShouldContain("CN=mhsm.example");
        text.ShouldContain("1m 5s"); // 65 s old
    }

    [Fact]
    public async Task ANewEvent_ShowsUpWithoutReloading()
    {
        var cut = Open();
        cut.FindAll("[data-role='events-table']").ShouldBeEmpty();

        InspectorFake.Publish(InspectorFake.NewConnectionEvent("handshake_failed", "conn-9", failureReason: "not_tls", failureDescription: "Plain HTTP was sent to the TLS port"));

        await cut.WaitForAssertionAsync(
            () =>
            {
                Text(cut.Find("[data-role='events-table']")).ShouldContain("Plain HTTP was sent to the TLS port");
                cut.Find("[data-role='handshakes-failed']").TextContent.ShouldBe("1");
            },
            TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task TheOpenConnectionCounters_RefreshOncePerSecond()
    {
        var cut = Open();
        cut.Find("[data-role='open-now']").TextContent.ShouldBe("0");

        InspectorFake.Open = [OpenConnection("conn-a")];

        await cut.WaitForAssertionAsync(() => cut.Find("[data-role='open-now']").TextContent.ShouldBe("1"), TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task LeavingThePage_UnsubscribesAndStopsTheTimer()
    {
        var cut = Open();
        InspectorFake.Feed.SubscriberCount.ShouldBe(1);

        await DisposeComponentsAsync();

        InspectorFake.Feed.SubscriberCount.ShouldBe(0);
        cut.ShouldNotBeNull();
    }
}
