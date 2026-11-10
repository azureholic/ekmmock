using AngleSharp.Dom;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Components;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.AspNetCore.Components.Web;

namespace EkmMock.Console.Tests;

/// <summary>The Exchange detail (spec 8.5.2): tabs, TLS facts, request/response bodies, the waterfall, KQL, copy, replay, reveal.</summary>
public sealed class ExchangeDetailTests : ConsoleTestBase
{
    private const string MaskedText = "32 bytes · fp 3f9a1c07b2e4";

    private IRenderedComponent<ExchangeDetailView> Open(long id, bool compact = false)
        => Render<ExchangeDetailView>(p => p.Add(static c => c.ExchangeId, id).Add(static c => c.Compact, compact));

    private static string Text(IElement element) => Dom.Text(element);

    private static void SelectTab(IRenderedComponent<ExchangeDetailView> cut, string tab) => cut.Find($"[role='tab'][data-tab='{tab}']").Click();

    private static MaskedField Masked(bool revealable = true) => new("value", MaskedText, 32, "3f9a1c07b2e4", revealable);

    private ExchangeRecord WrapWithMaskedDek(long id = 1, bool revealable = true, int status = 200)
        => Rec.Make(
            id,
            "wrapkey",
            status,
            bodyText: $$"""{"request_context":{"request_id":"r","correlation_id":"c","pool_name":"p"},"alg":"A256KWP","value":"{{MaskedText}}"}""",
            responseText: """{"value":"wrapped-ciphertext-is-not-secret"}""",
            requestMasked: [Masked(revealable)]);

    // ---- tabs ----

    [Fact]
    public void TheDetail_HasTheFiveSpecTabs_AsAnAccessibleTabList_WithOverviewFirst()
    {
        InspectorFake.Publish(Rec.Make(1));

        var cut = Open(1);

        cut.Find("[role='tablist']").ShouldNotBeNull();
        cut.FindAll("[role='tab']").Select(static t => Text(t)).ShouldBe(["Overview", "TLS & client certificate", "Request", "Response", "Timing"]);
        cut.Find("[role='tab'][data-tab='overview']").GetAttribute("aria-selected").ShouldBe("true");
        cut.FindAll("[role='tab'][aria-selected='false']").Count.ShouldBe(4);
        var panel = cut.Find("[role='tabpanel']");
        panel.GetAttribute("data-panel").ShouldBe("overview");
        panel.GetAttribute("aria-labelledby").ShouldBe("tab-overview");
        cut.FindAll("[role='tabpanel']").Count.ShouldBe(1, "only the active panel is in the page");
    }

    [Theory]
    [InlineData("tls", "tab-tls")]
    [InlineData("request", "tab-request")]
    [InlineData("response", "tab-response")]
    [InlineData("timing", "tab-timing")]
    [InlineData("overview", "tab-overview")]
    public void ClickingATab_ShowsItsPanel(string tab, string role)
    {
        InspectorFake.Publish(Rec.Make(1));
        var cut = Open(1);

        SelectTab(cut, tab);

        cut.Find($"[data-role='{role}']").ShouldNotBeNull();
        cut.Find($"[data-tab='{tab}']").GetAttribute("aria-selected").ShouldBe("true");
        cut.Find("[role='tabpanel']").GetAttribute("data-panel").ShouldBe(tab);
    }

    [Fact]
    public void TheTabs_FollowTheArrowKeyPattern_WithWrapping_AndRovingTabIndex()
    {
        InspectorFake.Publish(Rec.Make(1));
        var cut = Open(1);
        cut.Find("[data-tab='overview']").GetAttribute("tabindex").ShouldBe("0");
        cut.Find("[data-tab='tls']").GetAttribute("tabindex").ShouldBe("-1");

        cut.Find("[role='tablist']").KeyDown(new KeyboardEventArgs { Key = "ArrowRight" });
        cut.Find("[data-tab='tls']").GetAttribute("aria-selected").ShouldBe("true");
        cut.Find("[data-tab='tls']").GetAttribute("tabindex").ShouldBe("0");

        cut.Find("[role='tablist']").KeyDown(new KeyboardEventArgs { Key = "ArrowLeft" });
        cut.Find("[data-tab='overview']").GetAttribute("aria-selected").ShouldBe("true");
        cut.Find("[role='tablist']").KeyDown(new KeyboardEventArgs { Key = "ArrowLeft" });
        cut.Find("[data-tab='timing']").GetAttribute("aria-selected").ShouldBe("true"); // wraps to the last
        cut.Find("[role='tablist']").KeyDown(new KeyboardEventArgs { Key = "Home" });
        cut.Find("[data-tab='overview']").GetAttribute("aria-selected").ShouldBe("true");
        cut.Find("[role='tablist']").KeyDown(new KeyboardEventArgs { Key = "End" });
        cut.Find("[data-tab='timing']").GetAttribute("aria-selected").ShouldBe("true");
        cut.Find("[role='tablist']").KeyDown(new KeyboardEventArgs { Key = "x" });
        cut.Find("[data-tab='timing']").GetAttribute("aria-selected").ShouldBe("true");
    }

    // ---- overview ----

    [Fact]
    public void Overview_ShowsTheIdentityContextAndKeyFacts_WithCopyButtons()
    {
        InspectorFake.Publish(Rec.Make(12, "unwrapkey", 200, 12.3, "contoso", "my-key", "mhsm.example", "corr-12345678-abcdef", "pool-x", "req-9", alg: "RSA-OAEP-256"));

        var cut = Open(12);
        var overview = Text(cut.Find("[data-role='tab-overview']"));

        overview.ShouldContain("Exchange id 12");
        overview.ShouldContain("Namespace contoso");
        overview.ShouldContain("Key my-key");
        overview.ShouldContain("Algorithm RSA-OAEP-256");
        overview.ShouldContain("Client CN mhsm.example");
        overview.ShouldContain("request_id req-9");
        overview.ShouldContain("pool_name pool-x");
        overview.ShouldContain("oct 256 bits, Enabled");
        cut.Find("[data-role='detail-correlation-id']").TextContent.ShouldBe("corr-12345678-abcdef");
        cut.FindAll("[data-role='copy']").Count.ShouldBeGreaterThanOrEqualTo(4); // correlation_id, JSON, two KQL snippets
        cut.Find("[data-role='detail-status']").ClassList.ShouldContain("status-ok");
        cut.Find("h2").TextContent.ShouldContain("Exchange 12: unwrapkey");
    }

    [Fact]
    public void Overview_ShowsTheReadyMadeKqlSnippets_ForTheCorrelationId()
    {
        InspectorFake.Publish(Rec.Make(1, "wrapkey", correlationId: "aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85"));

        var cut = Open(1);

        var kql = cut.Find("[data-role='kql-correlation']").TextContent;
        kql.ShouldContain("aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85");
        kql.ShouldContain("EkmWrapKey");
        cut.Find("[data-role='kql-key-time']").TextContent.ShouldContain("aes-key-1");
    }

    [Fact]
    public void Overview_ShowsTheFaultBadge_AndTheInjectedDelay()
    {
        InspectorFake.Publish(Rec.Make(1, ms: 310, delayMs: 300, fault: new FaultFacts("delay-300")));

        var cut = Open(1);

        cut.Find("[data-role='tab-overview']").TextContent.ShouldContain("fault: delay-300");
        SelectTab(cut, "timing");
        Text(cut.Find("[data-role='timing-table']")).ShouldContain("Injected delay 300 ms");
    }

    [Fact]
    public void AnExchangeThatIsNoLongerInTheInspector_SaysSo()
    {
        var cut = Open(999);

        cut.Find("[data-role='detail-missing']").TextContent.ShouldContain("no longer in the inspector");
        cut.FindAll("[data-role='exchange-detail']").ShouldBeEmpty();
    }

    [Fact]
    public void ChangingTheExchange_ReloadsTheDetail_AndStartsAtTheOverview()
    {
        InspectorFake.Publish(Rec.Make(1, "info"));
        InspectorFake.Publish(Rec.Make(2, "wrapkey"));
        var cut = Open(1);
        SelectTab(cut, "timing");

        cut.Render(p => p.Add(static c => c.ExchangeId, 2L));

        cut.Find("[data-role='exchange-detail']").GetAttribute("data-exchange-id").ShouldBe("2");
        cut.Find("[role='tabpanel']").GetAttribute("data-panel").ShouldBe("overview");
    }

    // ---- TLS ----

    [Fact]
    public void TheTlsTab_ShowsTheHandshakeFacts_AndTheClientCertificate()
    {
        InspectorFake.Publish(Rec.Make(1, cn: "mhsm.example"));
        var cut = Open(1);

        SelectTab(cut, "tls");
        var tls = Text(cut.Find("[data-role='tab-tls']"));

        tls.ShouldContain("Protocol TLS 1.3");
        tls.ShouldContain("Cipher suite TLS_AES_256_GCM_SHA384");
        tls.ShouldContain("ALPN http/1.1");
        tls.ShouldContain("SNI ekm.test");
        tls.ShouldContain("Session resumed no");
        tls.ShouldContain("Handshake 2.50 ms");
        tls.ShouldContain("Presented yes");
        tls.ShouldContain("Subject CN=mhsm.example");
        tls.ShouldContain("Issuer CN=Test CA");
        tls.ShouldContain("Serial 0A");
        tls.ShouldContain("Thumbprint (SHA-256) AB12");
        tls.ShouldContain("Chain NoError");
        tls.ShouldContain("CN allowed yes");
        tls.ShouldContain("Namespace matched yes");
    }

    [Fact]
    public void TheTlsTab_ForARejectedClient_ShowsWhyTheServerRefusedIt()
    {
        InspectorFake.Publish(Rec.Make(1, status: 401, code: "Unauthenticated", cn: "wrong.example"));
        var cut = Open(1);

        SelectTab(cut, "tls");

        cut.Find("[data-role='auth-failure']").TextContent.ShouldContain("CommonNameNotAllowed");
        Text(cut.Find("[data-role='tab-tls']")).ShouldContain("CN allowed no");
    }

    [Fact]
    public void TheTlsTab_WithoutACertificate_SaysNotPresented()
    {
        InspectorFake.Publish(Rec.Make(1, status: 401, code: "Unauthenticated", cn: null));
        var cut = Open(1);

        SelectTab(cut, "tls");

        Text(cut.Find("[data-role='tab-tls']")).ShouldContain("Presented no");
    }

    // ---- request and response ----

    [Fact]
    public void TheRequestTab_ShowsHeaders_PrettyJson_AndRaw_WithSecretHeadersRedacted()
    {
        InspectorFake.Publish(WrapWithMaskedDek());
        var cut = Open(1);

        SelectTab(cut, "request");

        cut.Find("[data-role='tab-request']").TextContent.ShouldContain("POST");
        cut.Find("[data-role='tab-request']").TextContent.ShouldContain("/aes-key-1/wrapkey?api-version=0.1-preview");
        var headers = Text(cut.Find("[data-role='headers']"));
        headers.ShouldContain("Content-Type application/json");
        headers.ShouldContain("Authorization [redacted]");
        cut.Find("[data-role='body-json']").TextContent.ShouldContain("\"alg\": \"A256KWP\""); // indented
        cut.Find("[data-role='body-raw']").TextContent.ShouldContain("\"alg\":\"A256KWP\"");
        cut.FindAll("[data-role='copy']").ShouldNotBeEmpty();
    }

    [Fact]
    public void TheMaskedValue_IsShownExactlyAsLengthAndFingerprint()
    {
        InspectorFake.Publish(WrapWithMaskedDek());
        var cut = Open(1);
        SelectTab(cut, "request");

        cut.Find("[data-role='masked-value']").TextContent.ShouldBe("32 bytes · fp 3f9a1c07b2e4");
        cut.Find("[data-role='body-raw']").TextContent.ShouldContain("32 bytes · fp 3f9a1c07b2e4");
    }

    [Fact]
    public void TheResponseTab_ShowsTheStatus_Headers_AndBody()
    {
        InspectorFake.Publish(Rec.Make(1, "wrapkey", 403, code: "KeyDisabled", responseText: """{"code":"KeyDisabled","message":"Operation WrapKey is not allowed on a disabled key"}"""));
        var cut = Open(1);

        SelectTab(cut, "response");

        cut.Find("[data-role='tab-response'] strong").TextContent.ShouldBe("403 KeyDisabled");
        cut.Find("[data-role='tab-response'] strong").ClassList.ShouldContain("status-client");
        cut.Find("[data-role='body-json']").TextContent.ShouldContain("\"code\": \"KeyDisabled\"");
    }

    [Fact]
    public void ABodyThatWasNotCaptured_IsNotShown_AndSaysWhy()
    {
        var record = Rec.Make(1) with
        {
            Request = Rec.Make(1).Request with { Body = new CapturedBody { SizeBytes = 99, Captured = false, Note = "Unparseable body not captured" } },
        };
        InspectorFake.Publish(record);
        var cut = Open(1);

        SelectTab(cut, "request");

        cut.Find("[data-role='body-not-captured']").TextContent.ShouldBe("Unparseable body not captured");
        cut.FindAll("[data-role='body-raw']").ShouldBeEmpty();
    }

    [Fact]
    public void ATruncatedBody_SaysSo_AndHasNoPrettyJson()
    {
        var record = Rec.Make(1) with
        {
            Request = Rec.Make(1).Request with { Body = new CapturedBody { SizeBytes = 40_000, Truncated = true, Text = """{"request_context":{"correlation_id":"c""" } },
        };
        InspectorFake.Publish(record);
        var cut = Open(1);

        SelectTab(cut, "request");

        cut.Find("[data-role='tab-request']").TextContent.ShouldContain("truncated (only the beginning is shown)");
        cut.FindAll("[data-role='body-json']").ShouldBeEmpty();
        cut.Find("[data-role='body-raw']").ShouldNotBeNull();
    }

    // ---- timing ----

    [Fact]
    public void TheTimingTab_DrawsTheWaterfall_AgainstTheBudgetLine()
    {
        InspectorFake.Publish(Rec.Make(1, ms: 100, authMs: 5, cryptoMs: 20, delayMs: 30, queueMs: 2));
        var cut = Open(1);

        SelectTab(cut, "timing");

        var svg = cut.Find("[data-role='waterfall']");
        svg.GetAttribute("role").ShouldBe("img");
        svg.GetAttribute("aria-label")!.ShouldContain("total 100 ms");
        cut.FindAll("[data-segment]").Select(static g => g.GetAttribute("data-segment")).ShouldBe(["Queue wait", "Authorization", "Injected delay", "Crypto engine", "Other (routing, handling)", "Total"]);
        cut.Find("[data-role='waterfall'] [data-role='budget']").GetAttribute("data-value").ShouldBe("250");
        var table = Text(cut.Find("[data-role='timing-table']"));
        table.ShouldContain("Queue wait 2.00 ms");
        table.ShouldContain("Authorization 5.00 ms");
        table.ShouldContain("Crypto engine 20.0 ms");
        table.ShouldContain("Total (server time) 100 ms (fast)");
    }

    [Fact]
    public void TheWaterfall_SeparatesTheStages_AndTheBudgetLineIsRightOfAFastExchangeAndLeftOfASlowOne()
    {
        InspectorFake.Publish(Rec.Make(1, ms: 100));
        InspectorFake.Publish(Rec.Make(2, ms: 400, delayMs: 300));

        var fast = Open(1);
        SelectTab(fast, "timing");
        var slow = Open(2);
        SelectTab(slow, "timing");

        double Budget(IRenderedComponent<ExchangeDetailView> c) => double.Parse(c.Find("[data-role='waterfall'] [data-role='budget']").GetAttribute("x1")!, System.Globalization.CultureInfo.InvariantCulture);
        double TotalEnd(IRenderedComponent<ExchangeDetailView> c)
        {
            var bar = c.Find("[data-segment='Total'] rect");
            return double.Parse(bar.GetAttribute("x")!, System.Globalization.CultureInfo.InvariantCulture) + double.Parse(bar.GetAttribute("width")!, System.Globalization.CultureInfo.InvariantCulture);
        }

        TotalEnd(fast).ShouldBeLessThan(Budget(fast));
        TotalEnd(slow).ShouldBeGreaterThan(Budget(slow));
        slow.Find("[data-segment='Total'] rect").ClassList.ShouldContain("waterfall-red");
        slow.Find("[data-role='timing-table']").TextContent.ShouldContain("(over budget)");
    }

    // ---- reveal ----

    [Fact]
    public void ByDefault_NoRevealButtonIsShown_AndNothingSecretIsInThePage()
    {
        var dek = SecretScanner.RandomDek();
        InspectorFake.Publish(WrapWithMaskedDek());
        InspectorFake.AllowReveal(1, "request.value", SecretScanner.Base64Url(dek));
        var cut = Open(1);

        SelectTab(cut, "request");

        cut.FindAll("[data-role='reveal']").ShouldBeEmpty();
        SecretScanner.LeaksInText(cut.Markup, dek).ShouldBeFalse();
    }

    [Fact]
    public void RevealIsOffered_OnlyWhenAllowed_AndOnlyForARevealableField()
    {
        StatusFake.RevealAllowed = true;
        InspectorFake.Publish(WrapWithMaskedDek(1, revealable: true));
        InspectorFake.Publish(WrapWithMaskedDek(2, revealable: false));
        InspectorFake.Publish(Rec.Make(3, "info"));

        var revealable = Open(1);
        SelectTab(revealable, "request");
        revealable.FindAll("[data-role='reveal']").Count.ShouldBe(1);

        var notRevealable = Open(2);
        SelectTab(notRevealable, "request");
        notRevealable.FindAll("[data-role='reveal']").ShouldBeEmpty();

        var info = Open(3);
        SelectTab(info, "request");
        info.FindAll("[data-role='reveal']").ShouldBeEmpty();
    }

    [Fact]
    public async Task Reveal_CallsTheAuditedServiceAsTheCurrentUser_ShowsTheValueForAShortTime_AndHidesIt()
    {
        var dek = SecretScanner.RandomDek();
        var text = SecretScanner.Base64Url(dek);
        StatusFake.RevealAllowed = true;
        InspectorFake.RevealEnabled = true;
        InspectorFake.Publish(WrapWithMaskedDek());
        InspectorFake.AllowReveal(1, "request.value", text);
        UserFake.Info = new ConsoleUserInfo("11111111-1111-1111-1111-111111111111", "Alice Admin", ConsoleAuthMode.EntraId);
        var cut = Open(1);
        SelectTab(cut, "request");
        SecretScanner.LeaksInText(cut.Markup, dek).ShouldBeFalse("masked until revealed");

        cut.Find("[data-role='reveal']").Click();

        InspectorFake.Reveals.ShouldBe([(1, "request.value", "Alice Admin (11111111-1111-1111-1111-111111111111)")]);
        cut.Find("[data-role='revealed-value']").TextContent.ShouldBe(text);
        cut.Find("[data-role='revealed']").TextContent.ShouldContain("recorded in the audit log");

        // After the display time the value is gone from the page.
        ManualTime.Advance(TimeSpan.FromSeconds(ExchangeDetailView.RevealSeconds - 1));
        cut.FindAll("[data-role='revealed']").Count.ShouldBe(1);
        ManualTime.Advance(TimeSpan.FromSeconds(2));
        await cut.WaitForAssertionAsync(() => cut.FindAll("[data-role='revealed']").ShouldBeEmpty(), TimeSpan.FromSeconds(5));
        SecretScanner.LeaksInText(cut.Markup, dek).ShouldBeFalse();
    }

    [Fact]
    public void Reveal_NeverTouchesJavaScriptStorage_OrTheUrl()
    {
        var dek = SecretScanner.RandomDek();
        var text = SecretScanner.Base64Url(dek);
        StatusFake.RevealAllowed = true;
        InspectorFake.RevealEnabled = true;
        InspectorFake.Publish(WrapWithMaskedDek());
        InspectorFake.AllowReveal(1, "request.value", text);
        var cut = Open(1);
        SelectTab(cut, "request");

        cut.Find("[data-role='reveal']").Click();
        cut.Find("[data-role='hide-revealed']").Click();

        // Not one JavaScript call carried the value, and the page has no link or form that would put it in a URL.
        JSInterop.Invocations.ShouldNotContain(i => i.Arguments.Any(a => a != null && a.ToString()!.Contains(text, StringComparison.Ordinal)));
        JSInterop.Invocations.ShouldNotContain(static i => i.Identifier.Contains("localStorage", StringComparison.OrdinalIgnoreCase) || i.Identifier.Contains("sessionStorage", StringComparison.OrdinalIgnoreCase));
        cut.Markup.ShouldNotContain("href=\"?");
        SecretScanner.LeaksInText(cut.Markup, dek).ShouldBeFalse("hidden again");
    }

    [Fact]
    public void Reveal_HidesWhenTheUserNavigatesToAnotherExchange_OrPressesHide()
    {
        var text = SecretScanner.Base64Url(SecretScanner.RandomDek());
        StatusFake.RevealAllowed = true;
        InspectorFake.RevealEnabled = true;
        InspectorFake.Publish(WrapWithMaskedDek(1));
        InspectorFake.Publish(WrapWithMaskedDek(2));
        InspectorFake.AllowReveal(1, "request.value", text);
        var cut = Open(1);
        SelectTab(cut, "request");

        cut.Find("[data-role='reveal']").Click();
        cut.Find("[data-role='revealed-value']").TextContent.ShouldBe(text);
        cut.Find("[data-role='hide-revealed']").Click();
        cut.FindAll("[data-role='revealed']").ShouldBeEmpty();

        cut.Find("[data-role='reveal']").Click();
        cut.FindAll("[data-role='revealed']").Count.ShouldBe(1);
        cut.Render(p => p.Add(static c => c.ExchangeId, 2L));
        cut.Markup.ShouldNotContain(text);
    }

    [Fact]
    public void ARevealThatTheServiceRefuses_ShowsAGenericMessage_AndNoValue()
    {
        StatusFake.RevealAllowed = true;
        InspectorFake.RevealEnabled = true;
        InspectorFake.Publish(WrapWithMaskedDek()); // nothing retained in the fake: NotRetained
        var cut = Open(1);
        SelectTab(cut, "request");

        cut.Find("[data-role='reveal']").Click();

        cut.Find("[data-role='reveal-error']").TextContent.ShouldBe("The raw value is not available for this exchange.");
        cut.FindAll("[data-role='revealed']").ShouldBeEmpty();
    }

    // ---- replay ----

    [Fact]
    public void Replay_IsDisabled_WhenTheRawBodyIsNotAvailable_AndSaysWhy()
    {
        InspectorFake.Publish(Rec.Make(1));
        InspectorFake.Replay = new ReplayCheck(false, ReplayBlockReason.RevealNotAllowed);

        var cut = Open(1);

        cut.Find("[data-role='replay']").HasAttribute("disabled").ShouldBeTrue();
        cut.Find("[data-role='replay-hint']").TextContent.ShouldContain("EKMMOCK_INSPECTOR_ALLOW_REVEAL=true");
    }

    [Fact]
    public void Replay_IsEnabledWhenPossible_AndSendsTheExchangeThroughTheInspector_AsTheCurrentUser()
    {
        InspectorFake.Publish(Rec.Make(1));
        InspectorFake.Replay = new ReplayCheck(true, ReplayBlockReason.None);
        var cut = Open(1);
        cut.Find("[data-role='replay']").HasAttribute("disabled").ShouldBeFalse();

        InspectorFake.ReplayResult = new ReplayOutcome(true, 200, null);

        cut.Find("[data-role='replay']").Click();

        InspectorFake.Replays.Count.ShouldBe(1);
        InspectorFake.Replays[0].ExchangeId.ShouldBe(1);
        cut.WaitForAssertion(() => cut.Find("[data-role='replay-message']").TextContent.ShouldContain("200"), TimeSpan.FromSeconds(10));
    }

    // ---- the page and the leak scan ----

    [Fact]
    public void TheDeepLinkPage_ShowsTheDetailOfTheExchangeInTheUrl()
    {
        InspectorFake.Publish(Rec.Make(41, "unwrapkey"));

        var cut = Render<ExchangeDetailPage>(p => p.Add(static c => c.Id, 41L));

        cut.Find("h1").TextContent.ShouldBe("Exchange 41");
        cut.Find("[data-role='exchange-detail']").GetAttribute("data-exchange-id").ShouldBe("41");
        cut.Find("[data-role='back-to-live']").GetAttribute("href").ShouldBe("/");
    }

    [Fact]
    public void InDefaultMode_TheRawDek_NeverAppearsInTheRenderedMarkup_OfAnyTabOrThePage()
    {
        // The record is masked by construction (spec 8.4); this proves the console adds nothing: not in any tab, not in the page, not in the JSON the copy button carries.
        var dek = SecretScanner.RandomDek();
        InspectorFake.Publish(WrapWithMaskedDek());
        InspectorFake.AllowReveal(1, "request.value", SecretScanner.Base64Url(dek));
        var cut = Open(1);
        var all = new List<string> { cut.Markup };

        foreach (var tab in new[] { "tls", "request", "response", "timing", "overview" })
        {
            SelectTab(cut, tab);
            all.Add(cut.Markup);
        }

        var page = Render<LiveTraffic>();
        page.Find("[data-exchange-id='1']").Click();
        all.Add(page.Markup);

        SecretScanner.LeaksInText(string.Join('\n', all), dek).ShouldBeFalse("the raw DEK appeared in rendered markup");
        string.Join('\n', all).ShouldContain("32 bytes · fp 3f9a1c07b2e4");
    }
}
