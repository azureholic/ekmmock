using AngleSharp.Dom;
using EkmMock.Crypto;
using EkmMock.Server.Faults;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Components;
using EkmMock.Server.WebConsole.Layout;
using EkmMock.Server.WebConsole.Pages;
using EkmMock.TestSupport;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace EkmMock.Console.Tests;

/// <summary>An in-memory audit log for the page tests that need no file.</summary>
internal sealed class MemoryAuditLog : IAuditLog
{
    private readonly List<AuditEntry> _entries = [];

    public IReadOnlyList<AuditEntry> Entries
    {
        get
        {
            lock (_entries)
            {
                return [.. _entries];
            }
        }
    }

    public void Append(string user, string action, string target, string? detail = null)
    {
        lock (_entries)
        {
            _entries.Add(new AuditEntry(DateTimeOffset.UtcNow, user, action, target, detail));
        }
    }

    public IReadOnlyList<AuditEntry> ReadRecent(int count = 200) => Entries;
}

internal sealed class ToggleFaultGate : IFaultGate
{
    public ToggleFaultGate(bool enabled) => Enabled = enabled;

    public bool Enabled { get; }
}

/// <summary>The real fault rule store, service and status (no web host), wired into the component context. The fake <see cref="FakeFaults"/> of the base class is replaced.</summary>
public abstract class FaultPageTestBase : ConsoleTestBase
{
    private readonly TempFolder _folder = new("ekmmock-fault-page");

    private protected FaultPageTestBase(bool faultsEnabled = true)
    {
        Store = new FaultRuleStore(new ToggleFaultGate(faultsEnabled), TimeProvider.System, new SystemFaultRandom());
        Audit = new MemoryAuditLog();
        var namespaces = NamespaceStore.Open(_folder.Path);
        namespaces.Add(new NamespaceDefinition { Name = "_default", Prefix = string.Empty });
        namespaces.Add(new NamespaceDefinition { Name = "contoso", Prefix = "contoso/prod" });
        Service = new FaultAdminService(Store, new AuditRecorder(Audit, NullLogger<AuditRecorder>.Instance), namespaces, TimeProvider.System);
        Status = new FaultStatus(Store);
        Services.AddSingleton(Service);
        Services.AddSingleton<IFaultStatus>(Status);
    }

    internal FaultRuleStore Store { get; }

    internal MemoryAuditLog Audit { get; }

    internal FaultAdminService Service { get; }

    internal FaultStatus Status { get; }

    protected static string Text(IElement element) => Dom.Text(element);

    private bool _disposed;

    protected override void Dispose(bool disposing)
    {
        // See AdminPageTestBase: bUnit's DisposeAsync calls Dispose(false).
        if (!_disposed)
        {
            _disposed = true;
            Store.Dispose();
            _folder.Dispose();
        }

        base.Dispose(disposing);
    }

    private protected static void Type(IRenderedComponent<FaultsPage> cut, string role, string text)
    {
        var field = cut.Find($"[data-role='{role}']");
        field.Input(text);
        field.Change(text);
    }

    private protected static void Choose(IRenderedComponent<FaultsPage> cut, string role, string value) => cut.Find($"[data-role='{role}'] fluent-option[value='{value}']").Click();

    private protected static void Click(IRenderedComponent<FaultsPage> cut, string role) => cut.Find($"[data-role='{role}']").Click();
}

/// <summary>M7, spec 10.2 and 8.5.9: the Fault injection page.</summary>
public sealed class FaultsPageTests : FaultPageTestBase
{
    private IRenderedComponent<FaultsPage> Open() => Render<FaultsPage>();

    private static List<string> RuleKinds(IRenderedComponent<FaultsPage> cut) => [.. cut.FindAll("[data-role='rule-kind-text']").Select(static e => e.TextContent.Trim())];

    // ---- the page ----

    [Fact]
    public void WithFaultsEnabled_ThePageShowsTheFormThePresetsAndAnEmptyList()
    {
        var cut = Open();

        cut.FindAll("[data-role='faults-disabled']").ShouldBeEmpty();
        Text(cut.Find("[data-role='faults-state']")).ShouldContain("No rule is active");
        cut.Find("[data-role='rule-form']").ShouldNotBeNull();
        cut.FindAll("[data-role='preset']").Select(static b => b.GetAttribute("data-preset")).ShouldBe(["distant-hsm-100", "distant-hsm-200", "distant-hsm-260", "hsm-offline", "error-503-50"]);
        Text(cut.Find("[data-role='rules-empty']")).ShouldContain("No fault rules");
        cut.Find("[data-role='clear-all']").HasAttribute("disabled").ShouldBeTrue();
        cut.Find("h1").TextContent.ShouldBe("Fault injection");
    }

    [Fact]
    public void TheKindDropDown_OffersTheSixKinds_WithAHelpLine()
    {
        var cut = Open();

        cut.FindAll("[data-role='rule-kind'] fluent-option").Select(static o => o.GetAttribute("value")).ShouldBe(["delay", "error", "offline", "key_disabled", "blackhole", "close"]);
        Text(cut.Find("[data-role='kind-help']")).ShouldContain("distant network HSM");
    }

    // ---- disabled mode ----

    [Fact]
    public void WithoutTheEnvironmentSwitch_ThePageIsReadOnlyAndSaysDisabled()
    {
        using var disabled = new DisabledContext();

        var cut = disabled.Render<FaultsPage>();

        Text(cut.Find("[data-role='faults-disabled']")).ShouldContain("Fault injection is disabled");
        Text(cut.Find("[data-role='faults-disabled']")).ShouldContain("EKMMOCK_ENABLE_FAULTS=true");
        cut.FindAll("[data-role='rule-form']").ShouldBeEmpty();
        cut.FindAll("[data-role='presets']").ShouldBeEmpty();
        cut.FindAll("[data-role='preset']").ShouldBeEmpty();
        cut.FindAll("[data-role='clear-all']").ShouldBeEmpty();
        Text(cut.Find("[data-role='rules-empty']")).ShouldContain("disabled");
    }

    private sealed class DisabledContext : FaultPageTestBase
    {
        public DisabledContext()
            : base(faultsEnabled: false)
        {
        }
    }

    // ---- create ----

    [Fact]
    public void AddingAFixedDelay_ListsTheRule_AuditsIt_AndTurnsTheStatusOn()
    {
        var cut = Open();
        Type(cut, "rule-delay-ms", "300");
        Type(cut, "rule-description", "distant HSM");

        Click(cut, "rule-save");

        RuleKinds(cut).ShouldBe(["Delay"]);
        Text(cut.Find("[data-role='rule-params']")).ShouldBe("300 ms");
        Text(cut.Find("[data-role='rule-scope']")).ShouldBe("all requests");
        Text(cut.Find("[data-role='rule-state']")).ShouldContain("active");
        Text(cut.Find("[data-role='rule-description-text']")).ShouldBe("distant HSM");
        Text(cut.Find("[data-role='action-result']")).ShouldContain("Fault rule added");
        Text(cut.Find("[data-role='faults-state']")).ShouldContain("1 active rule.");
        Status.Active.ShouldBeTrue();
        Audit.Entries.Single().ShouldSatisfyAllConditions(
            static e => e.Action.ShouldBe("fault.create"),
            static e => e.User.ShouldBe("loopback"),
            static e => e.Target.ShouldBe("fault:f1"),
            static e => e.Detail.ShouldBe("delay 300 ms; all requests"));
    }

    [Fact]
    public void AddingAUniformRange_WithAScope_StoresBothEndsAndTheScope()
    {
        var cut = Open();
        Choose(cut, "rule-delay-mode", "Uniform range");
        Type(cut, "rule-min-ms", "50");
        Type(cut, "rule-max-ms", "150");
        Type(cut, "rule-key", "aes-key-1");

        Click(cut, "rule-save");

        var rule = Store.List().Single().Rule;
        rule.MinMs.ShouldBe(50);
        rule.MaxMs.ShouldBe(150);
        rule.DelayMs.ShouldBeNull();
        rule.Scope.Key.ShouldBe("aes-key-1");
        Text(cut.Find("[data-role='rule-params']")).ShouldBe("50-150 ms (uniform)");
        Text(cut.Find("[data-role='rule-scope']")).ShouldBe("key aes-key-1");
    }

    [Fact]
    public void AddingAnErrorRule_NeedsAPercentage_AndStoresTheStatus()
    {
        var cut = Open();
        Choose(cut, "rule-kind", "error");

        Type(cut, "rule-percent", "25.5");
        Click(cut, "rule-save");

        var rule = Store.List().Single().Rule;
        rule.Kind.ShouldBe(FaultKind.Error);
        rule.ErrorPercent.ShouldBe(25.5);
        rule.StatusCode.ShouldBe(503);
        Text(cut.Find("[data-role='rule-params']")).ShouldBe("25.5 % answer 503");
    }

    [Theory]
    [InlineData("offline", "HSM offline")]
    [InlineData("key_disabled", "Key disabled (temporary)")]
    [InlineData("blackhole", "Blackhole")]
    [InlineData("close", "Close connection")]
    public void TheKindsWithoutParameters_CanBeAddedAsTheyAre(string kind, string title)
    {
        var cut = Open();
        Choose(cut, "rule-kind", kind);

        Click(cut, "rule-save");

        RuleKinds(cut).ShouldBe([title]);
        Text(cut.Find("[data-role='rule-params']")).ShouldBe("-");
    }

    [Fact]
    public void HsmOffline_DisablesTheScopeFields_BecauseItAppliesToTheWholeEngine()
    {
        var cut = Open();

        Choose(cut, "rule-kind", "offline");

        cut.Find("[data-role='rule-key']").HasAttribute("disabled").ShouldBeTrue();
        cut.Find("[data-role='rule-namespace']").HasAttribute("disabled").ShouldBeTrue();
        cut.Find("[data-role='rule-op']").HasAttribute("disabled").ShouldBeTrue();
    }

    // ---- validation ----

    [Theory]
    [InlineData("delay", "rule-delay-ms", "abc", "whole number of milliseconds")]
    [InlineData("delay", "rule-delay-ms", "-5", "whole number of milliseconds")]
    [InlineData("delay", "rule-delay-ms", "60001", "delay_ms must be from 0 to 60000")]
    [InlineData("delay", "rule-delay-ms", "", "whole number of milliseconds")]
    [InlineData("error", "rule-percent", "101", "error_percent must be a number from 0 to 100")]
    [InlineData("error", "rule-percent", "-1", "error_percent must be a number from 0 to 100")]
    [InlineData("error", "rule-percent", "many", "number from 0 to 100")]
    public void InvalidValues_ShowAProblem_AndSaveIsDisabled(string kind, string field, string value, string problem)
    {
        var cut = Open();
        Choose(cut, "rule-kind", kind);

        Type(cut, field, value);

        Text(cut.Find("[data-role='rule-problem']")).ShouldContain(problem);
        cut.Find("[data-role='rule-problem']").ClassList.ShouldContain("field-invalid");
        cut.Find("[data-role='rule-problem']").GetAttribute("role").ShouldBe("alert");
        cut.Find("[data-role='rule-save']").HasAttribute("disabled").ShouldBeTrue();
        Store.Count.ShouldBe(0);
    }

    [Fact]
    public void ARangeWithMinAboveMax_IsRefused_AndFixingItEnablesSave()
    {
        var cut = Open();
        Choose(cut, "rule-delay-mode", "Uniform range");

        Type(cut, "rule-min-ms", "200");
        Type(cut, "rule-max-ms", "100");

        Text(cut.Find("[data-role='rule-problem']")).ShouldContain("min_ms must not be larger than max_ms");
        cut.Find("[data-role='rule-save']").HasAttribute("disabled").ShouldBeTrue();

        Type(cut, "rule-max-ms", "300");

        Text(cut.Find("[data-role='rule-problem']")).ShouldBe("Ready to save.");
        cut.Find("[data-role='rule-save']").HasAttribute("disabled").ShouldBeFalse();
    }

    [Fact]
    public void ABadKeyNameOrExpiry_IsRefused()
    {
        var cut = Open();
        Type(cut, "rule-key", "bad_key");
        Text(cut.Find("[data-role='rule-problem']")).ShouldContain("key must be 1 to 64");
        Type(cut, "rule-key", "");
        Type(cut, "rule-expires", "0");
        Text(cut.Find("[data-role='rule-problem']")).ShouldContain("Expiry must be a whole number of minutes");
        Type(cut, "rule-expires", "5");
        Text(cut.Find("[data-role='rule-problem']")).ShouldBe("Ready to save.");
    }

    [Fact]
    public void AnExpiry_IsStoredAsAnExpiryTime()
    {
        var cut = Open();
        Type(cut, "rule-expires", "15");

        Click(cut, "rule-save");

        var rule = Store.List().Single().Rule;
        rule.ExpiresAt.ShouldNotBeNull().ShouldBeInRange(DateTimeOffset.UtcNow.AddMinutes(14), DateTimeOffset.UtcNow.AddMinutes(16));
        Text(cut.Find("[data-role='rule-expires-at']")).ShouldEndWith("UTC");
    }

    // ---- presets ----

    [Theory]
    [InlineData("distant-hsm-100", "100 ms")]
    [InlineData("distant-hsm-200", "200 ms")]
    [InlineData("distant-hsm-260", "260 ms")]
    [InlineData("error-503-50", "50 % answer 503")]
    public void APreset_AddsItsRuleWithOneClick(string preset, string parameters)
    {
        var cut = Open();

        cut.Find($"[data-preset='{preset}']").Click();

        Text(cut.Find("[data-role='rule-params']")).ShouldBe(parameters);
        Audit.Entries.Single().Action.ShouldBe("fault.preset");
        Audit.Entries.Single().Detail.ShouldNotBeNull().ShouldStartWith($"preset {preset}:");
    }

    [Fact]
    public void TheHsmOfflinePreset_TurnsOnTheOfflineWarning_AndTheStoreReportsOffline()
    {
        var cut = Open();

        cut.Find("[data-preset='hsm-offline']").Click();

        Text(cut.Find("[data-role='faults-offline-note']")).ShouldContain("simulated as offline");
        Store.IsHsmOffline.ShouldBeTrue();
        Status.HsmOffline.ShouldBeTrue();
    }

    // ---- toggle, edit, delete, clear ----

    [Fact]
    public void TogglingARule_DisablesAndEnablesIt_AndTheStatusFollows()
    {
        var cut = Open();
        cut.Find("[data-preset='distant-hsm-100']").Click();

        Click(cut, "rule-toggle");

        Text(cut.Find("[data-role='rule-state']")).ShouldContain("disabled");
        Text(cut.Find("[data-role='rule-toggle']")).ShouldBe("Enable");
        Status.Active.ShouldBeFalse();
        Text(cut.Find("[data-role='faults-state']")).ShouldContain("No rule is active");

        Click(cut, "rule-toggle");

        Text(cut.Find("[data-role='rule-state']")).ShouldContain("active");
        Status.Active.ShouldBeTrue();
        Audit.Entries.Select(static e => e.Action).ShouldBe(["fault.preset", "fault.disable", "fault.enable"]);
    }

    [Fact]
    public void EditingARule_LoadsItIntoTheForm_AndSavingChangesItInPlace()
    {
        var cut = Open();
        Type(cut, "rule-delay-ms", "120");
        Type(cut, "rule-key", "aes-key-1");
        Click(cut, "rule-save");

        Click(cut, "rule-edit");

        Text(cut.Find("#rule-form-title")).ShouldBe("Edit rule f1");
        cut.Find("[data-role='rule-delay-ms']").GetAttribute("value").ShouldBe("120");
        cut.Find("[data-role='rule-key']").GetAttribute("value").ShouldBe("aes-key-1");
        Type(cut, "rule-delay-ms", "400");
        Click(cut, "rule-save");

        Text(cut.Find("#rule-form-title")).ShouldBe("Add a rule");
        cut.FindAll("[data-role='rule-id']").Count.ShouldBe(1);
        Text(cut.Find("[data-role='rule-params']")).ShouldBe("400 ms");
        Store.List().Single().Rule.Id.ShouldBe("f1");
        Audit.Entries.Select(static e => e.Action).ShouldBe(["fault.create", "fault.update"]);
    }

    [Fact]
    public void CancellingAnEdit_ChangesNothing()
    {
        var cut = Open();
        cut.Find("[data-preset='distant-hsm-100']").Click();
        Click(cut, "rule-edit");

        Type(cut, "rule-delay-ms", "999");
        Click(cut, "rule-cancel");

        Text(cut.Find("#rule-form-title")).ShouldBe("Add a rule");
        Store.List().Single().Rule.DelayMs.ShouldBe(100);
    }

    [Fact]
    public void DeletingARule_RemovesItAtOnce()
    {
        var cut = Open();
        cut.Find("[data-preset='distant-hsm-100']").Click();
        cut.Find("[data-preset='error-503-50']").Click();
        cut.FindAll("[data-role='rule-id']").Count.ShouldBe(2);

        cut.FindAll("[data-role='rule-delete']")[0].Click();

        cut.FindAll("[data-role='rule-id']").Count.ShouldBe(1);
        Text(cut.Find("[data-role='rule-id']")).ShouldBe("f2");
        Audit.Entries.Last().Action.ShouldBe("fault.delete");
        Audit.Entries.Last().Target.ShouldBe("fault:f1");
    }

    [Fact]
    public void ClearAll_RemovesEveryRule_AndTheBannerCondition()
    {
        var cut = Open();
        cut.Find("[data-preset='hsm-offline']").Click();
        cut.Find("[data-preset='distant-hsm-100']").Click();
        Status.Active.ShouldBeTrue();

        Click(cut, "clear-all");

        cut.FindAll("[data-role='rule-id']").ShouldBeEmpty();
        Text(cut.Find("[data-role='rules-empty']")).ShouldContain("No fault rules");
        Status.Active.ShouldBeFalse();
        Audit.Entries.Last().Action.ShouldBe("fault.clear");
    }

    [Fact]
    public void ARuleThatExpires_FlipsTheStateToExpired_WithoutAnyClick()
    {
        var cut = Open();
        Store.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 5, ExpiresAfter = TimeSpan.FromMilliseconds(200) });
        cut.WaitForAssertion(() => Text(cut.Find("[data-role='rule-state']")).ShouldContain("active"), Patience);

        cut.WaitForAssertion(() => Text(cut.Find("[data-role='rule-state']")).ShouldContain("expired"), Patience);
        Status.Active.ShouldBeFalse();
    }

    [Fact]
    public void ARuleCreatedElsewhere_ShowsUpOnAnOpenPage()
    {
        var cut = Open();

        Store.Create(new FaultSpec { Kind = FaultKind.Blackhole }); // another console, or the REST API

        cut.WaitForAssertion(() => RuleKinds(cut).ShouldBe(["Blackhole"]), Patience);
    }

    [Fact]
    public async Task ThePage_UnhooksItselfFromTheStatus_WhenItIsDisposed()
    {
        var cut = Open();
        await DisposeComponentsAsync();

        Should.NotThrow(() => Store.Create(new FaultSpec { Kind = FaultKind.Blackhole }));
        cut.ShouldNotBeNull();
    }

    [Fact]
    public void TheDescriptionOfARule_IsShownAsText_NeverAsMarkup()
    {
        var cut = Open();
        Type(cut, "rule-delay-ms", "10");
        Type(cut, "rule-description", "<img src=x onerror=alert(1)>");

        Click(cut, "rule-save");

        cut.FindAll("[data-role='rule-description-text'] img").ShouldBeEmpty();
        Text(cut.Find("[data-role='rule-description-text']")).ShouldBe("<img src=x onerror=alert(1)>");
    }
}

/// <summary>M7, spec 10.2: "A banner at the top of every console page says faults are active", Live traffic's fault badge, and the delay in the Detail view.</summary>
public sealed class FaultsBannerAndBadgeTests : FaultPageTestBase
{
    private IRenderedComponent<MainLayout> Layout()
        => Render<MainLayout>(p => p.Add(static c => c.Body, builder => builder.AddMarkupContent(0, "<p data-role=\"body\">page content</p>")));

    [Fact]
    public void TheBanner_IsOnEveryPage_WhenARuleIsActive_AndGoneWhenTheLastRuleIsRemoved()
    {
        var cut = Layout();
        cut.FindAll("[data-role='faults-banner']").ShouldBeEmpty();

        var rule = Store.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 100 });

        cut.WaitForAssertion(() => cut.Find("[data-role='main'] [data-role='faults-banner']").ShouldNotBeNull(), Patience);
        Text(cut.Find("[data-role='faults-banner']")).ShouldContain("Fault injection is active");
        Text(cut.Find("[data-role='faults-banner']")).ShouldContain("1 active rule");
        cut.Find("[data-role='faults-banner-link']").GetAttribute("href").ShouldBe("/faults");

        Store.Delete(rule.Id);

        cut.WaitForAssertion(() => cut.FindAll("[data-role='faults-banner']").ShouldBeEmpty(), Patience);
    }

    [Fact]
    public void TheBanner_StaysOff_ForADisabledRule_AndSaysTheHsmIsOfflineWhenItIs()
    {
        var cut = Layout();
        var rule = Store.Create(new FaultSpec { Kind = FaultKind.HsmOffline, Enabled = false });
        cut.FindAll("[data-role='faults-banner']").ShouldBeEmpty();

        Store.SetEnabled(rule.Id, true);

        cut.WaitForAssertion(() => Text(cut.Find("[data-role='faults-banner']")).ShouldContain("simulated as offline"), Patience);
        Text(cut.Find("[data-role='faults-banner']")).ShouldContain("answer 503");
        cut.Find("[data-role='faults-banner']").GetAttribute("role").ShouldBe("alert");
    }

    [Fact]
    public void TheBanner_ShowsTheCountOfActiveRules()
    {
        var cut = Layout();

        Store.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 1 });
        Store.Create(new FaultSpec { Kind = FaultKind.Blackhole });

        cut.WaitForAssertion(() => Text(cut.Find("[data-role='faults-banner']")).ShouldContain("2 active rules"), Patience);
    }

    [Fact]
    public void TheNavigation_LinksToTheFaultsPage()
    {
        var cut = Layout();

        var link = cut.Find("nav a[href='/faults']");
        Text(link).ShouldBe("Fault injection");
        cut.Find("nav [data-nav='faults']").ShouldNotBeNull();
    }

    // ---- the badge and the detail of an exchange that was hit by a fault ----

    private static FaultFacts Delay300 => new("f2", "delay", "delay 300 ms", "distant HSM");

    [Fact]
    public void LiveTraffic_ShowsTheFaultBadge_WithTheRuleInTheTooltip_AndARedLatency()
    {
        InspectorFake.Publish(Rec.Make(1));
        InspectorFake.Publish(Rec.Make(2, ms: 310, delayMs: 300, fault: Delay300));
        var cut = Render<LiveTraffic>();

        var badge = cut.Find("[data-exchange-id='2'] [data-role='fault']");
        Text(badge).ShouldContain("fault: delay 300 ms");
        badge.QuerySelector("fluent-badge")!.GetAttribute("title").ShouldBe("Fault rule f2: distant HSM");
        cut.Find("[data-exchange-id='2'] [data-role='latency']").GetAttribute("data-budget").ShouldBe("red");
        cut.Find("[data-exchange-id='1'] [data-role='fault']").TextContent.Trim().ShouldBeEmpty();
    }

    [Fact]
    public void LiveTraffic_ShowsANoResponseExchange_AsStatus499()
    {
        InspectorFake.Publish(Rec.Make(1, status: 499, code: null, fault: new FaultFacts("f3", "blackhole", "blackhole")));
        var cut = Render<LiveTraffic>();

        Text(cut.Find("[data-exchange-id='1'] [data-role='status']")).ShouldBe("499 No response");
        Text(cut.Find("[data-exchange-id='1'] [data-role='fault']")).ShouldContain("fault: blackhole");
    }

    [Fact]
    public void TheDetail_ShowsTheFaultAndTheDelaySegmentOfTheTimingWaterfall()
    {
        InspectorFake.Publish(Rec.Make(1, ms: 310, delayMs: 300, fault: Delay300));
        var cut = Render<ExchangeDetailView>(p => p.Add(static c => c.ExchangeId, 1L));

        Text(cut.Find("[data-role='detail-fault']")).ShouldBe("fault: delay 300 ms");
        Text(cut.Find("[data-role='detail-fault-rule']")).ShouldBe("rule f2: distant HSM");

        cut.Find("[role='tab'][data-tab='timing']").Click();

        Text(cut.Find("[data-role='timing-table']")).ShouldContain("Injected delay 300 ms");
        cut.FindAll(".waterfall-delay").ShouldNotBeEmpty("the waterfall has a delay segment");
    }

    [Fact]
    public void TheDetail_SaysWhenNoResponseWasSent()
    {
        InspectorFake.Publish(Rec.Make(1, status: 499, code: null) with { Response = Rec.Make(1, status: 499, code: null).Response with { ClosedByServer = true } });
        var cut = Render<ExchangeDetailView>(p => p.Add(static c => c.ExchangeId, 1L));

        cut.Find("[role='tab'][data-tab='response']").Click();

        Text(cut.Find("[data-role='tab-response']")).ShouldContain("no response was sent: the connection was closed by a fault rule");
    }
}
