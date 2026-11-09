using EkmMock.Crypto;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Console.Tests;

/// <summary>M6, spec 8.5.10: the Audit log page: newest first, paged, filterable, read-only, and free of secrets.</summary>
public sealed class AuditLogPageTests : AdminPageTestBase
{
    private IRenderedComponent<AuditLogPage> Open() => Render<AuditLogPage>();

    private void Seed(int count)
    {
        for (var i = 1; i <= count; i++)
        {
            Env.AuditLog.Append(i % 2 == 0 ? "alice" : "bob", i % 3 == 0 ? "key.destroy" : "key.create", $"key:_default/k{i:000}", $"entry {i}");
        }
    }

    private static void Type(IRenderedComponent<AuditLogPage> cut, string role, string text)
    {
        var field = cut.Find($"[data-role='{role}']");
        field.Input(text);
        field.Change(text);
    }

    private static List<string> Targets(IRenderedComponent<AuditLogPage> cut) => [.. cut.FindAll("[data-role='audit-target']").Select(static t => t.TextContent.Trim())];

    [Fact]
    public void WithoutEntries_ThePageSaysSo()
    {
        Text(Open().Find("[data-role='audit-empty']")).ShouldBe("No audit entries match.");
    }

    [Fact]
    public void TheEntries_AreShownNewestFirst_WithUserActionTargetAndDetail()
    {
        Seed(3);

        var cut = Open();

        Targets(cut).ShouldBe(["key:_default/k003", "key:_default/k002", "key:_default/k001"]);
        var first = cut.FindAll("tr").First(static r => r.QuerySelector("[data-role='audit-target']")?.TextContent.Contains("k003", StringComparison.Ordinal) == true);
        Text(first.QuerySelector("[data-role='audit-user']")!).ShouldBe("bob");
        Text(first.QuerySelector("[data-role='audit-action']")!).ShouldBe("key.destroy");
        Text(first.QuerySelector("[data-role='audit-detail']")!).ShouldBe("entry 3");
        Text(first.QuerySelector("[data-role='audit-time']")!).ShouldMatch(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$");
        Text(cut.Find("[data-role='audit-count']")).ShouldBe("(3 matches)");
    }

    [Fact]
    public void ThePager_ShowsTwentyFiveAtATime_AndMovesBothWays()
    {
        Seed(60);
        var cut = Open();

        Targets(cut).Count.ShouldBe(25);
        Targets(cut)[0].ShouldBe("key:_default/k060");
        Text(cut.Find("[data-role='page-range']")).ShouldBe("1 to 25 of 60");
        cut.Find("[data-role='page-newer']").HasAttribute("disabled").ShouldBeTrue();

        cut.Find("[data-role='page-older']").Click();
        Targets(cut)[0].ShouldBe("key:_default/k035");
        Text(cut.Find("[data-role='page-range']")).ShouldBe("26 to 50 of 60");

        cut.Find("[data-role='page-older']").Click();
        Targets(cut).Count.ShouldBe(10);
        cut.Find("[data-role='page-older']").HasAttribute("disabled").ShouldBeTrue();

        cut.Find("[data-role='page-newer']").Click();
        Targets(cut)[0].ShouldBe("key:_default/k035");
    }

    [Fact]
    public void TheFilters_NarrowByUserActionAndText_AndResetBringsEverythingBack()
    {
        Seed(12);
        var cut = Open();

        Type(cut, "filter-user", "ALICE");
        cut.Find("[data-role='filter-apply']").Click();
        Targets(cut).Count.ShouldBe(6);
        cut.FindAll("[data-role='audit-user']").ShouldAllBe(static u => u.TextContent.Trim() == "alice");

        cut.Find("[data-role='filter-reset']").Click();
        Targets(cut).Count.ShouldBe(12);

        cut.Find("[data-role='filter-action'] fluent-option[value='key.destroy']").Click();
        cut.Find("[data-role='filter-apply']").Click();
        Targets(cut).ShouldBe(["key:_default/k012", "key:_default/k009", "key:_default/k006", "key:_default/k003"]);

        cut.Find("[data-role='filter-reset']").Click();
        Type(cut, "filter-text", "k007");
        cut.Find("[data-role='filter-apply']").Click();
        Targets(cut).ShouldBe(["key:_default/k007"]);
    }

    [Fact]
    public void TheDateFilters_AreValidated_AndApplied()
    {
        Seed(3);
        var cut = Open();

        Type(cut, "filter-from", "not a date");
        cut.Find("[data-role='filter-apply']").Click();
        cut.Find("[data-role='filter-error']").TextContent.ShouldContain("yyyy-MM-dd");

        Type(cut, "filter-from", DateTimeOffset.UtcNow.AddDays(1).ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture));
        cut.Find("[data-role='filter-apply']").Click();
        cut.FindAll("[data-role='filter-error']").ShouldBeEmpty();
        cut.Find("[data-role='audit-empty']").ShouldNotBeNull();

        Type(cut, "filter-from", DateTimeOffset.UtcNow.AddDays(-1).ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture));
        cut.Find("[data-role='filter-apply']").Click();
        Targets(cut).Count.ShouldBe(3);
    }

    [Fact]
    public void ThePage_IsReadOnly_NoEditNoDeleteNoClear()
    {
        Seed(2);

        var cut = Open();

        var buttons = cut.FindAll("fluent-button").Select(static b => b.TextContent.Trim()).ToList();
        buttons.ShouldNotContain(static b => b.Contains("Delete", StringComparison.OrdinalIgnoreCase) || b.Contains("Edit", StringComparison.OrdinalIgnoreCase) || b.Contains("Clear", StringComparison.OrdinalIgnoreCase));
        cut.FindAll("input, textarea").ShouldBeEmpty("the entries themselves are never editable");
        Text(cut.Find("main, .page-intro")).ShouldContain("append-only");
    }

    [Fact]
    public void RealActionsOfTheServices_AppearOnThePage_WithoutSecrets()
    {
        Env.AddNamespace("_default", string.Empty, ("k1", KeyType.Oct, 256));
        Env.Keys.SetEnabled("alice (oid-1)", "_default", "k1", false);

        var cut = Open();

        var actions = cut.FindAll("[data-role='audit-action']").Select(static a => a.TextContent.Trim()).ToList();
        actions.ShouldBe(["key.disable", "key.create", "namespace.create"]);
        cut.FindAll("[data-role='audit-user']").Select(static u => u.TextContent.Trim()).First().ShouldBe("alice (oid-1)");
        cut.Markup.ShouldNotContain("PRIVATE KEY-----", Case.Sensitive);
    }

    [Fact]
    public void TheActionFilter_OffersEveryActionTheConsoleWrites()
    {
        var cut = Open();

        var offered = cut.FindAll("[data-role='filter-action'] fluent-option").Select(static o => o.GetAttribute("value")).Where(static v => !string.IsNullOrEmpty(v)).ToList();

        offered.Order(StringComparer.Ordinal).ShouldBe(AuditActions.All.Order(StringComparer.Ordinal));
    }
}
