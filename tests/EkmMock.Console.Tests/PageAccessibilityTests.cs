using AngleSharp.Dom;
using EkmMock.Crypto;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Console.Tests;

/// <summary>M6 accessibility basics of every new page: one h1 that takes focus on navigation, labelled regions and grids, and a name for every button.</summary>
public sealed class PageAccessibilityTests : AdminPageTestBase
{
    public PageAccessibilityTests()
        : base(allowImport: true)
    {
        Env.AddNamespace("_default", string.Empty, ("aes-key-1", KeyType.Oct, 256), ("rsa-key-1", KeyType.Rsa, 2048));
        Env.Namespaces.TrustConsoleTestClient("seed", "_default");
        Services.AddSingleton<IAboutService>(new FakeAbout());
    }

    public static TheoryData<string> Pages =>
    [
        nameof(KeysPage), nameof(NamespacesPage), nameof(CertificatesPage), nameof(PlaygroundPage), nameof(AuditLogPage), nameof(AboutPage),
    ];

    // The markup of the rendered page, parsed again: the assertions below only need to look at the DOM.
    private AngleSharp.Dom.IDocument Render(string page)
    {
        var markup = page switch
        {
            nameof(KeysPage) => Render<KeysPage>().Markup,
            nameof(NamespacesPage) => Render<NamespacesPage>().Markup,
            nameof(CertificatesPage) => Render<CertificatesPage>().Markup,
            nameof(PlaygroundPage) => Render<PlaygroundPage>().Markup,
            nameof(AuditLogPage) => Render<AuditLogPage>().Markup,
            _ => Render<AboutPage>().Markup,
        };
        return new AngleSharp.Html.Parser.HtmlParser().ParseDocument("<body>" + markup + "</body>");
    }
    [Theory]
    [MemberData(nameof(Pages))]
    public void EveryPage_HasOneHeading_ThatTheRouterCanFocus_AndAPageTitle(string page)
    {
        var cut = Render(page);

        var headings = cut.QuerySelectorAll("h1");
        headings.Length.ShouldBe(1);
        headings[0].GetAttribute("tabindex").ShouldBe("-1");
        headings[0].TextContent.Trim().ShouldNotBeEmpty();
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void EveryRegionAndGrid_IsLabelled(string page)
    {
        var cut = Render(page);

        foreach (var section in cut.QuerySelectorAll("section[aria-labelledby]"))
        {
            var id = section.GetAttribute("aria-labelledby")!;
            cut.QuerySelectorAll($"[id='{id}']").Length.ShouldBe(1, $"{page}: aria-labelledby '{id}' must point at exactly one heading");
        }

        foreach (var table in cut.QuerySelectorAll("table, [role='table']"))
        {
            (table.HasAttribute("aria-label") || table.QuerySelector("caption") is not null || table.HasAttribute("data-role")).ShouldBeTrue($"{page}: a table needs a name");
        }

        cut.QuerySelectorAll("fluent-data-grid, table.fluent-data-grid").ShouldAllBe(static g => g.HasAttribute("aria-label"), $"{page}: every data grid has an aria-label");
        if (page != nameof(AboutPage)) // the About page is static: nothing changes after it was rendered
        {
            cut.QuerySelectorAll("[role='status'], [role='alert']").ShouldNotBeEmpty($"{page}: results are announced to screen readers");
        }
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void EveryButton_HasAnAccessibleName(string page)
    {
        var cut = Render(page);

        foreach (var button in cut.QuerySelectorAll("button, fluent-button, [role='button']"))
        {
            var name = button.GetAttribute("aria-label") ?? button.GetAttribute("title") ?? button.TextContent;
            name.Trim().ShouldNotBeEmpty($"{page}: a button without a name: {button.OuterHtml[..Math.Min(120, button.OuterHtml.Length)]}");
        }
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void EveryInput_HasALabelOrAnAriaLabel(string page)
    {
        var cut = Render(page);

        foreach (var field in cut.QuerySelectorAll("fluent-text-field, fluent-text-area, fluent-select, fluent-number-field, fluent-checkbox, fluent-radio-group"))
        {
            // Fluent renders the Label parameter as a <label for=id> next to the field (or inside it); either way the field has an accessible name.
            var id = field.GetAttribute("id");
            var named = field.HasAttribute("aria-label") || field.HasAttribute("label") || field.QuerySelector("label") is not null || !string.IsNullOrWhiteSpace(field.TextContent) || field.HasAttribute("aria-labelledby")
                || (id is not null && cut.QuerySelector($"label[for='{id}']") is not null);
            named.ShouldBeTrue($"{page}: an input without a label: {field.OuterHtml[..Math.Min(160, field.OuterHtml.Length)]}");
        }
    }

    [Fact]
    public void TheIconOnlyActions_CarryTheNameOfTheirTarget()
    {
        var cut = Render<KeysPage>();

        cut.Find("[data-role='destroy']").GetAttribute("aria-label").ShouldBe("Destroy aes-key-1");
        cut.Find("[data-role='toggle-enabled']").GetAttribute("aria-label").ShouldBe("Disable aes-key-1");
        cut.Find("[data-role='details']").GetAttribute("aria-label").ShouldBe("Details of aes-key-1");
    }

    [Fact]
    public void StateIsNeverShownByColourAlone_AKeyStateHasAWordAndASymbol()
    {
        Env.Keys.SetEnabled("seed", "_default", "aes-key-1", false);

        var cut = Render<KeysPage>();

        var state = cut.Find("[data-key='aes-key-1'][data-role='key-name']").Closest("tr")!.QuerySelector("[data-role='key-state']")!;
        Dom.Text(state).ShouldContain("Disabled");
        state.QuerySelector(".state-icon")!.GetAttribute("aria-hidden").ShouldBe("true");
        state.QuerySelector(".state-icon")!.TextContent.ShouldNotBeEmpty();
    }
}
