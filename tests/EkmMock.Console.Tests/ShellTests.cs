using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Components;
using EkmMock.Server.WebConsole.Layout;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.FluentUI.AspNetCore.Components;

namespace EkmMock.Console.Tests;

/// <summary>The console shell: landmarks, navigation, theme toggle, the dev-mode and faults banners, the error boundary, and the reconnect UI.</summary>
public sealed class ShellTests : ConsoleTestBase
{
    private static string Text(AngleSharp.Dom.IElement element) => Dom.Text(element);

    private IRenderedComponent<MainLayout> Layout(string body = "<p data-role=\"body\">page content</p>")
        => Render<MainLayout>(p => p.Add(static c => c.Body, builder => builder.AddMarkupContent(0, body)));

    // ---- banners ----

    [Fact]
    public void TheDevModeBanner_IsShown_OnlyWithAThrowAwayMasterKey_AndSaysSoInWords()
    {
        var without = Render<DevModeBanner>();
        without.FindAll("[data-role='dev-banner']").ShouldBeEmpty();

        StatusFake.DevMasterKey = true;
        var with = Render<DevModeBanner>();

        var banner = with.Find("[data-role='dev-banner']");
        banner.GetAttribute("role").ShouldBe("alert");
        Text(banner).ShouldContain("DEV MODE: throw-away master key");
        Text(banner).ShouldContain("Never protect real data");
        banner.ClassList.ShouldContain("intent-error"); // the error alert: red tint, icon and a title; text uses the normal foreground token (WCAG AA in both themes)
    }

    [Fact]
    public void TheDevModeBanner_IsOnEveryPage_BecauseItLivesInTheLayout()
    {
        StatusFake.DevMasterKey = true;

        Layout().Find("[data-role='main'] [data-role='dev-banner']").ShouldNotBeNull();
    }

    [Fact]
    public void TheFaultsBanner_FollowsTheFaultStatus_ThroughTheHook()
    {
        var cut = Render<FaultsBanner>();
        cut.FindAll("[data-role='faults-banner']").ShouldBeEmpty();

        FaultsFake.Set(true);
        cut.Find("[data-role='faults-banner']").TextContent.ShouldContain("Fault injection is active");
        cut.Find("[data-role='faults-banner']").GetAttribute("role").ShouldBe("alert");

        FaultsFake.Set(false);
        cut.FindAll("[data-role='faults-banner']").ShouldBeEmpty();
    }

    [Fact]
    public async Task TheFaultsBanner_UnhooksItself_WhenTheComponentIsDisposed()
    {
        var cut = Render<FaultsBanner>();
        await DisposeComponentsAsync();

        Should.NotThrow(() => FaultsFake.Set(true));
        cut.ShouldNotBeNull();
    }

    // ---- landmarks and keyboard ----

    [Fact]
    public void TheLayout_HasTheLandmarks_ASkipLink_AndTheBodyInsideMain()
    {
        var cut = Layout();

        cut.Find("header.console-header").ShouldNotBeNull();
        cut.Find("nav[aria-label='Console sections']").ShouldNotBeNull();
        var main = cut.Find("main#console-main");
        main.GetAttribute("tabindex").ShouldBe("-1");
        main.QuerySelector("[data-role='body']")!.TextContent.ShouldBe("page content");
        var skip = cut.Find("a.skip-link");
        skip.GetAttribute("href").ShouldBe("#console-main");
        skip.TextContent.ShouldBe("Skip to main content");
        cut.Find("[data-role='user']").TextContent.ShouldBe("Local console (loopback)");
        cut.FindAll("a[href='/signout']").ShouldBeEmpty("no sign-out in LoopbackOnly");
    }

    [Fact]
    public void InEntraMode_TheHeaderShowsTheSignedInUser_AndASignOutLink()
    {
        UserFake.Info = new ConsoleUserInfo("11111111-1111-1111-1111-111111111111", "Alice Admin", ConsoleAuthMode.EntraId);

        var cut = Layout();

        cut.Find("[data-role='user']").TextContent.ShouldBe("Alice Admin");
        cut.Find("a[href='/signout']").TextContent.ShouldBe("Sign out");
    }

    [Fact]
    public void TheNavigation_LinksEveryBuiltPage_AsKeyboardReachableAnchors()
    {
        var cut = Layout();
        var nav = cut.Find("nav[aria-label='Console sections']");

        var links = nav.QuerySelectorAll("a[href]").ToList();

        links.Select(static a => a.GetAttribute("href")).ShouldBe(["/", "/connections", "/dashboard", "/keys", "/namespaces", "/certificates", "/playground", "/faults", "/audit", "/about"]);
        links.Select(static a => Text(a)).ShouldBe(["Live traffic", "Connections", "Dashboard", "Keys", "Namespaces & trust", "Certificates", "Playground", "Fault injection", "Audit log", "About"]);
        links.ShouldAllBe(static a => a.GetAttribute("tabindex") != "-1", "every enabled link is in the tab order");
        nav.QuerySelectorAll("[data-nav]").Select(static n => n.GetAttribute("data-nav")).ShouldBe(["live", "connections", "dashboard", "keys", "namespaces", "certificates", "playground", "faults", "audit", "about"]);
    }

    [Fact]
    public void EveryConsolePage_IsARealPage_NoPlaceholderIsLeft()
    {
        // Since M7 Fault injection is a real page too: the navigation has no "coming in M..." entry any more.
        var cut = Layout();

        cut.FindAll("[data-nav-placeholder]").ShouldBeEmpty();
        Text(cut.Find("[data-nav='faults']")).ShouldBe("Fault injection");
    }

    [Fact]
    public void ThePlaceholders_CanBeSwitchedOff()
    {
        using var context = new ConsoleOptionsContext(static o => o.ShowPlaceholderNavigation = false);

        var cut = context.Render<NavMenu>();

        cut.FindAll("[data-nav-placeholder]").ShouldBeEmpty();
        cut.FindAll("[data-nav]").Count.ShouldBe(10);
    }

    // ---- theme ----

    [Fact]
    public void TheThemeToggle_CyclesSystemLightDark_AndSaysWhichOneIsActive()
    {
        var cut = Layout();
        var toggle = () => cut.Find("[data-role='theme-toggle']");
        Text(toggle()).ShouldBe("System");

        toggle().Click();
        Text(toggle()).ShouldBe("Light");
        toggle().Click();
        Text(toggle()).ShouldBe("Dark");
        toggle().Click();
        Text(toggle()).ShouldBe("System");

        var theme = cut.FindComponent<FluentDesignTheme>();
        theme.Instance.Mode.ShouldBe(DesignThemeModes.System);
        theme.Instance.StorageName.ShouldBe("ekmmock-theme"); // the choice is remembered in the browser (a theme name, never a secret)
        toggle().GetAttribute("aria-label")!.ShouldContain("Theme: System");
    }

    // ---- the Fluent providers ----

    [Fact]
    public void TheLayout_HostsTheFluentProviders_SoToastsAndDialogsWork()
    {
        var cut = Layout();

        cut.FindComponents<FluentToastProvider>().Count.ShouldBe(1);
        cut.FindComponents<FluentDialogProvider>().Count.ShouldBe(1);
        cut.FindComponents<FluentMessageBarProvider>().Count.ShouldBe(1);
        cut.FindComponents<FluentTooltipProvider>().Count.ShouldBe(1);
    }

    // ---- error handling ----

    private sealed class Boom : ComponentBase
    {
        protected override void OnInitialized() => throw new InvalidOperationException("secret-detail-in-the-message C:\\stack\\trace.cs:line 42");
    }

    [Fact]
    public void AFailingPage_ShowsAGenericMessage_NeverTheExceptionOrAStackTrace_AndCanRecover()
    {
        var logs = new CapturingLogger();
        Services.AddSingleton<ILoggerFactory>(new CapturingLoggerFactory(logs));
        Services.AddLogging();

        var cut = Render<ConsoleErrorBoundary>(p => p.AddChildContent<Boom>());

        var error = cut.Find("[data-role='page-error']");
        error.GetAttribute("role").ShouldBe("alert");
        Text(error).ShouldContain("This page ran into a problem.");
        cut.Markup.ShouldNotContain("secret-detail-in-the-message");
        cut.Markup.ShouldNotContain("stack");
        cut.Markup.ShouldNotContain("InvalidOperationException");
        cut.Markup.ShouldNotContain("trace.cs");
        cut.Find("button.console-error-retry").TextContent.ShouldBe("Try again");
    }

    [Fact]
    public void AFailingInspector_BreaksOnlyThePage_TheShellAndNavigationStayUsable()
    {
        InspectorFake.ThrowOnQuery = true;

        var cut = Render<MainLayout>(p => p.Add(static c => c.Body, builder =>
        {
            builder.OpenComponent<LiveTraffic>(0);
            builder.CloseComponent();
        }));

        cut.Find("[data-role='page-error']").ShouldNotBeNull();
        cut.Markup.ShouldNotContain("boom (test)");
        cut.Find("nav[aria-label='Console sections']").QuerySelectorAll("a[href]").Count.ShouldBe(10);
        cut.Find("header.console-header").ShouldNotBeNull();

        InspectorFake.ThrowOnQuery = false;
        cut.Find("button.console-error-retry").Click();
        cut.FindAll("[data-role='page-error']").ShouldBeEmpty();
        cut.Find("h1").TextContent.ShouldBe("Live traffic");
    }

    // ---- the root document ----

    [Fact]
    public void TheRootDocument_HasTheReconnectUi_AndNoInlineScripts()
    {
        var markup = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "EkmMock.Server", "Console", "ConsoleApp.razor"));

        markup.ShouldContain("id=\"components-reconnect-modal\"");
        markup.ShouldContain("role=\"alertdialog\"");
        markup.ShouldContain("Trying to reconnect");
        markup.ShouldContain("Reload page");
        System.Text.RegularExpressions.Regex.Replace(markup, @"@\*.*?\*@", string.Empty, System.Text.RegularExpressions.RegexOptions.Singleline).ShouldNotContain("<ImportMap");
        markup.ShouldContain("prerender: false");
        System.Text.RegularExpressions.Regex.Matches(markup, "<script(?![^>]*src=)").Count.ShouldBe(0);
    }
}

internal sealed class CapturingLogger : ILogger
{
    public List<string> Messages { get; } = [];

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => Messages.Add(formatter(state, exception));
}

internal sealed class CapturingLoggerFactory : ILoggerFactory
{
    private readonly ILogger _logger;

    public CapturingLoggerFactory(ILogger logger) => _logger = logger;

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public ILogger CreateLogger(string categoryName) => _logger;

    public void Dispose()
    {
    }
}
