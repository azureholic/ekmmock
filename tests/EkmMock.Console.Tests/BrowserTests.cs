#pragma warning disable xUnit1051 // The browser tests use explicit Playwright and HttpClient timeouts.

using System.Diagnostics;
using System.Globalization;
using System.Net;
using Microsoft.Playwright;

namespace EkmMock.Console.Tests;

/// <summary>
/// The console in a real Chromium against the real server process (M5 "done when": live update visible within one second; and the visual check): every page loads without console
/// errors, CSP violations or failed requests, a request through the mutual-TLS EKM endpoint shows up in the page within a second, the detail panel opens, both themes render.
/// Trait <c>Category=Browser</c>; skipped with the reason when no browser can run here.
/// </summary>
[Trait("Category", "Browser")]
public sealed class BrowserTests : IClassFixture<BrowserFixture>
{
    private readonly BrowserFixture _fx;

    public BrowserTests(BrowserFixture fixture) => _fx = fixture;

    private sealed class Problems
    {
        public List<string> Items { get; } = [];
    }

    private async Task<(IBrowserContext Context, IPage Page, Problems Problems)> OpenAsync(string path = "/", bool dark = false)
    {
        Assert.SkipWhen(_fx.Unavailable is not null, "Browser tests are skipped: " + _fx.Unavailable);

        // IgnoreHTTPSErrors because the console serves the test server certificate, which this browser has no reason to trust (test PKI, 127.0.0.1).
        var context = await _fx.Browser!.NewContextAsync(new BrowserNewContextOptions
        {
            IgnoreHTTPSErrors = true,
            ViewportSize = new ViewportSize { Width = 1500, Height = 950 },
            ColorScheme = dark ? ColorScheme.Dark : ColorScheme.Light,
        });
        var page = await context.NewPageAsync();
        var problems = new Problems();
        page.Console += (_, message) =>
        {
            if (message.Type is "error" || message.Text.Contains("Content Security Policy", StringComparison.OrdinalIgnoreCase) || message.Text.Contains("Refused to", StringComparison.OrdinalIgnoreCase))
            {
                problems.Items.Add($"console {message.Type}: {message.Text} ({message.Location})");
            }
        };
        page.PageError += (_, error) => problems.Items.Add("page error: " + error);
        page.RequestFailed += (_, request) => problems.Items.Add($"request failed: {request.Url} {request.Failure}");
        page.Response += (_, response) =>
        {
            if (response.Status >= 400)
            {
                problems.Items.Add($"HTTP {response.Status}: {response.Url}");
            }
        };

        await page.GotoAsync(_fx.ConsoleUrl + path);
        return (context, page, problems);
    }

    private static async Task WaitForShellAsync(IPage page)
        => await page.Locator("main#console-main h1").WaitForAsync(new LocatorWaitForOptions { Timeout = 15_000 });

    private async Task ShotAsync(IPage page, string name)
        => await page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(BrowserFixture.ScreenshotFolder, name + ".png") });

    [Fact]
    public async Task ANewRequest_AppearsInTheLiveTrafficPage_WithinOneSecond_InARealBrowser()
    {
        var (context, page, problems) = await OpenAsync();
        await using var _ = context;
        await WaitForShellAsync(page);
        await page.Locator("[data-role='pause-resume']").WaitForAsync();

        // Warm-up: the first request pays for the TLS handshake and the JIT; the one-second budget is about the capture-to-screen path.
        (await _fx.SendWrapAsync("warm-up-correlation-0000")).Status.ShouldBe(HttpStatusCode.OK);
        await page.Locator("[data-role='correlation-id'][title='warm-up-correlation-0000']").WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });

        var latencies = new List<TimeSpan>();
        for (var i = 0; i < 10; i++)
        {
            var correlation = $"browser-correlation-{i:0000}";
            var (status, _) = await _fx.SendWrapAsync(correlation);
            var watch = Stopwatch.StartNew();
            status.ShouldBe(HttpStatusCode.OK);

            // Fails the test when the row is not on screen within 1000 ms of the response.
            await page.Locator($"[data-row='exchange'] [data-role='correlation-id'][title='{correlation}']").WaitForAsync(new LocatorWaitForOptions { Timeout = 1000 });
            watch.Stop();
            latencies.Add(watch.Elapsed);
        }

        latencies.Max().ShouldBeLessThan(TimeSpan.FromSeconds(1));
        File.AppendAllText(
            Path.Combine(AppContext.BaseDirectory, "live-update-latency.txt"),
            $"{DateTime.UtcNow:O} real browser (Chromium, real server process, real mTLS request): n={latencies.Count} p50={latencies.Order().ElementAt(latencies.Count / 2).TotalMilliseconds:0} ms max={latencies.Max().TotalMilliseconds:0} ms{Environment.NewLine}");

        problems.Items.ShouldBeEmpty(string.Join('\n', problems.Items));
    }

    [Fact]
    public async Task EveryPage_LoadsWithoutConsoleErrors_CspViolations_FailedRequests_OrExternalHosts()
    {
        await _fx.SendWrapAsync("pages-correlation-0001");
        await _fx.SendInfoAsync();
        await _fx.SendNotFoundAsync();

        var (context, page, problems) = await OpenAsync();
        await using var _ = context;
        var hosts = new HashSet<string>();
        page.Request += (_, request) => hosts.Add(new Uri(request.Url).Authority);

        await WaitForShellAsync(page);
        await page.Locator("[data-row='exchange']").First.WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });
        await ShotAsync(page, "01-live-traffic-light");

        foreach (var (path, heading) in new[] { ("/connections", "Connections"), ("/dashboard", "Dashboard"), ("/", "Live traffic") })
        {
            await page.Locator($"nav a[href='{path}']").ClickAsync();
            await page.Locator("main#console-main h1").Filter(new LocatorFilterOptions { HasText = heading }).WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });
        }

        await page.GotoAsync($"{_fx.ConsoleUrl}/exchange/1");
        await page.Locator("[data-role='exchange-detail']").WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });

        hosts.ShouldBe([$"127.0.0.1:{_fx.ConsolePort}"], "no request leaves the console's own origin (no CDN, no font fetch)");
        problems.Items.ShouldBeEmpty(string.Join('\n', problems.Items));
    }

    [Fact]
    public async Task TheDetailPanel_OpensFromARow_ShowsTheMaskedValue_AndTheRawDekIsNeverInThePage()
    {
        var (_, dek) = await _fx.SendWrapAsync("detail-correlation-0001");
        var (context, page, problems) = await OpenAsync();
        await using var _ = context;
        await WaitForShellAsync(page);

        await page.Locator("[data-row='exchange']").First.ClickAsync();
        await page.Locator("[data-role='detail-panel'] [data-role='exchange-detail']").WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });
        await ShotAsync(page, "02-detail-overview-light");

        await page.Locator("[role='tab'][data-tab='request']").ClickAsync();
        var masked = page.Locator("[data-role='masked-value']");
        await masked.WaitForAsync();
        (await masked.InnerTextAsync()).ShouldMatch(@"^32 bytes · fp [0-9a-f]{12}$");
        await ShotAsync(page, "03-detail-request-masked-light");
        await page.Locator("[role='tab'][data-tab='timing']").ClickAsync();
        await page.Locator("[data-role='waterfall']").WaitForAsync();
        await ShotAsync(page, "04-detail-timing-light");

        SecretScanner.LeaksInText(await page.ContentAsync(), dek).ShouldBeFalse("the raw DEK is in the browser's DOM");
        problems.Items.ShouldBeEmpty(string.Join('\n', problems.Items));
    }

    [Fact]
    public async Task TheThemeToggle_SwitchesBetweenLightAndDark_AndBothRender()
    {
        await _fx.SendWrapAsync("theme-correlation-0001");
        await _fx.SendInfoAsync();
        var (context, page, problems) = await OpenAsync();
        await using var _ = context;
        await WaitForShellAsync(page);
        await page.Locator("[data-row='exchange']").First.WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });

        var toggle = page.Locator("[data-role='theme-toggle']");
        await toggle.ClickAsync(); // System -> Light
        await Expect(toggle).ToContainTextAsync("Light");
        var light = await BackgroundLuminanceAsync(page);

        await toggle.ClickAsync(); // Light -> Dark
        await Expect(toggle).ToContainTextAsync("Dark");
        await page.WaitForTimeoutAsync(400);
        var dark = await BackgroundLuminanceAsync(page);
        await ShotAsync(page, "05-live-traffic-dark");

        light.ShouldBeGreaterThan(0.8);
        dark.ShouldBeLessThan(0.3);

        await page.Locator("[data-row='exchange']").First.ClickAsync();
        await page.Locator("[data-role='exchange-detail']").WaitForAsync();
        await ShotAsync(page, "06-detail-dark");
        await page.Locator("nav a[href='/dashboard']").ClickAsync();
        await page.Locator("[data-role='heartbeat']").WaitForAsync();
        await page.WaitForTimeoutAsync(2500);
        await ShotAsync(page, "07-dashboard-dark");
        await page.Locator("nav a[href='/connections']").ClickAsync();
        await page.Locator("[data-role='connection-statistics']").WaitForAsync();
        await ShotAsync(page, "08-connections-dark");

        await toggle.ClickAsync(); // Dark -> System (light scheme in this context)
        await page.Locator("nav a[href='/dashboard']").ClickAsync();
        await page.Locator("[data-role='heartbeat']").WaitForAsync();
        await ShotAsync(page, "09-dashboard-light");
        problems.Items.ShouldBeEmpty(string.Join('\n', problems.Items));
    }

    [Fact]
    public async Task TheDevModeBanner_IsVisible_AndTheShellHasKeyboardAccess()
    {
        var (context, page, problems) = await OpenAsync();
        await using var _ = context;
        await WaitForShellAsync(page);

        var banner = page.Locator("[data-role='dev-banner']");
        await banner.WaitForAsync();
        (await banner.InnerTextAsync()).ShouldContain("DEV MODE");

        // The skip link is the first stop of the page and moves the focus to the main landmark. (FocusOnNavigate puts the focus on the page's h1 after a navigation, so the
        // sequential focus start is there; the test starts from the link itself.)
        await page.Locator("a.skip-link").FocusAsync();
        (await page.EvaluateAsync<string>("document.activeElement.className")).ShouldContain("skip-link");
        await page.Keyboard.PressAsync("Enter");
        (await page.EvaluateAsync<string>("document.activeElement.id")).ShouldBe("console-main");

        // The navigation links are reachable with the keyboard.
        await page.Locator("nav a[href='/connections']").FocusAsync();
        await page.Keyboard.PressAsync("Enter");
        await page.Locator("main#console-main h1").Filter(new LocatorFilterOptions { HasText = "Connections" }).WaitForAsync();

        problems.Items.ShouldBeEmpty(string.Join('\n', problems.Items));
    }

    [Fact]
    public async Task ThePauseButton_FreezesTheTable_InTheBrowser_AndResumeShowsTheNewRows()
    {
        var (context, page, problems) = await OpenAsync();
        await using var _ = context;
        await WaitForShellAsync(page);
        await _fx.SendWrapAsync("pause-correlation-0001");
        await page.Locator("[data-role='correlation-id'][title='pause-correlation-0001']").WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });

        await page.Locator("[data-role='pause-resume']").ClickAsync();
        await _fx.SendWrapAsync("pause-correlation-0002");
        await page.Locator("[data-role='pending']").WaitForAsync(new LocatorWaitForOptions { Timeout = 5000 });
        (await page.Locator("[data-role='correlation-id'][title='pause-correlation-0002']").CountAsync()).ShouldBe(0);

        await page.Locator("[data-role='pause-resume']").ClickAsync();
        await page.Locator("[data-role='correlation-id'][title='pause-correlation-0002']").WaitForAsync(new LocatorWaitForOptions { Timeout = 5000 });

        problems.Items.ShouldBeEmpty(string.Join('\n', problems.Items));
    }

    private static ILocatorAssertions Expect(ILocator locator) => Assertions.Expect(locator);

    private static async Task<double> BackgroundLuminanceAsync(IPage page)
    {
        var rgb = await page.EvaluateAsync<string>("getComputedStyle(document.body).backgroundColor");
        var parts = rgb.Split('(', ')')[1].Split(',', StringSplitOptions.TrimEntries).Take(3).Select(p => double.Parse(p, CultureInfo.InvariantCulture) / 255).ToArray();
        return (0.2126 * parts[0]) + (0.7152 * parts[1]) + (0.0722 * parts[2]);
    }
}
