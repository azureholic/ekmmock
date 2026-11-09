#pragma warning disable xUnit1051 // The browser tests use explicit Playwright and HttpClient timeouts.

using System.Text.Json;
using EkmMock.Pki;
using Microsoft.Playwright;

namespace EkmMock.Console.Tests;

/// <summary>
/// M6 in a real Chromium against the real server process (<c>--dev</c>): the visual checks (WCAG contrast of the banners and status text in both themes) and the end-to-end flow of
/// the milestone: create a key, run the Playground "via EKM endpoint", see the exchanges in Live traffic and the actions in the Audit log. Screenshots of every new page in both themes
/// go to <see cref="BrowserFixture.ScreenshotFolder"/>. Trait <c>Category=Browser</c>; skipped with the reason when no browser can run here.
/// </summary>
[Trait("Category", "Browser")]
public sealed class AdminBrowserTests : IClassFixture<BrowserFixture>
{
    // Computes the WCAG contrast ratio of the text colour against the effective background (alpha layers composed) of every matching element.
    private const string ContrastScript = """
        (selector) => {
          const parse = c => { let m = c.match(/rgba?\(([^)]+)\)/); if (m) { const p = m[1].split(/[ ,\/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; }
            m = c.match(/color\(srgb ([^)]+)\)/); if (m) { const p = m[1].split(/[ \/]+/).filter(Boolean).map(Number); return { r: p[0] * 255, g: p[1] * 255, b: p[2] * 255, a: p.length > 3 ? p[3] : 1 }; } return null; };
          const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
          const background = el => { const layers = []; for (let e = el; e; e = e.parentElement) { const c = parse(getComputedStyle(e).backgroundColor); if (c && c.a > 0) { layers.push(c); if (c.a >= 1) break; } }
            let base = { r: 255, g: 255, b: 255, a: 1 }; for (let i = layers.length - 1; i >= 0; i--) { const l = layers[i]; base = { r: l.r * l.a + base.r * (1 - l.a), g: l.g * l.a + base.g * (1 - l.a), b: l.b * l.a + base.b * (1 - l.a), a: 1 }; } return base; };
          return [...document.querySelectorAll(selector)].filter(el => (el.innerText || '').trim().length > 0).map(el => { const fg = parse(getComputedStyle(el).color); const bg = background(el); const a = lum(fg), b = lum(bg);
            return { text: (el.innerText || '').trim().slice(0, 40), ratio: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) }; });
        }
        """;

    private readonly BrowserFixture _fx;

    public AdminBrowserTests(BrowserFixture fixture) => _fx = fixture;

    private async Task<(IBrowserContext Context, IPage Page, List<string> Problems)> OpenAsync(string path, bool dark)
    {
        Assert.SkipWhen(_fx.Unavailable is not null, "Browser tests are skipped: " + _fx.Unavailable);
        var context = await _fx.Browser!.NewContextAsync(new BrowserNewContextOptions
        {
            IgnoreHTTPSErrors = true,
            ViewportSize = new ViewportSize { Width = 1500, Height = 950 },
            ColorScheme = dark ? ColorScheme.Dark : ColorScheme.Light,
            AcceptDownloads = true,
        });
        var page = await context.NewPageAsync();
        var problems = new List<string>();
        page.Console += (_, message) =>
        {
            if (message.Type is "error" || message.Text.Contains("Content Security Policy", StringComparison.OrdinalIgnoreCase) || message.Text.Contains("Refused to", StringComparison.OrdinalIgnoreCase))
            {
                problems.Add($"console {message.Type}: {message.Text}");
            }
        };
        page.PageError += (_, error) => problems.Add("page error: " + error);
        page.RequestFailed += (_, request) => problems.Add($"request failed: {request.Url} {request.Failure}");
        page.Response += (_, response) =>
        {
            if (response.Status >= 400)
            {
                problems.Add($"HTTP {response.Status}: {response.Url}");
            }
        };
        await page.GotoAsync(_fx.ConsoleUrl + path);
        await page.Locator("main#console-main h1").WaitForAsync(new LocatorWaitForOptions { Timeout = 15_000 });
        return (context, page, problems);
    }

    private static async Task ShotAsync(IPage page, string name)
        => await page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(BrowserFixture.ScreenshotFolder, name + ".png"), FullPage = true });

    private static async Task<List<(string Text, double Ratio)>> ContrastAsync(IPage page, string selector)
    {
        var json = await page.EvaluateAsync<JsonElement>(ContrastScript, selector);
        return [.. json.EnumerateArray().Select(static e => (e.GetProperty("text").GetString()!, e.GetProperty("ratio").GetDouble()))];
    }

    private static async Task Navigate(IPage page, string href, string heading)
    {
        await page.Locator($"nav a[href='{href}']").ClickAsync();
        await page.Locator("main#console-main h1").Filter(new LocatorFilterOptions { HasText = heading }).WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheDevBanner_AndTheAlerts_MeetWcagAaContrast_InBothThemes(bool dark)
    {
        var (context, page, problems) = await OpenAsync("/certificates", dark);
        await using var _ = context;
        var theme = dark ? "dark" : "light";

        var banner = await ContrastAsync(page, "[data-role='dev-banner'], [data-role='dev-banner'] *");
        banner.ShouldNotBeEmpty();
        banner.ShouldAllBe(static c => c.Ratio >= 4.5, $"dev banner text contrast ({theme}): {string.Join(", ", banner.Select(static c => $"{c.Text}={c.Ratio:0.0}"))}");

        // The certificate page of a dev server shows the throw-away certificate warning (an alert) and status text of every colour.
        var alerts = await ContrastAsync(page, "[data-role='cert-warning'], [data-role='cert-warning'] *, .status-ok, .status-client, .status-server, .detail-note, .field-help");
        alerts.ShouldNotBeEmpty();
        alerts.ShouldAllBe(static c => c.Ratio >= 4.5, $"alert and status text contrast ({theme}): {string.Join(", ", alerts.Where(static c => c.Ratio < 4.5).Select(static c => $"{c.Text}={c.Ratio:0.0}"))}");

        await ShotAsync(page, $"m6-certificates-{theme}");
        problems.ShouldBeEmpty(string.Join('\n', problems));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EveryNewPage_RendersInBothThemes_WithoutConsoleErrorsOrCspViolations(bool dark)
    {
        var (context, page, problems) = await OpenAsync("/", dark);
        await using var _ = context;
        var theme = dark ? "dark" : "light";

        foreach (var (href, heading) in new[] { ("/keys", "Keys"), ("/namespaces", "Namespaces"), ("/certificates", "Certificates"), ("/playground", "Playground"), ("/audit", "Audit log"), ("/about", "About") })
        {
            await Navigate(page, href, heading);
            await page.WaitForTimeoutAsync(400);
            await ShotAsync(page, $"m6-{heading.Split(' ')[0].ToLowerInvariant()}-{theme}");

            // Every visible text of the page is readable in this theme.
            var texts = await ContrastAsync(page, "main h1, main h2, main p, main td, main th, main dt, main dd, main label, main li, main a, main span, main code");
            var weak = texts.Where(static c => c.Ratio < 4.5).Select(static c => $"{c.Text}={c.Ratio:0.0}").Distinct().ToList();
            weak.ShouldBeEmpty($"low contrast on {href} ({theme}): {string.Join(", ", weak)}");
        }

        problems.ShouldBeEmpty(string.Join('\n', problems));
    }

    [Fact]
    public async Task CreateAKey_RunThePlaygroundViaTheEkmEndpoint_SeeItInLiveTraffic_AndInTheAuditLog()
    {
        var (context, page, problems) = await OpenAsync("/keys", dark: false);
        await using var _ = context;

        // 1. Create a key.
        await page.Locator("[data-role='create-toggle']").ClickAsync();
        await page.Locator("[data-role='create-name'] input").FillAsync("browser-key-1");
        await page.Locator("[data-role='create-name-message']").Filter(new LocatorFilterOptions { HasText = "external key identifier" }).WaitForAsync(); // the circuit is live
        await page.Locator("[data-role='create-submit']").ClickAsync();
        await page.Locator("[data-role='action-result']").Filter(new LocatorFilterOptions { HasText = "Key browser-key-1 created" }).WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });
        await page.Locator("[data-role='key-name'][data-key='browser-key-1']").ClickAsync();
        await page.Locator("[data-role='az-command']").Filter(new LocatorFilterOptions { HasText = "--external-key-id browser-key-1" }).WaitForAsync();
        await ShotAsync(page, "m6-flow-1-key-created");

        // 2. Playground via the EKM endpoint: wrap, then unwrap the result and compare the fingerprints.
        await Navigate(page, "/playground", "Playground");
        await page.Locator("[data-role='mode-ekm']").ClickAsync();
        await page.Locator("[data-role='key']").ClickAsync();
        await page.Locator("[data-role='key'] fluent-option[value='browser-key-1']").ClickAsync();
        await page.Locator("[data-role='wrap']").ClickAsync();
        await page.Locator("[data-role='result'][data-ok='true']").WaitForAsync(new LocatorWaitForOptions { Timeout = 15_000 });
        (await page.Locator("[data-role='http-status']").InnerTextAsync()).ShouldContain("200");
        var correlation = (await page.Locator("[data-role='correlation-id']").InnerTextAsync()).Trim();
        await page.Locator("[data-role='unwrap-result']").ClickAsync();
        await page.Locator("[data-role='roundtrip']").Filter(new LocatorFilterOptions { HasText = "Round trip proven" }).WaitForAsync(new LocatorWaitForOptions { Timeout = 15_000 });
        await ShotAsync(page, "m6-flow-2-playground-roundtrip");

        // 3. The exchanges are in Live traffic like any other call, with the test client certificate's CN.
        await Navigate(page, "/", "Live traffic");
        await page.Locator("[data-row='exchange']").Filter(new LocatorFilterOptions { HasText = "browser-key-1" }).First.WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });
        var rows = await page.Locator("[data-row='exchange']").Filter(new LocatorFilterOptions { HasText = "browser-key-1" }).AllInnerTextsAsync();
        rows.Count.ShouldBe(2);
        rows.ShouldAllBe(static r => r.Contains("test.managedhsmclient.local", StringComparison.Ordinal));
        rows.ShouldContain(static r => r.Contains("wrapkey", StringComparison.Ordinal));
        rows.ShouldContain(static r => r.Contains("unwrapkey", StringComparison.Ordinal));
        await page.Locator("[data-role='correlation-id']").Filter(new LocatorFilterOptions { HasText = correlation[..8] }).First.WaitForAsync();
        await ShotAsync(page, "m6-flow-3-live-traffic");

        // 4. The audit log has the create and both playground runs.
        await Navigate(page, "/audit", "Audit log");
        var actions = await page.Locator("[data-role='audit-action']").AllInnerTextsAsync();
        actions.ShouldContain("key.create");
        actions.ShouldContain("playground.wrap");
        actions.ShouldContain("playground.unwrap");
        (await page.Locator("[data-role='audit-user']").First.InnerTextAsync()).Trim().ShouldBe("loopback");
        await ShotAsync(page, "m6-flow-4-audit-log");

        problems.ShouldBeEmpty(string.Join('\n', problems));
    }

    [Fact]
    public async Task TheTrustImport_ParsesAndPreviews_TheManagedHsmJson_BeforeSaving()
    {
        using var hsmCa = CertificateAuthority.CreateRoot("Managed HSM Test Pool CA " + Guid.NewGuid().ToString("N")[..6], PkiKeyAlgorithm.EcdsaP256);
        var json = JsonSerializer.Serialize(new { subjectCommonName = "pool.managedhsmclient.test", caCertificates = new[] { hsmCa.DerBase64 } });
        var (context, page, problems) = await OpenAsync("/namespaces", dark: false);
        await using var _ = context;

        await page.Locator("[data-role='ns-name'][data-ns='_default']").ClickAsync();
        await page.Locator("[data-role='import-text'] textarea").FillAsync(json);
        await page.Locator("[data-role='import-preview']").ClickAsync();
        await page.Locator("[data-role='import-preview-result']").WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });
        (await page.Locator("[data-role='preview-cns']").InnerTextAsync()).ShouldBe("pool.managedhsmclient.test");
        (await page.Locator("[data-role='preview-ca']").InnerTextAsync()).ShouldContain("Managed HSM Test Pool CA");
        await ShotAsync(page, "m6-trust-import-preview");

        await page.Locator("[data-role='import-save']").ClickAsync();
        await page.Locator("[data-role='action-result']").Filter(new LocatorFilterOptions { HasText = "Trust saved for _default" }).WaitForAsync(new LocatorWaitForOptions { Timeout = 10_000 });
        (await page.Locator("[data-role='cn-list']").InnerTextAsync()).ShouldContain("pool.managedhsmclient.test");
        await ShotAsync(page, "m6-trust-import-saved");

        problems.ShouldBeEmpty(string.Join('\n', problems));
    }
}

/// <summary>Generating test PKI replaces the server certificate of the whole process, so this runs on a server of its own.</summary>
[Trait("Category", "Browser")]
public sealed class CertificatesBrowserTests : IClassFixture<BrowserFixture>
{
    private readonly BrowserFixture _fx;

    public CertificatesBrowserTests(BrowserFixture fixture) => _fx = fixture;

    [Fact]
    public async Task GeneratingTestPki_InstallsItAndOffersThePublicRootCaForDownload()
    {
        Assert.SkipWhen(_fx.Unavailable is not null, "Browser tests are skipped: " + _fx.Unavailable);
        var context = await _fx.Browser!.NewContextAsync(new BrowserNewContextOptions { IgnoreHTTPSErrors = true, AcceptDownloads = true, ViewportSize = new ViewportSize { Width = 1500, Height = 950 } });
        await using var _ = context;
        var page = await context.NewPageAsync();
        await page.GotoAsync(_fx.ConsoleUrl + "/certificates");
        await page.Locator("[data-role='fqdn'] input").WaitForAsync(new LocatorWaitForOptions { Timeout = 15_000 });

        await page.Locator("[data-role='fqdn'] input").FillAsync("ekm.browser.test");
        await page.Locator("[data-role='fqdn-message']").Filter(new LocatorFilterOptions { HasText = "A DNS name or IP address" }).WaitForAsync(); // the circuit is live: the server validated the input
        await page.Locator("[data-role='generate-submit']").ClickAsync();
        try
        {
            await page.Locator("[data-role='root-ca-pem']").WaitForAsync(new LocatorWaitForOptions { Timeout = 20_000 });
        }
        catch (TimeoutException)
        {
            throw new InvalidOperationException("Generate did not show the root CA. Messages: " + await page.Locator("[data-role='messages']").InnerTextAsync() + " Server output: " + _fx.ServerOutput);
        }

        (await page.Locator("[data-role='cert-san']").InnerTextAsync()).ShouldContain("DNS:ekm.browser.test");
        var pem = await page.Locator("[data-role='root-ca-pem']").InnerTextAsync();
        pem.ShouldContain("BEGIN CERTIFICATE");
        pem.ShouldNotContain("PRIVATE");
        await page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(BrowserFixture.ScreenshotFolder, "m6-certificates-generated.png"), FullPage = true });

        // The link is a plain download anchor: check what the browser would fetch (a real download event is flaky when the machine is busy: the browser cancels it).
        var link = page.Locator("[data-role='root-ca-download']");
        (await link.GetAttributeAsync("download")).ShouldBe("root-ca.pem");
        var href = await link.GetAttributeAsync("href") ?? throw new InvalidOperationException("the download link has no href");
        var fetched = await context.APIRequest.GetAsync(new Uri(new Uri(_fx.ConsoleUrl), href).ToString());
        fetched.Status.ShouldBe(200);
        var downloaded = await fetched.TextAsync();
        downloaded.ReplaceLineEndings("\n").Trim().ShouldBe(pem.ReplaceLineEndings("\n").Trim());
        downloaded.ShouldNotContain("PRIVATE");
    }
}
