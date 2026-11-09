#pragma warning disable xUnit1051 // The HttpClients here have bounded timeouts; per-call cancellation tokens add nothing.

using System.Diagnostics;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.FluentUI.AspNetCore.Components;

namespace EkmMock.Console.Tests;

/// <summary>
/// Spec 14 test 20 / M5 "done when": a new exchange is visible in the console within one second. The logic test: the real production server (real mutual-TLS listener, real capture
/// pipeline, real inspector consumer and live feed) is sent a real request, and the Live traffic component, subscribed to that real feed, renders the row. The browser test of the
/// same path is in <see cref="BrowserTests"/>.
/// </summary>
public sealed class LiveUpdateTests : BunitContext, IAsyncLifetime
{
    private RealConsoleHost _host = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await RealConsoleHost.StartAsync();

        JSInterop.Mode = JSRuntimeMode.Loose;
        Services.AddSingleton(TimeProvider.System);
        Services.AddSingleton(_host.Inspector);
        Services.AddSingleton<IInspectorQuery>(_host.Inspector);
        Services.AddSingleton(_host.App.Services.GetRequiredService<IConsoleStatusProvider>());
        Services.AddSingleton<IFaultStatus>(new NoFaultStatus());
        Services.AddSingleton<IConsoleUser>(new FakeUser());
        Services.AddSingleton(Options.Create(new ConsoleOptions()));
        Services.AddSingleton(Options.Create(new LimitsOptions()));
        Services.AddFluentUIComponents();
    }

    public new async ValueTask DisposeAsync()
    {
        await DisposeComponentsAsync();
        await _host.DisposeAsync();
        await base.DisposeAsync();
    }

    [Fact]
    public async Task ARealMtlsRequest_AppearsInTheLiveTrafficComponent_WithinOneSecond()
    {
        var cut = Render<LiveTraffic>();
        using var ekm = _host.CreateEkmHttpClient();

        // One request first so the TLS connection and the JIT are warm: the budget is about the capture-to-screen path, not about the first handshake.
        (await RealConsoleHost.WrapAsync(ekm, SecretScanner.RandomDek())).EnsureSuccessStatusCode();
        await cut.WaitForAssertionAsync(() => cut.FindAll("[data-row='exchange']").Count.ShouldBe(1), TimeSpan.FromSeconds(5));

        var latencies = new List<TimeSpan>();
        for (var i = 0; i < 20; i++)
        {
            var correlation = $"live-correlation-{i:00}";
            var shown = cut.FindAll("[data-row='exchange']").Count;
            using var response = await RealConsoleHost.WrapAsync(ekm, SecretScanner.RandomDek(), correlationId: correlation);
            var sent = Stopwatch.StartNew();
            response.EnsureSuccessStatusCode();

            await cut.WaitForAssertionAsync(
                () => cut.FindAll("[data-row='exchange']").Count.ShouldBe(shown + 1),
                TimeSpan.FromSeconds(1));
            sent.Stop();
            latencies.Add(sent.Elapsed);
        }

        // Every single exchange was on screen within 1 s of its response (the assertion above times out at 1 s); report the real numbers.
        var worst = latencies.Max();
        worst.ShouldBeLessThan(TimeSpan.FromSeconds(1));
        File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "live-update-latency.txt"), $"{DateTime.UtcNow:O} bUnit live update: n={latencies.Count} p50={latencies.Order().ElementAt(latencies.Count / 2).TotalMilliseconds:0} ms max={worst.TotalMilliseconds:0} ms{Environment.NewLine}");

        var row = cut.Find("[data-row='exchange']");
        row.QuerySelector(".cell-op")!.TextContent.ShouldBe("wrapkey");
        row.QuerySelector(".cell-cn")!.TextContent.ShouldBe(RealConsoleHost.ClientCn);
        row.QuerySelector("[data-role='status']")!.TextContent.ShouldBe("200 OK");
    }

    [Fact]
    public async Task EveryKindOfRequest_ReachesTheScreen_Including401And404_WithinOneSecond()
    {
        var cut = Render<LiveTraffic>();
        using var ekm = _host.CreateEkmHttpClient();
        using var anonymous = new HttpClient(new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = static (_, _, _, _) => true } }) { BaseAddress = ekm.BaseAddress };

        (await ekm.PostAsync("/info?api-version=0.1-preview", Json(EkmBody))).EnsureSuccessStatusCode();
        await cut.WaitForAssertionAsync(() => cut.FindAll("[data-row='exchange']").Count.ShouldBe(1), TimeSpan.FromSeconds(5)); // warm: the first render and handshake are not what the one-second budget is about
        (await ekm.PostAsync("/no-such-key/metadata?api-version=0.1-preview", Json(EkmBody))).StatusCode.ShouldBe(System.Net.HttpStatusCode.NotFound);
        (await anonymous.PostAsync("/info?api-version=0.1-preview", Json(EkmBody))).StatusCode.ShouldBe(System.Net.HttpStatusCode.Unauthorized);

        await cut.WaitForAssertionAsync(
            () =>
            {
                cut.FindAll("[data-row='exchange']").Select(static r => r.QuerySelector("[data-role='status']")!.TextContent).Order()
                    .ShouldBe(["200 OK", "401 Unauthenticated", "404 KeyNotFound"]);
            },
            TimeSpan.FromSeconds(1));
    }

    private static StringContent Json(string text) => new(text, System.Text.Encoding.UTF8, "application/json");

    private const string EkmBody = """{"request_context":{"request_id":"r","correlation_id":"c","pool_name":"p"}}""";
}
