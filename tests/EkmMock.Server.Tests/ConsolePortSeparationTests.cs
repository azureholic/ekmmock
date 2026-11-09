#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// Spec 5.4 and 14 test 16, on real Kestrel listeners (ephemeral ports): the EKM endpoint and the console are separated by the local port of the connection, in both
/// directions. EKM routes answer 404 on the console port; console and admin routes (pages, <c>/_blazor</c>, <c>/_framework</c>, <c>/_content</c>, <c>/api/console/*</c>,
/// <c>/healthz</c>, <c>/readyz</c>, <c>/metrics</c>) answer 404 on the EKM port; a listener that is neither gets 404 for both.
/// </summary>
public sealed class ConsolePortSeparationTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync(plainListener: true);
        await _host.SendSampleTrafficAsync();
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private RealEkmHost Host => _host.Host;

    public static TheoryData<string> ConsolePaths =>
    [
        "/",
        "/connections",
        "/dashboard",
        "/exchange/1",
        "/healthz",
        "/readyz",
        "/metrics",
        "/api/console/status",
        "/api/console/exchanges",
        "/api/console/keys",
        "/api/console/faults",
        "/faults",
        "/playground",
        "/_blazor/negotiate?negotiateVersion=1",
        "/_blazor",
        "/_framework/blazor.web.js",
        "/_content/Microsoft.FluentUI.AspNetCore.Components/Microsoft.FluentUI.AspNetCore.Components.lib.module.js",
        "/console.css",
        "/signout",
    ];

    public static TheoryData<string> EkmPaths =>
    [
        "/info?api-version=0.1-preview",
        "/aes-key-1/metadata?api-version=0.1-preview",
        "/aes-key-1/wrapkey?api-version=0.1-preview",
        "/aes-key-1/unwrapkey?api-version=0.1-preview",
        "/rsa-key-1/metadata?api-version=0.1-preview",
    ];

    [Theory]
    [MemberData(nameof(EkmPaths))]
    public async Task EkmRoutes_AreNotFound_OnTheConsolePort(string path)
    {
        using var console = Host.CreateConsoleClient();

        foreach (var method in new[] { HttpMethod.Post, HttpMethod.Get })
        {
            using var response = await console.SendAsync(method, path, content: method == HttpMethod.Post ? new StringContent(EkmClient.Context, System.Text.Encoding.UTF8, "application/json") : null);

            response.StatusCode.ShouldBe(HttpStatusCode.NotFound, $"{method} {path} on the console port");
            // Not an EKM answer: no ProxyError, nothing that looks like the EKM contract.
            var body = await response.Content.ReadAsStringAsync();
            body.ShouldNotContain("\"code\"");
            body.ShouldNotContain("api_version");
        }
    }

    [Theory]
    [MemberData(nameof(ConsolePaths))]
    public async Task ConsoleRoutes_AreNotFound_OnTheEkmPort_WithAndWithoutAClientCertificate(string path)
    {
        var (ekm, _, owner) = _host.CreateTrustedEkmClient();
        using (owner)
        {
            using var anonymous = Host.CreateHttpClient();
            foreach (var http in new[] { ekm.Http, anonymous })
            {
                foreach (var method in new[] { HttpMethod.Get, HttpMethod.Post })
                {
                    using var request = new HttpRequestMessage(method, path);
                    HttpResponseMessage response;
                    try
                    {
                        response = await http.SendAsync(request);
                    }
                    catch (HttpRequestException ex)
                    {
                        // Open question 47: when the rare "chain not trusted" handshake failure happens, say what the server decided (its recorded verdict), so the next occurrence is diagnosable.
                        var failures = string.Join(" | ", _host.Inspector.ConnectionEvents(limit: 20)
                            .Where(static e => e.Kind == "handshake_failed")
                            .Select(static e => $"{e.FailureReason}: {e.FailureDescription} / {e.FailureDetail}"));
                        throw new InvalidOperationException($"{method} {path} failed: {ex.Message}. Server-side handshake failures: {failures}", ex);
                    }

                    using (response)
                    {
                        response.StatusCode.ShouldBe(HttpStatusCode.NotFound, $"{method} {path} on the EKM port");
                        (await response.Content.ReadAsStringAsync()).ShouldNotContain("EkmMock console");
                    }
                }
            }
        }
    }

    [Fact]
    public async Task HealthAndReadiness_AreServedOnTheConsolePortOnly()
    {
        using var console = Host.CreateConsoleClient();

        using var health = await console.GetAsync("/healthz");
        using var ready = await console.GetAsync("/readyz");

        health.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await health.Content.ReadAsStringAsync()).ShouldBe("""{"status":"alive"}""");
        ready.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await ready.Content.ReadAsStringAsync()).ShouldBe("""{"status":"ready"}""");

        using var ekm = Host.CreateHttpClient();
        (await ekm.GetAsync("/healthz")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await ekm.GetAsync("/readyz")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task TheLocalPort_NotTheHostHeader_DecidesWhichPipelineAnswers()
    {
        using var console = Host.CreateConsoleClient();
        using var ekm = Host.CreateHttpClient();

        // An EKM-looking Host on the console port and a console-looking Host on the EKM port change nothing.
        using var onConsole = new HttpRequestMessage(HttpMethod.Post, "/info?api-version=0.1-preview");
        onConsole.Headers.Host = $"127.0.0.1:{Host.Port}";
        using var onEkm = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        onEkm.Headers.Host = $"127.0.0.1:{Host.ConsolePort}";

        (await console.SendAsync(onConsole)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await ekm.SendAsync(onEkm)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task AListenerThatIsNeitherEkmNorConsole_ServesNeither()
    {
        Host.PlainHttpPort.ShouldNotBeNull();
        using var plain = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{Host.PlainHttpPort}/"), Timeout = TimeSpan.FromSeconds(10) };

        foreach (var path in new[] { "/healthz", "/", "/api/console/status", "/info?api-version=0.1-preview", "/aes-key-1/wrapkey?api-version=0.1-preview" })
        {
            using var request = new HttpRequestMessage(path.Contains("wrapkey", StringComparison.Ordinal) || path.StartsWith("/info", StringComparison.Ordinal) ? HttpMethod.Post : HttpMethod.Get, path);
            using var response = await plain.SendAsync(request);

            response.StatusCode.ShouldBe(HttpStatusCode.NotFound, path);
        }
    }

    [Fact]
    public async Task TheSignalRNegotiate_IsAvailableOnTheConsolePort_AndNotFoundOnTheEkmPort()
    {
        using var console = Host.CreateConsoleClient();
        using var ekm = Host.CreateHttpClient();

        using var onConsole = await console.PostAsync("/_blazor/negotiate?negotiateVersion=1", content: null);
        using var onEkm = await ekm.PostAsync("/_blazor/negotiate?negotiateVersion=1", content: null);

        onConsole.StatusCode.ShouldBe(HttpStatusCode.OK, await onConsole.Content.ReadAsStringAsync());
        (await onConsole.Content.ReadAsStringAsync()).ShouldContain("connectionToken");
        onEkm.StatusCode.ShouldBe(HttpStatusCode.NotFound);

        // A WebSocket upgrade request to the hub on the EKM port does not reach a hub either.
        using var upgrade = new HttpRequestMessage(HttpMethod.Get, "/_blazor?id=abc");
        upgrade.Headers.TryAddWithoutValidation("Connection", "Upgrade");
        upgrade.Headers.TryAddWithoutValidation("Upgrade", "websocket");
        upgrade.Headers.TryAddWithoutValidation("Sec-WebSocket-Version", "13");
        upgrade.Headers.TryAddWithoutValidation("Sec-WebSocket-Key", Convert.ToBase64String(new byte[16]));
        using var upgradeResponse = await ekm.SendAsync(upgrade);
        upgradeResponse.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task TheConsole_NeedsNoClientCertificate_AndAcceptsBrowserTlsVersions()
    {
        // No client certificate and TLS 1.2 are both fine on the console (the EKM listener refuses TLS 1.2: see MtlsEndpointTests).
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, Host.ConsolePort);
        await using var ssl = new SslStream(tcp.GetStream());
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "127.0.0.1",
            EnabledSslProtocols = SslProtocols.Tls12,
            RemoteCertificateValidationCallback = Host.ValidateServer,
        });

        ssl.SslProtocol.ShouldBe(SslProtocols.Tls12);

        using var console = Host.CreateConsoleClient();
        using var response = await console.GetAsync("/healthz");
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ConsoleRequests_AreNeverCapturedAsEkmTraffic_AndConsoleConnectionsAreNotEkmConnections()
    {
        var inspector = _host.Inspector;
        // Let capture and connection events of earlier tests on this shared host drain (the capture channel is asynchronous) before the baseline.
        await Task.Delay(500);
        var before = inspector.Status().ExchangesCaptured;
        var eventsBefore = inspector.ConnectionEvents(limit: 1000).Count;

        using var console = Host.CreateConsoleClient();
        for (var i = 0; i < 5; i++)
        {
            (await console.GetAsync("/healthz")).StatusCode.ShouldBe(HttpStatusCode.OK);
            (await console.GetAsync("/api/console/status")).StatusCode.ShouldBe(HttpStatusCode.OK);
        }

        await Task.Delay(300);
        inspector.Status().ExchangesCaptured.ShouldBe(before);
        inspector.ConnectionEvents(limit: 1000).Count.ShouldBe(eventsBefore);
        Host.App.Services.GetRequiredService<ListenerRegistry>().PortsOf(ListenerRegistry.EkmName).ShouldNotContain(Host.ConsolePort);
    }

    [Fact]
    public async Task TheEkmAndConsolePorts_AreDifferentAndKnownToTheirPolicies()
    {
        // Ephemeral listeners are learned from their first connection (the listener's own connection middleware registers the port).
        using var console = Host.CreateConsoleClient();
        (await console.GetAsync("/healthz")).StatusCode.ShouldBe(HttpStatusCode.OK);

        Host.Port.ShouldNotBe(Host.ConsolePort);
        Host.App.Services.GetRequiredService<Connections.IEkmPortPolicy>().IsEkmPort(Host.ConsolePort).ShouldBeFalse();
        Host.App.Services.GetRequiredService<WebConsole.IConsolePortPolicy>().IsConsolePort(Host.Port).ShouldBeFalse();
        Host.App.Services.GetRequiredService<WebConsole.IConsolePortPolicy>().IsConsolePort(Host.ConsolePort).ShouldBeTrue();
    }
}
