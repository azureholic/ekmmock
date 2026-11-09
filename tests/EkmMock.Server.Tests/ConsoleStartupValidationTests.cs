#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using EkmMock.Server.Hosting;
using EkmMock.Server.WebConsole;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>
/// Spec 5.4 and 14 test 17: the console start-up checks. <c>LoopbackOnly</c> with a non-loopback bind refuses to start (validator matrix, host builder, and a real child
/// process whose exit code and message are asserted); <c>EntraId</c> needs tenant, client, secret and an allow-list; a client secret in configuration is refused.
/// </summary>
public sealed class ConsoleStartupValidationTests
{
    private static ConsoleOptions Loopback() => new() { Auth = ConsoleAuthMode.LoopbackOnly };

    private static ConsoleOptions Entra(Action<EntraIdOptions>? configure = null)
    {
        var options = new ConsoleOptions
        {
            Auth = ConsoleAuthMode.EntraId,
            EntraId =
            {
                TenantId = "44444444-4444-4444-4444-444444444444",
                ClientId = "55555555-5555-5555-5555-555555555555",
                AllowedObjectIds = ["11111111-1111-1111-1111-111111111111"],
            },
        };
        configure?.Invoke(options.EntraId);
        return options;
    }

    private static IReadOnlyList<string> Validate(ConsoleOptions options, string url, string? ekmUrl = "https://0.0.0.0:8443", bool secret = true, Func<string, IReadOnlyList<IPAddress>>? resolve = null)
        => ConsoleConfigurationValidator.Validate(
            options,
            new ConsoleEndpointOptions { Url = url },
            ekmUrl,
            environment: name => secret && name == ConsoleSecrets.ClientSecretVariable ? "present" : null,
            resolve: resolve);

    // ---- LoopbackOnly: the bind address ----

    [Theory]
    [InlineData("https://127.0.0.1:8080")]
    [InlineData("https://127.1.2.3:8080")]
    [InlineData("https://[::1]:8080")]
    [InlineData("https://localhost:8080")]
    [InlineData("https://LOCALHOST:8080")]
    [InlineData("https://[::ffff:127.0.0.1]:8080")]
    [InlineData("https://127.0.0.1:0")]
    public void LoopbackOnly_WithALoopbackBind_IsAccepted(string url)
        => Validate(Loopback(), url).ShouldBeEmpty();

    [Theory]
    [InlineData("https://0.0.0.0:8080", "0.0.0.0")]
    [InlineData("https://[::]:8080", "::")]
    [InlineData("https://*:8080", "*")]
    [InlineData("https://+:8080", "+")]
    [InlineData("https://10.1.2.3:8080", "10.1.2.3")]
    [InlineData("https://192.168.0.10:8080", "192.168.0.10")]
    [InlineData("https://203.0.113.7:8080", "203.0.113.7")]
    [InlineData("https://[2001:db8::1]:8080", "2001:db8::1")]
    public void LoopbackOnly_WithAnyOtherBind_IsRefused_AndTheMessageNamesTheAddress(string url, string host)
    {
        var problems = Validate(Loopback(), url);

        problems.Count.ShouldBe(1);
        problems[0].ShouldContain("LoopbackOnly");
        problems[0].ShouldContain($"'{host}'");
        problems[0].ShouldContain("EntraId");
    }

    [Fact]
    public void LoopbackOnly_WithAHostName_IsAcceptedOnlyWhenEveryResolvedAddressIsLoopback()
    {
        Validate(Loopback(), "https://console.example:8080", resolve: _ => [IPAddress.Loopback, IPAddress.IPv6Loopback]).ShouldBeEmpty();

        // Resolves to a public address, to a mix, or does not resolve at all: refused.
        Validate(Loopback(), "https://console.example:8080", resolve: _ => [IPAddress.Parse("203.0.113.9")]).Count.ShouldBe(1);
        Validate(Loopback(), "https://console.example:8080", resolve: _ => [IPAddress.Loopback, IPAddress.Parse("203.0.113.9")]).Count.ShouldBe(1);
        Validate(Loopback(), "https://console.example:8080", resolve: _ => []).Count.ShouldBe(1);
        Validate(Loopback(), "https://console.example:8080", resolve: _ => throw new SocketException()).Count.ShouldBe(1);
    }

    [Theory]
    [InlineData("http://127.0.0.1:8080")]
    [InlineData("127.0.0.1:8080")]
    [InlineData("")]
    [InlineData("https://127.0.0.1")]
    [InlineData("https://127.0.0.1:99999")]
    [InlineData("https://bad host:8080")]
    public void AMalformedConsoleUrl_IsRefused(string url)
        => Validate(Loopback(), url).ShouldNotBeEmpty();

    [Fact]
    public void TheConsoleAndTheEkmEndpoint_MustNotShareAPort()
    {
        Validate(Loopback(), "https://127.0.0.1:8443", ekmUrl: "https://0.0.0.0:8443").ShouldContain(static p => p.Contains("different ports", StringComparison.Ordinal));
        Validate(Loopback(), "https://127.0.0.1:0", ekmUrl: "https://127.0.0.1:0").ShouldBeEmpty();
    }

    // ---- EntraId ----

    [Fact]
    public void EntraId_WithEverythingConfigured_IsAccepted_OnAnyBindAddress()
    {
        Validate(Entra(), "https://0.0.0.0:8080").ShouldBeEmpty();
        Validate(Entra(), "https://127.0.0.1:8080").ShouldBeEmpty();
        Validate(Entra(static e => { e.AllowedObjectIds = []; e.AllowedGroupId = "33333333-3333-3333-3333-333333333333"; }), "https://0.0.0.0:8080").ShouldBeEmpty();
    }

    [Fact]
    public void EntraId_MissingTenantClientSecretOrAllowList_IsRefused_WithAClearMessageForEach()
    {
        Validate(Entra(static e => e.TenantId = null), "https://0.0.0.0:8080").ShouldContain(static p => p.Contains("TenantId", StringComparison.Ordinal));
        Validate(Entra(static e => e.ClientId = " "), "https://0.0.0.0:8080").ShouldContain(static p => p.Contains("ClientId", StringComparison.Ordinal));
        Validate(Entra(), "https://0.0.0.0:8080", secret: false).ShouldContain(static p => p.Contains(ConsoleSecrets.ClientSecretVariable, StringComparison.Ordinal));
        Validate(Entra(static e => e.AllowedObjectIds = []), "https://0.0.0.0:8080").ShouldContain(static p => p.Contains("AllowedObjectIds", StringComparison.Ordinal));
        Validate(Entra(static e => e.AllowedObjectIds = ["not-a-guid"]), "https://0.0.0.0:8080").ShouldContain(static p => p.Contains("GUID", StringComparison.Ordinal));
        Validate(Entra(static e => { e.AllowedObjectIds = []; e.AllowedGroupId = "nope"; }), "https://0.0.0.0:8080").ShouldContain(static p => p.Contains("GUID", StringComparison.Ordinal));
        Validate(Entra(static e => e.Instance = "http://login.example/"), "https://0.0.0.0:8080").ShouldContain(static p => p.Contains("Instance", StringComparison.Ordinal));
    }

    [Fact]
    public void AClientSecretInConfiguration_IsRefused_InEveryMode()
    {
        var message = "Console:EntraId:ClientSecret must not be set in configuration";
        Validate(Entra(static e => e.ClientSecret = "from-appsettings"), "https://0.0.0.0:8080").ShouldContain(p => p.Contains(message, StringComparison.Ordinal));

        var loopback = Loopback();
        loopback.EntraId.ClientSecret = "from-appsettings";
        Validate(loopback, "https://127.0.0.1:8080").ShouldContain(p => p.Contains(message, StringComparison.Ordinal));

        // ... and the message never repeats the value.
        string.Join(' ', Validate(Entra(static e => e.ClientSecret = "from-appsettings"), "https://0.0.0.0:8080")).ShouldNotContain("from-appsettings");
    }

    [Fact]
    public void TheClientSecret_IsReadFromTheEnvironmentOrAFile_NeverFromConfiguration()
    {
        ConsoleSecrets.ReadClientSecret(static name => name == ConsoleSecrets.ClientSecretVariable ? "  from-env  " : null).ShouldBe("from-env");
        ConsoleSecrets.ReadClientSecret(static _ => null).ShouldBeNull();

        using var folder = new TempFolder();
        var file = folder.File("secret");
        File.WriteAllText(file, "from-file\n");
        ConsoleSecrets.ReadClientSecret(name => name == ConsoleSecrets.ClientSecretFileVariable ? file : null).ShouldBe("from-file");
        ConsoleSecrets.ReadClientSecret(name => name == ConsoleSecrets.ClientSecretFileVariable ? folder.File("missing") : null).ShouldBeNull();
        File.WriteAllText(file, "  \n");
        ConsoleSecrets.ReadClientSecret(name => name == ConsoleSecrets.ClientSecretFileVariable ? file : null).ShouldBeNull();
    }

    // ---- the host builder (before anything is built or bound) ----

    private static Action<WebApplicationBuilder> Customize(TempFolder folder, params (string Key, string Value)[] settings) => builder =>
    {
        var configuration = new Dictionary<string, string?>
        {
            ["Data:Path"] = folder.Path,
            ["Endpoints:Ekm:Url"] = "https://127.0.0.1:0",
            ["Endpoints:Console:Url"] = "https://127.0.0.1:0",
        };
        foreach (var (key, value) in settings)
        {
            configuration[key] = value;
        }

        builder.Configuration.AddInMemoryCollection(configuration);
        builder.Logging.ClearProviders();
    };

    [Theory]
    [InlineData("https://0.0.0.0:0")]
    [InlineData("https://[::]:0")]
    [InlineData("https://*:0")]
    [InlineData("https://192.0.2.10:0")]
    public void TheHostBuilder_RefusesToBuild_WhenLoopbackOnlyIsCombinedWithAPublicBind(string url)
    {
        using var folder = new TempFolder();

        var exception = Should.Throw<StartupConfigurationException>(() => EkmServerServiceCollectionExtensions.BuildEkmMockApp([], Customize(folder, ("Endpoints:Console:Url", url))));

        exception.Message.ShouldStartWith("EkmMock refuses to start");
        exception.Message.ShouldContain("LoopbackOnly");
        exception.Problems.Count.ShouldBe(1);
    }

    [Fact]
    public void TheHostBuilder_RefusesToBuild_WhenAClientSecretIsInConfiguration_OrEntraIsIncomplete()
    {
        using var folder = new TempFolder();

        Should.Throw<StartupConfigurationException>(() => EkmServerServiceCollectionExtensions.BuildEkmMockApp([], Customize(folder, ("Console:EntraId:ClientSecret", "x"))))
            .Message.ShouldNotContain("\"x\"");
        var incomplete = Should.Throw<StartupConfigurationException>(() => EkmServerServiceCollectionExtensions.BuildEkmMockApp([], Customize(folder, ("Console:Auth", "EntraId"))));
        incomplete.Problems.Count.ShouldBeGreaterThanOrEqualTo(3);
    }

    [Theory]
    [InlineData("https://127.0.0.1:0")]
    [InlineData("https://localhost:0")]
    public async Task LoopbackOnly_WithALoopbackBind_StartsAndServesTheConsole(string url)
    {
        using var pki = new TestPki();
        await using var host = await RealEkmHost.StartAsync(new RealEkmHostOptions { Pki = pki, Configuration = { ["Endpoints:Console:Url"] = url } });

        using var console = host.CreateConsoleClient();
        using var response = await console.GetAsync("/healthz");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task LoopbackOnly_WithAPublicBind_NeverStartsAnyListener()
    {
        using var pki = new TestPki();

        // The same options reach the host through configuration after the builder pre-flight (the options validation and the Kestrel set-up apply the same rules).
        var exception = await Should.ThrowAsync<StartupConfigurationException>(async () =>
            await RealEkmHost.StartAsync(new RealEkmHostOptions { Pki = pki, Configuration = { ["Endpoints:Console:Url"] = "https://0.0.0.0:0" } }));

        exception.Message.ShouldContain("LoopbackOnly");
    }

    // ---- a real child process: exit code and message (spec 14 test 17) ----

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static (Process Process, Task<string> Output, Task<string> Error) StartServer(TempFolder folder, string consoleUrl, int ekmPort, Action<ProcessStartInfo>? configure = null)
    {
        var dll = typeof(Program).Assembly.Location;
        var info = new ProcessStartInfo("dotnet", $"\"{dll}\" --dev")
        {
            WorkingDirectory = Path.GetDirectoryName(dll)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        info.Environment["Data__Path"] = folder.Path;
        info.Environment["Endpoints__Ekm__Url"] = $"https://127.0.0.1:{ekmPort}";
        info.Environment["Endpoints__Console__Url"] = consoleUrl;
        info.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";
        info.Environment.Remove(ConsoleSecrets.ClientSecretVariable);
        info.Environment.Remove(ConsoleSecrets.ClientSecretFileVariable);
        configure?.Invoke(info);
        var process = Process.Start(info)!;
        return (process, process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync());
    }

    [Fact]
    public async Task TheRealProcess_WithLoopbackOnlyAndAPublicBind_ExitsNonZero_WithAClearMessage_AndNothingListens()
    {
        using var folder = new TempFolder();
        var consolePort = FreePort();
        var (process, output, error) = StartServer(folder, $"https://0.0.0.0:{consolePort}", FreePort());
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            await process.WaitForExitAsync(timeout.Token);

            process.ExitCode.ShouldNotBe(0);
            var text = await error;
            text.ShouldContain("EkmMock refuses to start");
            text.ShouldContain("LoopbackOnly");
            text.ShouldContain("0.0.0.0");
            (await output).ShouldNotContain("Application started");

            // The port was never bound.
            using var probe = new TcpClient();
            await Should.ThrowAsync<SocketException>(async () => await probe.ConnectAsync(IPAddress.Loopback, consolePort));
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }

            process.Dispose();
        }
    }

    [Fact]
    public async Task TheRealProcess_WithEntraIdAndNoClientSecret_ExitsNonZero_NamingTheEnvironmentVariable()
    {
        using var folder = new TempFolder();
        var (process, _, error) = StartServer(
            folder,
            $"https://127.0.0.1:{FreePort()}",
            FreePort(),
            info =>
            {
                info.Environment["Console__Auth"] = "EntraId";
                info.Environment["Console__EntraId__TenantId"] = "44444444-4444-4444-4444-444444444444";
                info.Environment["Console__EntraId__ClientId"] = "55555555-5555-5555-5555-555555555555";
                info.Environment["Console__EntraId__AllowedObjectIds__0"] = "11111111-1111-1111-1111-111111111111";
            });
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            await process.WaitForExitAsync(timeout.Token);

            process.ExitCode.ShouldNotBe(0);
            (await error).ShouldContain(ConsoleSecrets.ClientSecretVariable);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }

            process.Dispose();
        }
    }

    [Fact]
    public async Task TheRealProcess_WithLoopbackOnlyAndALoopbackBind_StartsAndAnswersHealthz()
    {
        using var folder = new TempFolder();
        var consolePort = FreePort();
        var (process, _, _) = StartServer(folder, $"https://127.0.0.1:{consolePort}", FreePort());
        try
        {
            using var handler = new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = static (_, _, _, _) => true } };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };

            var up = await Wait.UntilAsync(
                () =>
                {
                    try
                    {
                        return http.GetAsync($"https://127.0.0.1:{consolePort}/healthz").GetAwaiter().GetResult().IsSuccessStatusCode;
                    }
                    catch (HttpRequestException)
                    {
                        return false;
                    }
                },
                TimeSpan.FromSeconds(45),
                TimeSpan.FromMilliseconds(300));

            up.ShouldBeTrue("the console did not come up");
            process.HasExited.ShouldBeFalse();
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }

            process.Dispose();
        }
    }

    // ---- the request-time guard (defence in depth) ----

    private static ConsoleRequestGuardMiddleware Guard(ConsoleOptions options)
        => new(static _ => Task.CompletedTask, Options.Create(options));

    private static DefaultHttpContext Request(string host, IPAddress? remote, string method = "GET", string path = "/", string? origin = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Request.Scheme = "https";
        context.Request.Host = new HostString(host);
        context.Connection.RemoteIpAddress = remote;
        if (origin is not null)
        {
            context.Request.Headers.Origin = origin;
        }

        return context;
    }

    [Fact]
    public void LoopbackOnly_RejectsANonLoopbackPeer_ByDefault_AndTheOptionTurnsItOff()
    {
        Guard(Loopback()).Check(Request("localhost:8080", IPAddress.Parse("10.0.0.5"))).ShouldNotBeNull().ShouldContain("local");
        Guard(Loopback()).Check(Request("localhost:8080", IPAddress.Loopback)).ShouldBeNull();
        Guard(Loopback()).Check(Request("localhost:8080", IPAddress.IPv6Loopback)).ShouldBeNull();
        Guard(Loopback()).Check(Request("localhost:8080", IPAddress.Parse("::ffff:127.0.0.1"))).ShouldBeNull();
        Guard(Loopback()).Check(Request("localhost:8080", null)).ShouldBeNull(); // the in-process test host has no socket

        var relaxed = Loopback();
        relaxed.EnforceLoopbackClient = false;
        Guard(relaxed).Check(Request("localhost:8080", IPAddress.Parse("10.0.0.5"))).ShouldBeNull();
        ConsoleOptionsDefaults.EnforceLoopbackClient.ShouldBeTrue("the runtime check is on by default");
    }

    [Fact]
    public void LoopbackOnly_RejectsAForeignHostHeader_AgainstDnsRebinding()
    {
        Guard(Loopback()).Check(Request("127.0.0.1:8080", IPAddress.Loopback)).ShouldBeNull();
        Guard(Loopback()).Check(Request("[::1]:8080", IPAddress.IPv6Loopback)).ShouldBeNull();
        Guard(Loopback()).Check(Request("evil.example:8080", IPAddress.Loopback)).ShouldNotBeNull();

        var withExtraHost = Loopback();
        withExtraHost.AllowedHosts = ["ekmmock.internal"];
        Guard(withExtraHost).Check(Request("ekmmock.internal:8080", IPAddress.Loopback)).ShouldBeNull();
    }

    [Fact]
    public void ACrossOriginHubOrStateChangingRequest_IsRefused_InBothModes()
    {
        foreach (var mode in new[] { Loopback(), Entra() })
        {
            var guard = Guard(mode);
            guard.Check(Request("localhost:8080", IPAddress.Loopback, "POST", "/api/console/x", "https://evil.example")).ShouldNotBeNull();
            guard.Check(Request("localhost:8080", IPAddress.Loopback, "GET", "/_blazor", "https://evil.example")).ShouldNotBeNull();
            guard.Check(Request("localhost:8080", IPAddress.Loopback, "POST", "/api/console/x", "https://localhost:8080")).ShouldBeNull();
            guard.Check(Request("localhost:8080", IPAddress.Loopback, "GET", "/_blazor", "https://localhost:8080")).ShouldBeNull();
            guard.Check(Request("localhost:8080", IPAddress.Loopback, "GET", "/healthz", "https://evil.example")).ShouldBeNull(); // plain reads need no origin
        }
    }

    [Fact]
    public void EntraId_AcceptsAnyPeerAndHost_BecauseTheSignInIsTheAccessControl()
        => Guard(Entra()).Check(Request("console.contoso.example", IPAddress.Parse("203.0.113.50"))).ShouldBeNull();
}

/// <summary>The defaults of <see cref="ConsoleOptions"/> that the tests pin.</summary>
internal static class ConsoleOptionsDefaults
{
    public static bool EnforceLoopbackClient => new ConsoleOptions().EnforceLoopbackClient;
}
