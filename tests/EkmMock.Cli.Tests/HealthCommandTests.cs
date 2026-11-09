namespace EkmMock.Cli.Tests;

/// <summary>
/// <c>ekmmock health</c> (the container's HEALTHCHECK, spec 11.1): exit 0 only when the console answers 200 with the expected status, 1 for every kind of "not healthy", 2 for a usage error;
/// the TLS trust options are the ones every console call uses, and the insecure switch is accepted for loopback only.
/// </summary>
public sealed class HealthCommandTests
{
    private static HttpResponseMessage Alive() => StubHandler.Json(200, """{"status":"alive"}""");

    // ---- against a scripted console ----

    [Fact]
    public async Task Healthy_WhenHealthzAnswers200Alive_AndAsksOnlyHealthz()
    {
        using var cli = new CliHarness();
        var stub = new StubHandler(static _ => Alive());
        cli.ConsoleHandler = () => stub;

        var run = await cli.RunAsync("health");

        run.ExitCode.ShouldBe(0, run.ToString());
        run.Out.ShouldContain("healthy");
        stub.Requests.Count.ShouldBe(1);
        stub.Requests[0].Method.ShouldBe("GET");
        stub.Requests[0].Path.ShouldBe("/healthz");
    }

    [Fact]
    public async Task Ready_AsksReadyz_AndRequiresTheReadyStatus()
    {
        using var cli = new CliHarness();
        var stub = new StubHandler(static _ => StubHandler.Json(200, """{"status":"ready"}"""));
        cli.ConsoleHandler = () => stub;

        (await cli.RunAsync("health", "--ready")).ExitCode.ShouldBe(0);
        stub.Requests.Single().Path.ShouldBe("/readyz");

        // /healthz's body is not an acceptable /readyz answer.
        var wrongBody = new StubHandler(static _ => Alive());
        cli.ConsoleHandler = () => wrongBody;
        (await cli.RunAsync("health", "--ready")).ExitCode.ShouldBe(1);
    }

    [Theory]
    [InlineData(503, """{"status":"not_ready","not_ready":["key_store"]}""")]
    [InlineData(404, "")]
    [InlineData(500, "boom")]
    [InlineData(403, "The console accepts local connections only.")]
    public async Task Unhealthy_ForAnyNon200Status_WithTheStatusInTheMessage(int status, string body)
    {
        using var cli = new CliHarness();
        cli.ConsoleHandler = () => new StubHandler(_ => StubHandler.Json(status, body));

        var run = await cli.RunAsync("health");

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain($"unhealthy: /healthz answered HTTP {status}");
        run.Out.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("""{"status":"dead"}""")]
    [InlineData("""{"state":"alive"}""")]
    [InlineData("not json")]
    [InlineData("")]
    [InlineData("[1]")]
    [InlineData("""{"status":1}""")]
    public async Task Unhealthy_WhenA200AnswerDoesNotSayAlive(string body)
    {
        using var cli = new CliHarness();
        cli.ConsoleHandler = () => new StubHandler(_ => StubHandler.Json(200, body));

        var run = await cli.RunAsync("health");

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain("unhealthy");
    }

    [Fact]
    public async Task Unhealthy_WhenTheConsoleCannotBeReached()
    {
        using var cli = new CliHarness();
        cli.ConsoleHandler = () => new StubHandler(static _ => throw new HttpRequestException("refused", new System.Net.Sockets.SocketException()));

        var run = await cli.RunAsync("health");

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain("cannot reach the console");
    }

    [Fact]
    public async Task Unhealthy_WhenTheConsoleDoesNotAnswerWithinTheTimeout_AndTheProbeReturnsPromptly()
    {
        using var cli = new CliHarness();
        cli.ConsoleHandler = () => new HangingHandler();
        var started = System.Diagnostics.Stopwatch.StartNew();

        var run = await cli.RunAsync("health", "--timeout", "300ms");

        started.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(5));
        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain("no answer within 300ms");
    }

    [Fact]
    public async Task TheConsoleUrl_DefaultsToTheEnvironmentVariable_ThenTheLoopbackDefault_AndNeverLeavesTheAuthority()
    {
        using var cli = new CliHarness();
        Uri? seen = null;
        cli.ConsoleHandler = () => new StubHandler(request =>
        {
            seen = request.RequestUri;
            return Alive();
        });

        await cli.RunAsync("health");
        seen!.ToString().ShouldBe("https://127.0.0.1:8080/healthz");

        cli.Environment = static name => name == "EKMMOCK_CONSOLE" ? "https://console.example:9443/some/path" : null;
        await cli.RunAsync("health");
        seen!.ToString().ShouldBe("https://console.example:9443/healthz");

        await cli.RunAsync("health", "--console", "https://[::1]:8081");
        seen!.ToString().ShouldBe("https://[::1]:8081/healthz");
    }

    [Theory]
    [InlineData("http://127.0.0.1:8080")]
    [InlineData("127.0.0.1:8080")]
    [InlineData("ftp://127.0.0.1")]
    public async Task ANonHttpsConsoleUrl_IsAUsageError(string url)
    {
        using var cli = new CliHarness();
        cli.ConsoleHandler = () => new StubHandler(static _ => Alive());

        var run = await cli.RunAsync("health", "--console", url);

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("https");
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1s")]
    [InlineData("soon")]
    public async Task ABadTimeout_IsAUsageError(string timeout)
    {
        using var cli = new CliHarness();
        cli.ConsoleHandler = () => new StubHandler(static _ => Alive());

        var run = await cli.RunAsync("health", "--timeout", timeout);

        run.ExitCode.ShouldBe(2, run.ToString());
    }

    [Theory]
    [InlineData("https://console.example:8080")]
    [InlineData("https://203.0.113.7:8080")]
    [InlineData("https://10.0.0.5:8080")]
    public async Task TheInsecureSwitch_IsRefusedForAnyNonLoopbackUrl(string url)
    {
        using var cli = new CliHarness();
        var stub = new StubHandler(static _ => Alive());
        cli.ConsoleHandler = () => stub;

        var run = await cli.RunAsync("health", "--console", url, "--insecure-console-cert");

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("loopback");
        stub.Requests.ShouldBeEmpty("nothing is sent before the trust options are accepted");
    }

    [Theory]
    [InlineData("https://127.0.0.1:8080")]
    [InlineData("https://localhost:8080")]
    [InlineData("https://[::1]:8080")]
    public async Task TheInsecureSwitch_IsAcceptedForLoopback(string url)
    {
        using var cli = new CliHarness();
        cli.ConsoleHandler = () => new StubHandler(static _ => Alive());

        (await cli.RunAsync("health", "--console", url, "--insecure-console-cert")).ExitCode.ShouldBe(0);
    }

    [Fact]
    public async Task AMissingCaFile_IsAUsageError()
    {
        using var cli = new CliHarness();

        var run = await cli.RunAsync("health", "--console-ca", cli.File("missing.pem"));

        run.ExitCode.ShouldBe(2, run.ToString());
    }

    [Fact]
    public async Task TheHelp_NamesTheCommand_AndTheExitCodes()
    {
        using var cli = new CliHarness();

        var run = await cli.RunAsync("health", "--help");

        run.ExitCode.ShouldBe(0, run.ToString());
        run.Out.ShouldContain("--insecure-console-cert");
        run.Out.ShouldContain("--ready");
        (await cli.RunAsync("--help")).Out.ShouldContain("health");
    }

    // ---- against the real server over real TLS ----

    [Collection("real server")]
    public sealed class AgainstTheRealServer
    {
        private readonly RealServerFixture _server;

        public AgainstTheRealServer(RealServerFixture server)
        {
            _server = server;
        }

        [Fact]
        public async Task Healthy_WithTheConsoleCa_TheCertificatePin_OrTheLoopbackOnlyInsecureSwitch()
        {
            var withCa = await _server.RunAsync("health", "--console", _server.ConsoleUrl, "--console-ca", _server.RootCa);
            withCa.ExitCode.ShouldBe(0, withCa.ToString());

            var ready = await _server.RunAsync("health", "--ready", "--console", _server.ConsoleUrl, "--console-ca", _server.RootCa);
            ready.ExitCode.ShouldBe(0, ready.ToString());
            ready.Out.ShouldContain("/readyz ready");

            var pinned = await _server.RunAsync("health", "--console", _server.ConsoleUrl, "--console-pin", _server.ServerCertificateThumbprint());
            pinned.ExitCode.ShouldBe(0, pinned.ToString());

            var insecure = await _server.RunAsync("health", "--console", _server.ConsoleUrl, "--insecure-console-cert");
            insecure.ExitCode.ShouldBe(0, insecure.ToString());
        }

        [Fact]
        public async Task Unhealthy_WhenTheCertificateIsNotTrusted_ThePinIsWrong_OrNothingListens()
        {
            // A CA that did not issue the console certificate.
            using var other = new CliHarness();
            (await other.RunAsync("certs", "ca", "--out", other.File("other"))).ExitCode.ShouldBe(0);
            var untrusted = await _server.RunAsync("health", "--console", _server.ConsoleUrl, "--console-ca", Path.Combine(other.File("other"), "root-ca.pem"));
            untrusted.ExitCode.ShouldBe(1, untrusted.ToString());

            var wrongPin = await _server.RunAsync("health", "--console", _server.ConsoleUrl, "--console-pin", new string('A', 64));
            wrongPin.ExitCode.ShouldBe(1, wrongPin.ToString());

            // No trust option at all: the OS store does not know the dev CA.
            var osStore = await _server.RunAsync("health", "--console", _server.ConsoleUrl);
            osStore.ExitCode.ShouldBe(1, osStore.ToString());

            using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var closed = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            var refused = await _server.RunAsync("health", "--console", $"https://127.0.0.1:{closed}", "--insecure-console-cert", "--timeout", "2s");
            refused.ExitCode.ShouldBe(1, refused.ToString());
            // Linux refuses at once; Windows retries a refused loopback connect for a couple of seconds, so there the timeout message is what the probe reports. Either way: unhealthy.
            (refused.Error.Contains("cannot reach the console", StringComparison.Ordinal) || refused.Error.Contains("no answer within", StringComparison.Ordinal)).ShouldBeTrue(refused.ToString());
        }

        [Fact]
        public async Task TheEkmPort_IsNotAHealthEndpoint()
        {
            // /healthz exists on the console port only (spec 5.4): asking the EKM port gives 404 (or a TLS failure), so the probe says unhealthy rather than healthy.
            var run = await _server.RunAsync("health", "--console", _server.EkmUrl, "--console-ca", _server.RootCa, "--timeout", "3s");

            run.ExitCode.ShouldBe(1, run.ToString());
        }
    }

    private sealed class HangingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return new HttpResponseMessage();
        }
    }
}
