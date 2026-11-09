using System.Text;
using System.Text.Json;
using EkmMock.Cli.Conformance;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Ekm;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Tests;

/// <summary>
/// M8 "done when": the full conformance suite, run by the real CLI against the real server over real mutual TLS with the dev PKI the CLI itself generated, is green. Also proves the suite
/// can fail, never skips silently, writes a clean report and leaks nothing.
/// </summary>
[Collection("real server")]
public sealed class ConformanceEndToEndTests
{
    /// <summary>The checks that cannot be done from outside; each is skipped with a reason and covered by the server's own tests (see DECISIONS "M8: conformance mapping").</summary>
    private static readonly string[] ExpectedSkipsOfAFullRun =
    [
        "14.13.a", // the restart test is two runs around a restart: PersistenceRestartTests does it
        "14.17.a", // LoopbackOnly + public bind refuses to start: needs a process start
        "14.19.a", // key store file and Corrupt state: needs the data volume and a restart
        "14.24.a", // inspector overhead: server-internal
        "14.25.a", // 60 s benchmark: the bench command
    ];

    private readonly RealServerFixture _server;

    public ConformanceEndToEndTests(RealServerFixture server)
    {
        _server = server;
    }

    private static JsonDocument ReadReport(string path) => JsonDocument.Parse(File.ReadAllText(path));

    [Fact]
    public async Task TheFullSuite_IsGreen_AgainstTheRealServer_WithAllOptionalInputsSupplied()
    {
        var report = Path.Combine(Path.GetTempPath(), $"ekmmock-report-{Guid.NewGuid():N}.json");
        try
        {
            var run = await _server.RunAsync(["test", "conformance", .. _server.FullConformanceArgs(report)]);

            run.ExitCode.ShouldBe(0, run.ToString());
            run.Out.ShouldContain("RESULT: PASSED");
            run.Out.ShouldNotContain("FAIL ");

            using var json = ReadReport(report);
            var root = json.RootElement;
            var tests = root.GetProperty("tests").EnumerateArray().ToList();
            var summary = root.GetProperty("summary");

            // Every test that exists ran, and the counts add up.
            tests.Count.ShouldBe(ConformanceSuite.All.Count);
            summary.GetProperty("total").GetInt32().ShouldBe(tests.Count);
            summary.GetProperty("failed").GetInt32().ShouldBe(0);
            summary.GetProperty("passed").GetInt32().ShouldBe(tests.Count(static t => t.GetProperty("status").GetString() == "PASS"));
            summary.GetProperty("skipped").GetInt32().ShouldBe(ExpectedSkipsOfAFullRun.Length);

            // Exactly these are skipped, each with a reason; nothing else.
            var skipped = tests.Where(static t => t.GetProperty("status").GetString() == "SKIP").ToList();
            skipped.Select(static t => t.GetProperty("id").GetString()).ShouldBe(ExpectedSkipsOfAFullRun, ignoreOrder: true);
            foreach (var test in skipped)
            {
                test.GetProperty("message").GetString()!.Length.ShouldBeGreaterThan(30, test.GetProperty("id").GetString());
            }

            // The passed ones carry no message; ids and Section 14 numbers are present.
            foreach (var test in tests.Where(static t => t.GetProperty("status").GetString() == "PASS"))
            {
                test.TryGetProperty("message", out _).ShouldBeFalse();
                test.GetProperty("id").GetString()!.ShouldStartWith(test.GetProperty("spec").GetString()! + ".");
                test.GetProperty("duration_ms").GetDouble().ShouldBeGreaterThanOrEqualTo(0);
            }

            // Section 14 numbers 1 to 27 are all covered by a passed or skipped check.
            tests.Select(static t => t.GetProperty("spec").GetString()).Distinct().Count().ShouldBe(27);

            // Everything the run created on the server was removed.
            root.GetProperty("cleanup").GetProperty("leftover").GetArrayLength().ShouldBe(0);
            root.GetProperty("cleanup").GetProperty("destroyed").GetArrayLength().ShouldBeGreaterThan(5);
        }
        finally
        {
            File.Delete(report);
        }
    }

    [Fact]
    public async Task TheReport_HasTheDocumentedShape_AndNoSecretsOrEndpointsOfTheClient()
    {
        var report = Path.Combine(Path.GetTempPath(), $"ekmmock-report-{Guid.NewGuid():N}.json");
        try
        {
            var run = await _server.RunAsync(["test", "conformance", "--only", "14.1,14.5", .. _server.FullConformanceArgs(report)]);
            run.ExitCode.ShouldBe(0, run.ToString());

            var text = File.ReadAllText(report);
            using var json = JsonDocument.Parse(text);
            var root = json.RootElement;
            root.GetProperty("tool").GetString().ShouldBe("ekmmock test conformance");
            root.GetProperty("version").GetString().ShouldBe(CliVersion.Current);
            root.GetProperty("started_at_utc").GetDateTimeOffset().ShouldBeLessThanOrEqualTo(root.GetProperty("finished_at_utc").GetDateTimeOffset());
            root.GetProperty("duration_ms").GetDouble().ShouldBeGreaterThan(0);
            root.GetProperty("target").GetProperty("url").GetString().ShouldBe(_server.EkmUrl);
            root.GetProperty("target").GetProperty("console").GetString().ShouldBe(_server.ConsoleUrl);
            root.GetProperty("inputs").GetProperty("console").GetBoolean().ShouldBeTrue();
            root.GetProperty("inputs").GetProperty("alt_client_certificate").GetBoolean().ShouldBeTrue();
            root.GetProperty("environment").GetProperty("os").GetString().ShouldNotBeNullOrEmpty();
            root.GetProperty("environment").GetProperty("processor_count").GetInt32().ShouldBeGreaterThan(0);
            root.GetProperty("tests").GetArrayLength().ShouldBe(4); // 14.1.a, 14.1.b, 14.5.a, 14.5.b

            text.ShouldNotContain("PRIVATE KEY", Case.Sensitive);
            text.ShouldNotContain("BEGIN CERTIFICATE");
            text.ShouldNotContain(".key");
            text.ShouldNotContain(Convert.ToBase64String(File.ReadAllBytes(Path.Combine(_server.Pki, "client.crt"))));
        }
        finally
        {
            File.Delete(report);
        }
    }

    [Fact]
    public async Task WithoutTheOptionalInputs_EverythingThatNeedsThemIsSkipped_WithTheReason_AndNothingPassesSilently()
    {
        var report = Path.Combine(Path.GetTempPath(), $"ekmmock-report-{Guid.NewGuid():N}.json");
        try
        {
            var run = await _server.RunAsync(["test", "conformance", .. _server.EndpointArgs(), "--report", report]);

            run.ExitCode.ShouldBe(0, run.ToString());
            using var json = ReadReport(report);
            var tests = json.RootElement.GetProperty("tests").EnumerateArray().ToDictionary(static t => t.GetProperty("id").GetString()!);
            var skips = tests.Values.Where(static t => t.GetProperty("status").GetString() == "SKIP").ToList();

            json.RootElement.GetProperty("summary").GetProperty("failed").GetInt32().ShouldBe(0);
            skips.Count.ShouldBeGreaterThan(15);
            foreach (var skip in skips)
            {
                var message = skip.GetProperty("message").GetString()!;
                (message.Contains("--", StringComparison.Ordinal) || message.Contains("outside", StringComparison.Ordinal) || message.Contains("covered", StringComparison.Ordinal) || message.Contains("bench", StringComparison.Ordinal))
                    .ShouldBeTrue($"{skip.GetProperty("id").GetString()}: the skip reason does not say what is missing: {message}");
            }

            // What needs the console is skipped for that reason...
            foreach (var id in new[] { "14.1.b", "14.4.b", "14.4.c", "14.7.a", "14.11.a", "14.11.b", "14.14.e", "14.16.a", "14.18.a", "14.20.a", "14.21.a", "14.22.a", "14.23.a", "14.26.a", "14.27.a" })
            {
                tests[id].GetProperty("status").GetString().ShouldBe("SKIP", id);
            }

            tests["14.14.c"].GetProperty("message").GetString()!.ShouldContain("--alt-client-cert");
            tests["14.14.d"].GetProperty("message").GetString()!.ShouldContain("--rogue-client-cert");
            tests["14.15.a"].GetProperty("message").GetString()!.ShouldContain("--replacement-server-cert");
            tests["14.27.a"].GetProperty("message").GetString()!.ShouldContain("--allow-disruptive");
            tests["14.26.a"].GetProperty("message").GetString()!.ShouldContain("--console");

            // ...while everything that can run with the sample keys does run and pass.
            foreach (var id in new[] { "14.1.a", "14.2.a", "14.3.a", "14.5.a", "14.6.a", "14.6.b", "14.6.c", "14.6.e", "14.8.a", "14.9.a", "14.10.a", "14.12.a", "14.12.b", "14.12.c", "14.14.a", "14.14.b", "14.16.b" })
            {
                tests[id].GetProperty("status").GetString().ShouldBe("PASS", id);
            }
        }
        finally
        {
            File.Delete(report);
        }
    }

    [Fact]
    public async Task TheRun_PrintsOnePassFailOrSkipLinePerTest_WithTheSection14Id_AndASummary()
    {
        var report = Path.Combine(Path.GetTempPath(), $"ekmmock-report-{Guid.NewGuid():N}.json");
        try
        {
            var run = await _server.RunAsync(["test", "conformance", "--only", "14.2,14.3", .. _server.FullConformanceArgs(report)]);

            var lines = run.Out.Split('\n').Where(static l => l.StartsWith("PASS", StringComparison.Ordinal) || l.StartsWith("FAIL", StringComparison.Ordinal) || l.StartsWith("SKIP", StringComparison.Ordinal)).ToList();
            lines.Count.ShouldBe(4); // 14.2.a 14.2.b 14.3.a 14.3.b
            lines.ShouldAllBe(static l => l.Contains(" 14.", StringComparison.Ordinal));
            run.Out.ShouldContain("Summary: 4 tests: 4 passed, 0 failed, 0 skipped.");
            run.Out.ShouldContain("Run id:");
        }
        finally
        {
            File.Delete(report);
        }
    }

    [Fact]
    public async Task AfterASuccessfulRun_TheAzCommandsAreFilledIn()
    {
        var report = Path.Combine(Path.GetTempPath(), $"ekmmock-report-{Guid.NewGuid():N}.json");
        try
        {
            var run = await _server.RunAsync(["test", "conformance", "--only", "14.1.a", .. _server.EndpointArgs(), "--aes-key", "aes-key-1", "--rsa-key", "rsa-key-1", "--report", report]);

            run.ExitCode.ShouldBe(0, run.ToString());
            run.Out.ShouldContain("az keyvault ekm-connection create --hsm-name $HSM --host 127.0.0.1 --server-ca-certificate root-ca.pem");
            run.Out.ShouldContain("az keyvault key create --hsm-name $HSM --name ekm-aes --external-key-id aes-key-1");
            run.Out.ShouldContain("az keyvault key create --hsm-name $HSM --name ekm-rsa --external-key-id rsa-key-1");
            run.Out.ShouldContain("az keyvault ekm-connection check --hsm-name $HSM");
        }
        finally
        {
            File.Delete(report);
        }
    }

    // ---- the suite can fail ----

    [Fact]
    public async Task AgainstAServerWhoseHsmIsOffline_TheSuiteFails_AndExitsNonZero()
    {
        var report = Path.Combine(Path.GetTempPath(), $"ekmmock-report-{Guid.NewGuid():N}.json");
        (await _server.RunOnConsoleAsync("faults", "preset", "--id", "hsm-offline")).ExitCode.ShouldBe(0);
        try
        {
            var run = await _server.RunAsync(["test", "conformance", "--only", "14.1.a,14.5.a,14.6.a,14.9.a", .. _server.EndpointArgs(), "--report", report]);

            run.ExitCode.ShouldBe(1, run.ToString());
            run.Out.ShouldContain("FAIL");
            run.Out.ShouldContain("RESULT: FAILED");
            run.Out.ShouldNotContain("az keyvault"); // the az commands are only for a successful run
            using var json = ReadReport(report);
            json.RootElement.GetProperty("summary").GetProperty("failed").GetInt32().ShouldBeGreaterThan(0);
            var failed = json.RootElement.GetProperty("tests").EnumerateArray().First(static t => t.GetProperty("status").GetString() == "FAIL");
            failed.GetProperty("message").GetString()!.ShouldContain("503");
        }
        finally
        {
            await _server.RunOnConsoleAsync("faults", "clear");
            File.Delete(report);
        }
    }

    [Fact]
    public async Task WithAClientCertificateTheServerDoesNotAllow_TheSuiteFails()
    {
        var report = Path.Combine(Path.GetTempPath(), $"ekmmock-report-{Guid.NewGuid():N}.json");
        try
        {
            var run = await _server.RunAsync(["test", "conformance", "--only", "14.1.a,14.5.a", .. _server.EndpointArgs("client-wrong-cn"), "--report", report]);

            run.ExitCode.ShouldBe(1, run.ToString());
            run.Out.ShouldContain("401");
        }
        finally
        {
            File.Delete(report);
        }
    }

    [Fact]
    public async Task AWrongServerRoot_IsAConnectionError_NotFortyFailures()
    {
        var run = await _server.RunAsync(["test", "conformance", "--url", _server.EkmUrl, "--server-name", "localhost", "--client-cert", Path.Combine(_server.Pki, "client.crt"), "--client-key", Path.Combine(_server.Pki, "client.key"), "--ca", Path.Combine(_server.Pki, "mhsm-client-ca.pem")]);

        run.ExitCode.ShouldBe(3, run.ToString());
        run.Error.ShouldContain("--ca");
        run.Out.ShouldNotContain("FAIL");
    }

    [Fact]
    public async Task AServerNameThatIsNotInTheCertificate_IsAConnectionError()
    {
        var run = await _server.RunAsync(["test", "conformance", "--url", _server.EkmUrl, "--server-name", "other.example", "--client-cert", Path.Combine(_server.Pki, "client.crt"), "--client-key", Path.Combine(_server.Pki, "client.key"), "--ca", _server.RootCa]);

        run.ExitCode.ShouldBe(3, run.ToString());
    }

    [Fact]
    public async Task ANonExistentEndpoint_IsAConnectionError()
    {
        var run = await _server.RunAsync(["test", "conformance", "--url", $"https://127.0.0.1:{Net.FreePort()}", "--client-cert", Path.Combine(_server.Pki, "client.crt"), "--client-key", Path.Combine(_server.Pki, "client.key"), "--ca", _server.RootCa]);

        run.ExitCode.ShouldBe(3, run.ToString());
    }

    // ---- no secrets ----

    [Fact]
    public async Task NothingTheRunPrintsOrWrites_ContainsAnyKeyMaterial()
    {
        var out1 = new StringWriter();
        var err1 = new StringWriter();
        var env = new CliEnvironment { Out = out1, Error = err1, GetEnvironmentVariable = static _ => null, WorkingDirectory = _server.Pki };
        using var client = ClientIdentity.Load(Path.Combine(_server.Pki, "client.crt"), Path.Combine(_server.Pki, "client.key"));
        using var alt = ClientIdentity.Load(Path.Combine(_server.Pki, "client-wrong-cn.crt"), Path.Combine(_server.Pki, "client-wrong-cn.key"));
        using var rogue = ClientIdentity.Load(Path.Combine(_server.Pki, "client-untrusted-ca.crt"), Path.Combine(_server.Pki, "client-untrusted-ca.key"));
        var roots = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
        roots.ImportFromPemFile(_server.RootCa);
        var options = new ConformanceOptions
        {
            Target = EkmTarget.Parse(_server.EkmUrl, "localhost"),
            Client = client,
            AltClient = alt,
            RogueClient = rogue,
            Roots = roots,
            Console = new ConsoleSettings(new Uri(_server.ConsoleUrl), _server.RootCa, null, false, ConsoleAuthMode.Auto, null, null),
        };
        IReadOnlyList<byte[]> secrets = [];

        var report = await ConformanceRunner.RunAsync(options, env, CancellationToken.None, used => secrets = used);

        report.Summary.Failed.ShouldBe(0, out1.ToString());
        secrets.Count.ShouldBeGreaterThan(50, "the run used many synthetic DEKs and KEKs");
        var reportJson = ConformanceRunner.ToJson(report);
        var surfaces = new[] { ("stdout", out1.ToString()), ("stderr", err1.ToString()), ("report", reportJson) };
        foreach (var (surface, text) in surfaces)
        {
            for (var i = 0; i < secrets.Count; i++)
            {
                if (secrets[i].Length < 8)
                {
                    continue;
                }

                foreach (var form in SecurityTests.LeakForms(secrets[i]))
                {
                    text.Contains(form.Value, form.Comparison).ShouldBeFalse($"secret #{i} ({form.Name}, {secrets[i].Length} bytes) appears in the {surface}");
                }
            }
        }

        // The master key and every private key of the PKI never appear either.
        var master = File.ReadAllText(Path.Combine(_server.Data, "master.key")).Trim();
        foreach (var (surface, text) in surfaces)
        {
            text.ShouldNotContain(master, customMessage: surface);
            text.ShouldNotContain("PRIVATE KEY", Case.Sensitive, surface);
        }

        foreach (var keyFile in Directory.GetFiles(_server.Pki, "*.key"))
        {
            var body = string.Concat(File.ReadAllLines(keyFile).Where(static l => !l.StartsWith("-----", StringComparison.Ordinal)))[..40];
            foreach (var (surface, text) in surfaces)
            {
                text.ShouldNotContain(body, customMessage: $"{surface} contains the start of {Path.GetFileName(keyFile)}");
            }
        }

        // The server's own output stays clean too.
        _server.ServerOutput.ShouldNotContain(master);
        foreach (var secret in secrets.Where(static s => s.Length >= 16).Take(40))
        {
            _server.ServerOutput.ShouldNotContain(Convert.ToBase64String(secret));
        }

        foreach (var root in roots)
        {
            root.Dispose();
        }
    }

    // ---- bench ----

    [Fact]
    public async Task Bench_ReportsPlausibleNumbers_WithoutErrors_AndItsRequestsAppearInTheConsole()
    {
        var run = await _server.RunAsync(["test", "bench", .. _server.EndpointArgs(), "--op", "unwrapkey", "--key", "aes-key-1", "--alg", "A256KWP", "--concurrency", "4", "--duration", "3s", "--warmup", "1s", "--output", "json"]);

        run.ExitCode.ShouldBe(0, run.ToString());
        using var json = JsonDocument.Parse(run.Out);
        var root = json.RootElement;
        root.GetProperty("operation").GetString().ShouldBe("unwrapkey");
        root.GetProperty("concurrency").GetInt32().ShouldBe(4);
        root.GetProperty("requests").GetInt64().ShouldBeGreaterThan(50);
        root.GetProperty("errors").GetInt64().ShouldBe(0);
        root.GetProperty("status_counts").GetProperty("200").GetInt64().ShouldBe(root.GetProperty("requests").GetInt64());
        root.GetProperty("throughput_rps").GetDouble().ShouldBeGreaterThan(10);
        var latency = root.GetProperty("latency_ms");
        var p50 = latency.GetProperty("p50").GetDouble();
        var p90 = latency.GetProperty("p90").GetDouble();
        var p99 = latency.GetProperty("p99").GetDouble();
        var max = latency.GetProperty("max").GetDouble();
        latency.GetProperty("min").GetDouble().ShouldBeGreaterThan(0);
        p50.ShouldBeLessThanOrEqualTo(p90);
        p90.ShouldBeLessThanOrEqualTo(p99);
        p99.ShouldBeLessThanOrEqualTo(max);
        p50.ShouldBeLessThan(250, "a local unwrap that takes a quarter of a second is not plausible");
        root.GetProperty("over_budget").GetProperty("threshold_ms").GetDouble().ShouldBe(250);
        root.GetProperty("over_budget").GetProperty("percent").GetDouble().ShouldBeGreaterThanOrEqualTo(0);
        root.GetProperty("histogram").EnumerateArray().Sum(static b => b.GetProperty("count").GetInt64()).ShouldBe(root.GetProperty("requests").GetInt64());
        root.GetProperty("model").GetString()!.ShouldContain("closed loop");
        root.GetProperty("environment").GetProperty("processor_count").GetInt32().ShouldBeGreaterThan(0);
        root.GetProperty("threshold_failures").GetArrayLength().ShouldBe(0);

        // The requests are ordinary EKM traffic: Live traffic shows them.
        using var console = _server.CreateConsoleClient();
        var page = await console.ExchangesAsync("?text=bench-&limit=20", CancellationToken.None);
        page.Items.Count.ShouldBeGreaterThan(0);
        page.Items.ShouldAllBe(static e => e.Request.Operation == "unwrapkey" && e.Response.Status == 200);
        page.Items[0].Context.PoolName.ShouldBe("ekmmock-conformance");
    }

    [Fact]
    public async Task Bench_PrintsAHumanSummary_ByDefault_AndWritesTheJsonReportToAFile()
    {
        var file = Path.Combine(Path.GetTempPath(), $"ekmmock-bench-{Guid.NewGuid():N}.json");
        try
        {
            var run = await _server.RunAsync(["test", "bench", .. _server.EndpointArgs(), "--op", "info", "--concurrency", "2", "--duration", "1500ms", "--warmup", "500ms", "--report", file]);

            run.ExitCode.ShouldBe(0, run.ToString());
            run.Out.ShouldContain("p50");
            run.Out.ShouldContain("p99");
            run.Out.ShouldContain("Histogram:");
            run.Out.ShouldContain("requests/s");
            run.Out.ShouldContain("Over 250 ms");
            using var json = JsonDocument.Parse(File.ReadAllText(file));
            json.RootElement.GetProperty("operation").GetString().ShouldBe("info");
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task Bench_AThresholdThatIsMissed_ExitsWithOne_AndSaysSo()
    {
        var run = await _server.RunAsync(["test", "bench", .. _server.EndpointArgs(), "--op", "info", "--concurrency", "2", "--duration", "1s", "--warmup", "300ms", "--assert-p99-ms", "0.0001"]);

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Out.ShouldContain("THRESHOLD FAILED");
        run.Out.ShouldContain("--assert-p99-ms");
    }

    [Fact]
    public async Task Bench_MetadataAndWrap_Work_AndAFailingKeyCountsAsErrorsPerStatus()
    {
        var wrap = await _server.RunAsync(["test", "bench", .. _server.EndpointArgs(), "--op", "wrapkey", "--key", "aes-key-1", "--alg", "A256KW", "--dek-size", "32", "--concurrency", "2", "--duration", "1s", "--warmup", "300ms", "--output", "json"]);
        wrap.ExitCode.ShouldBe(0, wrap.ToString());

        var metadata = await _server.RunAsync(["test", "bench", .. _server.EndpointArgs(), "--op", "metadata", "--key", "does-not-exist", "--concurrency", "2", "--duration", "1s", "--warmup", "300ms", "--output", "json", "--assert-no-errors"]);

        metadata.ExitCode.ShouldBe(1, metadata.ToString());
        using var json = JsonDocument.Parse(metadata.Out);
        json.RootElement.GetProperty("errors").GetInt64().ShouldBeGreaterThan(0);
        json.RootElement.GetProperty("status_counts").GetProperty("404").GetInt64().ShouldBe(json.RootElement.GetProperty("requests").GetInt64());
    }

    [Fact]
    public async Task Bench_UnwrapOfAnUnknownKey_FailsBeforeTheLoad_WithTheServersAnswer()
    {
        var run = await _server.RunAsync(["test", "bench", .. _server.EndpointArgs(), "--op", "unwrapkey", "--key", "does-not-exist", "--alg", "A256KWP", "--duration", "1s"]);

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain("404");
    }

    [Fact]
    public async Task Bench_OpenLoop_HoldsTheRequestedRate_AndSaysItCorrectsCoordinatedOmission()
    {
        var run = await _server.RunAsync(["test", "bench", .. _server.EndpointArgs(), "--op", "info", "--concurrency", "4", "--rate", "100", "--duration", "3s", "--warmup", "500ms", "--output", "json"]);

        run.ExitCode.ShouldBe(0, run.ToString());
        using var json = JsonDocument.Parse(run.Out);
        var requests = json.RootElement.GetProperty("requests").GetInt64();
        requests.ShouldBeInRange(240, 330, "100 requests/s for 3 s");
        json.RootElement.GetProperty("model").GetString()!.ShouldContain("coordinated omission");
        json.RootElement.GetProperty("target_rate").GetDouble().ShouldBe(100);
    }

    [Fact]
    public async Task Bench_AgainstAnUntrustedServer_IsAConnectionError()
    {
        var run = await _server.RunAsync(["test", "bench", "--url", _server.EkmUrl, "--server-name", "localhost", "--op", "info", "--duration", "1s", "--warmup", "300ms", "--client-cert", Path.Combine(_server.Pki, "client.crt"), "--client-key", Path.Combine(_server.Pki, "client.key"), "--ca", Path.Combine(_server.Pki, "mhsm-client-ca.pem")]);

        run.ExitCode.ShouldBe(3, run.ToString());
    }

    [Fact]
    public void TheLeakScanner_ActuallyFindsASecret_WhenItIsThere()
    {
        // The scan helper itself must not be a rubber stamp.
        var secret = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var text = $"x {Convert.ToBase64String(secret)} y";

        SecurityTests.LeakForms(secret).Any(form => text.Contains(form.Value, form.Comparison)).ShouldBeTrue();
        SecurityTests.LeakForms(secret).Any(form => $"x {Convert.ToHexString(secret).ToLowerInvariant()}".Contains(form.Value, form.Comparison)).ShouldBeTrue();
        SecurityTests.LeakForms(secret).Any(form => $"x {System.Buffers.Text.Base64Url.EncodeToString(secret)}".Contains(form.Value, form.Comparison)).ShouldBeTrue();
        SecurityTests.LeakForms(secret).Any(form => "nothing here".Contains(form.Value, form.Comparison)).ShouldBeFalse();
        _ = Encoding.UTF8;
    }
}

/// <summary>Spec 14 test 13 across a real restart of the server process: the CLI's two-phase persistence check.</summary>
public sealed class PersistenceRestartTests : IClassFixture<RealServerFixture>
{
    private readonly RealServerFixture _server;

    public PersistenceRestartTests(RealServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task KeysNamespacesAndWrappedDeks_SurviveARestartOfTheServer()
    {
        var state = Path.Combine(Path.GetTempPath(), $"ekmmock-persist-{Guid.NewGuid():N}.json");
        var report = Path.Combine(Path.GetTempPath(), $"ekmmock-report-{Guid.NewGuid():N}.json");
        try
        {
            string[] args = ["test", "conformance", "--only", "14.13", .. _server.EndpointArgs(), .. _server.ConsoleArgs, "--persistence-state", state, "--report", report];

            var phase1 = await _server.RunAsync(args);

            phase1.ExitCode.ShouldBe(0, phase1.ToString());
            phase1.Out.ShouldContain("SKIP");
            phase1.Out.ShouldContain("phase 1 of 2 done");
            File.Exists(state).ShouldBeTrue();
            var saved = File.ReadAllText(state);
            saved.ShouldContain("dek_sha256");
            saved.ShouldNotContain("PRIVATE", Case.Sensitive);

            await _server.RestartServerAsync();

            var phase2 = await _server.RunAsync(args);

            phase2.ExitCode.ShouldBe(0, phase2.ToString());
            phase2.Out.ShouldContain("PASS  14.13.a");
            phase2.Out.ShouldContain("Summary: 1 tests: 1 passed, 0 failed, 0 skipped.");
            File.Exists(state).ShouldBeFalse("a verified run removes its state file");
            var left = await _server.RunOnConsoleAsync("key", "list");
            left.Out.Split('\n').Where(static l => l.Contains("conf-persist", StringComparison.Ordinal)).ShouldAllBe(static l => l.Contains("Destroyed", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(state);
            File.Delete(report);
        }
    }

    [Fact]
    public async Task AfterARestart_TheDeletedStateOfAFailedPhaseTwo_IsReported()
    {
        var state = Path.Combine(Path.GetTempPath(), $"ekmmock-persist-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(state, "not a state file");

            var run = await _server.RunAsync(["test", "conformance", "--only", "14.13", .. _server.EndpointArgs(), .. _server.ConsoleArgs, "--persistence-state", state, "--report", state + ".report"]);

            run.ExitCode.ShouldBe(1, run.ToString());
            run.Out.ShouldContain("not a state file of this tool");
            File.ReadAllText(state).ShouldBe("not a state file");
        }
        finally
        {
            File.Delete(state);
            File.Delete(state + ".report");
        }
    }
}
