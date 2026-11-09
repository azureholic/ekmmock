#pragma warning disable xUnit1051 // The log tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Buffers.Text;
using System.Diagnostics;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using EkmMock.Server.Faults;
using EkmMock.Server.Inspector;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>Spec 9: the level of the request log line follows the latency (Warning above 150 ms, Error above 250 ms), decided by the same options that colour the budget.</summary>
public sealed class LogLevelTests
{
    private static readonly LimitsOptions Defaults = new();

    [Theory]
    [InlineData(0.0, LogLevel.Information)]
    [InlineData(1.0, LogLevel.Information)]
    [InlineData(149.999, LogLevel.Information)]
    [InlineData(150.0, LogLevel.Information)]      // "above 150 ms": exactly 150 is not above
    [InlineData(150.001, LogLevel.Warning)]
    [InlineData(200.0, LogLevel.Warning)]
    [InlineData(250.0, LogLevel.Warning)]         // "above 250 ms": exactly 250 is not above
    [InlineData(250.001, LogLevel.Error)]
    [InlineData(5000.0, LogLevel.Error)]
    public void TheLevel_FollowsTheSpec9ThresholdsStrictlyAbove(double durationMs, LogLevel expected)
        => EkmExchangeLog.LevelFor(durationMs, Defaults).ShouldBe(expected);

    [Fact]
    public void TheThresholds_AreTheLimitsOptions_NotConstants()
    {
        var custom = new LimitsOptions { LatencyWarningMs = 20, LatencyBudgetMs = 40 };

        EkmExchangeLog.LevelFor(20.0, custom).ShouldBe(LogLevel.Information);
        EkmExchangeLog.LevelFor(21.0, custom).ShouldBe(LogLevel.Warning);
        EkmExchangeLog.LevelFor(41.0, custom).ShouldBe(LogLevel.Error);
        EkmExchangeLog.LevelFor(160.0, Defaults).ShouldBe(LogLevel.Warning);
    }

    [Fact]
    public void AnUnexpectedException_IsAnErrorEvenWhenTheRequestWasFast()
    {
        var exchange = new EkmRequestContext(1, "c", DateTimeOffset.UtcNow, Stopwatch.GetTimestamp())
        {
            Duration = TimeSpan.FromMilliseconds(1),
            UnexpectedExceptionType = nameof(InvalidOperationException),
        };

        EkmExchangeLog.LevelFor(exchange, Defaults).ShouldBe(LogLevel.Error);
        exchange.UnexpectedExceptionType = null;
        EkmExchangeLog.LevelFor(exchange, Defaults).ShouldBe(LogLevel.Information);
    }

    // ---- the same thresholds end to end, made deterministic with injected delays and thresholds far from the delay ----

    private static async Task<LogLevel> LevelOfADelayedRequestAsync(int delayMs, int warningMs, int budgetMs)
    {
        using var factory = InspectorHarness.CreateFactory(
            faults: true,
            configuration: new()
            {
                ["Limits:LatencyWarningMs"] = warningMs.ToString(),
                ["Limits:LatencyBudgetMs"] = budgetMs.ToString(),
                ["Limits:InternalDeadlineMs"] = "60000",
            });
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = delayMs });

        (await factory.CreateEkmClient().InfoAsync()).StatusCode.ShouldBe(200);

        return factory.Logs.Entries.Single(static e => e.Category == "EkmMock.Exchange").Level;
    }

    [Fact]
    public async Task ARequestWellBelowTheWarningThreshold_IsInformation()
        => (await LevelOfADelayedRequestAsync(delayMs: 5, warningMs: 3000, budgetMs: 6000)).ShouldBe(LogLevel.Information);

    [Fact]
    public async Task ARequestAboveTheWarningThresholdButBelowTheBudget_IsAWarning()
        => (await LevelOfADelayedRequestAsync(delayMs: 300, warningMs: 50, budgetMs: 6000)).ShouldBe(LogLevel.Warning);

    [Fact]
    public async Task ARequestAboveTheBudget_IsAnError()
        => (await LevelOfADelayedRequestAsync(delayMs: 400, warningMs: 50, budgetMs: 150)).ShouldBe(LogLevel.Error);

    [Fact]
    public async Task WithTheSpecDefaults_A300msDelayedRequestIsAnError_AndAFastOneIsInformation()
    {
        // The Information/Warning/Error boundaries themselves are pinned deterministically by LevelFor (above); the end-to-end check only uses delays far from a boundary.
        using var factory = InspectorHarness.CreateFactory(faults: true);
        await factory.CreateEkmClient().InfoAsync();
        var rule = factory.Faults.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 300 });
        await factory.CreateEkmClient().InfoAsync();

        var lines = factory.Logs.Entries.Where(static e => e.Category == "EkmMock.Exchange").ToList();

        lines[0].Level.ShouldBe(LogLevel.Information);
        lines[1].Level.ShouldBe(LogLevel.Error);
        ((double)lines[1].Fields["duration_ms"]!).ShouldBeGreaterThan(250);
        ((double)lines[1].Fields["injected_delay_ms"]!).ShouldBeGreaterThan(270);
        lines[1].Fields["fault"].ShouldBe($"{rule.Id}:delay");
    }

    [Fact]
    public async Task AllFieldsOfSpec9_ArePresent_WithTheRealCryptoAndDelayTimes()
    {
        using var factory = InspectorHarness.CreateFactory(faults: true);
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 60, Scope = new FaultScope(Operation: EkmOperation.WrapKey) });

        await factory.CreateEkmClient().WrapAsync("aes-key-1", "A256KWP", Fx.Random(32));

        var line = factory.Logs.Entries.Single(static e => e.Category == "EkmMock.Exchange");
        foreach (var field in new[] { "exchange_id", "request_id", "correlation_id", "pool_name", "namespace", "op", "key", "alg", "status", "error_code", "client_cn", "duration_ms", "crypto_ms", "injected_delay_ms" })
        {
            line.Fields.ShouldContainKey(field);
        }

        ((double)line.Fields["injected_delay_ms"]!).ShouldBeGreaterThanOrEqualTo(55);
        ((double)line.Fields["crypto_ms"]!).ShouldBeLessThan(((double)line.Fields["injected_delay_ms"]!), "the delay is not crypto time");
        ((double)line.Fields["duration_ms"]!).ShouldBeGreaterThanOrEqualTo((double)line.Fields["injected_delay_ms"]! + (double)line.Fields["crypto_ms"]!);
    }
}

/// <summary>
/// Spec 9 and 14 test 18 (log part), extended for M7: after a full scenario that includes every fault kind, the concurrency limit, rejected and unauthenticated requests and TLS
/// failures, no DEK, <c>value</c>, key material, master key or Entra client secret appears in any captured log output (every category, down to Trace, so Kestrel and the framework
/// are included), in the metrics, or in the inspector export, as raw text, base64, base64url or hex. Runs alone because the Entra secret is a process environment variable.
/// </summary>
[Collection(ProcessEnvironmentCollection.Name)]
public sealed class LogRedactionTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;

    public async ValueTask InitializeAsync()
        => _host = await ConsoleTestHost.StartAsync(
            entra: true,
            allowKeyImport: true,
            faults: true,
            minLogLevel: LogLevel.Trace,
            // The shipped appsettings.json filters the framework categories to Warning; for this test every category is captured at Trace.
            configureServices: services => services.Configure<LoggerFilterOptions>(options =>
            {
                options.Rules.Clear();
                options.MinLevel = LogLevel.Trace;
            }),
            configuration: new()
            {
                ["Limits:MaxConcurrency"] = "3",
                ["Faults:BlackholeMaxHoldSeconds"] = "2",
                ["Metrics:AllowAnonymous"] = "true",
            });

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    [Fact]
    public async Task AfterAScenarioWithFaultsRejectionsAndTlsFailures_NoSecretAppearsInAnyLogOrMetricOrExport()
    {
        var host = _host.Host;
        var keys = host.Keys;
        var faults = host.App.Services.GetRequiredService<FaultRuleStore>();
        var aesKey = Fx.Random(32);
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: true);
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        ((IKeyManager)keys).Import("_default", "leak-aes", KeyType.Oct, aesKey);
        ((IKeyManager)keys).Import("_default", "leak-rsa", KeyType.Rsa, pkcs8);

        var (ekm, _, owner) = _host.CreateTrustedEkmClient();
        using (owner)
        {
            var deks = new List<byte[]>();
            byte[] NewDek()
            {
                var dek = Fx.Random(32);
                deks.Add(dek);
                return dek;
            }

            // Normal traffic.
            var dek = NewDek();
            var wrapped = await ekm.WrapAsync("leak-aes", "A256KWP", dek);
            (await ekm.UnwrapAsync("leak-aes", "A256KWP", wrapped.Value())).StatusCode.ShouldBe(200);
            var wrappedRsa = await ekm.WrapAsync("leak-rsa", "RSA-OAEP-256", NewDek());
            (await ekm.UnwrapAsync("leak-rsa", "RSA-OAEP-256", wrappedRsa.Value())).StatusCode.ShouldBe(200);
            (await ekm.MetadataAsync("leak-rsa")).StatusCode.ShouldBe(200);

            // Rejected requests that carry a DEK.
            var tampered = wrapped.Value().ToArray();
            tampered[2] ^= 1;
            (await ekm.UnwrapAsync("leak-aes", "A256KWP", tampered)).StatusCode.ShouldBe(400);
            (await ekm.WrapRawAsync("leak-aes", "A256KWP", Base64Url.EncodeToString(NewDek()) + "*")).StatusCode.ShouldBe(400);
            (await ekm.WrapRawAsync("leak-aes", Base64Url.EncodeToString(NewDek()), "AAAA")).StatusCode.ShouldBe(400);
            (await ekm.WrapAsync("no-such-key", "A256KWP", NewDek())).StatusCode.ShouldBe(404);
            (await ekm.PostAsync(EkmClient.Path(null, "leak-aes", "wrapkey"), "{\"request_context\":{},\"alg\":\"A256KWP\",\"value\":\"" + Base64Url.EncodeToString(NewDek()) + "\"")).StatusCode.ShouldBe(400);
            (await ekm.SendAsync(HttpMethod.Get, EkmClient.Path(null, "leak-aes", "wrapkey"), EkmClient.JsonBody(EkmClient.WrapBody("A256KWP", Base64Url.EncodeToString(NewDek()))))).StatusCode.ShouldBe(405);
            (await new EkmClient(host.CreateHttpClient()).WrapAsync("leak-aes", "A256KWP", NewDek())).StatusCode.ShouldBe(401);
            // An oversize body makes Kestrel close that connection after answering: use a connection of its own for it.
            var (bigClient, _, bigOwner) = _host.CreateTrustedEkmClient();
            using (bigOwner)
            {
                var oversize = "{\"request_context\":{},\"alg\":\"A256KWP\",\"value\":\"" + Base64Url.EncodeToString(NewDek()) + "\",\"pad\":\"" + new string('x', 20_000) + "\"}";
                (await bigClient.PostAsync(EkmClient.Path(null, "leak-aes", "wrapkey"), oversize)).StatusCode.ShouldBe(400);
            }

            // Every fault kind, each with DEK-carrying wrap and unwrap requests.
            var delay = faults.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 30 });
            (await ekm.WrapAsync("leak-aes", "A256KWP", NewDek())).StatusCode.ShouldBe(200);
            faults.Delete(delay.Id);

            foreach (var status in new[] { 429, 500, 503 })
            {
                var error = faults.Create(new FaultSpec { Kind = FaultKind.Error, ErrorPercent = 100, StatusCode = status });
                (await ekm.WrapAsync("leak-aes", "A256KWP", NewDek())).StatusCode.ShouldBe(status);
                faults.Delete(error.Id);
            }

            var offline = faults.Create(new FaultSpec { Kind = FaultKind.HsmOffline });
            (await ekm.UnwrapAsync("leak-aes", "A256KWP", wrapped.Value())).StatusCode.ShouldBe(503);
            (await ekm.InfoAsync()).StatusCode.ShouldBe(503);
            faults.Delete(offline.Id);

            var disabled = faults.Create(new FaultSpec { Kind = FaultKind.KeyDisabled });
            (await ekm.WrapAsync("leak-aes", "A256KWP", NewDek())).StatusCode.ShouldBe(403);
            faults.Delete(disabled.Id);

            var close = faults.Create(new FaultSpec { Kind = FaultKind.CloseConnection });
            await Should.ThrowAsync<HttpRequestException>(() => ekm.WrapAsync("leak-aes", "A256KWP", NewDek()));
            faults.Delete(close.Id);

            var blackhole = faults.Create(new FaultSpec { Kind = FaultKind.Blackhole });
            using (var giveUp = new CancellationTokenSource(TimeSpan.FromMilliseconds(300)))
            {
                await Should.ThrowAsync<OperationCanceledException>(() => ekm.Http.PostAsync(
                    EkmClient.Path(null, "leak-aes", "wrapkey"),
                    EkmClient.JsonBody(EkmClient.WrapBody("A256KWP", Base64Url.EncodeToString(NewDek()))),
                    giveUp.Token));
            }

            // Fill the concurrency limit with blackholed requests, get a 429, release (the hold cap of 2 s ends them if the client does not).
            using var release = new CancellationTokenSource();
            var pinned = Enumerable.Range(0, 3)
                .Select(_ => ekm.Http.PostAsync(EkmClient.Path(null, "leak-aes", "wrapkey"), EkmClient.JsonBody(EkmClient.WrapBody("A256KWP", Base64Url.EncodeToString(NewDek()))), release.Token))
                .ToList();
            (await Wait.UntilAsync(() => host.App.Services.GetRequiredService<ConcurrencyGate>().InFlight == 3)).ShouldBeTrue();
            var limited = await ekm.WrapAsync("leak-rsa", "RSA-OAEP-256", NewDek());
            limited.ShouldBeProxyError(429, "TooManyRequests");
            release.Cancel();
            foreach (var task in pinned)
            {
                await Should.ThrowAsync<OperationCanceledException>(() => task);
            }

            faults.Delete(blackhole.Id);
            (await Wait.UntilAsync(() => host.App.Services.GetRequiredService<ConcurrencyGate>().InFlight == 0)).ShouldBeTrue();

            // A TLS failure.
            await Should.ThrowAsync<Exception>(async () =>
            {
                var (stream, tcp) = await host.ConnectTlsAsync(host.CreateClientSslOptions(protocols: SslProtocols.Tls12));
                stream.Dispose();
                tcp.Dispose();
            });

            // The console: management calls (as the allowed user) that touch faults and keys, and the anonymous scrape.
            using var console = host.CreateConsoleClient(headers => headers.Add("X-Test-Oid", ConsoleTestHost.AllowedOid));
            var api = new AdminApi(console);
            (await api.PostAsync("/api/console/faults", new { kind = "delay", delay_ms = 10, description = "secret-looking-note" })).StatusCode.ShouldBe(201);
            (await api.PostAsync("/api/console/faults/clear")).StatusCode.ShouldBe(200);
            (await Wait.UntilAsync(() => host.App.Services.GetRequiredService<IInspector>().Status().ExchangesCaptured >= 25)).ShouldBeTrue("the inspector captured the scenario");
            await Task.Delay(300);

            var export = await api.GetAsync("/api/console/export?format=json");
            export.StatusCode.ShouldBe(200);
            using var anonymous = host.CreateConsoleClient();
            var scrape = await anonymous.GetStringAsync("/metrics");

            var corpus = new[]
            {
                ("logs", host.Logs.AllText),
                ("metrics", scrape),
                ("inspector export", export.Text),
            };
            host.Logs.Entries.Count.ShouldBeGreaterThan(50);
            host.Logs.Entries.Select(static e => e.Category).Distinct().Count().ShouldBeGreaterThan(3, "Kestrel, hosting and application categories are all in the corpus");
            host.Logs.Entries.ShouldContain(static e => e.Category == "EkmMock.Exchange" && e.Level == LogLevel.Error, "slow and failed requests are logged");

            var secrets = new List<(string Name, byte[] Bytes)>
            {
                ("the imported AES key", aesKey),
                ("RSA PKCS#8 encoding", pkcs8),
                ("RSA D", parameters.D!),
                ("RSA P", parameters.P!),
                ("RSA Q", parameters.Q!),
                ("RSA DP", parameters.DP!),
                ("RSA DQ", parameters.DQ!),
                ("RSA InverseQ", parameters.InverseQ!),
                ("the master key", EkmFactory.MasterKeyBytes("real-host")),
                ("the Entra client secret", Encoding.UTF8.GetBytes("test-value-no-tenant-behind-it")),
            };
            for (var i = 0; i < deks.Count; i++)
            {
                secrets.Add(($"DEK #{i}", deks[i]));
            }

            foreach (var (where, text) in corpus.Where(static c => c.Item1 != "inspector export"))
            {
                foreach (var (name, bytes) in secrets)
                {
                    SecretScanner.LeaksInText(text, bytes).ShouldBeFalse($"{name} leaked into {where}");
                }
            }

            // The export may show a DEK only masked (length and fingerprint): scan it for the keys and the Entra secret, and for every DEK in full.
            foreach (var (name, bytes) in secrets)
            {
                SecretScanner.LeaksInText(export.Text, bytes).ShouldBeFalse($"{name} leaked into the inspector export");
            }

            // Nothing client controlled or operator typed free text ended up in the log line either.
            host.Logs.AllText.ShouldNotContain("secret-looking-note");
            host.Logs.AllText.ShouldNotContain("request_context");
            host.Logs.AllText.ShouldNotContain("test-value-no-tenant-behind-it");
        }
    }
}
