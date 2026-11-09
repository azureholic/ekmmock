#pragma warning disable xUnit1051 // The metrics tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using System.Security.Authentication;
using EkmMock.Crypto;
using EkmMock.Pki;
using EkmMock.Server.Connections;
using EkmMock.Server.Ekm;
using EkmMock.Server.Faults;
using EkmMock.Server.Metrics;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// A real host that has served a known workload once: the Prometheus text of <c>/metrics</c> after it is the subject of <see cref="MetricsScrapeTests"/>. The workload covers success,
/// 4xx, an injected 429, an unauthenticated call, an unroutable path, a TLS handshake failure, a delayed request that misses the internal deadline, and AES and RSA crypto.
/// </summary>
public sealed class MetricsHostFixture : IAsyncLifetime
{
    private ConsoleTestHost _console = null!;
    private IssuedCertificate? _client;

    internal ConsoleTestHost Console => _console;

    internal RealEkmHost Host => _console.Host;

    /// <summary>The scrape taken right after the workload, while nothing is in flight.</summary>
    public string Scrape { get; private set; } = string.Empty;

    internal PromText Parsed { get; private set; } = null!;

    public async ValueTask InitializeAsync()
    {
        _console = await ConsoleTestHost.StartAsync(faults: true);
        _client = _console.Pki.ClientCaA.IssueClient(ConsoleTestHost.ClientCn);
        var ekm = new EkmClient(Host.CreateHttpClient(_client.Certificate));
        var faults = Host.App.Services.GetRequiredService<FaultRuleStore>();
        var dek = Fx.Random(32);

        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        (await ekm.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);
        (await ekm.MetadataAsync("no-such-key")).StatusCode.ShouldBe(404);
        var wrappedAes = new List<byte[]>();
        for (var i = 0; i < 3; i++)
        {
            var wrapped = await ekm.WrapAsync("aes-key-1", "A256KWP", dek);
            wrapped.StatusCode.ShouldBe(200);
            wrappedAes.Add(wrapped.Value());
        }

        foreach (var wrapped in wrappedAes)
        {
            (await ekm.UnwrapAsync("aes-key-1", "A256KWP", wrapped)).StatusCode.ShouldBe(200);
        }

        var wrappedRsa = await ekm.WrapAsync("rsa-key-1", "RSA-OAEP-256", dek);
        wrappedRsa.StatusCode.ShouldBe(200);
        (await ekm.UnwrapAsync("rsa-key-1", "RSA-OAEP-256", wrappedRsa.Value())).StatusCode.ShouldBe(200);
        (await ekm.WrapRawAsync("aes-key-1", "A128KW", "AAAA")).StatusCode.ShouldBe(400);
        (await new EkmClient(Host.CreateHttpClient()).InfoAsync()).StatusCode.ShouldBe(401);
        (await ekm.SendAsync(HttpMethod.Post, "/no/such/path/at/all?api-version=0.1-preview")).StatusCode.ShouldBe(404);

        var error = faults.Create(new FaultSpec { Kind = FaultKind.Error, ErrorPercent = 100, StatusCode = 429, Scope = new FaultScope(Key: "rate-key") });
        (await ekm.MetadataAsync("rate-key")).StatusCode.ShouldBe(429);
        faults.Delete(error.Id);

        var delay = faults.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 300, Scope = new FaultScope(Key: "aes-key-1", Operation: EkmOperation.WrapKey) });
        (await ekm.WrapAsync("aes-key-1", "A256KWP", dek)).StatusCode.ShouldBe(200);
        faults.Delete(delay.Id);

        // A TLS 1.2 client: refused during the handshake, counted by reason.
        await Should.ThrowAsync<Exception>(async () =>
        {
            var (stream, tcp) = await Host.ConnectTlsAsync(Host.CreateClientSslOptions(protocols: SslProtocols.Tls12));
            stream.Dispose();
            tcp.Dispose();
        });
        (await Wait.UntilAsync(() => Host.Metrics.TotalHandshakeFailures >= 1)).ShouldBeTrue();
        (await Wait.UntilAsync(() => Host.App.Services.GetRequiredService<ConcurrencyGate>().InFlight == 0)).ShouldBeTrue();

        Scrape = await ScrapeAsync();
        Parsed = PromText.Parse(Scrape);
    }

    internal async Task<string> ScrapeAsync()
    {
        using var console = Host.CreateConsoleClient();
        using var response = await console.GetAsync("/metrics");
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.ToString().ShouldBe("text/plain; version=0.0.4; charset=utf-8");
        return await response.Content.ReadAsStringAsync();
    }

    public async ValueTask DisposeAsync()
    {
        _client?.Dispose();
        await _console.DisposeAsync();
    }
}

/// <summary>Spec 9: the Prometheus scrape: names, types, label sets, bucket boundaries and values after a known workload; the cardinality rules; and who may scrape.</summary>
public sealed class MetricsScrapeTests : IClassFixture<MetricsHostFixture>
{
    private readonly MetricsHostFixture _fx;

    public MetricsScrapeTests(MetricsHostFixture fixture) => _fx = fixture;

    private PromText Prom => _fx.Parsed;

    // ---- names and types ----

    [Fact]
    public void EveryMetricOfSpec9_IsExposedWithItsTypeAndHelp()
    {
        var expected = new Dictionary<string, string>
        {
            ["ekmmock_requests_total"] = "counter",
            ["ekmmock_request_duration_seconds"] = "histogram",
            ["ekmmock_crypto_duration_seconds"] = "histogram",
            ["ekmmock_budget_exceeded_total"] = "counter",
            ["ekmmock_tls_handshake_failures_total"] = "counter",
            ["ekmmock_inspector_dropped_total"] = "counter",
            ["ekmmock_inflight_requests"] = "gauge",
        };

        Prom.Types.ShouldBe(expected, ignoreOrder: true);
        Prom.Help.Keys.Order().ShouldBe(expected.Keys.Order());
        Prom.Help.Values.ShouldAllBe(static h => h.Length > 10);
        Prom.Samples.Select(static s => s.Name).Distinct().ShouldAllBe(static n => n.StartsWith("ekmmock_", StringComparison.Ordinal), "nothing but our own metrics (no process or runtime noise)");
    }

    // ---- requests_total{op,status,namespace} ----

    [Fact]
    public void RequestsTotal_HasTheKnownWorkload_ByOperationStatusAndNamespace()
    {
        double Count(string op, string status, string ns = "_default") => Prom.Value("ekmmock_requests_total", ("op", op), ("status", status), ("namespace", ns));

        Count("info", "200").ShouldBe(2);
        Count("info", "401").ShouldBe(1);
        Count("metadata", "200").ShouldBe(1);
        Count("metadata", "404").ShouldBe(1);
        Count("metadata", "429").ShouldBe(1);
        Count("wrapkey", "200").ShouldBe(5);
        Count("wrapkey", "400").ShouldBe(1);
        Count("unwrapkey", "200").ShouldBe(4);
        Count("unrouted", "404", "unknown").ShouldBe(1);
        Prom.Named("ekmmock_requests_total").Sum(static s => s.Value).ShouldBe(2 + 1 + 1 + 1 + 1 + 5 + 1 + 4 + 1);
        Prom.Named("ekmmock_requests_total").ShouldAllBe(static s => s.Labels.Keys.Order().SequenceEqual(new[] { "namespace", "op", "status" }));
    }

    // ---- request_duration_seconds{op} ----

    [Fact]
    public void RequestDuration_HasTheSpecBuckets_CumulativeCountsAndASum()
    {
        double[] spec = [0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.25, 0.5, 1];
        foreach (var (op, count) in new[] { ("info", 3), ("metadata", 3), ("wrapkey", 6), ("unwrapkey", 4), ("unrouted", 1) })
        {
            var op1 = ("op", op);
            Prom.Bounds("ekmmock_request_duration_seconds", op1).ShouldBe(spec, $"buckets of {op}");
            var cumulative = Prom.Named("ekmmock_request_duration_seconds_bucket").Where(s => s.Label("op") == op).Select(static s => s.Value).ToList();
            cumulative.Count.ShouldBe(spec.Length + 1);
            cumulative.SequenceEqual(cumulative.Order()).ShouldBeTrue($"buckets are cumulative for {op}");
            Prom.Value("ekmmock_request_duration_seconds_bucket", op1, ("le", "+Inf")).ShouldBe(count);
            Prom.Value("ekmmock_request_duration_seconds_count", op1).ShouldBe(count);
            Prom.Value("ekmmock_request_duration_seconds_sum", op1).ShouldBeGreaterThan(0);
        }

        // The delayed wrap (300 ms) is above 0.25 s and at most 0.5 s: five of the six wraps are at or below 0.25 s.
        Prom.Value("ekmmock_request_duration_seconds_bucket", ("op", "wrapkey"), ("le", "0.25")).ShouldBe(5);
        Prom.Value("ekmmock_request_duration_seconds_bucket", ("op", "wrapkey"), ("le", "0.5")).ShouldBe(6);
        Prom.Value("ekmmock_request_duration_seconds_sum", ("op", "wrapkey")).ShouldBeGreaterThan(0.3);
    }

    // ---- crypto_duration_seconds{op,alg} ----

    [Fact]
    public void CryptoDuration_IsPerOperationAndAlgorithm_AndOnlyForCallsThatReachedTheEngine()
    {
        var series = Prom.Named("ekmmock_crypto_duration_seconds_count").ToDictionary(static s => (s.Label("op"), s.Label("alg")), static s => s.Value);

        series.Count.ShouldBe(5);
        series[("wrapkey", "A256KWP")].ShouldBe(4);
        series[("unwrapkey", "A256KWP")].ShouldBe(3);
        series[("wrapkey", "RSA-OAEP-256")].ShouldBe(1);
        series[("unwrapkey", "RSA-OAEP-256")].ShouldBe(1);
        series[("metadata", "none")].ShouldBe(2);
        Prom.Bounds("ekmmock_crypto_duration_seconds", ("op", "wrapkey"), ("alg", "A256KWP")).ShouldBe(EkmMetrics.CryptoBuckets);
        Prom.Value("ekmmock_crypto_duration_seconds_bucket", ("op", "wrapkey"), ("alg", "A256KWP"), ("le", "+Inf")).ShouldBe(4);
        Prom.Value("ekmmock_crypto_duration_seconds_bucket", ("op", "wrapkey"), ("alg", "A256KWP"), ("le", "0.25")).ShouldBe(4, "the injected delay is not crypto time");
        Prom.Value("ekmmock_crypto_duration_seconds_sum", ("op", "wrapkey"), ("alg", "RSA-OAEP-256")).ShouldBeGreaterThan(0);
    }

    // ---- the rest ----

    [Fact]
    public void BudgetExceeded_CountsTheDelayedRequestOnly()
    {
        Prom.Named("ekmmock_budget_exceeded_total").Select(static s => (s.Label("op"), s.Value)).ShouldBe([("wrapkey", 1.0)]);
    }

    [Fact]
    public void TlsHandshakeFailures_AreCountedByReason()
    {
        Prom.Value("ekmmock_tls_handshake_failures_total", ("reason", "tls_version_not_supported")).ShouldBeGreaterThanOrEqualTo(1);
        Prom.Named("ekmmock_tls_handshake_failures_total").ShouldAllBe(static s => s.Labels.Count == 1 && s.Labels.ContainsKey("reason"));
        _fx.Host.Metrics.HandshakeFailureCounts["tls_version_not_supported"].ShouldBe((long)Prom.Value("ekmmock_tls_handshake_failures_total", ("reason", "tls_version_not_supported")));
    }

    [Fact]
    public void InspectorDroppedAndInFlight_AreGaugesAndCountersWithoutLabels()
    {
        Prom.Value("ekmmock_inspector_dropped_total").ShouldBe(0);
        Prom.Value("ekmmock_inflight_requests").ShouldBe(0, "nothing is in flight when the scrape is taken");
    }

    [Fact]
    public void TheSeriesAreWrittenInAStableOrder_AndTwoRendersOfAnIdleProcessAreIdentical()
    {
        using var metrics = new EkmMetrics();
        foreach (var op in new[] { EkmOperation.WrapKey, EkmOperation.Info, EkmOperation.Metadata })
        {
            foreach (var status in new[] { 500, 200, 404 })
            {
                metrics.RecordRequest(op, status, "b-ns", TimeSpan.FromMilliseconds(status));
                metrics.RecordRequest(op, status, "a-ns", TimeSpan.FromMilliseconds(status));
            }
        }

        var first = PrometheusExposition.Render(metrics, 0);
        var second = PrometheusExposition.Render(metrics, 0);

        second.ShouldBe(first);
        var requestLines = first.Split('\n').Where(static l => l.StartsWith("ekmmock_requests_total{", StringComparison.Ordinal)).ToList();
        requestLines.ShouldBe(requestLines.Order(StringComparer.Ordinal).ToList());
    }

    // ---- cardinality (hostile input must not create new label values) ----

    [Fact]
    public async Task HostileKeyNamesAlgorithmsPathsAndCommonNames_NeverCreateNewLabelValues()
    {
        using var issued = _fx.Console.Pki.ClientCaA.IssueClient(ConsoleTestHost.ClientCn);
        var ekm = new EkmClient(_fx.Host.CreateHttpClient(issued.Certificate));
        var before = PromText.Parse(await _fx.ScrapeAsync());

        for (var i = 0; i < 25; i++)
        {
            var key = $"hostile-{Guid.NewGuid():N}";
            var alg = $"alg-{Guid.NewGuid():N}";
            await ekm.WrapRawAsync(key, alg, "AAAA");                                           // random key + random alg
            await ekm.WrapRawAsync("aes-key-1", alg.ToUpperInvariant(), "AAAA");                // random alg on a real key
            await ekm.WrapRawAsync("aes-key-1", "a256kwp", "AAAA");                             // wrong case of a real name
            await ekm.PostAsync($"/{Guid.NewGuid():N}/{key}/wrapkey?api-version=0.1-preview");  // random prefix
            await ekm.PostAsync(EkmClient.Path(null, key, "metadata", $"api-version={Guid.NewGuid():N}"));
            await ekm.SendAsync(new HttpMethod("X" + i), $"/{key}/wrapkey?api-version=0.1-preview");
        }

        // Random client certificate subject names (an unauthenticated CN is client controlled text): none may become a label.
        for (var i = 0; i < 6; i++)
        {
            using var stranger = _fx.Console.Pki.UntrustedClientCa.IssueClient($"stranger-{Guid.NewGuid():N}.example");
            using var http = _fx.Host.CreateHttpClient(stranger.Certificate);
            try
            {
                await new EkmClient(http).InfoAsync();
            }
            catch (HttpRequestException)
            {
                // the untrusted CA fails the handshake; that is counted by reason, never by name
            }
        }

        var after = PromText.Parse(await _fx.ScrapeAsync());

        string[] Values(PromText text, string label) => [.. text.Samples.Select(s => s.Label(label)).Where(static v => v.Length > 0).Distinct().Order()];
        Values(after, "op").ShouldBeSubsetOf(["info", "metadata", "wrapkey", "unwrapkey", "unrouted"]);
        Values(after, "alg").ShouldBeSubsetOf(["A256KW", "A256KWP", "RSA-OAEP-256", "RSA-OAEP", "unsupported", "none"]);
        Values(after, "namespace").ShouldBeSubsetOf(["_default", "unknown"]);
        Values(after, "status").ShouldAllBe(static s => s.Length == 3 && s.All(char.IsAsciiDigit));
        Values(after, "reason").ShouldBeSubsetOf(HandshakeFailureLabels());
        after.Samples.Count(static s => s.Name == "ekmmock_requests_total").ShouldBeLessThan(40);
        static string Shape(PromSample s) => s.Name + "{" + string.Join(",", s.Labels.Keys.Order()) + "}";
        after.Samples.Select(Shape).Distinct().Order().ShouldBe(before.Samples.Select(Shape).Distinct().Order(), "the hostile traffic added series values at most, never label names or metrics");
        (await _fx.ScrapeAsync()).ShouldNotContain("hostile-");
        (await _fx.ScrapeAsync()).ShouldNotContain("stranger-");
        (await _fx.ScrapeAsync()).ShouldNotContain("aes-key-1", Case.Insensitive);
    }

    private static string[] HandshakeFailureLabels()
        => [.. Enum.GetValues<HandshakeFailureReason>().Select(HandshakeFailureReasons.Label)];

    [Fact]
    public void TheUnitOfTheExposition_EscapesLabelValues_AndCountsDroppedRecords()
    {
        using var metrics = new EkmMetrics();
        metrics.RecordInspectorDropped();
        metrics.RecordInspectorDropped();
        metrics.RecordRequest(EkmOperation.WrapKey, 200, "ns\"with\\odd\nname", TimeSpan.FromMilliseconds(3));

        var text = PrometheusExposition.Render(metrics, inFlight: 7);

        text.ShouldContain("ekmmock_inspector_dropped_total 2\n");
        text.ShouldContain("ekmmock_inflight_requests 7\n");
        text.ShouldContain(@"namespace=""ns\""with\\odd\nname""");
        PromText.Parse(text).Value("ekmmock_inspector_dropped_total").ShouldBe(2);
    }

    [Fact]
    public void NamespaceLabels_AreBounded_AndAnythingBeyondTheBoundIsOther()
    {
        using var metrics = new EkmMetrics();
        for (var i = 0; i < EkmMetrics.MaxNamespaceLabels + 50; i++)
        {
            metrics.RecordRequest(EkmOperation.Info, 200, $"ns-{i}", TimeSpan.Zero);
        }

        var parsed = PromText.Parse(PrometheusExposition.Render(metrics, 0));
        var namespaces = parsed.Named("ekmmock_requests_total").Select(static s => s.Label("namespace")).Distinct().ToList();
        namespaces.Count.ShouldBe(EkmMetrics.MaxNamespaceLabels + 1);
        parsed.Value("ekmmock_requests_total", ("op", "info"), ("status", "200"), ("namespace", "other")).ShouldBe(50);
    }

    [Theory]
    [InlineData("A256KW", "A256KW")]
    [InlineData("RSA-OAEP", "RSA-OAEP")]
    [InlineData("a256kw", "unsupported")]
    [InlineData("<script>", "unsupported")]
    [InlineData(null, "none")]
    public void TheAlgorithmLabel_IsOneOfTheSupportedNames_Unsupported_Or_None(string? input, string expected)
        => EkmMetrics.AlgorithmLabel(input).ShouldBe(expected);

    [Theory]
    [InlineData(200, "200")]
    [InlineData(499, "499")]
    [InlineData(0, "other")]
    [InlineData(1000, "other")]
    public void TheStatusLabel_IsAThreeDigitHttpStatusOrOther(int status, string expected) => EkmMetrics.StatusLabel(status).ShouldBe(expected);

    // ---- where and for whom ----

    [Fact]
    public async Task OnTheEkmPort_MetricsIsA404_ForEveryMethod_EvenWithAClientCertificate()
    {
        using var issued = _fx.Console.Pki.ClientCaA.IssueClient(ConsoleTestHost.ClientCn);
        var ekm = new EkmClient(_fx.Host.CreateHttpClient(issued.Certificate));

        (await ekm.SendAsync(HttpMethod.Get, "/metrics")).ShouldBeProxyError(404, "NotFound");
        (await ekm.SendAsync(HttpMethod.Post, "/metrics")).ShouldBeProxyError(404, "NotFound");
        (await ekm.SendAsync(HttpMethod.Get, "/metrics?api-version=0.1-preview")).ShouldBeProxyError(404, "NotFound");
    }

    [Fact]
    public async Task InLoopbackOnlyMode_AnyLocalClientMayScrape()
    {
        using var console = _fx.Host.CreateConsoleClient();

        using var response = await console.GetAsync("/metrics");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        response.Headers.CacheControl!.NoStore.ShouldBeTrue("metrics are never cached");
    }

    [Fact]
    public async Task InEntraIdMode_MetricsNeedsAnAllowedUser_UnlessAnonymousScrapingIsSwitchedOn()
    {
        await using (var protectedHost = await ConsoleTestHost.StartAsync(entra: true))
        {
            using var console = protectedHost.Host.CreateConsoleClient();

            using var anonymous = await console.SendAsync(HttpMethod.Get, "/metrics");
            using var wrongUser = await console.SendAsync(HttpMethod.Get, "/metrics", r => r.Headers.Add("X-Test-Oid", ConsoleTestHost.OtherOid));
            using var allowed = await console.SendAsync(HttpMethod.Get, "/metrics", r => r.Headers.Add("X-Test-Oid", ConsoleTestHost.AllowedOid));

            anonymous.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
            wrongUser.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
            allowed.StatusCode.ShouldBe(HttpStatusCode.OK);
        }

        await using var open = await ConsoleTestHost.StartAsync(entra: true, configuration: new() { ["Metrics:AllowAnonymous"] = "true" });
        using var scraper = open.Host.CreateConsoleClient();
        using var scraped = await scraper.SendAsync(HttpMethod.Get, "/metrics");
        scraped.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await scraped.Content.ReadAsStringAsync()).ShouldContain("ekmmock_inflight_requests");
        using var status = await scraper.SendAsync(HttpMethod.Get, "/api/console/status");
        status.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "the option opens /metrics only, nothing else");
    }
}
