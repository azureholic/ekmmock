using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Ekm;

namespace EkmMock.Cli.Conformance;

/// <summary>Section 14, "Inspector" tests 20 to 24 and "Latency and resilience" tests 25 to 27, observed through the console API and the EKM endpoint.</summary>
internal static class ObservabilityTests
{
    private static readonly TimeSpan VisibleWithin = TimeSpan.FromSeconds(1);

    public static IEnumerable<ConformanceCase> All()
    {
        yield return new("14.20.a", "14.20", "requests with 2xx, 400, 401, 404 and 405 appear in Live traffic within 1 s, with bodies", Visible);
        yield return new("14.20.b", "14.20", "a 429 and a 503 (fault-injected) appear in Live traffic within 1 s, with the fault badge", VisibleFaults);
        yield return new("14.21.a", "14.21", "a failed TLS handshake appears as a connection event with a reason", HandshakeFailureEvent);
        yield return new("14.22.a", "14.22", "DEK values are masked (length and fingerprint); wrap input and unwrap output fingerprints match", Masking);
        yield return new("14.23.a", "14.23", "revealing a DEK is refused unless the server allows it", RevealGate);
        yield return new("14.24.a", "14.24", "the inspector adds less than 1 ms (p99) and drops the oldest entries when full", InspectorOverhead);
        yield return new("14.25.a", "14.25", "local bench at concurrency 16 for 60 s meets the latency targets", Benchmark);
        yield return new("14.26.a", "14.26", "a 300 ms fault delay is seen by the client, is red with the fault badge and counts against the budget", DelayFault);
        yield return new("14.27.a", "14.27", "a request over the concurrency limit gets 429 immediately", ConcurrencyLimit);
    }

    // ---- 20 ----

    private static async Task Visible(ConformanceContext ctx, CancellationToken ct)
    {
        var console = ctx.RequireConsole("to read Live traffic");
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var seen = new List<string>();

        async Task CheckAsync(string label, Func<Task<EkmReply>> send, int status, bool tagged = true)
        {
            var before = await NewestIdAsync(console, ct).ConfigureAwait(false);
            var reply = await send().ConfigureAwait(false);
            Expect.That(reply.Status == status, $"{label}: expected HTTP {status}, got {Expect.Describe(reply)}");
            var exchange = await WaitForAsync(console, tagged ? $"?text={Uri.EscapeDataString(reply.CorrelationId)}&limit=10" : $"?after_id={before}&limit=100", e => e.Response.Status == status && (tagged || e.Request.Method == "GET"), VisibleWithin, ct).ConfigureAwait(false)
                ?? throw new TestFailure($"{label}: the exchange (HTTP {status}) did not appear in Live traffic within {VisibleWithin.TotalSeconds:0} s");
            Expect.That(exchange.Response.Body.Captured && exchange.Response.Body.SizeBytes > 0, $"{label}: the response body was not captured");
            if (tagged)
            {
                Expect.That(exchange.Request.Body.Captured && exchange.Request.Body.SizeBytes > 0 && !string.IsNullOrEmpty(exchange.Request.Body.Text), $"{label}: the request body was not captured");
            }

            seen.Add($"{status}");
        }

        await CheckAsync("info 200", () => ctx.Ekm.InfoAsync(ct), 200).ConfigureAwait(false);
        await CheckAsync("wrapkey 200", () => ctx.Ekm.WrapAsync(key.Name, "A256KWP", ctx.Random(32), ct), 200).ConfigureAwait(false);
        await CheckAsync("wrapkey 400 (bad algorithm)", () => ctx.Ekm.WrapAsync(key.Name, "NOT-AN-ALG", ctx.Random(32), ct), 400).ConfigureAwait(false);
        await CheckAsync("metadata 404 (unknown key)", () => ctx.Ekm.MetadataAsync(ctx.Name("missing"), ct), 404).ConfigureAwait(false);
        using (var anonymous = ctx.CreateVariantClient(identity: null))
        {
            await CheckAsync("info 401 (no client certificate)", () => anonymous.InfoAsync(ct), 401).ConfigureAwait(false);
        }

        await CheckAsync("GET 405 (wrong method)", () => ctx.Ekm.SendAsync(HttpMethod.Get, ctx.Ekm.Path(key.Name, "metadata"), json: null, cancellationToken: ct), 405, tagged: false).ConfigureAwait(false);
    }

    private static async Task VisibleFaults(ConformanceContext ctx, CancellationToken ct)
    {
        await ctx.RequireFaultsAsync(ct).ConfigureAwait(false);
        var console = ctx.Console!;
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);

        async Task CheckAsync(string label, FaultRuleBody rule, Func<Task<EkmReply>> send, int status)
        {
            var created = await console.CreateFaultAsync(rule, ct).ConfigureAwait(false);
            ctx.TrackFault(created.Id);
            EkmReply reply;
            try
            {
                reply = await send().ConfigureAwait(false);
            }
            finally
            {
                await ctx.RemoveFaultAsync(created.Id).ConfigureAwait(false);
            }

            Expect.That(reply.Status == status, $"{label}: expected HTTP {status}, got {Expect.Describe(reply)}");
            var exchange = await WaitForAsync(console, $"?text={Uri.EscapeDataString(reply.CorrelationId)}&limit=10", e => e.Response.Status == status, VisibleWithin, ct).ConfigureAwait(false)
                ?? throw new TestFailure($"{label}: the exchange (HTTP {status}) did not appear in Live traffic within 1 s");
            Expect.That(exchange.Faults is not null && exchange.Faults.Rule == created.Id, $"{label}: the exchange does not carry the fault badge of rule {created.Id}");
            Expect.That(exchange.Response.Body.Captured && exchange.Response.Body.SizeBytes > 0, $"{label}: the response body was not captured");
        }

        await CheckAsync("429 (fault: error rate 100%)", new FaultRuleBody("error", null, key.Name, null, null, null, null, 100, 429, "ekmmock conformance", 60), () => ctx.Ekm.MetadataAsync(key.Name, ct), 429).ConfigureAwait(false);
        await CheckAsync("503 (fault: HSM offline)", new FaultRuleBody("offline", null, null, null, null, null, null, null, null, "ekmmock conformance", 30), () => ctx.Ekm.InfoAsync(ct), 503).ConfigureAwait(false);
    }

    // ---- 21 ----

    private static async Task HandshakeFailureEvent(ConformanceContext ctx, CancellationToken ct)
    {
        var console = ctx.RequireConsole("to read the connection events");
        var known = (await console.ConnectionsAsync("?kind=handshake_failed&limit=200", ct).ConfigureAwait(false)).Select(static e => e.ConnectionId).ToHashSet();
        using (var tls12 = ctx.CreateVariantClient(ctx.Options.Client, SslProtocols.Tls12))
        {
            try
            {
                await tls12.InfoAsync(ct).ConfigureAwait(false);
            }
            catch (HttpRequestException)
            {
                // expected: the failed handshake is what the event records
            }
        }

        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < VisibleWithin + TimeSpan.FromSeconds(1))
        {
            var failures = await console.ConnectionsAsync("?kind=handshake_failed&limit=200", ct).ConfigureAwait(false);
            if (failures.FirstOrDefault(e => !known.Contains(e.ConnectionId)) is { } fresh)
            {
                Expect.That(!string.IsNullOrWhiteSpace(fresh.FailureReason), "the connection event of the failed handshake has no reason");
                return;
            }

            await Task.Delay(50, ct).ConfigureAwait(false);
        }

        throw new TestFailure("the failed TLS 1.2 handshake did not appear as a connection event (handshake_failed) within 2 s");
    }

    // ---- 22 ----

    private static async Task Masking(ConformanceContext ctx, CancellationToken ct)
    {
        var console = ctx.RequireConsole("to read the captured exchanges");
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var dek = ctx.Random(32);
        var wrap = await ctx.Ekm.WrapAsync(key.Name, "A256KWP", dek, ct).ConfigureAwait(false);
        var wrapped = Expect.Value(wrap, "wrap");
        var unwrap = await ctx.Ekm.UnwrapAsync(key.Name, "A256KWP", wrapped, ct).ConfigureAwait(false);
        Expect.That(Expect.Value(unwrap, "unwrap").AsSpan().SequenceEqual(dek), "unwrap did not return the DEK");

        var wrapExchange = await WaitForAsync(console, $"?text={Uri.EscapeDataString(wrap.CorrelationId)}&limit=10", static e => e.Response.Status == 200, VisibleWithin, ct).ConfigureAwait(false)
            ?? throw new TestFailure("the wrap exchange did not appear in Live traffic");
        var unwrapExchange = await WaitForAsync(console, $"?text={Uri.EscapeDataString(unwrap.CorrelationId)}&limit=10", static e => e.Response.Status == 200, VisibleWithin, ct).ConfigureAwait(false)
            ?? throw new TestFailure("the unwrap exchange did not appear in Live traffic");

        var expectedFingerprint = Convert.ToHexString(SHA256.HashData(dek))[..12];
        var requestValue = wrapExchange.Request.Body.MaskedFields?.FirstOrDefault(static f => f.Field.EndsWith("value", StringComparison.Ordinal))
            ?? throw new TestFailure("the wrap request's value is not shown as a masked field");
        var responseValue = unwrapExchange.Response.Body.MaskedFields?.FirstOrDefault(static f => f.Field.EndsWith("value", StringComparison.Ordinal))
            ?? throw new TestFailure("the unwrap response's value is not shown as a masked field");

        Expect.That(requestValue.Bytes == 32 && responseValue.Bytes == 32, "the masked fields do not show the DEK length (32 bytes)");
        Expect.That(string.Equals(requestValue.Fingerprint, expectedFingerprint, StringComparison.OrdinalIgnoreCase), "the wrap request's fingerprint is not the first 12 hex characters of the SHA-256 of the DEK");
        Expect.That(string.Equals(responseValue.Fingerprint, requestValue.Fingerprint, StringComparison.OrdinalIgnoreCase), "the fingerprints of the wrap input and the unwrap output differ");

        foreach (var (label, text) in new[] { ("wrap request", wrapExchange.Request.Body.Text), ("unwrap response", unwrapExchange.Response.Body.Text) })
        {
            foreach (var form in SecurityTests.LeakForms(dek))
            {
                Expect.That(text is null || !text.Contains(form.Value, form.Comparison), $"the captured {label} contains the DEK ({form.Name})");
            }
        }

        // The wrapped value is not secret and is shown.
        Expect.That(wrapExchange.Response.Body.Text?.Contains(EkmClient.Base64Url(wrapped), StringComparison.Ordinal) == true, "the wrapped value (not secret) is not shown in the wrap response");
    }

    // ---- 23 ----

    private static async Task RevealGate(ConformanceContext ctx, CancellationToken ct)
    {
        var console = ctx.RequireConsole("to ask the console to reveal a value");
        var status = await ctx.StatusAsync(ct).ConfigureAwait(false);
        if (status.RevealAllowed)
        {
            throw new SkipTest("reveal is switched on in this server (EKMMOCK_INSPECTOR_ALLOW_REVEAL=true): the 'impossible without the switch' half cannot be shown here; run against a default server");
        }

        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var wrap = await ctx.Ekm.WrapAsync(key.Name, "A256KWP", ctx.Random(32), ct).ConfigureAwait(false);
        Expect.Status(wrap, 200, "wrap");
        var exchange = await WaitForAsync(console, $"?text={Uri.EscapeDataString(wrap.CorrelationId)}&limit=10", static e => e.Response.Status == 200, VisibleWithin, ct).ConfigureAwait(false)
            ?? throw new TestFailure("the wrap exchange did not appear in Live traffic");

        // The reveal endpoint is a browser-style action: antiforgery cookie plus header.
        using var browserLike = ConsoleApiClient.Create(ctx.Options.Console!, ctx.Env, useCookies: true);
        var token = await browserLike.GetAsync("/api/console/antiforgery", ConsoleApiJson.Default.AntiforgeryTokenBody, ct).ConfigureAwait(false);
        var body = JsonSerializer.SerializeToUtf8Bytes(new RevealRequest("request.value"), ConsoleApiJson.Default.RevealRequest);
        var (statusCode, answer) = await browserLike.TryAsync(HttpMethod.Post, $"/api/console/exchanges/{exchange.Identity.ExchangeId}/reveal", body, ct, new Dictionary<string, string> { [token.HeaderName] = token.Token }).ConfigureAwait(false);

        Expect.That(statusCode == HttpStatusCode.Forbidden, $"revealing without EKMMOCK_INSPECTOR_ALLOW_REVEAL=true answered {(int)statusCode}, expected 403");
        Expect.That(Encoding.UTF8.GetString(answer).Contains("RevealDisabled", StringComparison.Ordinal), "the refusal does not carry the code RevealDisabled");
        foreach (var form in SecurityTests.LeakForms(ctx.Secrets[^1]))
        {
            Expect.That(!Encoding.UTF8.GetString(answer).Contains(form.Value, form.Comparison), "the refusal contains the DEK");
        }
    }

    private static Task InspectorOverhead(ConformanceContext ctx, CancellationToken ct)
        => throw new SkipTest("the capture overhead (p99 < 1 ms) and the drop-oldest behaviour are server-internal and measured by the server's own tests (InspectorOverheadBenchmarkTests, ExchangeRingBufferTests); from outside only the total latency is visible: use 'ekmmock test bench'");

    private static Task Benchmark(ConformanceContext ctx, CancellationToken ct)
        => throw new SkipTest("a 60 s load test is not part of the functional run: use 'ekmmock test bench --url ... --op unwrapkey --key aes-key-1 --alg A256KWP --concurrency 16 --duration 60s --assert-p99-ms 10'");

    // ---- 26 ----

    private static async Task DelayFault(ConformanceContext ctx, CancellationToken ct)
    {
        await ctx.RequireFaultsAsync(ct).ConfigureAwait(false);
        var console = ctx.Console!;
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var dek = ctx.Random(32);
        var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(key.Name, "A256KWP", dek, ct).ConfigureAwait(false), "wrap");
        var before = PrometheusText.Sum(await console.GetTextAsync("/metrics", ct).ConfigureAwait(false), "ekmmock_budget_exceeded_total", ("op", "unwrapkey"));

        var rule = await console.CreateFaultAsync(new FaultRuleBody("delay", null, key.Name, "unwrapkey", 300, null, null, null, null, "ekmmock conformance: distant HSM 300 ms", 60), ct).ConfigureAwait(false);
        ctx.TrackFault(rule.Id);
        EkmReply reply;
        try
        {
            reply = await ctx.Ekm.UnwrapAsync(key.Name, "A256KWP", wrapped, ct).ConfigureAwait(false);
        }
        finally
        {
            await ctx.RemoveFaultAsync(rule.Id).ConfigureAwait(false);
        }

        Expect.Status(reply, 200, "unwrap with a 300 ms delay (the request is still answered)");
        Expect.That(reply.Elapsed > TimeSpan.FromMilliseconds(250), $"the client saw {reply.Elapsed.TotalMilliseconds:0} ms, expected more than 250 ms");

        var exchange = await WaitForAsync(console, $"?text={Uri.EscapeDataString(reply.CorrelationId)}&limit=10", static e => e.Response.Status == 200, VisibleWithin, ct).ConfigureAwait(false)
            ?? throw new TestFailure("the delayed exchange did not appear in Live traffic");
        Expect.That(string.Equals(exchange.Timing.Budget, "Red", StringComparison.OrdinalIgnoreCase), $"the exchange is '{exchange.Timing.Budget}', expected Red (over 250 ms)");
        Expect.That(exchange.Faults is not null && exchange.Faults.Rule == rule.Id, "the exchange does not carry the fault badge of the delay rule");
        Expect.That(exchange.Timing.InjectedDelayMs >= 290, $"the exchange shows an injected delay of {exchange.Timing.InjectedDelayMs:0} ms, expected about 300");

        var after = PrometheusText.Sum(await console.GetTextAsync("/metrics", ct).ConfigureAwait(false), "ekmmock_budget_exceeded_total", ("op", "unwrapkey"));
        Expect.That(after > before, $"ekmmock_budget_exceeded_total{{op=\"unwrapkey\"}} did not increase ({before.ToString(CultureInfo.InvariantCulture)} to {after.ToString(CultureInfo.InvariantCulture)})");
    }

    // ---- 27 ----

    private static async Task ConcurrencyLimit(ConformanceContext ctx, CancellationToken ct)
    {
        if (!ctx.Options.AllowDisruptive)
        {
            throw new SkipTest("disruptive: it holds every concurrency slot of the server for a moment with blackholed requests; pass --allow-disruptive to run it (never against a server in use)");
        }

        await ctx.RequireFaultsAsync(ct).ConfigureAwait(false);
        var console = ctx.Console!;
        var about = await ctx.AboutAsync(ct).ConfigureAwait(false);
        var limit = about.Configuration.FirstOrDefault(static c => c.Name == "MaxConcurrency" && c.Section == "Limits")?.Value is { } text && int.TryParse(text, CultureInfo.InvariantCulture, out var parsed) ? parsed : 64;
        Expect.That(limit is >= 1 and <= 512, $"the concurrency limit is {limit}; the check holds at most 512 connections");

        var held = await ctx.CreateExtraKeyAsync("blackholed", isRsa: false, ct).ConfigureAwait(false);
        var other = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var dek = ctx.Random(32);
        var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(held.Name, "A256KWP", dek, ct).ConfigureAwait(false), "wrap");

        var rule = await console.CreateFaultAsync(new FaultRuleBody("blackhole", null, held.Name, "unwrapkey", null, null, null, null, null, "ekmmock conformance: hold the concurrency slots", 60), ct).ConfigureAwait(false);
        ctx.TrackFault(rule.Id);
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var holder = ctx.CreateVariantClient(ctx.Options.Client, maxConnections: limit + 2, timeout: TimeSpan.FromMinutes(2));
        var hung = new List<Task>();
        try
        {
            for (var i = 0; i < limit; i++)
            {
                hung.Add(Task.Run(async () =>
                {
                    try
                    {
                        await holder.UnwrapAsync(held.Name, "A256KWP", wrapped, cancel.Token).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is OperationCanceledException or HttpRequestException)
                    {
                        // The request was held until the check cancelled it.
                    }
                }, CancellationToken.None));
            }

            // Wait until the server really holds all slots.
            var waited = Stopwatch.StartNew();
            double inFlight = 0;
            while (waited.Elapsed < TimeSpan.FromSeconds(20))
            {
                inFlight = PrometheusText.Sum(await console.GetTextAsync("/metrics", ct).ConfigureAwait(false), "ekmmock_inflight_requests");
                if (inFlight >= limit)
                {
                    break;
                }

                await Task.Delay(100, ct).ConfigureAwait(false);
            }

            Expect.That(inFlight >= limit, $"only {inFlight:0} of {limit} requests were in flight after 20 s; the limit could not be reached");
            var over = await ctx.Ekm.MetadataAsync(other.Name, ct).ConfigureAwait(false);
            Expect.ProxyError(over, 429, "TooManyRequests", "a request over the concurrency limit");
            Expect.That(over.Elapsed < TimeSpan.FromMilliseconds(250), $"the 429 took {over.Elapsed.TotalMilliseconds:0} ms; it must be immediate (under 250 ms)");
        }
        finally
        {
            await cancel.CancelAsync().ConfigureAwait(false);
            await Task.WhenAll(hung).ConfigureAwait(false);
            await ctx.RemoveFaultAsync(rule.Id).ConfigureAwait(false);
        }

        // The slots are released when the clients give up.
        var recovered = false;
        for (var attempt = 0; attempt < 50 && !recovered; attempt++)
        {
            recovered = (await ctx.Ekm.MetadataAsync(other.Name, ct).ConfigureAwait(false)).Status == 200;
            if (!recovered)
            {
                await Task.Delay(100, ct).ConfigureAwait(false);
            }
        }

        Expect.That(recovered, "the server still answered 429 five seconds after the held requests were cancelled: the slots were not released");
    }

    // ---- helpers ----

    private static async Task<long> NewestIdAsync(ConsoleApiClient console, CancellationToken ct)
    {
        var page = await console.ExchangesAsync("?limit=1", ct).ConfigureAwait(false);
        return page.Items.Count == 0 ? 0 : page.Items.Max(static e => e.Identity.ExchangeId);
    }

    /// <summary>Polls Live traffic until an exchange matching <paramref name="predicate"/> shows up or <paramref name="within"/> has passed.</summary>
    private static async Task<ExchangeView?> WaitForAsync(ConsoleApiClient console, string query, Func<ExchangeView, bool> predicate, TimeSpan within, CancellationToken ct)
    {
        var watch = Stopwatch.StartNew();
        while (true)
        {
            var page = await console.ExchangesAsync(query, ct).ConfigureAwait(false);
            if (page.Items.FirstOrDefault(predicate) is { } found)
            {
                return found;
            }

            if (watch.Elapsed >= within)
            {
                return null;
            }

            await Task.Delay(40, ct).ConfigureAwait(false);
        }
    }
}

/// <summary>Reads numbers out of a Prometheus text exposition (the console's <c>/metrics</c>).</summary>
internal static class PrometheusText
{
    /// <summary>The sum of every sample of <paramref name="metric"/> whose labels include all of <paramref name="labels"/>.</summary>
    public static double Sum(string text, string metric, params (string Name, string Value)[] labels)
    {
        var total = 0d;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#' || !line.StartsWith(metric, StringComparison.Ordinal))
            {
                continue;
            }

            var rest = line[metric.Length..];
            if (rest.Length == 0 || (rest[0] != '{' && rest[0] != ' '))
            {
                continue; // another metric that merely starts with the same name
            }

            if (labels.Any(l => !line.Contains($"{l.Name}=\"{l.Value}\"", StringComparison.Ordinal)))
            {
                continue;
            }

            var space = line.LastIndexOf(' ');
            if (space > 0 && double.TryParse(line[(space + 1)..], NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
            {
                total += value;
            }
        }

        return total;
    }
}
