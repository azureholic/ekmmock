#pragma warning disable xUnit1051 // The limits tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Diagnostics;
using System.Net;
using System.Text;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using EkmMock.Server.Faults;
using EkmMock.Server.Inspector;
using EkmMock.Server.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>Spec 10.1 and 14 test 27: the concurrency limit, the internal deadline, queue wait and the in-flight gauge.</summary>
public sealed class LimitsTests
{
    private const string Alg = "A256KWP";

    private static EkmFactory Create(int? maxConcurrency = null, int? deadlineMs = null, bool faults = true)
    {
        var configuration = new Dictionary<string, string?>();
        if (maxConcurrency is { } max)
        {
            configuration["Limits:MaxConcurrency"] = max.ToString();
        }

        if (deadlineMs is { } deadline)
        {
            configuration["Limits:InternalDeadlineMs"] = deadline.ToString();
        }

        return InspectorHarness.CreateFactory(faults: faults, configuration: configuration);
    }

    // ---- options ----

    [Fact]
    public void TheDefaults_AreTheSpecValues_AndTheOptionsAreValidated()
    {
        var defaults = new LimitsOptions();
        defaults.LatencyBudgetMs.ShouldBe(250);
        defaults.InternalDeadlineMs.ShouldBe(200);
        defaults.MaxConcurrency.ShouldBe(64);
        var validator = new InspectorOptionsValidator();
        validator.Validate(null, defaults).Succeeded.ShouldBeTrue();
        validator.Validate(null, new LimitsOptions { InternalDeadlineMs = 0 }).Failed.ShouldBeTrue();
        validator.Validate(null, new LimitsOptions { MaxConcurrency = 0 }).Failed.ShouldBeTrue();
        validator.Validate(null, new LimitsOptions { LatencyWarningMs = 300 }).Failed.ShouldBeTrue();
    }

    [Fact]
    public void TheOptions_CanBeConfigured()
    {
        using var factory = Create(maxConcurrency: 3, deadlineMs: 77);

        var limits = factory.Services.GetRequiredService<IOptions<LimitsOptions>>().Value;

        limits.MaxConcurrency.ShouldBe(3);
        limits.InternalDeadlineMs.ShouldBe(77);
        factory.Gate.Limit.ShouldBe(3);
    }

    // ---- the gate ----

    [Fact]
    public void TheGate_TakesSlotsUpToTheLimit_RefusesTheNextAtOnce_AndGivesSlotsBack()
    {
        var gate = new ConcurrencyGate(2);

        gate.TryEnter().ShouldBeTrue();
        gate.TryEnter().ShouldBeTrue();
        gate.TryEnter().ShouldBeFalse();
        gate.InFlight.ShouldBe(2, "a refused entry does not hold a slot");

        gate.Exit();
        gate.InFlight.ShouldBe(1);
        gate.TryEnter().ShouldBeTrue();
        gate.Exit();
        gate.Exit();
        gate.InFlight.ShouldBe(0);
    }

    [Fact]
    public async Task TheGate_NeverLetsMoreThanTheLimitIn_UnderContention()
    {
        var gate = new ConcurrencyGate(5);
        var peak = 0;
        var entered = 0L;
        var tasks = Enumerable.Range(0, 16).Select(_ => Task.Run(async () =>
        {
            for (var i = 0; i < 2000; i++)
            {
                if (!gate.TryEnter())
                {
                    continue;
                }

                Interlocked.Increment(ref entered);
                int seen;
                do
                {
                    seen = Volatile.Read(ref peak);
                }
                while (gate.InFlight > seen && Interlocked.CompareExchange(ref peak, gate.InFlight, seen) != seen);
                if (i % 50 == 0)
                {
                    await Task.Yield();
                }

                gate.Exit();
            }
        }));

        await Task.WhenAll(tasks);

        peak.ShouldBeLessThanOrEqualTo(5);
        entered.ShouldBeGreaterThan(0);
        gate.InFlight.ShouldBe(0);
    }

    // ---- 429 over the concurrency limit (spec 14 test 27) ----

    [Fact]
    public async Task OverTheConcurrencyLimit_TheAnswerIsAnImmediate429_AndSlotsComeBackWhenRequestsEnd()
    {
        using var factory = Create(maxConcurrency: 2);
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Blackhole, Scope = new FaultScope(Key: "pin")});
        factory.Keys.Create("_default", "pin", KeyType.Oct, 256);
        var ekm = factory.CreateEkmClient();

        // Warm up the 429 path (JIT, first-use costs) so that the measured answer is the steady-state one, with an injected 429 that uses the same error writer.
        var warm = factory.Faults.Create(new FaultSpec { Kind = FaultKind.Error, ErrorPercent = 100, StatusCode = 429 });
        (await ekm.InfoAsync()).StatusCode.ShouldBe(429);
        factory.Faults.Delete(warm.Id);
        (await ekm.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);

        using var release = new CancellationTokenSource();
        var pinned = Enumerable.Range(0, 2)
            .Select(_ => ekm.Http.PostAsync(EkmClient.Path(null, "pin", "metadata"), EkmClient.JsonBody(EkmClient.Context), release.Token))
            .ToList();
        (await Wait.UntilAsync(() => factory.Gate.InFlight == 2)).ShouldBeTrue("both slots are pinned by blackholed requests");

        var stopwatch = Stopwatch.StartNew();
        var rejected = await ekm.MetadataAsync("aes-key-1");
        stopwatch.Stop();

        rejected.ShouldBeProxyError(429, "TooManyRequests");
        stopwatch.Elapsed.ShouldBeLessThan(TimeSpan.FromMilliseconds(50), "over the limit is refused at once, not queued");
        factory.Gate.InFlight.ShouldBe(2, "the refused request holds no slot");

        release.Cancel();
        foreach (var task in pinned)
        {
            await Should.ThrowAsync<OperationCanceledException>(() => task);
        }

        (await Wait.UntilAsync(() => factory.Gate.InFlight == 0)).ShouldBeTrue("slots are released when the blackholed clients go away");
        (await ekm.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task ARejectedRequest_IsInTheMetrics_WithItsStatus_AndNothingElseIsCounted()
    {
        using var factory = Create(maxConcurrency: 1);
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Blackhole, Scope = new FaultScope(Key: "aes-key-1") });
        var ekm = factory.CreateEkmClient();
        using var release = new CancellationTokenSource();
        var pinned = ekm.Http.PostAsync(EkmClient.Path(null, "aes-key-1", "metadata"), EkmClient.JsonBody(EkmClient.Context), release.Token);
        (await Wait.UntilAsync(() => factory.Gate.InFlight == 1)).ShouldBeTrue();

        (await ekm.MetadataAsync("rsa-key-1")).StatusCode.ShouldBe(429);
        var text = PrometheusExposition.Render(factory.Metrics, factory.Gate.InFlight);

        text.ShouldContain("ekmmock_requests_total{op=\"metadata\",status=\"429\",namespace=\"_default\"} 1");
        text.ShouldContain("ekmmock_inflight_requests 1");
        release.Cancel();
        await Should.ThrowAsync<OperationCanceledException>(() => pinned);
    }

    [Fact]
    public async Task AFlood_NeverHasMoreInFlightThanTheLimit_EveryRequestIsAnsweredAndNoSlotLeaks()
    {
        const int limit = 4;
        using var factory = Create(maxConcurrency: limit);
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 30 });
        var ekm = factory.CreateEkmClient();
        var peak = 0;
        using var stop = new CancellationTokenSource();
        var sampler = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                peak = Math.Max(peak, factory.Gate.InFlight);
                await Task.Delay(1);
            }
        });

        var replies = await Task.WhenAll(Enumerable.Range(0, 120).Select(_ => ekm.MetadataAsync("aes-key-1")));
        await stop.CancelAsync();
        await sampler;

        replies.Select(static r => r.StatusCode).Distinct().Order().ShouldBe([200, 429]);
        replies.Count(static r => r.StatusCode == 200).ShouldBeGreaterThan(0);
        replies.Where(static r => r.StatusCode == 429).ShouldAllBe(static r => r.ErrorCode == "TooManyRequests");
        peak.ShouldBeLessThanOrEqualTo(limit);
        factory.Gate.InFlight.ShouldBe(0);
    }

    [Fact]
    public async Task RequestsThatFailInEveryWay_ReleaseTheirSlot()
    {
        using var factory = Create(maxConcurrency: 1);
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);

        for (var i = 0; i < 5; i++)
        {
            (await ekm.WrapAsync("no-such-key", Alg, dek)).StatusCode.ShouldBe(404);
            (await ekm.WrapRawAsync("aes-key-1", Alg, "not+base64")).StatusCode.ShouldBe(400);
            (await ekm.UnwrapAsync("aes-key-1", Alg, Fx.Random(40))).StatusCode.ShouldBe(400);
            (await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), "{not json")).StatusCode.ShouldBe(400);
            (await ekm.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);
        }

        factory.Gate.InFlight.ShouldBe(0);
    }

    // ---- the internal deadline ----

    [Fact]
    public async Task ACryptoCallThatEndsAfterTheDeadline_StillReturnsItsResult_AndIsCounted()
    {
        // The injected delay stands for a slow HSM: it is part of the crypto stage, so the deadline cannot cancel it (crypto is never cancelled once started).
        using var factory = Create(deadlineMs: 100);
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 250 });
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);

        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);

        wrapped.StatusCode.ShouldBe(200);
        Fx.Same((await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value())).Value(), dek).ShouldBeTrue();
        factory.Metrics.BudgetExceededCount(EkmOperation.WrapKey).ShouldBe(1);
        factory.Metrics.BudgetExceededCount(EkmOperation.UnwrapKey).ShouldBe(1, "the unwrap was delayed past the deadline too");
        factory.Metrics.BudgetExceededCount(EkmOperation.Info).ShouldBe(0);
    }

    [Fact]
    public async Task ARequestWithinTheDeadline_IsNotCounted()
    {
        using var factory = Create();
        var ekm = factory.CreateEkmClient();

        for (var i = 0; i < 10; i++)
        {
            await ekm.MetadataAsync("aes-key-1");
        }

        factory.Metrics.TotalBudgetExceeded.ShouldBe(0);
    }

    // ---- queue wait ----

    [Fact]
    public async Task AFastRequest_HasAQueueWaitOfAFewMillisecondsAtMost()
    {
        using var factory = Create();
        var ekm = factory.CreateEkmClient();
        for (var i = 0; i < 5; i++)
        {
            await ekm.InfoAsync();
        }

        var records = await InspectorHarness.SettleAsync(InspectorHarness.InspectorOf(factory), 5);

        records.Skip(1).ShouldAllBe(static r => r.Timing.QueueWaitMs < 100);
    }

    // ---- the pipeline order ----

    [Fact]
    public void ThePipelineOrder_IsRouteFaultsAuthLimits()
    {
        var source = File.ReadAllText(Path.Combine(RepoPaths.Src("EkmMock.Server"), "Ekm", "EkmPipeline.cs"));
        var route = source.IndexOf("UseMiddleware<EkmRouteMiddleware>", StringComparison.Ordinal);
        var faults = source.IndexOf("UseMiddleware<Faults.EkmFaultsMiddleware>", StringComparison.Ordinal);
        var auth = source.IndexOf("UseMiddleware<EkmAuthMiddleware>", StringComparison.Ordinal);
        var limits = source.IndexOf("UseMiddleware<EkmLimitsMiddleware>", StringComparison.Ordinal);

        route.ShouldBeGreaterThan(0);
        route.ShouldBeLessThan(faults);
        faults.ShouldBeLessThan(auth);
        auth.ShouldBeLessThan(limits);
    }
}
