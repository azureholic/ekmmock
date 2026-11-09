using System.Diagnostics;
using System.Net;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using EkmMock.Server.Faults;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EkmMock.Server.Tests;

/// <summary>
/// Spec 10.2 and 14 tests 1 and 26, in the in-process host: what each fault kind does to a request, what the exchange record, the log line and the metrics say about it,
/// and that rules are scoped, expire and can be removed again without a restart. Blackhole and close-connection against a real listener are in <see cref="FaultInjectionRealHostTests"/>.
/// </summary>
public sealed class FaultInjectionTests
{
    private const string Alg = "A256KWP";

    private static EkmFactory Create(
        IFaultRandom? random = null,
        Dictionary<string, string?>? configuration = null,
        TimeProvider? clock = null,
        bool faults = true)
        => InspectorHarness.CreateFactory(
            faults: faults,
            faultRandom: random,
            configuration: configuration,
            configure: services =>
            {
                if (clock is not null)
                {
                    services.AddSingleton(clock);
                }
            });

    private static FaultSpec Delay(int ms, FaultScope? scope = null) => new() { Kind = FaultKind.Delay, DelayMs = ms, Scope = scope ?? FaultScope.Global };

    private static async Task<ExchangeRecord> LastRecordAsync(EkmFactory factory, int count)
        => (await InspectorHarness.SettleAsync(InspectorHarness.InspectorOf(factory), count))[count - 1];

    // ---- delay (spec 14 test 26) ----

    [Fact]
    public async Task ADelayOf300ms_IsSeenByTheClient_CountsAsBudgetExceeded_AndTheExchangeIsRedWithTheFaultBadge()
    {
        using var factory = Create();
        var rule = factory.Faults.Create(Delay(300));
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);

        var stopwatch = Stopwatch.StartNew();
        var reply = await ekm.WrapAsync("aes-key-1", Alg, dek);
        stopwatch.Stop();

        // The request is still answered (the delay stands for the distance to the HSM; it is not a queue), but it is slow, and it is accounted for as such.
        reply.StatusCode.ShouldBe(200);
        stopwatch.Elapsed.TotalMilliseconds.ShouldBeGreaterThan(250);
        factory.Metrics.BudgetExceededCount(EkmOperation.WrapKey).ShouldBe(1);

        var record = await LastRecordAsync(factory, 1);
        record.Timing.Budget.ShouldBe(BudgetStatus.Red);
        record.Timing.TotalMs.ShouldBeGreaterThan(250);
        record.Timing.InjectedDelayMs.ShouldBeInRange(280, 1500, "Task.Delay(300) may fire a few milliseconds early on Linux");
        record.Timing.CryptoMs.ShouldBeLessThan(100, "the delay is not crypto time");
        record.Timing.TotalMs.ShouldBeGreaterThanOrEqualTo(record.Timing.InjectedDelayMs + record.Timing.CryptoMs);
        record.Timing.QueueWaitMs.ShouldBeLessThan(200);
        record.Faults.ShouldNotBeNull();
        record.Faults.Rule.ShouldBe(rule.Id);
        record.Faults.Kind.ShouldBe("delay");
        record.Faults.Label.ShouldBe("delay 300 ms");
        record.Response.Status.ShouldBe(200);
        var unwrapped = await ekm.UnwrapAsync("aes-key-1", Alg, reply.Value());
        Fx.Same(dek, unwrapped.Value()).ShouldBeTrue("the delayed wrap is a real wrap");
    }

    [Fact]
    public async Task ADelayThatStaysWithinTheDeadline_IsNotBudgetExceeded_EvenWhenTheRequestIsSlow()
    {
        // ekmmock_budget_exceeded_total counts the internal deadline (spec 10.1), not the 250 ms colour: with the deadline at 5 s a 300 ms delay is red but not "exceeded".
        using var factory = Create(configuration: new() { ["Limits:InternalDeadlineMs"] = "5000" });
        factory.Faults.Create(Delay(300));

        (await factory.CreateEkmClient().WrapAsync("aes-key-1", Alg, Fx.Random(32))).StatusCode.ShouldBe(200);

        factory.Metrics.TotalBudgetExceeded.ShouldBe(0);
        (await LastRecordAsync(factory, 1)).Timing.Budget.ShouldBe(BudgetStatus.Red);
    }

    [Fact]
    public async Task TheDelay_DoesNotBlockAThread_OtherRequestsKeepBeingServedWhileManyAreDelayed()
    {
        using var factory = Create();
        factory.Faults.Create(Delay(600, new FaultScope(Key: "rsa-key-1")));
        var ekm = factory.CreateEkmClient();
        var delayed = Enumerable.Range(0, 40).Select(_ => ekm.MetadataAsync("rsa-key-1")).ToList();
        (await Wait.UntilAsync(() => factory.Gate.InFlight >= 40)).ShouldBeTrue("all delayed requests are waiting");

        var stopwatch = Stopwatch.StartNew();
        var fast = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => ekm.MetadataAsync("aes-key-1")));
        stopwatch.Stop();

        fast.ShouldAllBe(static r => r.StatusCode == 200);
        stopwatch.Elapsed.ShouldBeLessThan(TimeSpan.FromMilliseconds(500), "40 requests are waiting in Task.Delay and no thread is held by them");
        (await Task.WhenAll(delayed)).ShouldAllBe(static r => r.StatusCode == 200);
    }

    [Fact]
    public async Task ARule_AppliesOnlyToItsNamespaceKeyAndOperation()
    {
        using var factory = Create();
        factory.Namespaces.Add(new NamespaceDefinition { Name = "other", Prefix = "other" });
        factory.Keys.Create("other", "aes-key-1", KeyType.Oct, 256);
        factory.Faults.Create(Delay(120, new FaultScope("_default", "aes-key-1", EkmOperation.WrapKey)));
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);

        await ekm.WrapAsync("aes-key-1", Alg, dek);                     // in scope
        await ekm.UnwrapAsync("aes-key-1", Alg, Fx.Random(40));         // other op
        await ekm.WrapAsync("rsa-key-1", "RSA-OAEP-256", dek);          // other key
        await ekm.WrapAsync("aes-key-1", Alg, dek, prefix: "other");    // other namespace
        await ekm.InfoAsync();                                          // other op, no key

        var records = await InspectorHarness.SettleAsync(InspectorHarness.InspectorOf(factory), 5);
        records.Select(static r => r.Faults is not null).ShouldBe([true, false, false, false, false]);
        records[0].Timing.InjectedDelayMs.ShouldBeGreaterThan(100);
        records.Skip(1).ShouldAllBe(static r => r.Timing.InjectedDelayMs == 0);
    }

    [Fact]
    public async Task ADelayRange_UsesTheDice_AndRecordsTheRolledDelay()
    {
        using var factory = Create(random: new ScriptedFaultRandom(0.0, 0.9999));
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Delay, MinMs = 40, MaxMs = 140 });
        var ekm = factory.CreateEkmClient();

        await ekm.InfoAsync();
        await ekm.InfoAsync();

        var records = await InspectorHarness.SettleAsync(InspectorHarness.InspectorOf(factory), 2);
        records[0].Faults!.Label.ShouldBe("delay 40 ms");
        records[1].Faults!.Label.ShouldBe("delay 140 ms");
        records[0].Timing.InjectedDelayMs.ShouldBeInRange(30, 400);
        records[1].Timing.InjectedDelayMs.ShouldBeInRange(130, 700);
    }

    [Fact]
    public async Task ARuleThatHasExpired_NoLongerApplies()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero));
        using var factory = Create(clock: clock);
        factory.Faults.Create(Delay(150) with { ExpiresAfter = TimeSpan.FromMinutes(1) });
        var ekm = factory.CreateEkmClient();

        await ekm.InfoAsync();
        clock.Advance(TimeSpan.FromMinutes(2));
        await ekm.InfoAsync();

        var records = await InspectorHarness.SettleAsync(InspectorHarness.InspectorOf(factory), 2);
        records[0].Timing.InjectedDelayMs.ShouldBeGreaterThan(100);
        records[1].Timing.InjectedDelayMs.ShouldBe(0);
        records[1].Faults.ShouldBeNull();
    }

    [Fact]
    public async Task ADelayRule_CanBeRemovedAgain_WithoutARestart()
    {
        using var factory = Create();
        var rule = factory.Faults.Create(Delay(150));
        var ekm = factory.CreateEkmClient();
        await ekm.InfoAsync();

        factory.Faults.Delete(rule.Id);
        await ekm.InfoAsync();

        var records = await InspectorHarness.SettleAsync(InspectorHarness.InspectorOf(factory), 2);
        records[0].Faults.ShouldNotBeNull();
        records[1].Faults.ShouldBeNull();
        records[1].Timing.InjectedDelayMs.ShouldBe(0);
    }

    [Fact]
    public async Task AClientThatGivesUpDuringTheDelay_IsRecordedAsNoResponse_AndFreesItsSlot()
    {
        using var factory = Create();
        factory.Faults.Create(Delay(30_000));
        var ekm = factory.CreateEkmClient();
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        await Should.ThrowAsync<OperationCanceledException>(() => ekm.Http.PostAsync(EkmClient.Path(null, null, "info"), EkmClient.JsonBody(EkmClient.Context), cancel.Token));

        (await Wait.UntilAsync(() => factory.Gate.InFlight == 0)).ShouldBeTrue("the slot was released");
        var record = await LastRecordAsync(factory, 1);
        record.Response.Status.ShouldBe(499);
        record.Response.ClientAborted.ShouldBeTrue();
        record.Faults!.Kind.ShouldBe("delay");
    }

    // ---- error rate ----

    [Theory]
    [InlineData(429, "TooManyRequests")]
    [InlineData(500, "InternalError")]
    [InlineData(503, "HsmUnavailable")]
    public async Task AnErrorRuleAt100Percent_AnswersTheConfiguredStatusWithAProxyErrorBody(int status, string code)
    {
        using var factory = Create();
        var rule = factory.Faults.Create(new FaultSpec { Kind = FaultKind.Error, ErrorPercent = 100, StatusCode = status });
        var ekm = factory.CreateEkmClient();

        var reply = await ekm.WrapAsync("aes-key-1", Alg, Fx.Random(32));

        reply.ShouldBeProxyError(status, code);
        var record = await LastRecordAsync(factory, 1);
        record.Response.Status.ShouldBe(status);
        record.Response.Code.ShouldBe(code);
        record.Faults!.Rule.ShouldBe(rule.Id);
        record.Faults.Kind.ShouldBe("error");
        record.Faults.Label.ShouldBe($"error {status} (100 %)");
        record.Key.ShouldBeNull("the engine was never asked");
        record.Request.Body.MaskedFields.ShouldHaveSingleItem("the DEK in the request is masked even though the request failed");
    }

    [Fact]
    public async Task AnErrorRuleAt0Percent_NeverFires()
    {
        using var factory = Create();
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Error, ErrorPercent = 0, StatusCode = 503 });
        var ekm = factory.CreateEkmClient();

        for (var i = 0; i < 20; i++)
        {
            (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        }

        factory.Faults.List().Single().Fired.ShouldBe(0);
    }

    [Fact]
    public async Task AnErrorRuleAtFiftyPercent_WithScriptedDice_FailsEverySecondRequest()
    {
        using var factory = Create(random: new ScriptedFaultRandom(0.1, 0.9));
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Error, ErrorPercent = 50, StatusCode = 503 });
        var ekm = factory.CreateEkmClient();

        var statuses = new List<int>();
        for (var i = 0; i < 6; i++)
        {
            statuses.Add((await ekm.InfoAsync()).StatusCode);
        }

        statuses.ShouldBe([503, 200, 503, 200, 503, 200]);
        factory.Faults.List().Single().Fired.ShouldBe(3);
    }

    [Fact]
    public async Task AnErrorRuleAtFiftyPercent_WithASeed_GivesAStableRoughlyEvenSplit()
    {
        using var factory = Create(random: new ScriptedFaultRandom(2026));
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Error, ErrorPercent = 50, StatusCode = 500 });
        var ekm = factory.CreateEkmClient();

        var failures = 0;
        for (var i = 0; i < 200; i++)
        {
            failures += (await ekm.InfoAsync()).StatusCode == 500 ? 1 : 0;
        }

        failures.ShouldBeInRange(75, 125);
    }

    [Fact]
    public async Task AnInjectedError_IsNotAFailureOfTheServer_NoExceptionTypeIsLogged()
    {
        using var factory = Create();
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Error, ErrorPercent = 100, StatusCode = 500 });

        await factory.CreateEkmClient().InfoAsync();

        var line = factory.Logs.Entries.Single(static e => e.Category == "EkmMock.Exchange");
        line.Level.ShouldBe(LogLevel.Information);
        line.Fields["exception_type"].ShouldBeNull();
        line.Fields["status"].ShouldBe(500);
        line.Fields["fault"].ShouldBe("f1:error");
    }

    // ---- HSM offline (spec 14 test 1) ----

    [Fact]
    public async Task HsmOffline_MakesInfoAndEveryOperationAnswer503_AndSwitchingItOffRestoresServiceWithoutARestart()
    {
        using var factory = Create();
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);
        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);

        var rule = factory.Faults.Create(new FaultSpec { Kind = FaultKind.HsmOffline });

        (await ekm.InfoAsync()).ShouldBeProxyError(503, "HsmUnavailable");
        (await ekm.MetadataAsync("aes-key-1")).ShouldBeProxyError(503, "HsmUnavailable");
        (await ekm.WrapAsync("aes-key-1", Alg, dek)).ShouldBeProxyError(503, "HsmUnavailable");
        (await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value())).ShouldBeProxyError(503, "HsmUnavailable");
        factory.Services.GetRequiredService<IEngineAvailability>().IsAvailable.ShouldBeFalse("the seam of spec 4.6 reflects the fault");

        factory.Faults.SetEnabled(rule.Id, false);

        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        Fx.Same((await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value())).Value(), dek).ShouldBeTrue();
        factory.Services.GetRequiredService<IEngineAvailability>().IsAvailable.ShouldBeTrue();

        var records = await InspectorHarness.SettleAsync(InspectorHarness.InspectorOf(factory), 8);
        records.Skip(2).Take(4).ShouldAllBe(static r => r.Faults != null && r.Faults.Kind == "offline" && r.Faults.Label == "HSM offline" && r.Response.Status == 503);
        records.Count(static r => r.Faults is null).ShouldBe(4);
    }

    // ---- key disabled (temporary) ----

    [Fact]
    public async Task KeyDisabled_Answers403OnWrapAndUnwrap_MetadataStays200_AndTheKeyStoreIsUntouched()
    {
        using var factory = Create();
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);
        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);
        var rule = factory.Faults.Create(new FaultSpec { Kind = FaultKind.KeyDisabled, Scope = new FaultScope(Key: "aes-key-1") });
        var metadata = await ekm.MetadataAsync("aes-key-1");
        var otherKey = await ekm.WrapAsync("rsa-key-1", "RSA-OAEP-256", dek); // a real wrap on another key changes its usage counters: do it before the snapshot
        factory.Backend.Flush();
        var before = File.ReadAllBytes(factory.Backend.KeyStorePath);

        var wrap = await ekm.WrapAsync("aes-key-1", Alg, dek);
        var unwrap = await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value());

        wrap.ShouldBeProxyError(403, "KeyDisabled");
        wrap.Text.ShouldContain("Operation WrapKey is not allowed on a disabled key");
        unwrap.ShouldBeProxyError(403, "KeyDisabled");
        metadata.StatusCode.ShouldBe(200);
        otherKey.StatusCode.ShouldBe(200);
        factory.Backend.Flush();
        File.ReadAllBytes(factory.Backend.KeyStorePath).ShouldBe(before, "the fault never touches the key store");
        factory.Keys.Get(new KeyRef("_default", "aes-key-1"))!.State.ShouldBe(KeyState.Enabled);

        var records = await InspectorHarness.SettleAsync(InspectorHarness.InspectorOf(factory), 5);
        records[3].Faults!.Rule.ShouldBe(rule.Id);
        records[3].Faults!.Kind.ShouldBe("key_disabled");
        records[1].Faults.ShouldBeNull("metadata is not affected, so the fault did not fire");
        records[2].Faults.ShouldBeNull();

        factory.Faults.Delete(rule.Id);
        (await ekm.WrapAsync("aes-key-1", Alg, dek)).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task KeyDisabled_StillAnswersLikeTheEngineForBadInputAndUnknownKeys()
    {
        using var factory = Create();
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.KeyDisabled });
        var ekm = factory.CreateEkmClient();

        (await ekm.WrapAsync("no-such-key", Alg, Fx.Random(32))).ShouldBeProxyError(404, "KeyNotFound");
        (await ekm.WrapRawAsync("aes-key-1", "A128KW", "AAAA")).ShouldBeProxyError(400, "UnsupportedAlgorithm");
        (await ekm.WrapRawAsync("aes-key-1", Alg, "not+base64")).ShouldBeProxyError(400, "InvalidRequest");
    }

    // ---- disabled mode ----

    [Fact]
    public async Task WithoutTheEnvironmentSwitch_NoRuleExists_AndTrafficIsUnaffected()
    {
        using var factory = Create(faults: false);

        Should.Throw<FaultStoreException>(() => factory.Faults.Create(Delay(500))).Failure.ShouldBe(FaultStoreFailure.Disabled);
        var stopwatch = Stopwatch.StartNew();
        var reply = await factory.CreateEkmClient().InfoAsync();
        stopwatch.Stop();

        reply.StatusCode.ShouldBe(200);
        stopwatch.Elapsed.TotalMilliseconds.ShouldBeLessThan(450);
        (await LastRecordAsync(factory, 1)).Faults.ShouldBeNull();
    }

    // ---- a fault that never acted is not recorded ----

    [Fact]
    public async Task ADelayOrKeyDisabledRule_ThatNeverActedOnARequest_IsNotRecordedOrCounted()
    {
        using var factory = Create();
        var delay = factory.Faults.Create(Delay(150));
        var disabled = factory.Faults.Create(new FaultSpec { Kind = FaultKind.KeyDisabled, Scope = new FaultScope(Key: "no-such-key") });
        var ekm = factory.CreateEkmClient();

        // Rejected by the request validation (no request_context) before the delay point: not delayed, not flagged.
        (await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "metadata"), "{}")).StatusCode.ShouldBe(400);
        // An unknown key: the key-disabled rule answers like the engine (404) and has not acted either.
        (await ekm.WrapAsync("no-such-key", Alg, Fx.Random(32))).ShouldBeProxyError(404, "KeyNotFound");

        var records = await InspectorHarness.SettleAsync(InspectorHarness.InspectorOf(factory), 2);
        records[0].Faults.ShouldBeNull();
        records[0].Timing.InjectedDelayMs.ShouldBe(0);
        // The more specific key-disabled rule was chosen for the unknown key (and so shadowed the delay); it did not act, so nothing is recorded and nothing is delayed.
        records[1].Faults.ShouldBeNull();
        records[1].Timing.InjectedDelayMs.ShouldBe(0);
        factory.Faults.Get(delay.Id)!.Fired.ShouldBe(0);
        factory.Faults.Get(disabled.Id)!.Fired.ShouldBe(0);

        // A request that does reach the crypto stage is delayed, flagged and counted.
        (await ekm.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);
        (await InspectorHarness.SettleAsync(InspectorHarness.InspectorOf(factory), 3))[2].Faults!.Kind.ShouldBe("delay");
        factory.Faults.Get(delay.Id)!.Fired.ShouldBe(1);
    }

    // ---- the log line ----

    [Fact]
    public async Task TheLogLine_ShowsTheInjectedDelayAndTheFault_AndNeverTheDescription()
    {
        using var factory = Create();
        factory.Faults.Create(Delay(170) with { Description = "client-visible-secret-looking-text" });

        await factory.CreateEkmClient().InfoAsync();

        var line = factory.Logs.Entries.Single(static e => e.Category == "EkmMock.Exchange");
        ((double)line.Fields["injected_delay_ms"]!).ShouldBeInRange(150, 1500);
        line.Fields["fault"].ShouldBe("f1:delay");
        line.Level.ShouldNotBe(LogLevel.Information, "170+ ms is above the 150 ms warning threshold of spec 9 (Warning, or Error on a machine so loaded that it ran past 250 ms; the exact boundaries are pinned by LevelFor tests)");
        factory.Logs.AllText.ShouldNotContain("client-visible-secret-looking-text");
    }

    [Fact]
    public async Task ABlackholeScopedElsewhere_DoesNotTouchOtherTraffic_AndHealthyRequestsAreNotFlagged()
    {
        using var factory = Create();
        factory.Faults.Create(new FaultSpec { Kind = FaultKind.Blackhole, Scope = new FaultScope(Key: "some-other-key") });

        var reply = await factory.CreateEkmClient().MetadataAsync("aes-key-1");

        reply.StatusCode.ShouldBe(200);
        (await LastRecordAsync(factory, 1)).Faults.ShouldBeNull();
        factory.Gate.InFlight.ShouldBe(0);
        ((HttpStatusCode)reply.StatusCode).ShouldBe(HttpStatusCode.OK);
    }
}
