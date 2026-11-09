using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using EkmMock.Server.Faults;

namespace EkmMock.Server.Tests;

/// <summary>Spec 10.2: rule storage, scoping, precedence, the dice and expiry, without any HTTP.</summary>
public sealed class FaultRuleStoreTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);

    private static EkmRoute Route(string ns = "_default", string? key = "aes-key-1", EkmOperation op = EkmOperation.WrapKey)
        => new(new NamespaceDefinition { Name = ns, Prefix = ns == "_default" ? string.Empty : ns }, op, op == EkmOperation.Info ? null : key);

    private static FaultRuleStore Store(IFaultRandom? random = null, bool enabled = true, TimeProvider? time = null)
        => new(new FixedFaultGate(enabled), time ?? new ManualTimeProvider(Start), random ?? new ScriptedFaultRandom(0.0));

    private static FaultSpec Delay(int ms, FaultScope? scope = null) => new() { Kind = FaultKind.Delay, DelayMs = ms, Scope = scope ?? FaultScope.Global };

    private static FaultSpec Error(double percent, int status = 503, FaultScope? scope = null) => new() { Kind = FaultKind.Error, ErrorPercent = percent, StatusCode = status, Scope = scope ?? FaultScope.Global };

    // ---- gate ----

    [Fact]
    public void WithoutTheGate_NoRuleCanBeCreated_AndNothingEverApplies()
    {
        using var store = Store(enabled: false);

        var failure = Should.Throw<FaultStoreException>(() => store.Create(Delay(100)));

        failure.Failure.ShouldBe(FaultStoreFailure.Disabled);
        store.Count.ShouldBe(0);
        store.Resolve(Route()).ShouldBeNull();
        store.IsHsmOffline.ShouldBeFalse();
        store.ActiveCount.ShouldBe(0);
        Should.Throw<FaultStoreException>(() => store.Clear()).Failure.ShouldBe(FaultStoreFailure.Disabled);
    }

    // ---- scope ----

    [Fact]
    public void ARule_AppliesOnlyWithinItsScope()
    {
        using var store = Store();
        store.Create(Delay(10, new FaultScope(Namespace: "contoso")));
        store.Create(Delay(20, new FaultScope(Key: "special")));
        store.Create(Delay(30, new FaultScope(Operation: EkmOperation.Info)));

        store.Resolve(Route("contoso", "any"))!.Delay.ShouldBe(TimeSpan.FromMilliseconds(10));
        store.Resolve(Route("_default", "special"))!.Delay.ShouldBe(TimeSpan.FromMilliseconds(20));
        store.Resolve(Route("_default", null, EkmOperation.Info))!.Delay.ShouldBe(TimeSpan.FromMilliseconds(30));
        store.Resolve(Route("_default", "other")).ShouldBeNull();
        store.Resolve(Route("Contoso", "any")).ShouldBeNull(); // names are case-sensitive on the wire
    }

    [Fact]
    public void AKeyScopedRule_NeverMatchesInfo_ButANamespaceScopedOneDoes()
    {
        using var store = Store();
        store.Create(Delay(10, new FaultScope(Key: "aes-key-1")));
        store.Resolve(Route("_default", null, EkmOperation.Info)).ShouldBeNull();

        store.Create(Delay(20, new FaultScope(Namespace: "_default")));
        store.Resolve(Route("_default", null, EkmOperation.Info))!.Delay.ShouldBe(TimeSpan.FromMilliseconds(20));
    }

    [Fact]
    public void KeyDisabled_OnlyAffectsWrapAndUnwrap_NeverMetadataOrInfo()
    {
        using var store = Store();
        store.Create(new FaultSpec { Kind = FaultKind.KeyDisabled });

        store.Resolve(Route(op: EkmOperation.WrapKey))!.Kind.ShouldBe(FaultKind.KeyDisabled);
        store.Resolve(Route(op: EkmOperation.UnwrapKey))!.Kind.ShouldBe(FaultKind.KeyDisabled);
        store.Resolve(Route(op: EkmOperation.Metadata)).ShouldBeNull();
        store.Resolve(Route(op: EkmOperation.Info)).ShouldBeNull();
    }

    // ---- precedence ----

    [Fact]
    public void TheMostSpecificScopeWins_KeyThenOperationThenNamespaceThenGlobal()
    {
        using var store = Store();
        store.Create(Delay(1)); // global
        store.Create(Delay(2, new FaultScope(Namespace: "_default")));
        store.Create(Delay(3, new FaultScope(Operation: EkmOperation.WrapKey)));
        store.Create(Delay(4, new FaultScope(Key: "aes-key-1")));

        store.Resolve(Route())!.Delay.ShouldBe(TimeSpan.FromMilliseconds(4), "key beats operation, namespace and global");
        store.Resolve(Route(key: "other"))!.Delay.ShouldBe(TimeSpan.FromMilliseconds(3), "operation beats namespace and global");
        store.Resolve(Route(key: "other", op: EkmOperation.UnwrapKey))!.Delay.ShouldBe(TimeSpan.FromMilliseconds(2), "namespace beats global");
        store.Resolve(Route("elsewhere", "other", EkmOperation.UnwrapKey))!.Delay.ShouldBe(TimeSpan.FromMilliseconds(1));
    }

    [Fact]
    public void WhenScopesAreEquallySpecific_TheOldestRuleWins()
    {
        using var store = Store();
        store.Create(Delay(11));
        store.Create(Delay(22));

        store.Resolve(Route())!.Delay.ShouldBe(TimeSpan.FromMilliseconds(11));
    }

    [Fact]
    public void HsmOffline_OverridesEverythingElse_AndIgnoresScope()
    {
        using var store = Store();
        store.Create(Delay(5, new FaultScope(Key: "aes-key-1")));
        store.Create(new FaultSpec { Kind = FaultKind.Blackhole, Scope = new FaultScope(Key: "aes-key-1") });
        store.Create(new FaultSpec { Kind = FaultKind.HsmOffline, Scope = new FaultScope(Key: "some-other-key") }); // a scope on offline is dropped: it is process wide

        var decision = store.Resolve(Route(key: "aes-key-1"));

        decision!.Kind.ShouldBe(FaultKind.HsmOffline);
        store.IsHsmOffline.ShouldBeTrue();
        store.List().Single(static e => e.Rule.Kind == FaultKind.HsmOffline).Rule.Scope.IsGlobal.ShouldBeTrue();
        store.Resolve(Route(op: EkmOperation.Info))!.Kind.ShouldBe(FaultKind.HsmOffline);
    }

    [Fact]
    public void AnErrorRuleThatMisses_LetsTheNextRuleHaveItsTurn()
    {
        var dice = new ScriptedFaultRandom(0.99, 0.01); // 99 % misses a 50 % rule, 1 % hits it
        using var store = Store(dice);
        store.Create(Error(50, scope: new FaultScope(Key: "aes-key-1")));
        store.Create(Delay(40));

        var miss = store.Resolve(Route());
        var hit = store.Resolve(Route());

        miss!.Kind.ShouldBe(FaultKind.Delay);
        hit!.Kind.ShouldBe(FaultKind.Error);
    }

    // ---- error rate ----

    [Fact]
    public void ErrorRate_ZeroNeverFires_HundredAlwaysFires_WhateverTheDice()
    {
        using var never = Store(new ScriptedFaultRandom(0.0));
        never.Create(Error(0));
        using var always = Store(new ScriptedFaultRandom(0.999999999));
        always.Create(Error(100));

        for (var i = 0; i < 50; i++)
        {
            never.Resolve(Route()).ShouldBeNull();
            always.Resolve(Route()).ShouldNotBeNull();
        }
    }

    [Fact]
    public void ErrorRate_FiftyPercent_WithASeed_IsDeterministicAndRoughlyHalf()
    {
        int Hits(int seed)
        {
            using var store = Store(new ScriptedFaultRandom(seed));
            store.Create(Error(50));
            return Enumerable.Range(0, 2000).Count(_ => store.Resolve(Route()) is not null);
        }

        var first = Hits(42);
        first.ShouldBe(Hits(42)); // same seed, same sequence
        first.ShouldBeInRange(900, 1100);
    }

    [Fact]
    public void TheFireCount_CountsOnlyRequestsTheRuleActedOn_NotTheOnesItWasChosenFor()
    {
        using var store = Store(new ScriptedFaultRandom(0.9, 0.1, 0.9, 0.1)); // 50 %: miss, hit, miss, hit
        var rule = store.Create(Error(50));

        for (var i = 0; i < 4; i++)
        {
            var decision = store.Resolve(Route());
            store.Get(rule.Id)!.Fired.ShouldBe(i / 2, "choosing a rule does not count; the stage that acts does");
            decision?.Counter.Increment();
        }

        store.Get(rule.Id)!.Fired.ShouldBe(2);
    }

    // ---- delay ----

    [Fact]
    public void ADelayRange_IsUniform_AndInclusiveOfBothEnds()
    {
        using var low = Store(new ScriptedFaultRandom(0.0));
        low.Create(new FaultSpec { Kind = FaultKind.Delay, MinMs = 50, MaxMs = 150 });
        using var high = Store(new ScriptedFaultRandom(0.9999999));
        high.Create(new FaultSpec { Kind = FaultKind.Delay, MinMs = 50, MaxMs = 150 });
        using var seeded = Store(new ScriptedFaultRandom(7));
        seeded.Create(new FaultSpec { Kind = FaultKind.Delay, MinMs = 50, MaxMs = 150 });

        low.Resolve(Route())!.Delay.ShouldBe(TimeSpan.FromMilliseconds(50));
        high.Resolve(Route())!.Delay.ShouldBe(TimeSpan.FromMilliseconds(150));
        var samples = Enumerable.Range(0, 500).Select(_ => seeded.Resolve(Route())!.Delay.TotalMilliseconds).ToList();
        samples.ShouldAllBe(static ms => ms >= 50 && ms <= 150);
        samples.Distinct().Count().ShouldBeGreaterThan(50);
    }

    [Fact]
    public void ADegenerateRange_IsAFixedDelay()
    {
        using var store = Store(new ScriptedFaultRandom(0.5));
        store.Create(new FaultSpec { Kind = FaultKind.Delay, MinMs = 80, MaxMs = 80 });

        store.Resolve(Route())!.Delay.ShouldBe(TimeSpan.FromMilliseconds(80));
    }

    // ---- enable, disable, edit, delete ----

    [Fact]
    public void ADisabledRule_DoesNotApply_AndCanBeEnabledAgain()
    {
        using var store = Store();
        var rule = store.Create(Delay(10));

        store.SetEnabled(rule.Id, false);
        store.Resolve(Route()).ShouldBeNull();
        store.ActiveCount.ShouldBe(0);

        store.SetEnabled(rule.Id, true);
        store.Resolve(Route()).ShouldNotBeNull();
        store.ActiveCount.ShouldBe(1);
    }

    [Fact]
    public void Update_ReplacesTheParameters_KeepsIdOrderAndFireCount()
    {
        using var store = Store();
        var first = store.Create(Delay(10));
        store.Create(Delay(99));
        store.Resolve(Route())!.Counter.Increment(); // a firing is counted by the stage that acts (FaultDecisions.Fire), not by the choice

        var changed = store.Update(first.Id, Delay(77));

        changed.Id.ShouldBe(first.Id);
        changed.Sequence.ShouldBe(first.Sequence);
        changed.CreatedAt.ShouldBe(first.CreatedAt);
        store.Get(first.Id)!.Fired.ShouldBe(1);
        store.Resolve(Route())!.Delay.ShouldBe(TimeSpan.FromMilliseconds(77), "still the oldest of two equally specific rules");
    }

    [Fact]
    public void Delete_Clear_AndUnknownIds()
    {
        using var store = Store();
        var a = store.Create(Delay(1));
        store.Create(Delay(2));

        store.Delete(a.Id);
        store.Count.ShouldBe(1);
        Should.Throw<FaultStoreException>(() => store.Delete(a.Id)).Failure.ShouldBe(FaultStoreFailure.NotFound);
        Should.Throw<FaultStoreException>(() => store.SetEnabled("f999", true)).Failure.ShouldBe(FaultStoreFailure.NotFound);
        Should.Throw<FaultStoreException>(() => store.Update("f999", Delay(1))).Failure.ShouldBe(FaultStoreFailure.NotFound);
        store.Clear().ShouldBe(1);
        store.Count.ShouldBe(0);
    }

    [Fact]
    public void TheNumberOfRules_IsBounded()
    {
        using var store = Store();
        for (var i = 0; i < FaultRuleStore.MaxRules; i++)
        {
            store.Create(Delay(1));
        }

        Should.Throw<FaultStoreException>(() => store.Create(Delay(1))).Failure.ShouldBe(FaultStoreFailure.TooManyRules);
    }

    [Fact]
    public void Ids_AreSequential_AndNeverReused()
    {
        using var store = Store();
        var a = store.Create(Delay(1));
        store.Delete(a.Id);
        var b = store.Create(Delay(1));

        a.Id.ShouldBe("f1");
        b.Id.ShouldBe("f2");
    }

    // ---- expiry ----

    [Fact]
    public void ARuleWithAnExpiry_StopsApplying_ButStaysListedAsExpired()
    {
        var clock = new ManualTimeProvider(Start);
        using var store = Store(time: clock);
        var rule = store.Create(Delay(10) with { ExpiresAfter = TimeSpan.FromMinutes(5) });
        rule.ExpiresAt.ShouldBe(Start.AddMinutes(5));

        clock.Advance(TimeSpan.FromMinutes(4) + TimeSpan.FromSeconds(59));
        store.Resolve(Route()).ShouldNotBeNull();
        store.ActiveCount.ShouldBe(1);

        clock.Advance(TimeSpan.FromSeconds(1));
        store.Resolve(Route()).ShouldBeNull();
        store.ActiveCount.ShouldBe(0);
        store.IsHsmOffline.ShouldBeFalse();
        store.List().Single().Rule.IsExpired(clock.GetUtcNow()).ShouldBeTrue();
    }

    [Fact]
    public void AnExpiredHsmOfflineRule_NoLongerMakesTheEngineUnavailable()
    {
        var clock = new ManualTimeProvider(Start);
        using var store = Store(time: clock);
        store.Create(new FaultSpec { Kind = FaultKind.HsmOffline, ExpiresAfter = TimeSpan.FromSeconds(30) });
        store.IsHsmOffline.ShouldBeTrue();

        clock.Advance(TimeSpan.FromSeconds(31));

        store.IsHsmOffline.ShouldBeFalse();
    }

    [Fact]
    public async Task WhenARuleExpires_TheChangeNotificationFires_SoTheBannerCanGoAway()
    {
        using var store = Store(time: TimeProvider.System);
        var changes = 0;
        store.Changed += () => Interlocked.Increment(ref changes);

        store.Create(Delay(10) with { ExpiresAfter = TimeSpan.FromMilliseconds(150) });
        var afterCreate = Volatile.Read(ref changes);

        (await Wait.UntilAsync(() => Volatile.Read(ref changes) > afterCreate, TimeSpan.FromSeconds(10))).ShouldBeTrue();
        store.ActiveCount.ShouldBe(0);
    }

    [Fact]
    public void ChangeNotifications_FireForEveryMutation_AndASubscriberThatThrowsBreaksNothing()
    {
        using var store = Store();
        var changes = 0;
        store.Changed += () => changes++;
        store.Changed += () => throw new InvalidOperationException("a closed circuit");

        var rule = store.Create(Delay(1));
        store.SetEnabled(rule.Id, false);
        store.Update(rule.Id, Delay(2));
        store.Delete(rule.Id);
        store.Clear();

        changes.ShouldBe(5);
    }

    // ---- descriptions ----

    [Fact]
    public void TheDescriptions_AreBuiltFromRuleParametersOnly()
    {
        using var store = Store(new ScriptedFaultRandom(0.0));
        var fixedDelay = store.Create(Delay(300));
        var range = store.Create(new FaultSpec { Kind = FaultKind.Delay, MinMs = 100, MaxMs = 200, Scope = new FaultScope("contoso", "k1", EkmOperation.WrapKey) });
        var error = store.Create(Error(12.5, 429));

        FaultDescriptions.Parameters(fixedDelay).ShouldBe("300 ms");
        FaultDescriptions.Parameters(range).ShouldBe("100-200 ms (uniform)");
        FaultDescriptions.Parameters(error).ShouldBe("12.5 % answer 429");
        range.Scope.ToString().ShouldBe("namespace contoso, key k1, op wrapkey");
        FaultScope.Global.ToString().ShouldBe("all requests");
        FaultDescriptions.AuditDetail(range).ShouldBe("delay 100-200 ms (uniform); namespace contoso, key k1, op wrapkey");
        FaultDescriptions.Describe(new FaultDecision(fixedDelay, TimeSpan.FromMilliseconds(300), new FaultCounter())).Label.ShouldBe("delay 300 ms");
        FaultDescriptions.Describe(new FaultDecision(error, TimeSpan.Zero, new FaultCounter())).Label.ShouldBe("error 429 (12.5 %)");
    }
}
