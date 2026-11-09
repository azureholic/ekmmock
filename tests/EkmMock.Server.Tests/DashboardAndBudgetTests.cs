using EkmMock.Server.Inspector;

namespace EkmMock.Server.Tests;

/// <summary>Budget status (spec 8.1), the KQL snippet (spec 8.5) and the dashboard aggregates (spec 8.5).</summary>
public sealed class BudgetStatusTests
{
    [Theory]
    [InlineData(0, "Green")]
    [InlineData(149, "Green")]
    [InlineData(149.999, "Green")]
    [InlineData(150, "Amber")]
    [InlineData(200, "Amber")]
    [InlineData(250, "Amber")]
    [InlineData(250.001, "Red")]
    [InlineData(251, "Red")]
    [InlineData(5000, "Red")]
    public void Boundaries_AreGreenBelow150_AmberUpTo250_RedAbove(double milliseconds, string expected)
        => LatencyBudget.Classify(milliseconds, 150, 250).ToString().ShouldBe(expected);

    [Fact]
    public void TheThresholdsComeFromLimitsOptions_WithTheSpecDefaults()
    {
        var defaults = new LimitsOptions();
        defaults.LatencyBudgetMs.ShouldBe(250);
        defaults.LatencyWarningMs.ShouldBe(150);

        var custom = new LimitsOptions { LatencyWarningMs = 20, LatencyBudgetMs = 40 };
        LatencyBudget.Classify(TimeSpan.FromMilliseconds(19), custom).ShouldBe(BudgetStatus.Green);
        LatencyBudget.Classify(TimeSpan.FromMilliseconds(20), custom).ShouldBe(BudgetStatus.Amber);
        LatencyBudget.Classify(TimeSpan.FromMilliseconds(41), custom).ShouldBe(BudgetStatus.Red);
    }

    [Fact]
    public void LimitsOptions_AreValidatedAtStart()
    {
        new LimitsOptions().IsValid().ShouldBeTrue();
        new LimitsOptions { LatencyWarningMs = 300, LatencyBudgetMs = 250 }.IsValid().ShouldBeFalse();
        new LimitsOptions { LatencyWarningMs = -1 }.IsValid().ShouldBeFalse();
        new InspectorOptions().IsValid(out _).ShouldBeTrue();
        new InspectorOptions { RingBufferSize = 0 }.IsValid(out var error).ShouldBeFalse();
        error.ShouldContain("RingBufferSize");
    }
}

public sealed class KqlSnippetTests
{
    [Fact]
    public void ByCorrelationId_UsesTheDocumentedAzureDiagnosticsSchema()
    {
        var kql = KqlSnippets.ByCorrelationId("aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85", "wrapkey").ShouldNotBeNull();

        kql.ShouldContain("AzureDiagnostics");
        kql.ShouldContain("ResourceProvider == \"MICROSOFT.KEYVAULT\"");
        kql.ShouldContain("OperationName == \"EkmWrapKey\"");
        kql.ShouldContain("column_ifexists(\"correlationId_g\", \"\") == \"aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85\"");
        kql.ShouldContain("column_ifexists(\"CorrelationId\", \"\") == \"aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85\"");
        kql.ShouldContain("requestUri_s");
        kql.ShouldContain("ResultType");
        kql.ShouldContain("ResultDescription");
    }

    [Theory]
    [InlineData("info", "EkmGetProxyInfo")]
    [InlineData("metadata", "EkmGetKeyMetadata")]
    [InlineData("wrapkey", "EkmWrapKey")]
    [InlineData("unwrapkey", "EkmUnwrapKey")]
    public void EveryOperation_MapsToItsManagedHsmOperationName(string operation, string expected)
    {
        KqlSnippets.OperationNameFor(operation).ShouldBe(expected);
        KqlSnippets.ByCorrelationId("c", operation).ShouldNotBeNull().ShouldContain($"OperationName == \"{expected}\"");
    }

    [Fact]
    public void AnUnknownOperation_SearchesAllFourOperationNames()
    {
        var kql = KqlSnippets.ByCorrelationId("c", null).ShouldNotBeNull();

        KqlSnippets.OperationNameFor(null).ShouldBeNull();
        kql.ShouldContain("OperationName in (\"EkmGetProxyInfo\", \"EkmGetKeyMetadata\", \"EkmWrapKey\", \"EkmUnwrapKey\")");
    }

    [Fact]
    public void NoCorrelationId_GivesNoCorrelationQuery_ButTheFallbackExists()
    {
        KqlSnippets.ByCorrelationId(null).ShouldBeNull();
        KqlSnippets.ByCorrelationId("  ").ShouldBeNull();

        var record = Rec.Make(7, op: "unwrapkey", key: "aes-key-1", correlationId: null, at: new DateTimeOffset(2026, 11, 9, 12, 55, 40, TimeSpan.Zero));
        var snippet = KqlSnippets.For(record);

        snippet.ByCorrelationId.ShouldBeNull();
        snippet.Primary.ShouldBe(snippet.ByKeyAndTime);
        snippet.ByKeyAndTime.ShouldNotBeNull().ShouldContain("datetime(2026-11-09T12:55:40.0000000Z)");
        snippet.ByKeyAndTime.ShouldContain("TimeGenerated between ((exchangeTime - 1s) .. (exchangeTime + 1s))");
        snippet.ByKeyAndTime.ShouldContain("requestUri_s has \"aes-key-1\"");
        snippet.ByKeyAndTime.ShouldContain("OperationName == \"EkmUnwrapKey\"");
    }

    [Fact]
    public void ClientSuppliedText_CannotBreakOutOfTheStringLiteral()
    {
        var hostile = "x\" or 1==1 //\\\n| take 1";

        var kql = KqlSnippets.ByCorrelationId(hostile).ShouldNotBeNull();

        kql.ShouldContain("\"x\\\" or 1==1 //\\\\| take 1\"");
        kql.Split('\n').ShouldNotContain("| take 1"); // the newline in the input did not become a new pipeline stage
        KqlSnippets.Literal("a\"b\\c").ShouldBe("\"a\\\"b\\\\c\"");
    }

    [Fact]
    public void For_UsesTheCorrelationIdOfTheRecord_FirstAndTheFallbackSecond()
    {
        var snippet = KqlSnippets.For(Rec.Make(1, op: "wrapkey", correlationId: "abc"));

        snippet.Primary.ShouldBe(snippet.ByCorrelationId);
        snippet.ByCorrelationId.ShouldNotBeNull().ShouldContain("\"abc\"");
        snippet.ByKeyAndTime.ShouldNotBeNull();
    }
}

public sealed class DashboardAggregatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 9, 12, 30, 20, TimeSpan.Zero);

    private static (DashboardAggregator Aggregator, ManualTimeProvider Time) Create(int maxSamples = 4096)
    {
        var time = new ManualTimeProvider(Now);
        return (new DashboardAggregator(time, maxSamples), time);
    }

    private static ExchangeRecord At(TimeSpan ago, string? op, double ms, int status = 200, string? code = null, string? cn = "mhsm.a", long id = 0)
        => Rec.Make(id == 0 ? Random.Shared.NextInt64(1, long.MaxValue) : id, op: op, status: status, ms: ms, code: code, cn: cn, at: Now - ago);

    [Fact]
    public void Percentiles_AreNearestRank_OfTheObservedValues()
    {
        var (aggregator, _) = Create();
        for (var ms = 1; ms <= 100; ms++)
        {
            aggregator.Add(At(TimeSpan.FromSeconds(5), "unwrapkey", ms));
        }

        var stats = aggregator.Window(15).Operations.Single();

        stats.Operation.ShouldBe("unwrapkey");
        stats.Count.ShouldBe(100);
        stats.P50Ms.ShouldBe(50);
        stats.P95Ms.ShouldBe(95);
        stats.P99Ms.ShouldBe(99);
        stats.MaxMs.ShouldBe(100);
    }

    [Fact]
    public void Percentiles_OfASmallSample_AreObservedValues_NotInterpolations()
    {
        var (aggregator, _) = Create();
        foreach (var ms in new double[] { 10, 20, 30, 40 })
        {
            aggregator.Add(At(TimeSpan.Zero, "wrapkey", ms));
        }

        var stats = aggregator.Window(15).Operations.Single();

        stats.P50Ms.ShouldBe(20); // rank ceil(0.5 * 4) = 2
        stats.P95Ms.ShouldBe(40);
        stats.P99Ms.ShouldBe(40);
        Percentiles.NearestRank([], 99).ShouldBe(0);
        Percentiles.NearestRank([7.0], 1).ShouldBe(7);
    }

    [Fact]
    public void PerOperationStatistics_AreSeparate_AndSortedByName()
    {
        var (aggregator, _) = Create();
        aggregator.Add(At(TimeSpan.Zero, "wrapkey", 100));
        aggregator.Add(At(TimeSpan.Zero, "unwrapkey", 10));
        aggregator.Add(At(TimeSpan.Zero, "info", 1));
        aggregator.Add(At(TimeSpan.Zero, null, 2, 404, "NotFound"));

        var window = aggregator.Window(15);

        window.Operations.Select(static o => o.Operation).ShouldBe(["(unrouted)", "info", "unwrapkey", "wrapkey"]);
        window.Operations.Single(static o => o.Operation == "wrapkey").P50Ms.ShouldBe(100);
        window.Operations.Single(static o => o.Operation == "unwrapkey").P50Ms.ShouldBe(10);
    }

    [Fact]
    public void ShareOverBudget_IsTheRedShare_OfAllRequestsInTheWindow()
    {
        var (aggregator, _) = Create();
        for (var i = 0; i < 90; i++)
        {
            aggregator.Add(At(TimeSpan.Zero, "unwrapkey", 5));
        }

        for (var i = 0; i < 10; i++)
        {
            aggregator.Add(At(TimeSpan.Zero, "unwrapkey", 251));
        }

        aggregator.Add(At(TimeSpan.Zero, "unwrapkey", 250)); // exactly at the budget is amber, not over it

        var window = aggregator.Window(15);

        window.Total.ShouldBe(101);
        window.OverBudget.ShouldBe(10);
        window.OverBudgetShare.ShouldBe(10.0 / 101, 1e-9);
        window.Operations.Single().OverBudget.ShouldBe(10);
    }

    [Fact]
    public void ErrorsByCode_CountStatus400AndUp_WithAFallbackForAMissingCode()
    {
        var (aggregator, _) = Create();
        aggregator.Add(At(TimeSpan.Zero, "wrapkey", 5, 200));
        aggregator.Add(At(TimeSpan.Zero, "wrapkey", 5, 400, "InvalidRequest"));
        aggregator.Add(At(TimeSpan.Zero, "wrapkey", 5, 400, "InvalidRequest"));
        aggregator.Add(At(TimeSpan.Zero, "unwrapkey", 5, 401, "Unauthenticated"));
        aggregator.Add(Rec.Make(99, op: "info", status: 499, at: Now) with { Response = Rec.Make(99, status: 499).Response with { Code = null } });

        var window = aggregator.Window(15);

        window.Errors.ShouldBe(4);
        window.ErrorsByCode.ShouldBe(new Dictionary<string, long> { ["InvalidRequest"] = 2, ["Unauthenticated"] = 1, ["HTTP 499"] = 1 }, ignoreOrder: true);
        window.Operations.Single(static o => o.Operation == "wrapkey").Errors.ShouldBe(2);
    }

    [Fact]
    public void Windows_CoverTheLast15Minutes_AndTheLastHour()
    {
        var (aggregator, _) = Create();
        aggregator.Add(At(TimeSpan.FromMinutes(1), "wrapkey", 1)); // in both
        aggregator.Add(At(TimeSpan.FromMinutes(14), "wrapkey", 1)); // in both (current minute + 14 before)
        aggregator.Add(At(TimeSpan.FromMinutes(16), "wrapkey", 1)); // only the hour
        aggregator.Add(At(TimeSpan.FromMinutes(59), "wrapkey", 1)); // only the hour
        aggregator.Add(At(TimeSpan.FromMinutes(75), "wrapkey", 1)); // in neither

        var snapshot = aggregator.Snapshot(0);

        snapshot.Last15Minutes.Total.ShouldBe(2);
        snapshot.LastHour.Total.ShouldBe(4);
        snapshot.Last15Minutes.Minutes.ShouldBe(15);
        snapshot.LastHour.Minutes.ShouldBe(60);
        snapshot.ExchangesSinceStart.ShouldBe(5);
    }

    [Fact]
    public void RequestsPerMinute_ByOperation_OverTheLastHour()
    {
        var (aggregator, _) = Create();
        for (var i = 0; i < 3; i++)
        {
            aggregator.Add(At(TimeSpan.FromSeconds(1), "wrapkey", 1));
        }

        aggregator.Add(At(TimeSpan.FromSeconds(1), "info", 1));
        aggregator.Add(At(TimeSpan.FromMinutes(2), "wrapkey", 1));

        var points = aggregator.Snapshot(0).RequestsPerMinute;

        points.Count.ShouldBe(60);
        points[^1].MinuteStartUtc.ShouldBe(new DateTimeOffset(2026, 11, 9, 12, 30, 0, TimeSpan.Zero));
        points[^1].ByOperation.ShouldBe(new Dictionary<string, long> { ["wrapkey"] = 3, ["info"] = 1 }, ignoreOrder: true);
        points[^3].ByOperation.ShouldBe(new Dictionary<string, long> { ["wrapkey"] = 1 });
        points[0].ByOperation.ShouldBeEmpty();
    }

    [Fact]
    public void LatencyPerMinute_HasPercentilesPerOperationAndMinute()
    {
        var (aggregator, _) = Create();
        for (var ms = 1; ms <= 20; ms++)
        {
            aggregator.Add(At(TimeSpan.FromSeconds(1), "unwrapkey", ms));
            aggregator.Add(At(TimeSpan.FromMinutes(3), "unwrapkey", ms * 10));
        }

        var series = aggregator.Snapshot(0).LatencyPerMinute;

        series.Count.ShouldBe(2);
        series[0].Operation.ShouldBe("unwrapkey");
        series[0].P95Ms.ShouldBe(190);
        series[1].P95Ms.ShouldBe(19);
        series[1].MinuteStartUtc.ShouldBeGreaterThan(series[0].MinuteStartUtc);
    }

    [Fact]
    public void Heartbeat_ShowsTheLastInfoCall_WhoMadeIt_AndWhetherItIsStale()
    {
        var (aggregator, time) = Create();
        aggregator.Snapshot(0).Heartbeat.ShouldBe(new HeartbeatInfo(false, null, null, null, null, null, true));

        aggregator.Add(At(TimeSpan.FromSeconds(14), "info", 1, cn: "mhsm.pool.a"));
        aggregator.Add(At(TimeSpan.Zero, "wrapkey", 1, cn: "someone.else")); // not a heartbeat

        var fresh = aggregator.Snapshot(0).Heartbeat;
        fresh.EverSeen.ShouldBeTrue();
        fresh.LastInfoClientCommonName.ShouldBe("mhsm.pool.a");
        fresh.AgeSeconds.ShouldBe(14);
        fresh.IsStale.ShouldBeFalse();
        fresh.LastInfoStatus.ShouldBe(200);

        time.Advance(TimeSpan.FromSeconds(46));
        aggregator.Snapshot(0).Heartbeat.IsStale.ShouldBeFalse(); // 60 s old: not yet red ("red if > 60 s")
        time.Advance(TimeSpan.FromSeconds(1));
        var stale = aggregator.Snapshot(0).Heartbeat;
        stale.IsStale.ShouldBeTrue();
        stale.AgeSeconds.ShouldBe(61);
    }

    [Fact]
    public void Heartbeat_ARejectedProbe_StillCounts_ButTheLastSuccessIsKeptSeparately()
    {
        var (aggregator, _) = Create();
        aggregator.Add(At(TimeSpan.FromSeconds(30), "info", 1));
        aggregator.Add(At(TimeSpan.FromSeconds(5), "info", 1, 401, "Unauthenticated", cn: null));

        var heartbeat = aggregator.Snapshot(0).Heartbeat;

        heartbeat.LastInfoStatus.ShouldBe(401);
        heartbeat.AgeSeconds.ShouldBe(5);
        heartbeat.LastSuccessfulInfoAtUtc.ShouldBe(Now - TimeSpan.FromSeconds(30));
        heartbeat.IsStale.ShouldBeFalse();
    }

    [Fact]
    public void DroppedCaptures_AreReportedFromTheCaller()
        => Create().Aggregator.Snapshot(droppedCaptures: 42).DroppedCaptures.ShouldBe(42);

    [Fact]
    public void OldMinutes_AreForgotten_SoMemoryStaysBounded()
    {
        var (aggregator, _) = Create();
        for (var minute = 0; minute < 500; minute++)
        {
            aggregator.Add(Rec.Make(minute + 1, at: Now.AddMinutes(-499 + minute)));
        }

        aggregator.Window(500, Now).Total.ShouldBeLessThanOrEqualTo(63);
        aggregator.Window(60).Total.ShouldBe(60);
    }

    [Fact]
    public void TheSamplesPerMinute_AreBounded_ButCountsStayExact()
    {
        var (aggregator, _) = Create(maxSamples: 100);
        for (var i = 1; i <= 5000; i++)
        {
            aggregator.Add(At(TimeSpan.Zero, "unwrapkey", i % 100 + 1));
        }

        var stats = aggregator.Window(15).Operations.Single();

        stats.Count.ShouldBe(5000);
        stats.MaxMs.ShouldBe(100);
        stats.P50Ms.ShouldBeInRange(35, 65); // a uniform sample of 1..100: roughly the middle
    }

    [Fact]
    public async Task ParallelWritersAndReaders_NeverThrow()
    {
        var (aggregator, _) = Create();
        var stop = false;
        var readers = Enumerable.Range(0, 2).Select(_ => Task.Run(() =>
        {
            while (!Volatile.Read(ref stop))
            {
                aggregator.Snapshot(0);
            }
        })).ToArray();
        var writers = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < 5000; i++)
            {
                aggregator.Add(At(TimeSpan.FromSeconds(i % 3000), i % 3 == 0 ? "info" : "wrapkey", i % 300, i % 11 == 0 ? 500 : 200));
            }
        })).ToArray();

        await Task.WhenAll(writers);
        Volatile.Write(ref stop, true);
        await Task.WhenAll(readers);

        aggregator.Snapshot(0).ExchangesSinceStart.ShouldBe(20_000);
    }
}
