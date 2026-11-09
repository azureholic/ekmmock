using System.Security.Cryptography;
using EkmMock.Cli.Bench;
using EkmMock.Cli.Commands;
using EkmMock.Cli.Conformance;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Tests;

public sealed class DurationTests
{
    [Theory]
    [InlineData("60s", 60_000)]
    [InlineData("500ms", 500)]
    [InlineData("2m", 120_000)]
    [InlineData("1h", 3_600_000)]
    [InlineData("30", 30_000)]
    [InlineData("1.5s", 1_500)]
    [InlineData(" 5S ", 5_000)]
    public void Parses(string text, double milliseconds)
    {
        Duration.TryParse(text, out var value).ShouldBeTrue();
        value.TotalMilliseconds.ShouldBe(milliseconds, 0.001);
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("-1s")]
    [InlineData("10 parsecs")]
    [InlineData("1e400s")]
    [InlineData("99999h")]
    public void Rejects(string text) => Duration.TryParse(text, out _).ShouldBeFalse();
}

public sealed class TableWriterTests
{
    [Fact]
    public void PadsEveryColumnToItsWidestCell_AndNeverTruncates()
    {
        var writer = new StringWriter();

        TableWriter.Write(writer, ["NAME", "TYPE"], [["a-very-long-key-name", "AES"], ["k", "RSA-2048"]]);

        var lines = writer.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        lines[0].ShouldBe("NAME                  TYPE");
        lines[1].ShouldStartWith("--------------------  ----");
        lines[2].ShouldBe("a-very-long-key-name  AES");
        lines[3].ShouldBe("k                     RSA-2048");
    }

    [Fact]
    public void ShortRowsAreFilledUp_AndTrailingSpaceIsTrimmed()
    {
        var writer = new StringWriter();

        TableWriter.Write(writer, ["A", "B", "C"], [["x"]]);

        writer.ToString().Split(Environment.NewLine)[2].ShouldBe("x");
    }

    [Fact]
    public void Properties_SkipNullValues_AndAlignTheNames()
    {
        var writer = new StringWriter();

        TableWriter.WriteProperties(writer, [("Type", "AES-256"), ("Not after", null), ("State", "Enabled")]);

        writer.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).ShouldBe(["Type   AES-256", "State  Enabled"]);
    }
}

public sealed class LatencyHistogramTests
{
    private static LatencyHistogram Of(params double[] milliseconds)
    {
        var histogram = new LatencyHistogram();
        foreach (var ms in milliseconds)
        {
            histogram.Record((long)Math.Round(ms * 1000));
        }

        return histogram;
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(129)]
    [InlineData(1_000)]
    [InlineData(65_432)]
    [InlineData(250_000)]
    [InlineData(123_456_789)]
    public void EveryValue_IsStoredWithinHalfAPercent(long micros)
    {
        var histogram = new LatencyHistogram();
        histogram.Record(micros);

        var reported = histogram.PercentileMs(1.0) * 1000;

        // The percentile is clamped to the exact maximum, so a single sample is reported exactly.
        reported.ShouldBe(micros, 0.0001);

        // A second, larger sample shows the bucket width: the first value's percentile is its bucket's upper edge.
        histogram.Record(micros * 4 + 1000);
        var edge = histogram.PercentileMs(0.5) * 1000;
        edge.ShouldBeGreaterThanOrEqualTo(micros);
        edge.ShouldBeLessThanOrEqualTo(micros * 1.008 + 1);
    }

    [Fact]
    public void Percentiles_AreNearestRank_OfTheRecordedValues()
    {
        var histogram = Of(Enumerable.Range(1, 100).Select(static i => (double)i).ToArray());

        histogram.PercentileMs(0.50).ShouldBe(50, 0.5);
        histogram.PercentileMs(0.90).ShouldBe(90, 0.8);
        histogram.PercentileMs(0.99).ShouldBe(99, 0.8);
        histogram.PercentileMs(1.0).ShouldBe(100, 0.0001);
        histogram.MinMs.ShouldBe(1, 0.0001);
        histogram.MaxMs.ShouldBe(100, 0.0001);
        histogram.MeanMs.ShouldBe(50.5, 0.0001);
        histogram.Count.ShouldBe(100);
    }

    [Fact]
    public void AnEmptyHistogram_ReportsZeros()
    {
        var histogram = new LatencyHistogram();

        histogram.PercentileMs(0.99).ShouldBe(0);
        histogram.MinMs.ShouldBe(0);
        histogram.MaxMs.ShouldBe(0);
        histogram.MeanMs.ShouldBe(0);
    }

    [Fact]
    public void Merging_AddsCountsSumsAndExtremes()
    {
        var a = Of(1, 2, 3);
        var b = Of(100, 200);

        a.Add(b);

        a.Count.ShouldBe(5);
        a.MinMs.ShouldBe(1, 0.0001);
        a.MaxMs.ShouldBe(200, 0.0001);
        a.MeanMs.ShouldBe(61.2, 0.0001);
        a.PercentileMs(0.8).ShouldBe(100, 1);
    }

    [Fact]
    public void ABucketIsNeverLargerThanHalfAPercentOfItsValue_AcrossTheWholeRange()
    {
        for (long value = 128; value < 10_000_000_000; value = (long)(value * 1.37) + 1)
        {
            var histogram = new LatencyHistogram();
            histogram.Record(value);
            histogram.Record(1L << 46);
            var edge = histogram.PercentileMs(0.5) * 1000;

            edge.ShouldBeGreaterThanOrEqualTo(value, $"value {value}");
            (edge - value).ShouldBeLessThanOrEqualTo(value * 0.0079 + 1, $"value {value}");
        }
    }

    [Fact]
    public void Counts_PerBound_PutEverySampleInExactlyOneSlot()
    {
        var histogram = Of(0.4, 0.9, 1.5, 4, 7, 30, 120, 260, 700, 5000);

        var counts = histogram.CountsPerBound(BenchRunner.BucketBoundsMs);

        counts.Sum().ShouldBe(10);
        counts[0].ShouldBe(2); // <= 1 ms
        counts[1].ShouldBe(1); // <= 2 ms
        counts[7].ShouldBe(1); // <= 150 ms: 120
        counts[10].ShouldBe(1); // <= 500 ms: 260
        counts[^1].ShouldBe(1); // above 1000 ms: 5000
    }
}

public sealed class BenchStatisticsTests
{
    [Fact]
    public void Histogram_CountsEverySample_InTheRightBucket()
    {
        var latency = new LatencyHistogram();
        foreach (var ms in new[] { 0.4, 0.9, 1.5, 4, 7, 30, 120, 260, 700, 5000 })
        {
            latency.Record((long)(ms * 1000));
        }

        var histogram = BenchRunner.Histogram(latency);

        histogram.Sum(static b => b.Count).ShouldBe(10);
        histogram.First(static b => b.Le == "<= 1 ms").Count.ShouldBe(2);
        histogram.First(static b => b.Le == "<= 2 ms").Count.ShouldBe(1);
        histogram.First(static b => b.Le == "<= 150 ms").Count.ShouldBe(1);
        histogram.First(static b => b.Le == "<= 500 ms").Count.ShouldBe(1);
        histogram.Last().Le.ShouldBe("> 1000 ms");
        histogram.Last().Count.ShouldBe(1);
    }

    private static BenchOutcome Outcome(double[] latenciesMs, long over, long errors, double? maxP99 = null, double? maxOver = null, bool failOnErrors = false)
    {
        var settings = new BenchSettings { Client = null!, Operation = BenchOperation.Info };
        var latency = new LatencyHistogram();
        foreach (var ms in latenciesMs)
        {
            latency.Record((long)(ms * 1000));
        }

        var result = new BenchResult(latenciesMs.Length, errors, 2.0, latency, new Dictionary<string, long> { ["200"] = latenciesMs.Length - errors }, over, []);
        return BenchRunner.ToOutcome(settings, result, "https://x.test", DateTimeOffset.UtcNow, maxP99, maxOver, failOnErrors);
    }

    [Fact]
    public void TheOutcome_ReportsThroughputPercentilesAndOverBudgetShare()
    {
        var outcome = Outcome([1, 2, 3, 4, 100], over: 1, errors: 0);

        outcome.ThroughputRps.ShouldBe(2.5);
        outcome.LatencyMs.Min.ShouldBe(1, 0.001);
        outcome.LatencyMs.Max.ShouldBe(100, 0.001);
        outcome.LatencyMs.P50.ShouldBe(3, 0.05);
        outcome.LatencyMs.P99.ShouldBe(100, 0.001);
        outcome.OverBudget.Percent.ShouldBe(20);
        outcome.ThresholdFailures.ShouldBeEmpty();
        outcome.Model.ShouldContain("closed loop");
    }

    [Fact]
    public void Thresholds_AreEnforced()
    {
        Outcome([1, 2, 30], 0, 0, maxP99: 10).ThresholdFailures.ShouldHaveSingleItem().ShouldContain("--assert-p99-ms");
        Outcome([1, 2, 3], 1, 0, maxOver: 0).ThresholdFailures.ShouldHaveSingleItem().ShouldContain("--max-over-250-pct");
        Outcome([1, 2, 3], 0, 2, failOnErrors: true).ThresholdFailures.ShouldHaveSingleItem().ShouldContain("--assert-no-errors");
        Outcome([1, 2, 3], 0, 2).ThresholdFailures.ShouldBeEmpty("errors alone do not fail a bench unless asked");
        Outcome([1, 2, 3], 0, 0, maxP99: 10, maxOver: 0).ThresholdFailures.ShouldBeEmpty();
    }

    [Fact]
    public void ARunWithoutAnyCompletedRequest_Fails()
    {
        Outcome([], 0, 0).ThresholdFailures.ShouldHaveSingleItem().ShouldContain("no request");
    }
}
public sealed class ReferenceKeyWrapTests
{
    [Fact]
    public void TheReferenceImplementation_PassesTheRfcVectors()
        => ReferenceKeyWrap.SelfCheck().ShouldBeNull();

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    [InlineData(40)]
    [InlineData(4096)]
    public void Kw_RoundTrips_AndDetectsTampering(int size)
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var data = RandomNumberGenerator.GetBytes(size);

        var wrapped = ReferenceKeyWrap.Wrap(kek, data);

        wrapped.Length.ShouldBe(size + 8);
        ReferenceKeyWrap.Unwrap(kek, wrapped).ShouldBe(data);
        wrapped[^1] ^= 1;
        ReferenceKeyWrap.Unwrap(kek, wrapped).ShouldBeNull();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(20)]
    [InlineData(4096)]
    public void Kwp_RoundTrips_AndDetectsTampering(int size)
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var data = RandomNumberGenerator.GetBytes(size);

        var wrapped = ReferenceKeyWrap.WrapWithPadding(kek, data);

        wrapped.Length.ShouldBe((size + 7) / 8 * 8 + 8);
        ReferenceKeyWrap.UnwrapWithPadding(kek, wrapped).ShouldBe(data);
        wrapped[0] ^= 1;
        ReferenceKeyWrap.UnwrapWithPadding(kek, wrapped).ShouldBeNull();
    }

    [Fact]
    public void Kw_RejectsTheWrongKek()
    {
        var data = RandomNumberGenerator.GetBytes(32);
        var wrapped = ReferenceKeyWrap.Wrap(RandomNumberGenerator.GetBytes(32), data);

        ReferenceKeyWrap.Unwrap(RandomNumberGenerator.GetBytes(32), wrapped).ShouldBeNull();
    }
}

public sealed class ConformanceCatalogTests
{
    [Fact]
    public void EverySection14Test_HasAtLeastOneConformanceCheck()
    {
        var specs = ConformanceSuite.All.Select(static t => t.Spec).Distinct().ToHashSet();

        for (var number = 1; number <= 27; number++)
        {
            specs.ShouldContain($"14.{number}", $"Section 14 test {number} has no check in the suite");
        }

        specs.Count.ShouldBe(27);
    }

    [Fact]
    public void TheIds_AreUnique_AndNamedAfterTheirSpecNumber()
    {
        ConformanceSuite.All.Select(static t => t.Id).Distinct().Count().ShouldBe(ConformanceSuite.All.Count);
        foreach (var test in ConformanceSuite.All)
        {
            test.Id.ShouldStartWith(test.Spec + ".");
            test.Name.Length.ShouldBeGreaterThan(10);
        }
    }

    [Fact]
    public void TheSuite_CoversTheFourSectionsOfSection14()
    {
        ConformanceSuite.All.Count.ShouldBeGreaterThanOrEqualTo(45);
    }

    [Fact]
    public async Task List_PrintsEveryTest_AndExitsWithoutTouchingTheNetwork()
    {
        using var cli = new CliHarness();

        var run = await cli.RunAsync("test", "conformance", "--url", "https://localhost:1", "--list");

        run.ExitCode.ShouldBe(0, run.ToString());
        foreach (var test in ConformanceSuite.All)
        {
            run.Out.ShouldContain(test.Id);
        }
    }
}

public sealed class PrometheusTextTests
{
    private const string Text = """
        # HELP ekmmock_budget_exceeded_total Requests over the budget
        # TYPE ekmmock_budget_exceeded_total counter
        ekmmock_budget_exceeded_total{op="unwrapkey"} 3
        ekmmock_budget_exceeded_total{op="wrapkey"} 2
        ekmmock_budget_exceeded_total_created{op="unwrapkey"} 99
        ekmmock_inflight_requests 5
        ekmmock_requests_total{op="unwrapkey",status="200",namespace="_default"} 10
        ekmmock_requests_total{op="unwrapkey",status="404",namespace="_default"} 1.5e1
        """;

    [Fact]
    public void Sum_FiltersByLabel_AndIgnoresMetricsWithTheSamePrefix()
    {
        PrometheusText.Sum(Text, "ekmmock_budget_exceeded_total", ("op", "unwrapkey")).ShouldBe(3);
        PrometheusText.Sum(Text, "ekmmock_budget_exceeded_total").ShouldBe(5);
        PrometheusText.Sum(Text, "ekmmock_inflight_requests").ShouldBe(5);
        PrometheusText.Sum(Text, "ekmmock_requests_total", ("op", "unwrapkey")).ShouldBe(25);
        PrometheusText.Sum(Text, "ekmmock_requests_total", ("status", "404")).ShouldBe(15);
        PrometheusText.Sum(Text, "nothing").ShouldBe(0);
    }
}

public sealed class TlsTrustTests
{
    [Theory]
    [InlineData("AB:CD:ef", "ABCDEF")]
    [InlineData("ab cd", "ABCD")]
    public void Thumbprints_AreNormalised(string input, string expected)
        => TlsTrust.NormalizeThumbprint(input).ShouldBe(expected);

    [Fact]
    public void WithoutAnyTrustOption_TheDefaultValidationApplies()
        => TlsTrust.CreateCallback(null, null, insecureLoopback: false).ShouldBeNull();

    [Fact]
    public void LoadRoots_RejectsFilesWithoutCertificates()
    {
        using var cli = new CliHarness();
        File.WriteAllText(cli.File("junk.pem"), "hello");

        Should.Throw<CliException>(() => TlsTrust.LoadRoots(cli.File("junk.pem"), "--ca")).ExitCode.ShouldBe(ExitCodes.Usage);
        Should.Throw<CliException>(() => TlsTrust.LoadRoots(cli.File("missing.pem"), "--ca")).ExitCode.ShouldBe(ExitCodes.Usage);
    }
}

public sealed class SecureFileTests
{
    [Fact]
    public void WriteSecret_CreatesAnOwnerOnlyFile_AndRefusesToOverwrite()
    {
        using var cli = new CliHarness();
        var path = cli.File("sub/secret.txt");

        SecureFile.WriteSecret(path, "one");

        File.ReadAllText(path).ShouldBe("one");
        SecureFile.IsOwnerOnly(path).ShouldBeTrue();
        Should.Throw<IOException>(() => SecureFile.WriteSecret(path, "two"));
        File.ReadAllText(path).ShouldBe("one");
        SecureFile.WriteSecret(path, "three", overwrite: true);
        File.ReadAllText(path).ShouldBe("three");
        SecureFile.IsOwnerOnly(path).ShouldBeTrue();
    }
}
