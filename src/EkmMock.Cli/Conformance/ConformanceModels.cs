using System.Text.Json.Serialization;

namespace EkmMock.Cli.Conformance;

/// <summary>The JSON report of <c>ekmmock test conformance</c> (<c>--report</c>). It holds results and environment facts only: no certificates, no tokens, no key or DEK material.</summary>
internal sealed record ConformanceReport(
    string Tool,
    string Version,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset FinishedAtUtc,
    double DurationMs,
    ReportTarget Target,
    ReportInputs Inputs,
    ReportEnvironment Environment,
    ReportSummary Summary,
    List<ReportTest> Tests,
    ReportCleanup Cleanup);

internal sealed record ReportTarget(string Url, string Prefix, string? Console);

/// <summary>Which optional inputs were supplied (the reason most tests are skipped when they are missing).</summary>
internal sealed record ReportInputs(bool Console, bool AltClientCertificate, bool RogueClientCertificate, bool AllowDisruptive, bool PersistenceState, bool CustomCaRoots);

internal sealed record ReportEnvironment(string Os, string Architecture, string Runtime, int ProcessorCount);

internal sealed record ReportSummary(int Total, int Passed, int Failed, int Skipped);

internal sealed record ReportTest(string Id, string Spec, string Name, string Status, double DurationMs, string? Message);

internal sealed record ReportCleanup(List<string> Destroyed, List<string> Leftover);

internal enum TestStatus
{
    Pass,
    Fail,
    Skip,
}

/// <summary>A conformance test: the identifier shows the Section 14 test it belongs to (<c>14.6.a</c> is test 6, check a).</summary>
internal sealed record ConformanceCase(string Id, string Spec, string Name, Func<ConformanceContext, CancellationToken, Task> Run);

/// <summary>The check failed. The message is shown and written to the report: never put secret material in it.</summary>
internal sealed class TestFailure : Exception
{
    public TestFailure(string message)
        : base(message)
    {
    }
}

/// <summary>The check cannot run with the inputs given (or against this server's configuration); the message says why and what to supply.</summary>
internal sealed class SkipTest : Exception
{
    public SkipTest(string reason)
        : base(reason)
    {
    }
}
