namespace EkmMock.Crypto;

public enum SelfTestOutcome
{
    Passed,
    Failed,

    /// <summary>Not run (for example a key that is already corrupt). Does not count as a failure.</summary>
    Skipped,
}

/// <summary>One self-test case. <see cref="Error"/> is a short fixed description, never key material.</summary>
public sealed record SelfTestCaseResult(string Name, SelfTestOutcome Outcome, TimeSpan Duration, string? Error);

public sealed record SelfTestOptions
{
    /// <summary>When set, a failed self-test means the host must refuse to start (<c>SelfTest:Strict=true</c>).</summary>
    public bool Strict { get; init; }
}

/// <summary>Structured self-test outcome for the console About page and the readiness probe.</summary>
public sealed record SelfTestResult(IReadOnlyList<SelfTestCaseResult> Cases, DateTimeOffset RanAt, bool Strict)
{
    public bool Passed => Cases.All(static c => c.Outcome != SelfTestOutcome.Failed);

    /// <summary>True when the host must not start accepting traffic (<see cref="Strict"/> and at least one failure).</summary>
    public bool RefuseToStart => Strict && !Passed;

    public IEnumerable<SelfTestCaseResult> Failures => Cases.Where(static c => c.Outcome == SelfTestOutcome.Failed);
}
