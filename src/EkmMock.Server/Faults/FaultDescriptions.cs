using System.Globalization;
using EkmMock.Server.Inspector;

namespace EkmMock.Server.Faults;

/// <summary>Words for fault rules: the badge in Live traffic, the table on the Faults page, the audit detail. Built from rule parameters only (never from a request).</summary>
internal static class FaultDescriptions
{
    /// <summary>The parameters of a rule in words: <c>300 ms</c>, <c>100-200 ms</c>, <c>50 % answer 503</c>, or empty for kinds without parameters.</summary>
    public static string Parameters(FaultRule rule) => rule.Kind switch
    {
        FaultKind.Delay when rule.DelayMs is { } fixedMs => $"{fixedMs.ToString(CultureInfo.InvariantCulture)} ms",
        FaultKind.Delay => $"{(rule.MinMs ?? 0).ToString(CultureInfo.InvariantCulture)}-{(rule.MaxMs ?? 0).ToString(CultureInfo.InvariantCulture)} ms (uniform)",
        FaultKind.Error => $"{Percent(rule.ErrorPercent)} % answer {rule.StatusCode.ToString(CultureInfo.InvariantCulture)}",
        _ => string.Empty,
    };

    /// <summary>What the badge and the detail say, for example <c>delay 300 ms</c>, <c>error 503 (50 %)</c>, <c>HSM offline</c>. For a delay it uses the delay that was rolled for the request.</summary>
    public static string Summary(FaultDecision decision) => decision.Kind switch
    {
        FaultKind.Delay => $"delay {decision.Delay.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture)} ms",
        FaultKind.Error => $"error {decision.StatusCode.ToString(CultureInfo.InvariantCulture)} ({Percent(decision.Rule.ErrorPercent)} %)",
        _ => decision.Rule.Label(),
    };

    public static FaultFacts Describe(FaultDecision decision)
        => new(decision.Rule.Id, decision.Kind.WireName(), Summary(decision), decision.Rule.Description);

    /// <summary>A one-line description of a rule for the audit log: kind, scope and parameters. The operator's free-text description is not included.</summary>
    public static string AuditDetail(FaultRule rule)
    {
        var parameters = Parameters(rule);
        var expiry = rule.ExpiresAt is { } at ? $", expires {at.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} UTC" : string.Empty;
        return $"{rule.Kind.WireName()}{(parameters.Length == 0 ? string.Empty : " " + parameters)}; {rule.Scope}{expiry}";
    }

    private static string Percent(double value) => value.ToString("0.##", CultureInfo.InvariantCulture);
}
