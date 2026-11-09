using System.Text.Json.Serialization;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Conformance;

namespace EkmMock.Cli.Commands;

// ---- the JSON the commands print with --output json (indented, snake_case, nulls omitted) ----

internal sealed record InitResult(string DataPath, string MasterKeyFile, bool MasterKeyCreated, List<string> CreatedFolders, bool MasterKeyOwnerOnly, Dictionary<string, string> Environment, string? MasterKey);

internal sealed record CertFile(string Role, string Path, bool Secret);

internal sealed record CertsResult(string Notice, List<CertFile> Files, Dictionary<string, string> Details);

internal sealed record KeyCreatedResult(KeyView Key, PublicKeyView? PublicKey, string AzCommand);

internal sealed record BenchOutcome(
    string Tool,
    string Version,
    DateTimeOffset StartedAtUtc,
    string Target,
    string Operation,
    string Key,
    string? Algorithm,
    int Concurrency,
    double DurationSeconds,
    double WarmupSeconds,
    double? TargetRate,
    string Model,
    long Requests,
    long Errors,
    double ThroughputRps,
    LatencySummary LatencyMs,
    OverBudget OverBudget,
    Dictionary<string, long> StatusCounts,
    List<HistogramBucket> Histogram,
    List<string> ThresholdFailures,
    List<SlowRequest> SlowRequests,
    BenchEnvironment Environment);

internal sealed record LatencySummary(double Min, double Mean, double P50, double P90, double P99, double P999, double Max);

internal sealed record OverBudget(double ThresholdMs, long Count, double Percent);

internal sealed record HistogramBucket(string Le, long Count);

/// <summary>A request that took longer than 100 ms: when it started (seconds into the measurement) and how long it took.</summary>
internal sealed record SlowRequest(double OffsetSeconds, double LatencyMs);

internal sealed record BenchEnvironment(string Os, string Architecture, string Runtime, int ProcessorCount);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    WriteIndented = true)]
[JsonSerializable(typeof(InitResult))]
[JsonSerializable(typeof(CertsResult))]
[JsonSerializable(typeof(KeyCreatedResult))]
[JsonSerializable(typeof(KeyList))]
[JsonSerializable(typeof(KeyView))]
[JsonSerializable(typeof(KeyDetail))]
[JsonSerializable(typeof(NamespaceList))]
[JsonSerializable(typeof(NamespaceView))]
[JsonSerializable(typeof(NamespaceDeleted))]
[JsonSerializable(typeof(TrustPreview))]
[JsonSerializable(typeof(FaultList))]
[JsonSerializable(typeof(FaultRuleView))]
[JsonSerializable(typeof(FaultCleared))]
[JsonSerializable(typeof(BenchOutcome))]
[JsonSerializable(typeof(ConformanceReport))]
internal sealed partial class CliOutputJson : JsonSerializerContext
{
}
