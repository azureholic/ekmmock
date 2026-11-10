using Microsoft.Extensions.Options;

namespace EkmMock.Server.Inspector;

/// <summary>How the inspector shows secret values (spec 8.4). Only the two modes of the spec exist; there is no "plain" mode.</summary>
internal enum SecretDisplayMode
{
    /// <summary>Length and a fingerprint only. The raw value is never retained.</summary>
    Masked,

    /// <summary>Masked, plus a per-field Reveal action. Only effective when the process also started with <c>EKMMOCK_INSPECTOR_ALLOW_REVEAL=true</c>.</summary>
    Reveal,
}

/// <summary>The <c>Inspector</c> configuration section (spec 8.3, 8.4).</summary>
internal sealed class InspectorOptions
{
    public const string SectionName = "Inspector";

    /// <summary>The environment variable that must be <c>true</c> at process start before any reveal is possible (spec 8.4).</summary>
    public const string AllowRevealVariable = "EKMMOCK_INSPECTOR_ALLOW_REVEAL";

    /// <summary>Exchanges kept in memory (spec 8.3: default 10 000).</summary>
    public int RingBufferSize { get; set; } = 10_000;

    /// <summary>
    /// Upper bound of the memory the ring buffer retains, in bytes (security review M2): the oldest records are evicted until the estimated total is under it, even
    /// when <see cref="RingBufferSize"/> is not reached. The estimate counts what a record stores (strings at two bytes per character, retained raw bodies, a fixed
    /// overhead per record); it is not a process memory limit. Default 128 MiB.
    /// </summary>
    public long MaxBytes { get; set; } = DefaultMaxBytes;

    /// <summary>The smallest accepted <see cref="MaxBytes"/> (a record can be large; below this the buffer would hold almost nothing).</summary>
    public const long MinMaxBytes = 64 * 1024;

    public const long DefaultMaxBytes = 128L * 1024 * 1024;

    /// <summary>Capacity of the bounded queue between the request path and the consumer. When it is full the oldest record is dropped and counted.</summary>
    public int ChannelCapacity { get; set; } = 4096;

    /// <summary>Capacity of every live-feed subscription (one per open console). A slow console loses its own oldest items, nobody else's.</summary>
    public int SubscriberCapacity { get; set; } = 1000;

    public SecretDisplayMode SecretDisplay { get; set; } = SecretDisplayMode.Masked;

    /// <summary>Write masked JSONL files to the data volume (spec 8.3).</summary>
    public bool Persist { get; set; }

    /// <summary>Folder for the JSONL files. Empty means <c>&lt;Data:Path&gt;/inspector</c>.</summary>
    public string? PersistPath { get; set; }

    /// <summary>A file is rolled over (<c>.1</c>, <c>.2</c>, ...) before it grows past this size.</summary>
    public long MaxFileBytes { get; set; } = 50L * 1024 * 1024;

    /// <summary>The oldest files are deleted when all inspector files together are larger than this.</summary>
    public long MaxTotalBytes { get; set; } = 500L * 1024 * 1024;

    /// <summary>Files older than this many days (by the date in the file name) are deleted.</summary>
    public int RetainDays { get; set; } = 14;

    /// <summary>Latency samples kept per operation and minute for the dashboard percentiles (reservoir sampling beyond this).</summary>
    public int MaxSamplesPerMinuteAndOperation { get; set; } = 4096;

    public bool IsValid(out string error)
    {
        if (RingBufferSize < 1)
        {
            error = "Inspector:RingBufferSize must be at least 1";
        }
        else if (MaxBytes < MinMaxBytes)
        {
            error = $"Inspector:MaxBytes must be at least {MinMaxBytes}";
        }
        else if (ChannelCapacity < 1)
        {
            error = "Inspector:ChannelCapacity must be at least 1";
        }
        else if (SubscriberCapacity < 1)
        {
            error = "Inspector:SubscriberCapacity must be at least 1";
        }
        else if (MaxFileBytes < 1024)
        {
            error = "Inspector:MaxFileBytes must be at least 1024";
        }
        else if (MaxTotalBytes < MaxFileBytes)
        {
            error = "Inspector:MaxTotalBytes must not be smaller than Inspector:MaxFileBytes";
        }
        else if (RetainDays < 1)
        {
            error = "Inspector:RetainDays must be at least 1";
        }
        else if (MaxSamplesPerMinuteAndOperation < 16)
        {
            error = "Inspector:MaxSamplesPerMinuteAndOperation must be at least 16";
        }
        else
        {
            error = string.Empty;
            return true;
        }

        return false;
    }
}

/// <summary>Startup validation with a readable message (a wrong inspector setting fails the start, not the first request).</summary>
internal sealed class InspectorOptionsValidator : IValidateOptions<InspectorOptions>, IValidateOptions<LimitsOptions>
{
    public ValidateOptionsResult Validate(string? name, InspectorOptions options)
        => options.IsValid(out var error) ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(error);

    public ValidateOptionsResult Validate(string? name, LimitsOptions options)
    {
        if (!options.IsValid())
        {
            return ValidateOptionsResult.Fail("Limits:LatencyBudgetMs must not be smaller than Limits:LatencyWarningMs, and neither may be negative");
        }

        if (options.InternalDeadlineMs < 1)
        {
            return ValidateOptionsResult.Fail("Limits:InternalDeadlineMs must be at least 1");
        }

        if (options.MaxConnections < 1)
        {
            return ValidateOptionsResult.Fail("Limits:MaxConnections must be at least 1");
        }

        return options.MaxConcurrency < 1
            ? ValidateOptionsResult.Fail("Limits:MaxConcurrency must be at least 1")
            : ValidateOptionsResult.Success;
    }
}

/// <summary>The latency budget and the limits of the EKM endpoint (spec 10.1, 8.1).</summary>
internal sealed class LimitsOptions
{
    public const string SectionName = "Limits";

    /// <summary>Managed HSM's per-request timeout: above this a request is red (spec 8.1, 10.1) and logged as an error (spec 9).</summary>
    public int LatencyBudgetMs { get; set; } = 250;

    /// <summary>From here on a request is amber (spec 8.1: green below 150 ms) and, strictly above it, logged as a warning (spec 9).</summary>
    public int LatencyWarningMs { get; set; } = 150;

    /// <summary>
    /// The internal deadline (spec 10.1), measured from the start of the request: when it has passed before the crypto call starts the answer is an immediate
    /// <c>429</c>; a crypto call that ends after it still returns its result and is counted in <c>ekmmock_budget_exceeded_total</c>. Default 200 ms, 50 ms under the budget.
    /// </summary>
    public int InternalDeadlineMs { get; set; } = 200;

    /// <summary>Requests in flight at the same time (spec 10.1); one more is answered <c>429</c> immediately. There is no queue. Default 64.</summary>
    public int MaxConcurrency { get; set; } = 64;

    /// <summary>
    /// Open connections (handshaking or established) the EKM listener accepts at the same time; the next one is closed at once (security review L1). Default 1000. Counted per listener, so a flood
    /// on the public EKM port cannot lock out the console (Kestrel's own <c>MaxConcurrentConnections</c> is server wide).
    /// </summary>
    public int MaxConnections { get; set; } = EkmMock.Server.Connections.ConnectionCapture.DefaultMaxConnections;

    public bool IsValid() => LatencyWarningMs >= 0 && LatencyBudgetMs >= LatencyWarningMs;
}

/// <summary>The three colours of the budget indicator (spec 8.1).</summary>
internal enum BudgetStatus
{
    Green,
    Amber,
    Red,
}

/// <summary>Budget classification as a pure function: green below the warning threshold, amber up to and including the budget, red above it.</summary>
internal static class LatencyBudget
{
    public static BudgetStatus Classify(double milliseconds, double warningMs, double budgetMs)
        => milliseconds > budgetMs ? BudgetStatus.Red
            : milliseconds >= warningMs ? BudgetStatus.Amber
            : BudgetStatus.Green;

    public static BudgetStatus Classify(TimeSpan duration, LimitsOptions limits)
        => Classify(duration.TotalMilliseconds, limits.LatencyWarningMs, limits.LatencyBudgetMs);
}

/// <summary>
/// Decides whether reveal is possible at all (spec 8.4). Two independent switches must both be on: <c>Inspector:SecretDisplay=Reveal</c>
/// and the environment variable <c>EKMMOCK_INSPECTOR_ALLOW_REVEAL=true</c>, which is read once at process start and never from configuration
/// (a configuration file cannot grant it). Anything else means: nothing secret is ever retained.
/// </summary>
internal interface IInspectorRevealGate
{
    bool IsAllowed { get; }
}

internal sealed class EnvironmentRevealGate : IInspectorRevealGate
{
    public EnvironmentRevealGate(IOptions<InspectorOptions> options)
        => IsAllowed = options.Value.SecretDisplay == SecretDisplayMode.Reveal && IsEnvironmentFlagSet();

    public bool IsAllowed { get; }

    public static bool IsEnvironmentFlagSet()
        => string.Equals(Environment.GetEnvironmentVariable(InspectorOptions.AllowRevealVariable), "true", StringComparison.OrdinalIgnoreCase);
}
