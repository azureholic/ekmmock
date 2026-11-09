using EkmMock.Server.Ekm;

namespace EkmMock.Server.Faults;

/// <summary>The six fault kinds of spec 10.2.</summary>
internal enum FaultKind
{
    /// <summary>Waits (asynchronously) before the crypto call. Counted as "injected delay", never as crypto time.</summary>
    Delay,

    /// <summary>Answers a configurable share of requests with 429, 500 or 503.</summary>
    Error,

    /// <summary>The engine reports itself unavailable: <c>info</c> and every operation answer 503 HsmUnavailable. Process wide.</summary>
    HsmOffline,

    /// <summary>Wrap and unwrap answer 403 KeyDisabled without touching the key store. Metadata is unaffected, as for a really disabled key.</summary>
    KeyDisabled,

    /// <summary>Accepts the request and never answers, until the client gives up (or the optional hold cap is reached).</summary>
    Blackhole,

    /// <summary>Aborts the connection without a response.</summary>
    CloseConnection,
}

internal static class FaultKinds
{
    public const string Delay = "delay";
    public const string Error = "error";
    public const string Offline = "offline";
    public const string KeyDisabled = "key_disabled";
    public const string Blackhole = "blackhole";
    public const string Close = "close";

    public static readonly IReadOnlyList<string> All = [Delay, Error, Offline, KeyDisabled, Blackhole, Close];

    public static string WireName(this FaultKind kind) => kind switch
    {
        FaultKind.Delay => Delay,
        FaultKind.Error => Error,
        FaultKind.HsmOffline => Offline,
        FaultKind.KeyDisabled => KeyDisabled,
        FaultKind.Blackhole => Blackhole,
        FaultKind.CloseConnection => Close,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
    };

    public static bool TryParse(string? text, out FaultKind kind)
    {
        switch (text)
        {
            case Delay:
                kind = FaultKind.Delay;
                return true;
            case Error:
                kind = FaultKind.Error;
                return true;
            case Offline:
                kind = FaultKind.HsmOffline;
                return true;
            case KeyDisabled:
                kind = FaultKind.KeyDisabled;
                return true;
            case Blackhole:
                kind = FaultKind.Blackhole;
                return true;
            case Close:
                kind = FaultKind.CloseConnection;
                return true;
            default:
                kind = default;
                return false;
        }
    }

    /// <summary>A short human name for the badge and the table ("delay", "error 503", ...). Free of client input.</summary>
    public static string Label(this FaultRule rule) => rule.Kind switch
    {
        FaultKind.Delay => "delay",
        FaultKind.Error => $"error {rule.StatusCode}",
        FaultKind.HsmOffline => "HSM offline",
        FaultKind.KeyDisabled => "key disabled",
        FaultKind.Blackhole => "blackhole",
        FaultKind.CloseConnection => "close connection",
        _ => rule.Kind.ToString(),
    };
}

/// <summary>
/// Where a rule applies (spec 10.2: "globally or per namespace / key / op"). A null member is a wildcard. Key and namespace compare ordinally
/// (names are case-sensitive on the wire).
/// </summary>
internal sealed record FaultScope(string? Namespace = null, string? Key = null, EkmOperation? Operation = null)
{
    public static readonly FaultScope Global = new();

    public bool IsGlobal => Namespace is null && Key is null && Operation is null;

    /// <summary>
    /// How specific the scope is. A key beats an operation, an operation beats a namespace (see DECISIONS.md "M7: Rule precedence"): the weights are
    /// 4, 2 and 1, so every combination has a distinct score.
    /// </summary>
    public int Specificity => (Key is null ? 0 : 4) + (Operation is null ? 0 : 2) + (Namespace is null ? 0 : 1);

    public bool Matches(EkmRoute route)
        => (Namespace is null || string.Equals(Namespace, route.Namespace.Name, StringComparison.Ordinal))
            && (Key is null || string.Equals(Key, route.KeyName, StringComparison.Ordinal))
            && (Operation is null || Operation == route.Operation);

    public override string ToString()
        => IsGlobal ? "all requests" : string.Join(", ", new[]
        {
            Namespace is null ? null : $"namespace {Namespace}",
            Key is null ? null : $"key {Key}",
            Operation is null ? null : $"op {Operation.Value.WireName()}",
        }.Where(static part => part is not null));
}

/// <summary>
/// An immutable fault rule. <see cref="Sequence"/> is the creation order (the tie-breaker of the precedence rule); <see cref="Id"/> is what the console and the REST API call the rule.
/// Parameters that do not belong to the <see cref="Kind"/> are zero or null.
/// </summary>
internal sealed record FaultRule
{
    public required string Id { get; init; }

    public required long Sequence { get; init; }

    public required FaultKind Kind { get; init; }

    public bool Enabled { get; init; } = true;

    public FaultScope Scope { get; init; } = FaultScope.Global;

    /// <summary>Delay: the fixed delay, or null when a <see cref="MinMs"/>-<see cref="MaxMs"/> range is used.</summary>
    public int? DelayMs { get; init; }

    public int? MinMs { get; init; }

    public int? MaxMs { get; init; }

    /// <summary>Error: the share of requests that fail, 0 to 100.</summary>
    public double ErrorPercent { get; init; }

    /// <summary>Error: 429, 500 or 503.</summary>
    public int StatusCode { get; init; }

    public string? Description { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>The rule stops applying at this time (it stays listed as expired until it is deleted); null for no expiry.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    public bool IsExpired(DateTimeOffset now) => ExpiresAt is { } expiry && now >= expiry;

    public bool IsActive(DateTimeOffset now) => Enabled && !IsExpired(now);

    /// <summary>Whether the rule can act on this operation at all: key-disabled only affects wrap and unwrap (metadata of a disabled key is 200).</summary>
    public bool AppliesTo(EkmOperation operation)
        => Kind != FaultKind.KeyDisabled || operation is EkmOperation.WrapKey or EkmOperation.UnwrapKey;
}

/// <summary>Counts how often a rule fired. Kept apart from the immutable <see cref="FaultRule"/> so an edit does not reset it and the hot path stays lock free.</summary>
internal sealed class FaultCounter
{
    private long _fired;

    public long Fired => Interlocked.Read(ref _fired);

    public void Increment() => Interlocked.Increment(ref _fired);
}

/// <summary>
/// The outcome of evaluating the rules for one request: the rule that was chosen, with the randomness already resolved (the rolled delay), so that
/// the stages that carry it out are deterministic. A decision is only <em>fired</em> (<see cref="FaultDecisions.Fire"/>) when its fault actually acts on the request: a
/// blackhole, delay or key-disabled decision on a request that Auth or the validation rejects first never acted, is not recorded on the exchange and is not counted.
/// </summary>
internal sealed record FaultDecision(FaultRule Rule, TimeSpan Delay, FaultCounter Counter)
{
    public FaultKind Kind => Rule.Kind;

    public int StatusCode => Rule.StatusCode;
}

internal static class FaultDecisions
{
    /// <summary>Records the decision on the exchange (log line, inspector badge) and counts the firing on its rule.</summary>
    public static void Fire(this EkmRequestContext exchange, FaultDecision decision)
    {
        exchange.Fault = decision;
        decision.Counter.Increment();
    }
}
