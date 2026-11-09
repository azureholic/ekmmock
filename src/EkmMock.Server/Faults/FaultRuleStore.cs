using System.Diagnostics.CodeAnalysis;
using EkmMock.Server.Ekm;

namespace EkmMock.Server.Faults;

/// <summary>
/// Whether fault injection exists at all in this process (spec 10.2): only when it was started with <c>EKMMOCK_ENABLE_FAULTS=true</c>. Read once at start, from the
/// environment and never from configuration (a configuration file cannot switch it on); tests replace the gate through DI.
/// </summary>
internal interface IFaultGate
{
    bool Enabled { get; }
}

internal sealed class EnvironmentFaultGate : IFaultGate
{
    public const string Variable = "EKMMOCK_ENABLE_FAULTS";

    public bool Enabled { get; } = string.Equals(Environment.GetEnvironmentVariable(Variable), "true", StringComparison.OrdinalIgnoreCase);
}

/// <summary>The dice of the fault rules. Injectable so that error-rate and delay-range tests are deterministic.</summary>
internal interface IFaultRandom
{
    /// <summary>A number in [0, 1).</summary>
    double NextDouble();

    /// <summary>A number in [<paramref name="minInclusive"/>, <paramref name="maxInclusive"/>].</summary>
    int Next(int minInclusive, int maxInclusive);
}

/// <summary>Uses <see cref="Random.Shared"/> (thread safe). Fault dice are test data, not security: no cryptographic randomness needed.</summary>
[SuppressMessage("Security", "CA5394:Do not use insecure randomness", Justification = "Fault injection dice; nothing secret depends on them.")]
internal sealed class SystemFaultRandom : IFaultRandom
{
    public double NextDouble() => Random.Shared.NextDouble();

    public int Next(int minInclusive, int maxInclusive) => minInclusive >= maxInclusive ? minInclusive : Random.Shared.Next(minInclusive, maxInclusive + 1);
}

/// <summary>A validated request to create or change a rule (the service layer validated it; the store only stores).</summary>
internal sealed record FaultSpec
{
    public required FaultKind Kind { get; init; }

    public FaultScope Scope { get; init; } = FaultScope.Global;

    public int? DelayMs { get; init; }

    public int? MinMs { get; init; }

    public int? MaxMs { get; init; }

    public double ErrorPercent { get; init; }

    public int StatusCode { get; init; }

    public string? Description { get; init; }

    public TimeSpan? ExpiresAfter { get; init; }

    public bool Enabled { get; init; } = true;
}

/// <summary>A rule together with the number of times it fired, as the console lists it.</summary>
internal sealed record FaultRuleEntry(FaultRule Rule, long Fired);

internal enum FaultStoreFailure
{
    /// <summary>Fault injection is not switched on in this process.</summary>
    Disabled,

    NotFound,

    TooManyRules,
}

internal sealed class FaultStoreException : Exception
{
    public FaultStoreException(FaultStoreFailure failure, string message)
        : base(message)
    {
        Failure = failure;
    }

    public FaultStoreFailure Failure { get; }
}

/// <summary>
/// The fault rules of the process: in memory only (a restart clears them on purpose, see DECISIONS.md "M7: Faults are not persisted"), at most <see cref="MaxRules"/>,
/// readable lock free from the request path (an immutable snapshot is swapped on every change) and changed under a lock.
/// <para>
/// <b>Precedence</b> (deterministic, see DECISIONS.md "M7: Rule precedence"): an active HSM-offline rule overrides everything. Otherwise the rules that match the request
/// are tried in the order most specific scope first (key, then operation, then namespace; a global rule last), then oldest first. The first rule that <em>fires</em> wins; an
/// error-rate rule whose dice say "not this time" lets the next rule have its turn. Exactly one rule acts on a request.
/// </para>
/// </summary>
internal sealed class FaultRuleStore : IDisposable
{
    public const int MaxRules = 100;

    private readonly IFaultGate _gate;
    private readonly TimeProvider _time;
    private readonly IFaultRandom _random;
    private readonly object _writeGate = new();
    private volatile Entry[] _snapshot = [];
    private long _nextSequence;
    private ITimer? _expiryTimer;
    private bool _disposed;

    public FaultRuleStore(IFaultGate gate, TimeProvider time, IFaultRandom random)
    {
        _gate = gate;
        _time = time;
        _random = random;
    }

    /// <summary>Raised (on whatever thread made the change, or on a timer thread when a rule expires) after the set of active rules may have changed.</summary>
    public event Action? Changed;

    public bool Enabled => _gate.Enabled;

    public int Count => _snapshot.Length;

    /// <summary>All rules, oldest first, with their fire counts.</summary>
    public IReadOnlyList<FaultRuleEntry> List() => [.. _snapshot.Select(static e => new FaultRuleEntry(e.Rule, e.Counter.Fired))];

    public FaultRuleEntry? Get(string id)
        => _snapshot.FirstOrDefault(e => string.Equals(e.Rule.Id, id, StringComparison.Ordinal)) is { } entry ? new FaultRuleEntry(entry.Rule, entry.Counter.Fired) : null;

    /// <summary>Number of enabled, unexpired rules (what the "faults active" banner reflects). Zero when fault injection is switched off.</summary>
    public int ActiveCount
    {
        get
        {
            if (!_gate.Enabled)
            {
                return 0;
            }

            var now = _time.GetUtcNow();
            return _snapshot.Count(e => e.Rule.IsActive(now));
        }
    }

    /// <summary>True while an enabled, unexpired HSM-offline rule exists: the engine reports itself unavailable (<see cref="Hosting.IEngineAvailability"/>).</summary>
    public bool IsHsmOffline
    {
        get
        {
            if (!_gate.Enabled)
            {
                return false;
            }

            var now = _time.GetUtcNow();
            foreach (var entry in _snapshot)
            {
                if (entry.Rule.Kind == FaultKind.HsmOffline && entry.Rule.IsActive(now))
                {
                    return true;
                }
            }

            return false;
        }
    }

    // ---- changes ----

    public FaultRule Create(FaultSpec spec)
    {
        FaultRule rule;
        lock (_writeGate)
        {
            RequireEnabled();
            if (_snapshot.Length >= MaxRules)
            {
                throw new FaultStoreException(FaultStoreFailure.TooManyRules, $"At most {MaxRules} fault rules can exist. Delete some first.");
            }

            var sequence = ++_nextSequence;
            rule = Build(spec, $"f{sequence}", sequence, _time.GetUtcNow());
            _snapshot = [.. _snapshot, new Entry(rule, new FaultCounter())];
            ArmExpiryTimer();
        }

        RaiseChanged();
        return rule;
    }

    public FaultRule Update(string id, FaultSpec spec)
    {
        FaultRule rule;
        lock (_writeGate)
        {
            RequireEnabled();
            var index = IndexOf(id);
            var existing = _snapshot[index];
            rule = Build(spec, existing.Rule.Id, existing.Rule.Sequence, _time.GetUtcNow(), existing.Rule.CreatedAt);
            var next = _snapshot.ToArray();
            next[index] = existing with { Rule = rule };
            _snapshot = next;
            ArmExpiryTimer();
        }

        RaiseChanged();
        return rule;
    }

    public FaultRule SetEnabled(string id, bool enabled)
    {
        FaultRule rule;
        lock (_writeGate)
        {
            RequireEnabled();
            var index = IndexOf(id);
            var existing = _snapshot[index];
            rule = existing.Rule with { Enabled = enabled };
            var next = _snapshot.ToArray();
            next[index] = existing with { Rule = rule };
            _snapshot = next;
            ArmExpiryTimer();
        }

        RaiseChanged();
        return rule;
    }

    public FaultRule Delete(string id)
    {
        FaultRule removed;
        lock (_writeGate)
        {
            RequireEnabled();
            var index = IndexOf(id);
            removed = _snapshot[index].Rule;
            _snapshot = [.. _snapshot.Where((_, i) => i != index)];
            ArmExpiryTimer();
        }

        RaiseChanged();
        return removed;
    }

    /// <summary>Removes every rule; returns how many there were.</summary>
    public int Clear()
    {
        int removed;
        lock (_writeGate)
        {
            RequireEnabled();
            removed = _snapshot.Length;
            _snapshot = [];
            ArmExpiryTimer();
        }

        RaiseChanged();
        return removed;
    }

    // ---- evaluation (request path) ----

    /// <summary>
    /// Decides what, if anything, happens to this request. Cheap when there is nothing to do: a disabled process or an empty rule set returns without allocating.
    /// This only <em>chooses</em> (and rolls the dice): the stage that acts calls <see cref="FaultDecisions.Fire"/>, which records the fault on the exchange and counts the firing.
    /// </summary>
    public FaultDecision? Resolve(EkmRoute route)
    {
        if (!_gate.Enabled)
        {
            return null;
        }

        var snapshot = _snapshot;
        if (snapshot.Length == 0)
        {
            return null;
        }

        var now = _time.GetUtcNow();
        List<Entry>? candidates = null;
        foreach (var entry in snapshot)
        {
            var rule = entry.Rule;
            if (!rule.IsActive(now) || !rule.AppliesTo(route.Operation))
            {
                continue;
            }

            // HSM offline is process wide: its scope is not consulted.
            if (rule.Kind != FaultKind.HsmOffline && !rule.Scope.Matches(route))
            {
                continue;
            }

            (candidates ??= []).Add(entry);
        }

        if (candidates is null)
        {
            return null;
        }

        candidates.Sort(static (a, b) =>
        {
            var offline = (b.Rule.Kind == FaultKind.HsmOffline).CompareTo(a.Rule.Kind == FaultKind.HsmOffline);
            if (offline != 0)
            {
                return offline;
            }

            var specificity = b.Rule.Scope.Specificity.CompareTo(a.Rule.Scope.Specificity);
            return specificity != 0 ? specificity : a.Rule.Sequence.CompareTo(b.Rule.Sequence);
        });

        foreach (var entry in candidates)
        {
            if (TryDecide(entry, out var decision))
            {
                return decision;
            }
        }

        return null;
    }

    private bool TryDecide(Entry entry, [NotNullWhen(true)] out FaultDecision? decision)
    {
        var rule = entry.Rule;
        switch (rule.Kind)
        {
            case FaultKind.Error:
                // 100 % always fires and 0 % never does, whatever the dice (they return values in [0, 1)).
                decision = _random.NextDouble() * 100 < rule.ErrorPercent ? new FaultDecision(rule, TimeSpan.Zero, entry.Counter) : null;
                return decision is not null;

            case FaultKind.Delay:
                var milliseconds = rule.DelayMs ?? _random.Next(rule.MinMs ?? 0, rule.MaxMs ?? rule.MinMs ?? 0);
                decision = new FaultDecision(rule, TimeSpan.FromMilliseconds(milliseconds), entry.Counter);
                return true;

            default:
                decision = new FaultDecision(rule, TimeSpan.Zero, entry.Counter);
                return true;
        }
    }

    // ---- helpers ----

    private static FaultRule Build(FaultSpec spec, string id, long sequence, DateTimeOffset now, DateTimeOffset? createdAt = null)
        => new()
        {
            Id = id,
            Sequence = sequence,
            Kind = spec.Kind,
            Enabled = spec.Enabled,
            Scope = spec.Kind == FaultKind.HsmOffline ? FaultScope.Global : spec.Scope,
            DelayMs = spec.DelayMs,
            MinMs = spec.MinMs,
            MaxMs = spec.MaxMs,
            ErrorPercent = spec.ErrorPercent,
            StatusCode = spec.StatusCode,
            Description = spec.Description,
            CreatedAt = createdAt ?? now,
            ExpiresAt = spec.ExpiresAfter is { } after ? now + after : null,
        };

    private void RequireEnabled()
    {
        if (!_gate.Enabled)
        {
            throw new FaultStoreException(FaultStoreFailure.Disabled, "Fault injection is disabled: start the process with EKMMOCK_ENABLE_FAULTS=true to use it.");
        }
    }

    private int IndexOf(string id)
    {
        var snapshot = _snapshot;
        for (var i = 0; i < snapshot.Length; i++)
        {
            if (string.Equals(snapshot[i].Rule.Id, id, StringComparison.Ordinal))
            {
                return i;
            }
        }

        throw new FaultStoreException(FaultStoreFailure.NotFound, "The fault rule does not exist (any more).");
    }

    /// <summary>One timer for the next expiry: when a rule expires the banner and the page must update without anybody touching a rule. Called under the write lock.</summary>
    private void ArmExpiryTimer()
    {
        _expiryTimer?.Dispose();
        _expiryTimer = null;
        if (_disposed)
        {
            return;
        }

        var now = _time.GetUtcNow();
        DateTimeOffset? next = null;
        foreach (var entry in _snapshot)
        {
            if (entry.Rule is { Enabled: true, ExpiresAt: { } expiry } && expiry > now && (next is null || expiry < next))
            {
                next = expiry;
            }
        }

        if (next is { } due)
        {
            _expiryTimer = _time.CreateTimer(static state => ((FaultRuleStore)state!).OnExpiry(), this, due - now + TimeSpan.FromMilliseconds(5), Timeout.InfiniteTimeSpan);
        }
    }

    private void OnExpiry()
    {
        lock (_writeGate)
        {
            ArmExpiryTimer();
        }

        RaiseChanged();
    }

    private void RaiseChanged()
    {
        try
        {
            Changed?.Invoke();
        }
        catch (Exception)
        {
            // A broken subscriber (a closed circuit) must never break a fault change or the timer thread.
        }
    }

    public void Dispose()
    {
        lock (_writeGate)
        {
            _disposed = true;
            _expiryTimer?.Dispose();
            _expiryTimer = null;
        }
    }

    private sealed record Entry(FaultRule Rule, FaultCounter Counter);
}
