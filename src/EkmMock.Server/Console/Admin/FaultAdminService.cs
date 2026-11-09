using System.Globalization;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using EkmMock.Server.Faults;

namespace EkmMock.Server.WebConsole;

/// <summary>A fault rule as the console and the REST API show it (spec 10.2). Contains nothing but the rule's own parameters.</summary>
internal sealed record FaultRuleView(
    string Id,
    bool Enabled,
    string Kind,
    string? Namespace,
    string? Key,
    string? Op,
    int? DelayMs,
    int? MinMs,
    int? MaxMs,
    double? ErrorPercent,
    int? StatusCode,
    string? Description,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    long Fired,
    string State,
    string Parameters,
    string Scope)
{
    public bool IsExpired => State == FaultStates.Expired;

    public static FaultRuleView From(FaultRuleEntry entry, DateTimeOffset now)
    {
        var rule = entry.Rule;
        return new FaultRuleView(
            rule.Id,
            rule.Enabled,
            rule.Kind.WireName(),
            rule.Scope.Namespace,
            rule.Scope.Key,
            rule.Scope.Operation?.WireName(),
            rule.Kind == FaultKind.Delay ? rule.DelayMs : null,
            rule.Kind == FaultKind.Delay && rule.DelayMs is null ? rule.MinMs : null,
            rule.Kind == FaultKind.Delay && rule.DelayMs is null ? rule.MaxMs : null,
            rule.Kind == FaultKind.Error ? rule.ErrorPercent : null,
            rule.Kind == FaultKind.Error ? rule.StatusCode : null,
            rule.Description,
            rule.CreatedAt,
            rule.ExpiresAt,
            entry.Fired,
            rule.IsExpired(now) ? FaultStates.Expired : rule.Enabled ? FaultStates.Active : FaultStates.Disabled,
            FaultDescriptions.Parameters(rule),
            rule.Scope.ToString());
    }
}

internal static class FaultStates
{
    public const string Active = "active";
    public const string Disabled = "disabled";
    public const string Expired = "expired";
}

/// <summary>A ready-made rule the page offers as one click (spec 8.5.9 presets).</summary>
internal sealed record FaultPresetView(string Id, string Title, string Description);

/// <summary>Everything the Faults page and <c>GET /api/console/faults</c> need.</summary>
internal sealed record FaultList(bool Enabled, bool HsmOffline, int ActiveRules, int MaxRules, IReadOnlyList<FaultRuleView> Rules, IReadOnlyList<FaultPresetView> Presets);

internal sealed record FaultCleared(int Removed);

/// <summary>The input of a create or an edit, before validation. <c>Namespace</c>, <c>Key</c> and <c>Op</c> may be empty or <c>*</c> for "any".</summary>
internal sealed record FaultRuleRequest(
    string? Kind,
    string? Namespace = null,
    string? Key = null,
    string? Op = null,
    int? DelayMs = null,
    int? MinMs = null,
    int? MaxMs = null,
    double? ErrorPercent = null,
    int? StatusCode = null,
    string? Description = null,
    int? ExpiresAfterSeconds = null,
    bool? Enabled = null);

/// <summary>
/// The fault injection actions of the console (spec 10.2, 8.5.9), shared by the Faults page and <c>/api/console/faults</c>. Every change is audited with the acting user, and
/// when the process was not started with <c>EKMMOCK_ENABLE_FAULTS=true</c> every change is refused here (<see cref="ConsoleErrorCode.FaultsDisabled"/>), so neither UI nor API
/// can create a rule that could ever apply. Validation lives here and nowhere else, so both callers report the same words.
/// </summary>
internal sealed class FaultAdminService
{
    /// <summary>The longest fixed or maximum delay: a minute is far beyond any proxy timeout and still finite.</summary>
    public const int MaxDelayMs = 60_000;

    public const int MaxDescriptionLength = 200;

    /// <summary>One week: auto-expiry exists to prevent a forgotten rule, not to schedule a long experiment.</summary>
    public const int MaxExpirySeconds = 7 * 24 * 3600;

    public static readonly IReadOnlyList<int> ErrorStatuses = [429, 500, 503];

    public static readonly IReadOnlyList<string> Operations = ["info", "metadata", "wrapkey", "unwrapkey"];

    public static readonly IReadOnlyList<FaultPresetView> Presets =
    [
        new("distant-hsm-100", "Distant HSM, 100 ms", "Adds 100 ms to every request: a network HSM about 100 ms away. Comfortably inside the 250 ms budget."),
        new("distant-hsm-200", "Distant HSM, 200 ms", "Adds 200 ms to every request: at the 200 ms internal deadline, so crypto ends right at the limit."),
        new("distant-hsm-260", "Distant HSM, 260 ms", "Adds 260 ms to every request: past the 250 ms budget, where Managed HSM is expected to start failing."),
        new("hsm-offline", "HSM offline", "info and every operation answer 503 HsmUnavailable."),
        new("error-503-50", "50 % answer 503", "Every second request, on average, answers 503 HsmUnavailable."),
    ];

    private readonly FaultRuleStore _rules;
    private readonly AuditRecorder _audit;
    private readonly NamespaceStore _namespaces;
    private readonly TimeProvider _time;

    public FaultAdminService(FaultRuleStore rules, AuditRecorder audit, NamespaceStore namespaces, TimeProvider time)
    {
        _rules = rules;
        _audit = audit;
        _namespaces = namespaces;
        _time = time;
    }

    /// <summary>False when the process was not started with <c>EKMMOCK_ENABLE_FAULTS=true</c>: the page is read-only and says "disabled".</summary>
    public bool Enabled => _rules.Enabled;

    /// <summary>The configured namespace names, for the scope drop-down.</summary>
    public IReadOnlyList<string> NamespaceNames() => [.. _namespaces.List().Select(static n => n.Name).Order(StringComparer.Ordinal)];

    public FaultList List()
    {
        var now = _time.GetUtcNow();
        return new FaultList(
            _rules.Enabled,
            _rules.IsHsmOffline,
            _rules.ActiveCount,
            FaultRuleStore.MaxRules,
            [.. _rules.List().Select(entry => FaultRuleView.From(entry, now))],
            Presets);
    }

    public FaultRuleView Get(string id)
        => _rules.Get(id) is { } entry ? FaultRuleView.From(entry, _time.GetUtcNow()) : throw new ConsoleActionException(ConsoleErrorCode.NotFound, "The fault rule does not exist (any more).");

    public FaultRuleView Create(string actor, FaultRuleRequest request)
    {
        RequireEnabled();
        var spec = Validate(request);
        var rule = Run(() => _rules.Create(spec));
        _audit.Record(actor, AuditActions.FaultCreate, Target(rule.Id), FaultDescriptions.AuditDetail(rule));
        return View(rule);
    }

    public FaultRuleView Update(string actor, string id, FaultRuleRequest request)
    {
        RequireEnabled();
        var spec = Validate(request);
        var rule = Run(() => _rules.Update(id, spec));
        _audit.Record(actor, AuditActions.FaultUpdate, Target(rule.Id), FaultDescriptions.AuditDetail(rule));
        return View(rule);
    }

    public FaultRuleView SetEnabled(string actor, string id, bool enabled)
    {
        RequireEnabled();
        var rule = Run(() => _rules.SetEnabled(id, enabled));
        _audit.Record(actor, enabled ? AuditActions.FaultEnable : AuditActions.FaultDisable, Target(rule.Id), FaultDescriptions.AuditDetail(rule));
        return View(rule);
    }

    public void Delete(string actor, string id)
    {
        RequireEnabled();
        var rule = Run(() => _rules.Delete(id));
        _audit.Record(actor, AuditActions.FaultDelete, Target(rule.Id), FaultDescriptions.AuditDetail(rule));
    }

    /// <summary>Removes every rule ("clear all"); returns how many there were.</summary>
    public int Clear(string actor)
    {
        RequireEnabled();
        var removed = Run(() => _rules.Clear());
        _audit.Record(actor, AuditActions.FaultClear, "fault:*", $"{removed.ToString(CultureInfo.InvariantCulture)} rule(s) removed");
        return removed;
    }

    public FaultRuleView ApplyPreset(string actor, string presetId)
    {
        RequireEnabled();
        var request = PresetRequest(presetId) ?? throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Unknown preset.");
        var rule = Run(() => _rules.Create(Validate(request)));
        _audit.Record(actor, AuditActions.FaultPreset, Target(rule.Id), $"preset {presetId}: {FaultDescriptions.AuditDetail(rule)}");
        return View(rule);
    }

    internal static FaultRuleRequest? PresetRequest(string presetId) => presetId switch
    {
        "distant-hsm-100" => new FaultRuleRequest(FaultKinds.Delay, DelayMs: 100, Description: "Preset: distant HSM, 100 ms"),
        "distant-hsm-200" => new FaultRuleRequest(FaultKinds.Delay, DelayMs: 200, Description: "Preset: distant HSM, 200 ms"),
        "distant-hsm-260" => new FaultRuleRequest(FaultKinds.Delay, DelayMs: 260, Description: "Preset: distant HSM, 260 ms"),
        "hsm-offline" => new FaultRuleRequest(FaultKinds.Offline, Description: "Preset: HSM offline"),
        "error-503-50" => new FaultRuleRequest(FaultKinds.Error, ErrorPercent: 50, StatusCode: 503, Description: "Preset: 50 % answer 503"),
        _ => null,
    };

    // ---- validation ----

    /// <summary>Turns a request into a store specification or throws <see cref="ConsoleErrorCode.InvalidRequest"/> with a message that names the field. Public text, no input echoed.</summary>
    internal static FaultSpec Validate(FaultRuleRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!FaultKinds.TryParse(request.Kind, out var kind))
        {
            throw Invalid($"kind must be one of {string.Join(", ", FaultKinds.All)}.");
        }

        var scope = ParseScope(request);
        if (kind == FaultKind.HsmOffline && !scope.IsGlobal)
        {
            throw Invalid("HSM offline applies to the whole engine: leave namespace, key and op empty.");
        }

        if (kind == FaultKind.KeyDisabled && scope.Operation is EkmOperation.Info or EkmOperation.Metadata)
        {
            throw Invalid("Key disabled only affects wrapkey and unwrapkey (metadata of a disabled key still works): choose op wrapkey, unwrapkey or any.");
        }

        var spec = new FaultSpec
        {
            Kind = kind,
            Scope = scope,
            Description = ParseDescription(request.Description),
            ExpiresAfter = ParseExpiry(request.ExpiresAfterSeconds),
            Enabled = request.Enabled ?? true,
        };

        return kind switch
        {
            FaultKind.Delay => ValidateDelay(request, spec),
            FaultKind.Error => ValidateError(request, spec),
            _ => spec,
        };
    }

    private static FaultSpec ValidateDelay(FaultRuleRequest request, FaultSpec spec)
    {
        var hasFixed = request.DelayMs is not null;
        var hasRange = request.MinMs is not null || request.MaxMs is not null;
        if (hasFixed == hasRange)
        {
            throw Invalid("A delay rule needs either delay_ms, or min_ms and max_ms.");
        }

        if (hasFixed)
        {
            RequireDelay(request.DelayMs!.Value, "delay_ms");
            return spec with { DelayMs = request.DelayMs };
        }

        if (request.MinMs is not { } min || request.MaxMs is not { } max)
        {
            throw Invalid("A delay range needs both min_ms and max_ms.");
        }

        RequireDelay(min, "min_ms");
        RequireDelay(max, "max_ms");
        return min > max ? throw Invalid("min_ms must not be larger than max_ms.") : spec with { MinMs = min, MaxMs = max };
    }

    private static FaultSpec ValidateError(FaultRuleRequest request, FaultSpec spec)
    {
        if (request.ErrorPercent is not { } percent || double.IsNaN(percent) || percent < 0 || percent > 100)
        {
            throw Invalid("error_percent must be a number from 0 to 100.");
        }

        return request.StatusCode is { } status && ErrorStatuses.Contains(status)
            ? spec with { ErrorPercent = percent, StatusCode = status }
            : throw Invalid("status_code must be 429, 500 or 503.");
    }

    private static void RequireDelay(int milliseconds, string field)
    {
        if (milliseconds is < 0 or > MaxDelayMs)
        {
            throw Invalid($"{field} must be from 0 to {MaxDelayMs.ToString(CultureInfo.InvariantCulture)} ms.");
        }
    }

    private static FaultScope ParseScope(FaultRuleRequest request)
    {
        var ns = Wildcard(request.Namespace);
        if (ns is not null && !IsValidNamespaceName(ns))
        {
            throw Invalid("namespace must be 1 to 64 letters, digits, '-' or '_' (or empty for any).");
        }

        var key = Wildcard(request.Key);
        if (key is not null && !EkmNames.IsValidKeyName(key))
        {
            throw Invalid("key must be 1 to 64 letters, digits or '-' (or empty for any).");
        }

        EkmOperation? operation = null;
        if (Wildcard(request.Op) is { } op)
        {
            operation = op switch
            {
                "info" => EkmOperation.Info,
                "metadata" => EkmOperation.Metadata,
                "wrapkey" => EkmOperation.WrapKey,
                "unwrapkey" => EkmOperation.UnwrapKey,
                _ => throw Invalid($"op must be one of {string.Join(", ", Operations)} (or empty for any)."),
            };
        }

        return new FaultScope(ns, key, operation);
    }

    private static string? ParseDescription(string? description)
    {
        if (string.IsNullOrWhiteSpace(description))
        {
            return null;
        }

        var text = description.Trim();
        return text.Length > MaxDescriptionLength || text.Any(char.IsControl)
            ? throw Invalid($"description must be at most {MaxDescriptionLength.ToString(CultureInfo.InvariantCulture)} characters without control characters.")
            : text;
    }

    private static TimeSpan? ParseExpiry(int? seconds)
        => seconds is null ? null
            : seconds is >= 1 and <= MaxExpirySeconds ? TimeSpan.FromSeconds(seconds.Value)
            : throw Invalid($"expires_after_seconds must be from 1 to {MaxExpirySeconds.ToString(CultureInfo.InvariantCulture)}.");

    private static string? Wildcard(string? value) => string.IsNullOrWhiteSpace(value) || value.Trim() == "*" ? null : value.Trim();

    private static bool IsValidNamespaceName(string name)
        => name.Length is >= 1 and <= 64 && name.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    // ---- plumbing ----

    private void RequireEnabled()
    {
        if (!_rules.Enabled)
        {
            throw new ConsoleActionException(ConsoleErrorCode.FaultsDisabled, "Fault injection is disabled. Start the process with EKMMOCK_ENABLE_FAULTS=true to use it.");
        }
    }

    private static T Run<T>(Func<T> action)
    {
        try
        {
            return action();
        }
        catch (FaultStoreException exception)
        {
            throw new ConsoleActionException(
                exception.Failure switch
                {
                    FaultStoreFailure.Disabled => ConsoleErrorCode.FaultsDisabled,
                    FaultStoreFailure.NotFound => ConsoleErrorCode.NotFound,
                    _ => ConsoleErrorCode.Conflict,
                },
                exception.Message);
        }
    }

    private FaultRuleView View(FaultRule rule) => FaultRuleView.From(_rules.Get(rule.Id) ?? new FaultRuleEntry(rule, 0), _time.GetUtcNow());

    private static string Target(string id) => $"fault:{id}";

    private static ConsoleActionException Invalid(string message) => new(ConsoleErrorCode.InvalidRequest, message);
}
