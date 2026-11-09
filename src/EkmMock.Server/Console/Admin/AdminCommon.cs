using EkmMock.Crypto;
using EkmMock.Server.Inspector;

namespace EkmMock.Server.WebConsole;

/// <summary>Why a console action was refused. The names are the wire <c>code</c> values of <c>/api/console/*</c> errors.</summary>
internal enum ConsoleErrorCode
{
    InvalidRequest,
    NotFound,
    Conflict,
    Forbidden,

    /// <summary>The typed confirmation (key name, namespace name) did not match. Enforced here, not only in the UI.</summary>
    ConfirmationMismatch,

    /// <summary>The thing the action needs is not available right now (EKM listener not bound, engine unavailable).</summary>
    Unavailable,

    /// <summary>The audit entry could not be written. The action has already been applied when this is raised for a completed change.</summary>
    AuditUnavailable,
}

/// <summary>
/// A refused or failed console action with a message that is safe to show (never key material, certificate or exception details). The UI and the REST API both
/// catch exactly this type, so both report the same words.
/// </summary>
internal sealed class ConsoleActionException : Exception
{
    public ConsoleActionException(ConsoleErrorCode code, string message)
        : base(message)
    {
        Code = code;
    }

    public ConsoleErrorCode Code { get; }

    public int HttpStatus => Code switch
    {
        ConsoleErrorCode.InvalidRequest => StatusCodes.Status400BadRequest,
        ConsoleErrorCode.ConfirmationMismatch => StatusCodes.Status400BadRequest,
        ConsoleErrorCode.NotFound => StatusCodes.Status404NotFound,
        ConsoleErrorCode.Conflict => StatusCodes.Status409Conflict,
        ConsoleErrorCode.Forbidden => StatusCodes.Status403Forbidden,
        _ => StatusCodes.Status503ServiceUnavailable,
    };

    /// <summary>Maps the typed failures of the engine and of the namespace store to a console error; the messages of both are fixed, secret-free strings.</summary>
    public static ConsoleActionException From(Exception exception) => exception switch
    {
        ConsoleActionException already => already,
        EkmEngineException engine => new ConsoleActionException(
            engine.Kind switch
            {
                EkmErrorKind.KeyNotFound => ConsoleErrorCode.NotFound,
                EkmErrorKind.KeyAlreadyExists or EkmErrorKind.KeyNameReserved => ConsoleErrorCode.Conflict,
                EkmErrorKind.OperationNotAllowed or EkmErrorKind.KeyDisabled or EkmErrorKind.KeyExpired => ConsoleErrorCode.Forbidden,
                EkmErrorKind.HsmUnavailable => ConsoleErrorCode.Unavailable,
                _ => ConsoleErrorCode.InvalidRequest,
            },
            engine.Kind == EkmErrorKind.InternalError ? "The crypto engine could not complete the action." : engine.Message),
        NamespaceException ns => new ConsoleActionException(
            ns.Kind switch
            {
                NamespaceErrorKind.NotFound => ConsoleErrorCode.NotFound,
                NamespaceErrorKind.Duplicate => ConsoleErrorCode.Conflict,
                _ => ConsoleErrorCode.InvalidRequest,
            },
            ns.Message),
        _ => throw exception,
    };
}

/// <summary>
/// The audit action names of the console (spec 5.4: "every console action that changes state is written to the audit log with user, time, action and target").
/// Names are <c>area.verb</c>, lower case, stable (the CLI and the audit filter use them). The target says <em>what</em> (<c>key:ns/name</c>, <c>namespace:name</c>,
/// <c>certificate:...</c>, <c>exchange:id</c>); the detail is a short fixed note and never carries secret or uploaded material.
/// </summary>
internal static class AuditActions
{
    public const string KeyCreate = "key.create";
    public const string KeyImport = "key.import";
    public const string KeyEnable = "key.enable";
    public const string KeyDisable = "key.disable";
    public const string KeyExpirySet = "key.expiry.set";
    public const string KeyExpiryClear = "key.expiry.clear";
    public const string KeyDestroy = "key.destroy";

    public const string NamespaceCreate = "namespace.create";
    public const string NamespaceUpdate = "namespace.update";
    public const string NamespaceDelete = "namespace.delete";
    public const string TrustImport = "namespace.trust.import";
    public const string TrustTestClient = "namespace.trust.test-client";

    public const string CertificateUpload = "certificate.upload";
    public const string CertificateGenerate = "certificate.generate";

    public const string PlaygroundWrap = "playground.wrap";
    public const string PlaygroundUnwrap = "playground.unwrap";
    public const string PlaygroundReveal = "playground.reveal";
    public const string PlaygroundRevealDenied = "playground.reveal.denied";

    // Written by the inspector service (M4); listed so the Audit page can offer them in its filter.
    public const string InspectorReveal = "inspector.reveal";
    public const string InspectorRevealDenied = "inspector.reveal.denied";
    public const string InspectorReplay = "inspector.replay";

    /// <summary>Every action the console can write, for the filter drop-down and for the test that walks them all.</summary>
    public static readonly IReadOnlyList<string> All =
    [
        KeyCreate, KeyImport, KeyEnable, KeyDisable, KeyExpirySet, KeyExpiryClear, KeyDestroy,
        NamespaceCreate, NamespaceUpdate, NamespaceDelete, TrustImport, TrustTestClient,
        CertificateUpload, CertificateGenerate,
        PlaygroundWrap, PlaygroundUnwrap, PlaygroundReveal, PlaygroundRevealDenied,
        InspectorReveal, InspectorRevealDenied, InspectorReplay,
    ];
}

/// <summary>Writes audit entries for the console services. A failure to write is reported to the caller (never swallowed): an unaudited change is not acceptable.</summary>
internal sealed class AuditRecorder
{
    private readonly IAuditLog _audit;
    private readonly ILogger<AuditRecorder> _logger;

    public AuditRecorder(IAuditLog audit, ILogger<AuditRecorder> logger)
    {
        _audit = audit;
        _logger = logger;
    }

    public void Record(string actor, string action, string target, string? detail = null)
    {
        try
        {
            _audit.Append(actor, action, target, detail);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _logger.LogError("The audit entry for {Action} could not be written ({ExceptionType}).", action, exception.GetType().Name);
            throw new ConsoleActionException(ConsoleErrorCode.AuditUnavailable, "The audit log could not be written. The change was applied but is not recorded; check the data volume.");
        }
    }
}

/// <summary>Filters the audit log for the Audit page and <c>GET /api/console/audit</c>.</summary>
internal sealed record AuditFilter
{
    /// <summary>Case-insensitive substring of the user.</summary>
    public string? User { get; init; }

    /// <summary>Exact action name, or an area such as <c>key</c> (matches <c>key.*</c>).</summary>
    public string? Action { get; init; }

    /// <summary>Case-insensitive substring of user, action, target or detail.</summary>
    public string? Text { get; init; }

    public DateTimeOffset? From { get; init; }

    public DateTimeOffset? To { get; init; }
}

internal sealed record AuditPage(IReadOnlyList<AuditEntry> Entries, int Total, int Skip, int Take);

internal static class AuditQuery
{
    public const int MaxTake = 500;

    /// <summary>Newest first, filtered, paged. The log itself is append-only; nothing here writes.</summary>
    public static AuditPage Query(this IAuditLog audit, AuditFilter? filter, int skip = 0, int take = 50)
    {
        take = Math.Clamp(take, 1, MaxTake);
        skip = Math.Max(0, skip);
        var all = audit.ReadRecent(100_000);
        var matches = new List<AuditEntry>();
        for (var i = all.Count - 1; i >= 0; i--)
        {
            if (Matches(all[i], filter))
            {
                matches.Add(all[i]);
            }
        }

        return new AuditPage([.. matches.Skip(skip).Take(take)], matches.Count, skip, take);
    }

    public static bool Matches(AuditEntry entry, AuditFilter? filter)
    {
        if (filter is null)
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(filter.User) && !entry.User.Contains(filter.User, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(filter.Action)
            && !(entry.Action.Equals(filter.Action, StringComparison.Ordinal) || entry.Action.StartsWith(filter.Action + ".", StringComparison.Ordinal)))
        {
            return false;
        }

        if (filter.From is { } from && entry.At < from)
        {
            return false;
        }

        if (filter.To is { } to && entry.At > to)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(filter.Text)
            && !(entry.User.Contains(filter.Text, StringComparison.OrdinalIgnoreCase)
                || entry.Action.Contains(filter.Text, StringComparison.OrdinalIgnoreCase)
                || entry.Target.Contains(filter.Text, StringComparison.OrdinalIgnoreCase)
                || (entry.Detail?.Contains(filter.Text, StringComparison.OrdinalIgnoreCase) ?? false)))
        {
            return false;
        }

        return true;
    }
}
