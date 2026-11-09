using EkmMock.Crypto;

namespace EkmMock.Server.Ekm;

internal enum EkmOperation
{
    Info,
    Metadata,
    WrapKey,
    UnwrapKey,
}

internal static class EkmOperations
{
    /// <summary>The last path segment as it appears on the wire (also the <c>op</c> log field).</summary>
    public static string WireName(this EkmOperation operation) => operation switch
    {
        EkmOperation.Info => "info",
        EkmOperation.Metadata => "metadata",
        EkmOperation.WrapKey => "wrapkey",
        EkmOperation.UnwrapKey => "unwrapkey",
        _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, null),
    };

    /// <summary>Name used in messages such as "Operation WrapKey is not allowed on a disabled key".</summary>
    public static string DisplayName(this EkmOperation? operation) => operation switch
    {
        EkmOperation.Info => "Info",
        EkmOperation.Metadata => "Metadata",
        EkmOperation.WrapKey => "WrapKey",
        EkmOperation.UnwrapKey => "UnwrapKey",
        _ => "this operation",
    };

    public static bool TryParseKeyOperation(string segment, out EkmOperation operation)
    {
        // Case-sensitive (spec 4.2).
        switch (segment)
        {
            case "metadata":
                operation = EkmOperation.Metadata;
                return true;
            case "wrapkey":
                operation = EkmOperation.WrapKey;
                return true;
            case "unwrapkey":
                operation = EkmOperation.UnwrapKey;
                return true;
            default:
                operation = default;
                return false;
        }
    }
}

/// <summary>A request path resolved to a namespace, an operation and (for key operations) the still unvalidated key name.</summary>
internal sealed record EkmRoute(NamespaceDefinition Namespace, EkmOperation Operation, string? KeyName);

/// <summary>
/// Routing (spec 4.2). No template routes: the longest configured prefix wins (<see cref="NamespaceResolver"/>), then the
/// remaining segments must be exactly <c>info</c> or <c>{key}/{metadata|wrapkey|unwrapkey}</c>.
/// </summary>
internal static class EkmRouter
{
    /// <returns>Null when no namespace claims the path or the remaining segments are not an EKM operation (the caller answers 404).</returns>
    public static EkmRoute? TryRoute(NamespaceStore namespaces, string? path)
    {
        var match = namespaces.Resolve(path);
        return match is null ? null : TryParse(match);
    }

    public static EkmRoute? TryParse(NamespaceMatch match)
    {
        var segments = match.RemainingSegments;
        if (segments.Count == 1 && segments[0] == "info")
        {
            return new EkmRoute(match.Namespace, EkmOperation.Info, null);
        }

        if (segments.Count == 2 && EkmOperations.TryParseKeyOperation(segments[1], out var operation))
        {
            return new EkmRoute(match.Namespace, operation, segments[0]);
        }

        return null;
    }
}
