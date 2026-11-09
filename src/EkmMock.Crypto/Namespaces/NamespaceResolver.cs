namespace EkmMock.Crypto;

/// <summary>
/// Pure, ASP.NET-free longest-prefix match (spec 4.2). Matches whole path segments only, case-sensitively,
/// so prefix <c>contoso</c> never matches <c>/contosoX/...</c>. The empty-prefix namespace (<c>_default</c>) matches anything
/// not claimed by a longer prefix; the caller then parses the remaining segments (<c>info</c> or <c>{key}/{op}</c>) and
/// answers 404 when they do not fit.
/// </summary>
public static class NamespaceResolver
{
    /// <param name="namespaces">Defined namespaces (prefixes already normalised).</param>
    /// <param name="path">Request path such as <c>/contoso/prod/my-key/wrapkey</c>; a single trailing slash is tolerated.</param>
    /// <returns>Null when no namespace claims the path or the path contains empty segments.</returns>
    public static NamespaceMatch? Resolve(IReadOnlyList<NamespaceDefinition> namespaces, string? path)
    {
        ArgumentNullException.ThrowIfNull(namespaces);
        if (path is null || path.Contains("//", StringComparison.Ordinal))
        {
            // Empty inner segments are never valid.
            return null;
        }

        var trimmed = path;
        if (trimmed.StartsWith('/'))
        {
            trimmed = trimmed[1..];
        }

        if (trimmed.EndsWith('/'))
        {
            trimmed = trimmed[..^1];
        }

        if (trimmed.Length == 0)
        {
            // The bare "/" path has no operation segment but still belongs to the default namespace.
            return MatchRoot(namespaces);
        }

        NamespaceDefinition? best = null;
        foreach (var candidate in namespaces)
        {
            var prefix = candidate.Prefix;
            if (best is not null && prefix.Length <= best.Prefix.Length)
            {
                continue;
            }

            var matches = prefix.Length == 0
                || (trimmed.StartsWith(prefix, StringComparison.Ordinal)
                    && (trimmed.Length == prefix.Length || trimmed[prefix.Length] == '/'));
            if (matches)
            {
                best = candidate;
            }
        }

        if (best is null)
        {
            return null;
        }

        var rest = best.Prefix.Length == 0
            ? trimmed
            : trimmed.Length == best.Prefix.Length ? string.Empty : trimmed[(best.Prefix.Length + 1)..];
        var segments = rest.Length == 0 ? [] : rest.Split('/');
        return new NamespaceMatch(best, segments);
    }

    private static NamespaceMatch? MatchRoot(IReadOnlyList<NamespaceDefinition> namespaces)
    {
        foreach (var candidate in namespaces)
        {
            if (candidate.Prefix.Length == 0)
            {
                return new NamespaceMatch(candidate, []);
            }
        }

        return null;
    }
}
