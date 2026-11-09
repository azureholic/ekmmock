namespace EkmMock.Crypto;

/// <summary>Name rules shared by the engine and the (later) EKM routing layer.</summary>
public static class EkmNames
{
    public const int MaxKeyNameLength = 64;
    public const int MaxPrefixLength = 64;
    public const string DefaultNamespace = "_default";

    /// <summary>Spec 4.2: <c>^[A-Za-z0-9-]{1,64}$</c>. Hand written so a trailing newline can never slip through.</summary>
    public static bool IsValidKeyName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxKeyNameLength)
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c == '-'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Namespace identifiers: <c>[A-Za-z0-9_-]{1,64}</c> (so <c>_default</c> is valid; ':' is excluded because it delimits the AAD).</summary>
    public static bool IsValidNamespaceName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxKeyNameLength)
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Normalises and validates a path prefix (spec 4.2): leading/trailing slashes are removed, at most 64
    /// characters, only <c>[A-Za-z0-9/-]</c>, no empty segments. The empty result is the default namespace.
    /// </summary>
    public static bool TryNormalizePrefix(
        string? prefix,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? normalized,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(false)] out string? error)
    {
        normalized = null;
        var value = (prefix ?? string.Empty).Trim('/');

        if (value.Length > MaxPrefixLength)
        {
            error = $"Prefix is longer than {MaxPrefixLength} characters";
            return false;
        }

        var previousWasSlash = false;
        foreach (var c in value)
        {
            var isSlash = c == '/';
            if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || isSlash))
            {
                error = "Prefix may only contain letters, digits, '-' and '/'";
                return false;
            }

            if (isSlash && previousWasSlash)
            {
                error = "Prefix must not contain empty segments";
                return false;
            }

            previousWasSlash = isSlash;
        }

        normalized = value;
        error = null;
        return true;
    }
}
