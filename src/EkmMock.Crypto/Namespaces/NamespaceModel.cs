using System.Text.Json.Serialization;

namespace EkmMock.Crypto;

/// <summary>
/// Who may call a namespace (spec 5.1, 6.3): exact, case-sensitive subject CNs plus the root CA certificates
/// (base64 DER) the client chain must build to. Trust is never by fingerprint.
/// Property names match the <c>SeedNamespaces</c> section of appsettings.json.
/// </summary>
public sealed record ClientTrust
{
    public IReadOnlyList<string> SubjectCommonNames { get; init; } = [];

    public IReadOnlyList<string> CaCertificatesDerBase64 { get; init; } = [];
}

/// <summary>A namespace: one path prefix, its client trust and (by name) its keys. The no-prefix namespace is <c>_default</c>.</summary>
public sealed record NamespaceDefinition
{
    public string Name { get; init; } = string.Empty;

    /// <summary>Path prefix without leading/trailing slash, for example <c>contoso/prod</c>; empty for <c>_default</c>.</summary>
    public string Prefix { get; init; } = string.Empty;

    public ClientTrust ClientTrust { get; init; } = new();
}

public enum NamespaceErrorKind
{
    InvalidName,
    InvalidPrefix,
    InvalidTrust,
    Duplicate,
    NotFound,
}

/// <summary>Namespace/trust validation or conflict failure. Messages never contain certificate contents.</summary>
public sealed class NamespaceException : Exception
{
    public NamespaceException(NamespaceErrorKind kind, string message)
        : base(message)
    {
        Kind = kind;
    }

    public NamespaceErrorKind Kind { get; }
}

/// <summary>Result of resolving a request path: the namespace and the path segments after its prefix.</summary>
public sealed record NamespaceMatch(NamespaceDefinition Namespace, IReadOnlyList<string> RemainingSegments);

// Source-generated persistence model (snake_case) for namespaces.json.
internal sealed class NamespacesFile
{
    public int Version { get; set; } = 1;

    public List<NamespaceDefinition> Namespaces { get; set; } = [];
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, WriteIndented = true)]
[JsonSerializable(typeof(NamespacesFile))]
internal sealed partial class NamespacesJsonContext : JsonSerializerContext
{
}
