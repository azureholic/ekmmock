using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using EkmMock.Crypto.Internal;

namespace EkmMock.Crypto;

/// <summary>
/// Namespaces persisted in <c>namespaces.json</c> (atomic writes, loaded into memory, lock-free reads of an immutable snapshot).
/// Seeding from configuration happens only when the file does not exist yet. Console/audit concerns live elsewhere.
/// </summary>
public sealed class NamespaceStore
{
    private readonly string _path;
    private readonly object _gate = new();
    private volatile IReadOnlyList<NamespaceDefinition> _snapshot;

    private NamespaceStore(string path, IReadOnlyList<NamespaceDefinition> initial)
    {
        _path = path;
        _snapshot = initial;
    }

    /// <summary>Opens (or creates on first change) <c>namespaces.json</c> in <paramref name="dataPath"/>.</summary>
    /// <param name="seed">Configuration seed, used only if the file does not exist.</param>
    public static NamespaceStore Open(string dataPath, IEnumerable<NamespaceDefinition>? seed = null, string fileName = "namespaces.json")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataPath);
        var path = Path.Combine(dataPath, fileName);
        Directory.CreateDirectory(dataPath);
        AtomicFile.DeleteStaleTempFiles(path);

        if (File.Exists(path))
        {
            NamespacesFile? file;
            try
            {
                file = JsonSerializer.Deserialize(File.ReadAllBytes(path), NamespacesJsonContext.Default.NamespacesFile);
            }
            catch (JsonException)
            {
                throw new InvalidDataException("namespaces.json is not valid JSON; refusing to start so it is not overwritten.");
            }

            if (file is null || file.Version != 1)
            {
                throw new InvalidDataException("namespaces.json has an unsupported format version.");
            }

            try
            {
                return new NamespaceStore(path, ValidateSet(file.Namespaces));
            }
            catch (NamespaceException ex)
            {
                throw new InvalidDataException($"namespaces.json is invalid: {ex.Message}");
            }
        }

        var seeded = ValidateSet((seed ?? []).ToList());
        var store = new NamespaceStore(path, seeded);
        if (seeded.Count > 0)
        {
            store.Persist(seeded);
        }

        return store;
    }

    /// <summary>Immutable snapshot, safe to hand to <see cref="NamespaceResolver"/> without locking.</summary>
    public IReadOnlyList<NamespaceDefinition> List() => _snapshot;

    public NamespaceDefinition? Get(string name) => _snapshot.FirstOrDefault(n => n.Name == name);

    /// <summary>Longest-prefix match of a request path against the current namespaces.</summary>
    public NamespaceMatch? Resolve(string? path) => NamespaceResolver.Resolve(_snapshot, path);

    public NamespaceDefinition Add(NamespaceDefinition definition)
    {
        var validated = Validate(definition);
        lock (_gate)
        {
            var current = _snapshot;
            if (current.Any(n => n.Name == validated.Name))
            {
                throw new NamespaceException(NamespaceErrorKind.Duplicate, "A namespace with this name already exists");
            }

            EnsurePrefixFree(current, validated, ignoreName: null);
            Commit([.. current, validated]);
        }

        return validated;
    }

    /// <summary>Replaces the namespace with the same <see cref="NamespaceDefinition.Name"/> (prefix and/or trust changes).</summary>
    public NamespaceDefinition Update(NamespaceDefinition definition)
    {
        var validated = Validate(definition);
        lock (_gate)
        {
            var current = _snapshot;
            if (!current.Any(n => n.Name == validated.Name))
            {
                throw new NamespaceException(NamespaceErrorKind.NotFound, "Namespace not found");
            }

            EnsurePrefixFree(current, validated, ignoreName: validated.Name);
            Commit([.. current.Select(n => n.Name == validated.Name ? validated : n)]);
        }

        return validated;
    }

    public NamespaceDefinition SetTrust(string name, ClientTrust trust)
    {
        var existing = Get(name) ?? throw new NamespaceException(NamespaceErrorKind.NotFound, "Namespace not found");
        return Update(existing with { ClientTrust = trust });
    }

    /// <summary>Removes a namespace definition. Keys in the key store are not touched.</summary>
    public bool Remove(string name)
    {
        lock (_gate)
        {
            var current = _snapshot;
            if (!current.Any(n => n.Name == name))
            {
                return false;
            }

            Commit([.. current.Where(n => n.Name != name)]);
            return true;
        }
    }

    // Caller holds _gate. Persist first, then publish, so a failed write leaves memory and disk consistent.
    private void Commit(IReadOnlyList<NamespaceDefinition> next)
    {
        Persist(next);
        _snapshot = next;
    }

    private void Persist(IReadOnlyList<NamespaceDefinition> namespaces)
    {
        var file = new NamespacesFile { Namespaces = [.. namespaces.OrderBy(static n => n.Name, StringComparer.Ordinal)] };
        AtomicFile.Write(_path, JsonSerializer.SerializeToUtf8Bytes(file, NamespacesJsonContext.Default.NamespacesFile));
    }

    private static void EnsurePrefixFree(IReadOnlyList<NamespaceDefinition> current, NamespaceDefinition candidate, string? ignoreName)
    {
        if (current.Any(n => n.Name != ignoreName && n.Prefix == candidate.Prefix))
        {
            throw new NamespaceException(NamespaceErrorKind.Duplicate, "Another namespace already uses this prefix");
        }
    }

    private static List<NamespaceDefinition> ValidateSet(List<NamespaceDefinition> definitions)
    {
        var result = new List<NamespaceDefinition>(definitions.Count);
        foreach (var definition in definitions)
        {
            var validated = Validate(definition);
            if (result.Any(n => n.Name == validated.Name))
            {
                throw new NamespaceException(NamespaceErrorKind.Duplicate, "Duplicate namespace name");
            }

            EnsurePrefixFree(result, validated, ignoreName: null);
            result.Add(validated);
        }

        return result;
    }

    /// <summary>Validates a definition and returns its normalised form (prefix slashes trimmed, trust de-duplicated).</summary>
    public static NamespaceDefinition Validate(NamespaceDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);

        if (!EkmNames.IsValidNamespaceName(definition.Name))
        {
            throw new NamespaceException(NamespaceErrorKind.InvalidName, "Namespace name must match [A-Za-z0-9_-]{1,64}");
        }

        if (!EkmNames.TryNormalizePrefix(definition.Prefix, out var prefix, out var prefixError))
        {
            throw new NamespaceException(NamespaceErrorKind.InvalidPrefix, prefixError);
        }

        var isDefaultName = definition.Name == EkmNames.DefaultNamespace;
        if (isDefaultName != (prefix.Length == 0))
        {
            throw new NamespaceException(
                NamespaceErrorKind.InvalidPrefix,
                $"The no-prefix namespace must be named {EkmNames.DefaultNamespace}, and only it may have an empty prefix");
        }

        return definition with { Prefix = prefix, ClientTrust = ValidateTrust(definition.ClientTrust) };
    }

    private static ClientTrust ValidateTrust(ClientTrust? trust)
    {
        trust ??= new ClientTrust();

        var commonNames = new List<string>();
        foreach (var cn in trust.SubjectCommonNames ?? [])
        {
            if (string.IsNullOrWhiteSpace(cn) || cn.Length > 253 || cn.Any(char.IsControl))
            {
                throw new NamespaceException(NamespaceErrorKind.InvalidTrust, "A subject common name is empty, too long or contains control characters");
            }

            // Case-sensitive, exact match semantics; keep the first occurrence only.
            if (!commonNames.Contains(cn, StringComparer.Ordinal))
            {
                commonNames.Add(cn);
            }
        }

        var certificates = new List<string>();
        var index = 0;
        foreach (var base64 in trust.CaCertificatesDerBase64 ?? [])
        {
            index++;
            try
            {
                using var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(base64));
            }
            catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException or ArgumentNullException)
            {
                throw new NamespaceException(NamespaceErrorKind.InvalidTrust, $"CA certificate #{index} is not valid base64 DER");
            }

            if (!certificates.Contains(base64, StringComparer.Ordinal))
            {
                certificates.Add(base64);
            }
        }

        return new ClientTrust { SubjectCommonNames = commonNames, CaCertificatesDerBase64 = certificates };
    }
}
