using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Crypto;
using EkmMock.Server.Tls;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.WebConsole;

/// <summary>A trusted CA certificate as the console shows it: public facts only, plus the problems that make it useless or risky as a trust anchor.</summary>
internal sealed record CaCertificateView(
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string ThumbprintSha256,
    bool IsSelfSigned,
    bool IsCa,
    bool IsExpired,
    bool IsNotYetValid,
    bool IsConsoleTestCa,
    IReadOnlyList<string> Warnings,
    string DerBase64);

internal sealed record NamespaceView(
    string Name,
    string Prefix,
    string DisplayPrefix,
    IReadOnlyList<string> SubjectCommonNames,
    IReadOnlyList<CaCertificateView> CaCertificates,
    int KeyCount,
    int DestroyedKeyCount,
    string AzCommand,
    IReadOnlyList<string> Warnings,
    bool TrustsConsoleTestClient);

internal sealed record NamespaceChange(string Name, string Prefix, IReadOnlyList<string>? SubjectCommonNames, IReadOnlyList<string>? CaCertificatesDerBase64);

/// <summary>What a trust import would do (or did). Built before anything is saved so that the user can review the CN and every CA.</summary>
internal sealed record TrustPreview(
    string Namespace,
    string Format,
    string Mode,
    IReadOnlyList<string> SubjectCommonNames,
    IReadOnlyList<CaCertificateView> CaCertificates,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> ResultingSubjectCommonNames,
    int ResultingCaCount,
    bool Saved);

internal static class TrustImportModes
{
    public const string Merge = "merge";
    public const string Replace = "replace";
}

/// <summary>
/// Namespace and client-trust management of the console (spec 8.5.6), shared by the page and <c>/api/console/namespaces</c>. Changes go to <see cref="NamespaceStore"/>
/// (atomic write of <c>namespaces.json</c>) and <see cref="Tls.ClientTrustProvider"/> picks up the new list on the next handshake: no restart.
/// </summary>
internal sealed class NamespaceAdminService
{
    public const int MaxTrustInputChars = 262_144;

    private readonly NamespaceStore _namespaces;
    private readonly IKeyManager _keys;
    private readonly AuditRecorder _audit;
    private readonly ConsoleTestIdentity _testIdentity;
    private readonly IServiceProvider _services;
    private readonly TlsOptions _tls;
    private readonly TimeProvider _time;

    public NamespaceAdminService(
        NamespaceStore namespaces,
        IKeyManager keys,
        AuditRecorder audit,
        ConsoleTestIdentity testIdentity,
        IServiceProvider services,
        IOptions<TlsOptions> tls,
        TimeProvider time)
    {
        _namespaces = namespaces;
        _keys = keys;
        _audit = audit;
        _testIdentity = testIdentity;
        _services = services;
        _tls = tls.Value;
        _time = time;
    }

    public IReadOnlyList<NamespaceView> List()
    {
        var all = _namespaces.List();
        var keys = SafeKeys();
        return [.. all.OrderBy(static n => n.Name, StringComparer.Ordinal).Select(n => ToView(n, all, keys))];
    }

    public NamespaceView Get(string name)
    {
        var all = _namespaces.List();
        var definition = all.FirstOrDefault(n => n.Name == name) ?? throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Namespace not found.");
        return ToView(definition, all, SafeKeys());
    }

    public NamespaceView Create(string actor, NamespaceChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        var definition = new NamespaceDefinition
        {
            Name = change.Name,
            Prefix = change.Prefix,
            ClientTrust = new ClientTrust
            {
                SubjectCommonNames = [.. change.SubjectCommonNames ?? []],
                CaCertificatesDerBase64 = [.. change.CaCertificatesDerBase64 ?? []],
            },
        };

        NamespaceDefinition saved;
        try
        {
            saved = _namespaces.Add(definition);
        }
        catch (NamespaceException exception)
        {
            throw ConsoleActionException.From(exception);
        }

        _audit.Record(actor, AuditActions.NamespaceCreate, Target(saved.Name), $"prefix=/{saved.Prefix} cns={saved.ClientTrust.SubjectCommonNames.Count} cas={saved.ClientTrust.CaCertificatesDerBase64.Count}");
        return Get(saved.Name);
    }

    /// <summary>Changes the prefix and/or replaces the trust lists of an existing namespace (the name cannot change: keys belong to it by name). Null lists keep what is there.</summary>
    public NamespaceView Update(string actor, NamespaceChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        var existing = _namespaces.Get(change.Name) ?? throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Namespace not found.");
        var updated = existing with
        {
            Prefix = change.Prefix,
            ClientTrust = new ClientTrust
            {
                SubjectCommonNames = change.SubjectCommonNames is null ? existing.ClientTrust.SubjectCommonNames : [.. change.SubjectCommonNames],
                CaCertificatesDerBase64 = change.CaCertificatesDerBase64 is null ? existing.ClientTrust.CaCertificatesDerBase64 : [.. change.CaCertificatesDerBase64],
            },
        };

        NamespaceDefinition saved;
        try
        {
            saved = _namespaces.Update(updated);
        }
        catch (NamespaceException exception)
        {
            throw ConsoleActionException.From(exception);
        }

        _audit.Record(actor, AuditActions.NamespaceUpdate, Target(saved.Name), $"prefix=/{saved.Prefix} cns={saved.ClientTrust.SubjectCommonNames.Count} cas={saved.ClientTrust.CaCertificatesDerBase64.Count}");
        return Get(saved.Name);
    }

    /// <summary>
    /// Deletes a namespace. Rules (DECISIONS "M6: Namespace delete"): the namespace name must be typed (<paramref name="confirmName"/>) every time; while it still has
    /// keys that are not destroyed the delete is refused unless <paramref name="destroyKeys"/> is set, in which case every one of those keys is destroyed first
    /// (irreversibly, each with its own <c>key.destroy</c> audit entry). Tombstones of already destroyed keys stay in the key store and keep their names reserved.
    /// </summary>
    /// <returns>The number of keys that were destroyed.</returns>
    public int Delete(string actor, string name, string? confirmName, bool destroyKeys)
    {
        var existing = _namespaces.Get(name) ?? throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Namespace not found.");
        if (!string.Equals(confirmName, name, StringComparison.Ordinal))
        {
            throw new ConsoleActionException(ConsoleErrorCode.ConfirmationMismatch, "Type the exact namespace name to confirm. Nothing was changed.");
        }

        var live = SafeKeys().Where(k => k.Namespace == name && k.State != KeyState.Destroyed).ToList();
        if (live.Count > 0 && !destroyKeys)
        {
            throw new ConsoleActionException(
                ConsoleErrorCode.Conflict,
                $"The namespace still has {live.Count} key(s) that are not destroyed. Destroy them first, or confirm that deleting the namespace destroys all of them (irreversible).");
        }

        // Audit first, change second, for every irreversible step (security review L3): each key destroy and the namespace delete are written before they are applied.
        foreach (var key in live)
        {
            _audit.Intend(actor, AuditActions.KeyDestroy, $"key:{name}/{key.Name}", "irreversible crypto-shred, via namespace.delete", () =>
            {
                try
                {
                    _keys.Destroy(key.Ref, actor);
                }
                catch (EkmEngineException exception)
                {
                    throw ConsoleActionException.From(exception);
                }
            });
        }

        _audit.Intend(actor, AuditActions.NamespaceDelete, Target(name), $"destroyed_keys={live.Count}", () =>
        {
            if (!_namespaces.Remove(existing.Name))
            {
                throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Namespace not found.");
            }
        });
        return live.Count;
    }

    /// <summary>Parses client trust input without saving, so the page can show the CN and every CA before the user commits.</summary>
    public TrustPreview Preview(string ns, string content, string? format = null, IEnumerable<string>? subjectCommonNames = null, string mode = TrustImportModes.Merge)
        => BuildPreview(ns, content, format, subjectCommonNames, mode, out _);

    /// <summary>
    /// Imports trust into a namespace. With <paramref name="dryRun"/> nothing is saved (the same preview is returned). <see cref="TrustImportModes.Merge"/> adds the CNs and
    /// CAs to what the namespace already trusts; <see cref="TrustImportModes.Replace"/> replaces both lists.
    /// </summary>
    public TrustPreview Import(string actor, string ns, string content, string? format = null, IEnumerable<string>? subjectCommonNames = null, string mode = TrustImportModes.Merge, bool dryRun = false)
    {
        var preview = BuildPreview(ns, content, format, subjectCommonNames, mode, out var resulting);
        if (dryRun)
        {
            return preview;
        }

        // Trust decides who may call the endpoint, so the import is audited before it is applied (security review L3).
        _audit.Intend(actor, AuditActions.TrustImport, Target(ns), $"mode={preview.Mode} format={preview.Format} cns={preview.ResultingSubjectCommonNames.Count} cas={preview.ResultingCaCount}", () =>
        {
            try
            {
                _namespaces.SetTrust(ns, resulting);
            }
            catch (NamespaceException exception)
            {
                throw ConsoleActionException.From(exception);
            }
        });
        return preview with { Saved = true };
    }

    /// <summary>The one-click "trust the console test CA in this namespace" of the Playground and Replay (audited). Earlier test CAs of other runs are replaced, not piled up.</summary>
    public NamespaceView TrustConsoleTestClient(string actor, string ns)
    {
        var existing = _namespaces.Get(ns) ?? throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Namespace not found.");
        var cas = existing.ClientTrust.CaCertificatesDerBase64.Where(der => !IsTestCa(der)).ToList();
        cas.Add(_testIdentity.CaDerBase64);
        var cns = existing.ClientTrust.SubjectCommonNames.Contains(ConsoleTestIdentity.CommonName, StringComparer.Ordinal)
            ? existing.ClientTrust.SubjectCommonNames
            : [.. existing.ClientTrust.SubjectCommonNames, ConsoleTestIdentity.CommonName];

        _audit.Intend(actor, AuditActions.TrustTestClient, Target(ns), $"cn={ConsoleTestIdentity.CommonName}", () =>
        {
            try
            {
                _namespaces.SetTrust(ns, new ClientTrust { SubjectCommonNames = cns, CaCertificatesDerBase64 = cas });
            }
            catch (NamespaceException exception)
            {
                throw ConsoleActionException.From(exception);
            }
        });
        return Get(ns);
    }

    /// <summary>True when the namespace already trusts the current console test CA and the test client's common name.</summary>
    public bool TrustsConsoleTestClient(string ns)
        => _namespaces.Get(ns) is { } definition && TrustsTestClient(definition);

    /// <summary>The command that points Managed HSM at this namespace (spec 15). <c>&lt;hsm&gt;</c> is a placeholder; the host comes from <c>Tls:ServerName</c> or the certificate SAN.</summary>
    public string AzCreateCommand(NamespaceDefinition definition, string hsm = "<hsm>")
    {
        var command = $"az keyvault ekm-connection create --hsm-name {hsm} --host {HostForCommand()} --server-ca-certificate root-ca.pem";
        return definition.Prefix.Length == 0 ? command : command + $" --path-prefix /{definition.Prefix}";
    }

    // ---- internals ----

    private TrustPreview BuildPreview(string ns, string content, string? format, IEnumerable<string>? subjectCommonNames, string mode, out ClientTrust resulting)
    {
        var existing = _namespaces.Get(ns) ?? throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Namespace not found.");
        if (string.IsNullOrWhiteSpace(content))
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "Paste the JSON of 'az keyvault ekm-connection certificate show' or PEM certificates.");
        }

        if (content.Length > MaxTrustInputChars)
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The trust input is too large.");
        }

        if (mode is not (TrustImportModes.Merge or TrustImportModes.Replace))
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The import mode must be 'merge' or 'replace'.");
        }

        var detected = DetectFormat(content, format);
        TrustImportResult imported;
        try
        {
            imported = detected == "json" ? TrustImporter.FromAzureCliJson(content) : TrustImporter.FromPem(content, subjectCommonNames);
        }
        catch (NamespaceException exception)
        {
            throw ConsoleActionException.From(exception);
        }

        var importedCas = imported.Trust.CaCertificatesDerBase64.Select(CaView).ToList();
        var importedCns = imported.Trust.SubjectCommonNames;

        var warnings = new List<string>();
        if (importedCns.Count == 0)
        {
            warnings.Add(detected == "json"
                ? "The JSON has no subjectCommonName: no caller will be authorized until a common name is added."
                : "PEM carries no common name: add the Managed HSM client certificate common name, or no caller will be authorized.");
        }

        foreach (var ca in importedCas)
        {
            warnings.AddRange(ca.Warnings.Select(w => $"{ShortSubject(ca.Subject)}: {w}"));
        }

        var finalCns = mode == TrustImportModes.Replace
            ? importedCns
            : [.. existing.ClientTrust.SubjectCommonNames, .. importedCns.Where(cn => !existing.ClientTrust.SubjectCommonNames.Contains(cn, StringComparer.Ordinal))];
        var finalCas = mode == TrustImportModes.Replace
            ? imported.Trust.CaCertificatesDerBase64
            : [.. existing.ClientTrust.CaCertificatesDerBase64, .. imported.Trust.CaCertificatesDerBase64.Where(der => !existing.ClientTrust.CaCertificatesDerBase64.Contains(der, StringComparer.Ordinal))];

        if (mode == TrustImportModes.Replace && existing.ClientTrust.CaCertificatesDerBase64.Any(IsTestCa) && !finalCas.Any(IsTestCa))
        {
            warnings.Add("Replacing removes the console test CA from this namespace: the Playground and Replay need the one-click 'trust the test CA' again.");
        }

        resulting = new ClientTrust { SubjectCommonNames = finalCns, CaCertificatesDerBase64 = finalCas };
        try
        {
            resulting = NamespaceStore.Validate(new NamespaceDefinition { Name = existing.Name, Prefix = existing.Prefix, ClientTrust = resulting }).ClientTrust;
        }
        catch (NamespaceException exception)
        {
            throw ConsoleActionException.From(exception);
        }

        return new TrustPreview(ns, detected, mode, importedCns, importedCas, warnings, resulting.SubjectCommonNames, resulting.CaCertificatesDerBase64.Count, Saved: false);
    }

    private static string DetectFormat(string content, string? format)
    {
        var requested = format?.ToLowerInvariant();
        if (requested is "json" or "pem")
        {
            return requested;
        }

        return content.TrimStart().StartsWith('{') ? "json" : "pem";
    }

    private NamespaceView ToView(NamespaceDefinition definition, IReadOnlyList<NamespaceDefinition> all, IReadOnlyList<KeyInfo> keys)
    {
        var cas = definition.ClientTrust.CaCertificatesDerBase64.Select(CaView).ToList();
        var warnings = new List<string>();

        if (definition.ClientTrust.SubjectCommonNames.Count == 0 && cas.Count == 0)
        {
            warnings.Add("No client trust yet: every caller gets 401 Unauthenticated. Import the Managed HSM trust or trust the console test CA.");
        }
        else if (definition.ClientTrust.SubjectCommonNames.Count == 0)
        {
            warnings.Add("No allowed common name: no caller can be authorized.");
        }
        else if (cas.Count == 0)
        {
            warnings.Add("No trusted CA: no caller can be authorized.");
        }

        foreach (var ca in cas)
        {
            warnings.AddRange(ca.Warnings.Select(w => $"{ShortSubject(ca.Subject)}: {w}"));
        }

        foreach (var other in all.Where(o => o.Name != definition.Name && Overlaps(definition.Prefix, o.Prefix)))
        {
            warnings.Add($"The prefix overlaps with namespace '{other.Name}' (/{other.Prefix}). That is allowed: the longest matching prefix wins for each request.");
        }

        if (definition.Prefix.Length > 0 && !definition.Prefix.Contains('/', StringComparison.Ordinal)
            && keys.Any(k => k.Namespace == EkmNames.DefaultNamespace && k.State != KeyState.Destroyed && k.Name == definition.Prefix))
        {
            warnings.Add($"A key named '{definition.Prefix}' exists in _default: its path /{definition.Prefix}/wrapkey now belongs to this namespace (longest prefix wins).");
        }

        var mine = keys.Where(k => k.Namespace == definition.Name).ToList();
        return new NamespaceView(
            definition.Name,
            definition.Prefix,
            definition.Prefix.Length == 0 ? "(no prefix)" : "/" + definition.Prefix,
            definition.ClientTrust.SubjectCommonNames,
            cas,
            mine.Count(static k => k.State != KeyState.Destroyed),
            mine.Count(static k => k.State == KeyState.Destroyed),
            AzCreateCommand(definition),
            warnings,
            TrustsTestClient(definition));
    }

    // Two non-empty prefixes overlap when one is a whole-segment prefix of the other (contoso and contoso/prod). The empty _default prefix overlaps with everything by design and is not reported.
    private static bool Overlaps(string a, string b)
        => a.Length > 0 && b.Length > 0 && (a.StartsWith(b + "/", StringComparison.Ordinal) || b.StartsWith(a + "/", StringComparison.Ordinal));

    private bool TrustsTestClient(NamespaceDefinition definition)
        => definition.ClientTrust.SubjectCommonNames.Contains(ConsoleTestIdentity.CommonName, StringComparer.Ordinal)
            && definition.ClientTrust.CaCertificatesDerBase64.Contains(_testIdentity.CaDerBase64, StringComparer.Ordinal);

    private CaCertificateView CaView(string derBase64)
    {
        using var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(derBase64));
        var now = _time.GetUtcNow();
        var notBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero);
        var notAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        var selfSigned = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
        var basic = certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        var isCa = basic?.CertificateAuthority ?? false;
        var expired = notAfter <= now;
        var notYetValid = notBefore > now;

        var warnings = new List<string>();
        if (expired)
        {
            warnings.Add($"expired on {notAfter:yyyy-MM-dd}; clients below it are not authenticated.");
        }
        else if (notYetValid)
        {
            warnings.Add($"not valid before {notBefore:yyyy-MM-dd}.");
        }

        if (!isCa)
        {
            warnings.Add("this is not a CA certificate (basicConstraints CA=false or missing): it looks like a leaf certificate instead of the root CA, so it will not authenticate anyone.");
        }
        else if (!selfSigned)
        {
            warnings.Add("this is an issuing CA, not a self-signed root. EkmMock trusts by ROOT CA only (custom root trust): paste the root, otherwise no client chain can end in it (open question 18).");
        }

        return new CaCertificateView(
            certificate.Subject,
            certificate.Issuer,
            notBefore,
            notAfter,
            certificate.GetCertHashString(HashAlgorithmName.SHA256),
            selfSigned,
            isCa,
            expired,
            notYetValid,
            ConsoleTestIdentity.IsConsoleTestCaSubject(certificate.Subject),
            warnings,
            derBase64);
    }

    private static bool IsTestCa(string derBase64)
    {
        try
        {
            using var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(derBase64));
            return ConsoleTestIdentity.IsConsoleTestCaSubject(certificate.Subject);
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            return false;
        }
    }

    private string HostForCommand()
    {
        if (!string.IsNullOrWhiteSpace(_tls.ServerName))
        {
            return _tls.ServerName;
        }

        // Resolved lazily: the provider throws when no certificate is configured, which must not stop a namespace listing from working.
        try
        {
            var dns = _services.GetRequiredService<IServerCertificateProvider>().Info.SubjectAlternativeNames
                .Where(static n => n.StartsWith("DNS:", StringComparison.Ordinal))
                .Select(static n => n[4..])
                .FirstOrDefault(static n => !n.Equals("localhost", StringComparison.OrdinalIgnoreCase));
            return dns ?? "<fqdn>";
        }
        catch (InvalidOperationException)
        {
            return "<fqdn>";
        }
    }

    private IReadOnlyList<KeyInfo> SafeKeys()
    {
        try
        {
            return _keys.List();
        }
        catch (EkmEngineException)
        {
            return [];
        }
    }

    private static string ShortSubject(string subject) => subject.Length <= 60 ? subject : subject[..60] + "…";

    private static string Target(string name) => $"namespace:{name}";
}
