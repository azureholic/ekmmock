using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using EkmMock.Pki;
using EkmMock.Server.Hosting;
using EkmMock.Server.Tls;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.WebConsole;

/// <summary>The served EKM server certificate as the console shows it: public facts only. The private key is never part of a view.</summary>
internal sealed record ServerCertificateView(
    string Subject,
    string Issuer,
    IReadOnlyList<string> SubjectAlternativeNames,
    IReadOnlyList<string> Chain,
    int ChainLength,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    int DaysRemaining,
    string ThumbprintSha256,
    string Source,
    DateTimeOffset LoadedAt,
    bool ExpiresSoon,
    bool IsExpired,
    bool IsDevelopmentCertificate);

internal sealed record TlsPolicyView(string Protocol, IReadOnlyList<string> PermittedCipherSuites, string Enforcement, string Summary, bool CipherSuitesEnforced);

internal sealed record CertificatePageModel(
    ServerCertificateView Certificate,
    string? LastError,
    DateTimeOffset? LastErrorAt,
    TlsPolicyView Tls,
    string? ConfiguredServerName,
    IReadOnlyList<string> Warnings,
    bool RootCaAvailable,
    string? RootCaSubject,
    string StorageNote);

/// <summary>The result of generating test PKI: the new certificate and the root CA's <em>public</em> certificate. The CA's private key does not exist any more.</summary>
internal sealed record GeneratedPki(ServerCertificateView Certificate, string RootCaPem, string RootCaThumbprintSha256, string RootCaSubject);

/// <summary>
/// The server certificate actions of the console (spec 8.5.7, 5.3), shared by the Certificates page and <c>/api/console/certificates</c>. The uploaded private key is
/// handed to <see cref="IServerCertificateProvider.ReplaceAsync"/> and nothing else: it is not logged, not echoed in an error, not in the audit entry and not returned.
/// </summary>
internal sealed class CertificateAdminService
{
    public const string RootCaFileName = "root-ca.pem";
    public const int MaxPemChars = 131_072;

    private static readonly Regex DnsNamePattern = new(
        @"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(250));

    private readonly IServerCertificateProvider _certificates;
    private readonly TlsPolicy _policy;
    private readonly TlsOptions _tls;
    private readonly AuditRecorder _audit;
    private readonly string _dataTlsFolder;
    private readonly TimeProvider _time;

    public CertificateAdminService(
        IServerCertificateProvider certificates,
        TlsPolicy policy,
        IOptions<TlsOptions> tls,
        IOptions<DataOptions> data,
        AuditRecorder audit,
        TimeProvider time)
    {
        _certificates = certificates;
        _policy = policy;
        _tls = tls.Value;
        _audit = audit;
        _time = time;
        _dataTlsFolder = Path.Combine(Path.GetFullPath(data.Value.Path), ServerCertificateProvider.ManagedFolderName);
    }

    public CertificatePageModel GetPage()
    {
        var info = _certificates.Info;
        var view = ToView(_certificates.Current);
        var warnings = new List<string>();
        if (info.IsExpired)
        {
            warnings.Add($"The server certificate EXPIRED on {info.NotAfterUtc:yyyy-MM-dd}: clients refuse it. Upload or generate a new one.");
        }
        else if (info.ExpiresSoon)
        {
            warnings.Add($"The server certificate expires in {view.DaysRemaining} day(s) ({info.NotAfterUtc:yyyy-MM-dd}); the warning starts {_tls.ExpiryWarningDays} days before expiry.");
        }

        if (info.IsDevelopmentCertificate)
        {
            warnings.Add("This is the throw-away development certificate for localhost. Managed HSM cannot use it: generate test PKI for your FQDN or upload a certificate.");
        }

        if (!string.IsNullOrWhiteSpace(_tls.ServerName) && !CoversHost(info.SubjectAlternativeNames, _tls.ServerName))
        {
            warnings.Add($"No SAN of the certificate matches the configured server name '{_tls.ServerName}' (Tls:ServerName). Managed HSM checks the SAN against the --host value.");
        }

        if (info.SubjectAlternativeNames.Count == 0)
        {
            warnings.Add("The certificate has no subject alternative name; Managed HSM requires the host name in the SAN.");
        }

        var root = ReadRootCa();
        var error = _certificates.LastError;
        return new CertificatePageModel(
            view,
            error?.Message,
            error?.AtUtc,
            TlsPolicyView(),
            _tls.ServerName,
            warnings,
            root is not null,
            root?.Subject,
            _tls.HasFiles
                ? "Uploaded and generated certificates are written to the configured Tls:CertFile and Tls:KeyFile."
                : "Uploaded and generated certificates are saved on the data volume in the tls folder (the key with owner-only permissions where the OS supports them) and loaded again after a restart.");
    }

    public TlsPolicyView TlsPolicyView()
    {
        var effective = _policy.Effective;
        return new TlsPolicyView(
            effective.Protocol,
            effective.PermittedCipherSuites,
            effective.CipherSuiteEnforcement.ToString(),
            effective.CipherSuiteSummary,
            effective.CipherSuiteEnforcement == CipherSuiteEnforcement.EnforcedByTlsStack);
    }

    /// <summary>
    /// Validates and installs a certificate chain with its private key and serves it to new connections (hot reload). The input is checked first: at least one certificate,
    /// an unencrypted private key, a SAN, and the key must belong to the certificate (the provider checks that). On any problem the served certificate stays as it was.
    /// </summary>
    public async Task<ServerCertificateView> UploadAsync(string actor, string? certificatePem, string? privateKeyPem, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(certificatePem) || string.IsNullOrWhiteSpace(privateKeyPem))
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "Provide the certificate chain (PEM) and its private key (PEM).");
        }

        if (certificatePem.Length > MaxPemChars || privateKeyPem.Length > MaxPemChars)
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The certificate or key input is too large.");
        }

        RequireSan(certificatePem);
        RequireUnencryptedKey(privateKeyPem);

        try
        {
            await _certificates.ReplaceAsync(certificatePem, privateKeyPem, cancellationToken, ServerCertificateSource.Uploaded).ConfigureAwait(false);
        }
        catch (ServerCertificateException exception)
        {
            // The message is fixed text ("key does not belong to the certificate", ...), never file or key content.
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, exception.Message + ". The previous certificate is still served.");
        }

        DeleteRootCa();
        var view = ToView(_certificates.Current);
        _audit.Record(actor, AuditActions.CertificateUpload, $"certificate:{Short(view.ThumbprintSha256)}", $"san={string.Join(',', view.SubjectAlternativeNames)}");
        return view;
    }

    /// <summary>
    /// Generates a test root CA and a server certificate for <paramref name="hostNames"/> (DNS names or IP addresses), serves it and keeps the root CA certificate for download.
    /// <b>CA key policy:</b> the root CA's private key exists only inside this method and is discarded after the server certificate is signed; it is not stored, not
    /// encrypted under the master key, and not downloadable. To re-issue, generate again (a new root: update <c>--server-ca-certificate</c>).
    /// </summary>
    public async Task<GeneratedPki> GenerateTestPkiAsync(string actor, IEnumerable<string> hostNames, CancellationToken cancellationToken = default)
    {
        var names = ParseHostNames(hostNames);
        string rootPem;
        string rootThumbprint;
        string rootSubject;
        using (var root = CertificateAuthority.CreateRoot("EkmMock Test Root CA " + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)), PkiKeyAlgorithm.Rsa2048))
        using (var server = root.IssueServer(names, TimeSpan.FromDays(397)))
        {
            rootPem = root.CertificatePem;
            rootSubject = root.Subject;
            rootThumbprint = Convert.ToHexString(SHA256.HashData(root.Der));
            try
            {
                await _certificates.ReplaceAsync(server.ChainPem, server.PrivateKeyPem, cancellationToken, ServerCertificateSource.ConsoleGenerated).ConfigureAwait(false);
            }
            catch (ServerCertificateException exception)
            {
                throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, exception.Message + ". The previous certificate is still served.");
            }
        }

        // The root's private key is gone here (the using scope disposed it); what is kept for download is the public certificate only.
        Directory.CreateDirectory(_dataTlsFolder);
        await File.WriteAllTextAsync(Path.Combine(_dataTlsFolder, RootCaFileName), rootPem, cancellationToken).ConfigureAwait(false);

        var view = ToView(_certificates.Current);
        _audit.Record(actor, AuditActions.CertificateGenerate, $"certificate:{names[0]}", $"san={string.Join(',', names)} thumbprint={Short(view.ThumbprintSha256)} root={Short(rootThumbprint)}");
        return new GeneratedPki(view, rootPem, rootThumbprint, rootSubject);
    }

    /// <summary>
    /// The public root CA certificate to pass as <c>--server-ca-certificate</c>: the one saved by "generate test PKI" while it still issued the served certificate, or the
    /// dev-mode root while the generated localhost certificate is served. Null otherwise (an uploaded chain: use the CA that issued it).
    /// </summary>
    public string? GetRootCaPem() => ReadRootCa()?.Pem;

    // ---- internals ----

    private (string Pem, string Subject)? ReadRootCa()
    {
        var current = _certificates.Current;
        var path = Path.Combine(_dataTlsFolder, RootCaFileName);
        if (File.Exists(path))
        {
            try
            {
                var pem = File.ReadAllText(path);
                using var root = X509Certificate2.CreateFromPem(pem);

                // Only while it still is the issuer of what is served: a stale file from an earlier generation would send the user to the wrong CA.
                if (string.Equals(root.Subject, current.Certificate.Issuer, StringComparison.Ordinal))
                {
                    return (pem, root.Subject);
                }
            }
            catch (Exception exception) when (exception is IOException or CryptographicException or ArgumentException)
            {
                // Unreadable: treated as not available.
            }
        }

        if (current.Source == ServerCertificateSource.DevelopmentGenerated && _certificates.DevelopmentRootCaPem is { } devPem)
        {
            using var dev = X509Certificate2.CreateFromPem(devPem);
            return (devPem, dev.Subject);
        }

        return null;
    }

    private void DeleteRootCa()
    {
        try
        {
            File.Delete(Path.Combine(_dataTlsFolder, RootCaFileName));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A stale file is filtered by the issuer check in ReadRootCa anyway.
        }
    }

    private ServerCertificateView ToView(ServerCertificateSnapshot snapshot)
    {
        var info = snapshot.ToInfo(_time.GetUtcNow(), _tls.ExpiryWarningDays);
        return new ServerCertificateView(
            info.Subject,
            info.Issuer,
            info.SubjectAlternativeNames,
            snapshot.ChainSubjects,
            info.ChainLength,
            info.NotBeforeUtc,
            info.NotAfterUtc,
            (int)Math.Floor((info.NotAfterUtc - _time.GetUtcNow()).TotalDays),
            info.ThumbprintSha256,
            info.Source.ToString(),
            info.LoadedAtUtc,
            info.ExpiresSoon,
            info.IsExpired,
            info.IsDevelopmentCertificate);
    }

    private static void RequireSan(string certificatePem)
    {
        try
        {
            var text = certificatePem.AsSpan();
            while (PemEncoding.TryFind(text, out var fields))
            {
                if (text[fields.Label].SequenceEqual("CERTIFICATE"))
                {
                    using var leaf = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(text[fields.Base64Data].ToString()));
                    if (ServerCertificateSnapshot.SubjectAlternativeNames(leaf).Count == 0)
                    {
                        throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The certificate has no subject alternative name (SAN). Managed HSM checks the host name against the SAN. The previous certificate is still served.");
                    }

                    return;
                }

                text = text[fields.Location.End..];
            }
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The certificate is not a valid PEM certificate. The previous certificate is still served.");
        }

        throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The certificate input contains no PEM certificate. The previous certificate is still served.");
    }

    private static void RequireUnencryptedKey(string keyPem)
    {
        var text = keyPem.AsSpan();
        var found = false;
        while (PemEncoding.TryFind(text, out var fields))
        {
            var label = text[fields.Label];
            if (label.SequenceEqual("ENCRYPTED PRIVATE KEY"))
            {
                throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "Encrypted private keys are not supported: upload an unencrypted PKCS#8 (or PKCS#1/SEC1) key. The previous certificate is still served.");
            }

            found |= label.EndsWith("PRIVATE KEY", StringComparison.Ordinal);
            text = text[fields.Location.End..];
        }

        if (!found)
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The key input contains no PEM private key. The previous certificate is still served.");
        }
    }

    private static string[] ParseHostNames(IEnumerable<string> hostNames)
    {
        var names = hostNames
            .SelectMany(static h => (h ?? string.Empty).Split([',', ' ', ';', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries))
            .Select(static h => h.Trim())
            .Where(static h => h.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (names.Length == 0)
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "Enter the FQDN the certificate is for (the value you pass as --host).");
        }

        if (names.Length > 10)
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "At most 10 host names are supported.");
        }

        foreach (var name in names)
        {
            if (!IsValidHostName(name))
            {
                throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, $"'{Truncate(name)}' is not a valid DNS name or IP address.");
            }
        }

        return names;
    }

    internal static bool IsValidHostName(string name)
    {
        if (IPAddress.TryParse(name, out _))
        {
            return true;
        }

        try
        {
            return DnsNamePattern.IsMatch(name);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    internal static bool CoversHost(IReadOnlyList<string> sans, string host)
    {
        foreach (var san in sans)
        {
            var name = san.Length > 4 && (san.StartsWith("DNS:", StringComparison.Ordinal) || san.StartsWith("IP:", StringComparison.Ordinal)) ? san[(san.IndexOf(':') + 1)..] : san;
            if (name.Equals(host, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (name.StartsWith("*.", StringComparison.Ordinal) && host.IndexOf('.') is var dot and > 0 && host[dot..].Equals(name[1..], StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string Short(string thumbprint) => thumbprint.Length <= 16 ? thumbprint : thumbprint[..16];

    private static string Truncate(string value) => value.Length <= 40 ? value : value[..40] + "…";
}
