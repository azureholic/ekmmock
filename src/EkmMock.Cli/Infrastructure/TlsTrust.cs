using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EkmMock.Cli.Infrastructure;

/// <summary>
/// Who the CLI trusts as the server, in one place (console API and EKM endpoint). There is deliberately no blanket "accept anything" switch except the console's loopback-only escape hatch:
/// <list type="bullet">
/// <item><b>custom root trust</b> (<c>--ca</c>, <c>--console-ca</c>): the given PEM certificates are the <em>only</em> roots; the chain must build to one of them, the server-auth usage must be allowed and the
/// host name must match the certificate's SAN. The OS store is not consulted.</item>
/// <item><b>pin</b> (<c>--console-pin</c>): the leaf certificate must have exactly this SHA-256 thumbprint (the dev certificate of a throw-away server changes on every start, so this is the safe way to trust it).</item>
/// <item><b>insecure, loopback only</b> (<c>--insecure-console-cert</c>): accepts any certificate, and only when the console URL is a loopback address, so a man in the middle on a network can never be trusted by mistake.</item>
/// <item>nothing given: the operating system's trust store and the usual host name check.</item>
/// </list>
/// </summary>
internal static class TlsTrust
{
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    /// <summary>Returns the validation callback for the given options, or null for the default (OS) validation.</summary>
    public static RemoteCertificateValidationCallback? CreateCallback(X509Certificate2Collection? roots, string? pinSha256, bool insecureLoopback)
    {
        if (insecureLoopback)
        {
            return static (_, _, _, _) => true;
        }

        if (!string.IsNullOrWhiteSpace(pinSha256))
        {
            var expected = NormalizeThumbprint(pinSha256);
            return (_, certificate, _, _) =>
            {
                if (certificate is null)
                {
                    return false;
                }

                using var leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                return string.Equals(NormalizeThumbprint(leaf.GetCertHashString(HashAlgorithmName.SHA256)), expected, StringComparison.Ordinal);
            };
        }

        if (roots is { Count: > 0 })
        {
            return (_, certificate, chain, errors) => ValidateAgainstRoots(roots, certificate, chain, errors);
        }

        return null;
    }

    public static string NormalizeThumbprint(string text) => text.Replace(":", string.Empty, StringComparison.Ordinal).Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();

    private static bool ValidateAgainstRoots(X509Certificate2Collection roots, X509Certificate? certificate, X509Chain? presented, SslPolicyErrors errors)
    {
        if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0 || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
        {
            return false;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthOid));

        // The intermediates the server sent (never trust anchors: only the given roots are).
        if (presented is not null)
        {
            foreach (var extra in presented.ChainPolicy.ExtraStore)
            {
                chain.ChainPolicy.ExtraStore.Add(extra);
            }

            foreach (var element in presented.ChainElements.Skip(1))
            {
                chain.ChainPolicy.ExtraStore.Add(element.Certificate);
            }
        }

        using var leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        return chain.Build(leaf);
    }

    /// <summary>Loads every certificate of a PEM file or bundle. Throws <see cref="CliException"/> (usage) for a missing file or a file without a certificate.</summary>
    public static X509Certificate2Collection LoadRoots(string path, string optionName)
    {
        if (!File.Exists(path))
        {
            throw CliException.Usage($"The file given to {optionName} does not exist: {path}");
        }

        var collection = new X509Certificate2Collection();
        try
        {
            collection.ImportFromPemFile(path);
        }
        catch (CryptographicException)
        {
            throw CliException.Usage($"The file given to {optionName} is not a PEM certificate file: {path}");
        }

        if (collection.Count == 0)
        {
            throw CliException.Usage($"The file given to {optionName} contains no certificate: {path}");
        }

        return collection;
    }
}
