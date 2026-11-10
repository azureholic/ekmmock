using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace EkmMock.Server.Tls;

/// <summary>\n/// What the handshake-time validation decided about a presented client certificate, for the connection event. <see cref="LeafThumbprintSha256"/> is the SHA-256\n/// thumbprint (hex) of the leaf the validation callback actually saw; the authorizer binds each request to it (security review M1).\n/// </summary>
internal sealed record HandshakeVerdict(bool Accepted, string ChainStatus, IReadOnlyList<byte[]> PresentedIntermediates, string? LeafThumbprintSha256 = null);

/// <summary>
/// Client certificate validation during the TLS handshake (spec 5.1). The operating system's trust is ignored completely:
/// the chain is built against a <em>custom</em> root store that is the union of every namespace's root CAs, because the
/// namespace is not known yet at handshake time. Revocation is not checked and nothing is downloaded (no AIA fetch, no network).
/// <para>
/// Only "does this chain to a CA that some namespace trusts" decides here. Validity dates are deliberately <em>not</em> judged at
/// this stage (<see cref="X509VerificationFlags.IgnoreNotTimeValid"/>): an expired Managed HSM client certificate then reaches the
/// authorization middleware and gets a diagnosable JSON 401 plus a captured exchange, instead of an opaque handshake failure.
/// Time, key usage, the per-namespace roots and the common name are all enforced by authorization (DECISIONS.md, M3).
/// </para>
/// </summary>
internal sealed class ClientCertificateValidator
{
    private const int MaxPresentedIntermediates = 8;

    private readonly ClientTrustProvider _trust;

    public ClientCertificateValidator(ClientTrustProvider trust) => _trust = trust;

    /// <summary>
    /// The signature Kestrel's <c>ClientCertificateValidation</c> expects. Never throws. Kestrel only calls it when the client presented a
    /// certificate (no certificate proceeds to the middleware). The verdict is also stored on the connection being handshaken
    /// (<see cref="Connections.ConnectionState.Current"/>) so a rejected certificate can be named as the reason of the failed handshake.
    /// </summary>
    public bool Validate(X509Certificate2 certificate, X509Chain? presentedChain, SslPolicyErrors sslPolicyErrors)
    {
        HandshakeVerdict verdict;
        var leafThumbprint = SafeThumbprint(certificate);
        try
        {
            var trust = _trust.Current;
            var presented = ExtractIntermediates(certificate, presentedChain);

            using var chain = new X509Chain();
            var policy = chain.ChainPolicy;
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            policy.CustomTrustStore.AddRange(trust.UnionRoots);
            policy.RevocationMode = X509RevocationMode.NoCheck;
            policy.DisableCertificateDownloads = true;
            policy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
            foreach (var der in presented)
            {
                policy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(der));
            }

            var accepted = chain.Build(certificate);
            verdict = new HandshakeVerdict(accepted, DescribeStatus(chain), presented, leafThumbprint);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or ArgumentException or InvalidOperationException)
        {
            verdict = new HandshakeVerdict(false, "ChainBuildError", [], leafThumbprint);
        }

        Connections.ConnectionState.Current?.SetClientCertificateVerdict(verdict);
        return verdict.Accepted;
    }
    private static string? SafeThumbprint(X509Certificate2 certificate)
    {
        try
        {
            return certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    internal static string DescribeStatus(X509Chain chain)
    {
        if (chain.ChainStatus.Length == 0)
        {
            return nameof(X509ChainStatusFlags.NoError);
        }

        var flags = chain.ChainStatus.Aggregate(X509ChainStatusFlags.NoError, static (all, status) => all | status.Status);
        return flags.ToString();
    }

    // The certificates the client sent (and the OS chain walked) between the leaf and the root: needed to rebuild the chain
    // later against one namespace's roots. They are never trusted by themselves; only the custom roots are trust anchors.
    private static List<byte[]> ExtractIntermediates(X509Certificate2 leaf, X509Chain? presentedChain)
    {
        var result = new List<byte[]>();
        if (presentedChain is null)
        {
            return result;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { leaf.Thumbprint };

        void Add(X509Certificate2 candidate)
        {
            if (result.Count >= MaxPresentedIntermediates || !seen.Add(candidate.Thumbprint))
            {
                return;
            }

            result.Add(candidate.RawData);
        }

        foreach (var extra in presentedChain.ChainPolicy.ExtraStore)
        {
            Add(extra);
        }

        foreach (var element in presentedChain.ChainElements)
        {
            Add(element.Certificate);
        }

        return result;
    }
}
