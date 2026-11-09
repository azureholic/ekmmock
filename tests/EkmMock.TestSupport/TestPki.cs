using EkmMock.Pki;

namespace EkmMock.TestSupport;

/// <summary>
/// A complete little PKI for tests: a server CA (what clients trust to verify the EKM server), two <em>trusted</em> client CAs
/// (standing in for the Managed HSM client CA of two different pools) and one <em>untrusted</em> client CA that no namespace knows.
/// Everything lives in memory; write the pieces you need to a temp folder.
/// </summary>
public sealed class TestPki : IDisposable
{
    // Every PKI gets unique CA names. On Windows the TLS stack caches the CA certificates it sees in the current user's
    // "Intermediate Certification Authorities" store, where equal subject names from earlier runs make chain building ambiguous
    // (and slowly pollute the developer's machine); unique names avoid the ambiguity and Dispose removes what this PKI left behind.
    private readonly string _tag = Guid.NewGuid().ToString("N")[..8];

    public TestPki(PkiKeyAlgorithm algorithm = PkiKeyAlgorithm.EcdsaP256)
    {
        Algorithm = algorithm;
        ServerCa = CertificateAuthority.CreateRoot(Name("EkmMock Test Server Root CA"), algorithm);
        ClientCaA = CertificateAuthority.CreateRoot(Name("EkmMock Test Client Root CA A"), algorithm);
        ClientCaB = CertificateAuthority.CreateRoot(Name("EkmMock Test Client Root CA B"), algorithm);
        UntrustedClientCa = CertificateAuthority.CreateRoot(Name("EkmMock Test UNTRUSTED Root CA"), algorithm);
    }

    /// <summary>A name made unique for this PKI (use it for any CA you create from it).</summary>
    public string Name(string baseName) => $"{baseName} {_tag}";

    public PkiKeyAlgorithm Algorithm { get; }

    /// <summary>Signs server certificates; its PEM is what a client passes as the trusted server root (<c>--server-ca-certificate</c>).</summary>
    public CertificateAuthority ServerCa { get; }

    public CertificateAuthority ClientCaA { get; }

    public CertificateAuthority ClientCaB { get; }

    /// <summary>A CA that is configured in no namespace.</summary>
    public CertificateAuthority UntrustedClientCa { get; }

    /// <summary>A server certificate for <c>localhost</c>, <c>127.0.0.1</c> and <c>::1</c> unless other names are given.</summary>
    public IssuedCertificate IssueServer(params string[] hostNames)
        => ServerCa.IssueServer(hostNames.Length == 0 ? ["localhost", "127.0.0.1", "::1"] : hostNames);

    public void Dispose()
    {
        ServerCa.Dispose();
        ClientCaA.Dispose();
        ClientCaB.Dispose();
        UntrustedClientCa.Dispose();
        RemoveCachedCertificates();
    }

    // Best effort: delete the certificates of this PKI that the Windows TLS stack cached in the current user's CA store.
    private void RemoveCachedCertificates()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            using var store = new System.Security.Cryptography.X509Certificates.X509Store(
                System.Security.Cryptography.X509Certificates.StoreName.CertificateAuthority,
                System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
            store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
            foreach (var certificate in store.Certificates)
            {
                if (certificate.Subject.Contains(_tag, StringComparison.Ordinal) || certificate.Issuer.Contains(_tag, StringComparison.Ordinal))
                {
                    store.Remove(certificate);
                }

                certificate.Dispose();
            }
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or UnauthorizedAccessException)
        {
            // Not worth failing a test run over.
        }
    }
}

/// <summary>A temp folder that deletes itself.</summary>
public sealed class TempFolder : IDisposable
{
    public TempFolder(string prefix = "ekmmock-test")
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), prefix + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort cleanup.
        }
    }
}
