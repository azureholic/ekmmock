using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EkmMock.Pki;

/// <summary>Key algorithm of a generated certificate. Both are fine for TLS 1.3 and for the EKM trust checks.</summary>
public enum PkiKeyAlgorithm
{
    Rsa2048,
    EcdsaP256,
}

/// <summary>
/// A certificate together with its private key, as produced by <see cref="CertificateAuthority"/>. <see cref="Certificate"/> has an
/// accessible private key on every OS. Leaf certificates (server, client) get a regular key container on Windows, which SChannel needs and which is deleted when
/// the certificate is disposed: <b>dispose them</b> (a CA's certificate has an ephemeral key and leaves nothing behind).
/// This is test PKI only: keys are generated in memory and are meant to be written to a temp folder or a test data volume.
/// </summary>
public sealed class IssuedCertificate : IDisposable
{
    internal IssuedCertificate(X509Certificate2 certificate, string privateKeyPem, IReadOnlyList<string> intermediatePems)
    {
        Certificate = certificate;
        PrivateKeyPem = privateKeyPem;
        IntermediatePems = intermediatePems;
    }

    /// <summary>The certificate including its private key.</summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>The private key as PKCS#8 PEM. Treat as a secret even though it is test PKI.</summary>
    public string PrivateKeyPem { get; }

    /// <summary>PEM of the issuing CAs between this certificate and the root (nearest issuer first); the root is not included.</summary>
    public IReadOnlyList<string> IntermediatePems { get; }

    public string CertificatePem => Certificate.ExportCertificatePem();

    /// <summary>The certificate followed by its intermediates: the content of a server <c>Tls:CertFile</c>.</summary>
    public string ChainPem => string.Join('\n', [CertificatePem, .. IntermediatePems]);

    public string Subject => Certificate.Subject;

    public string Thumbprint => Certificate.GetCertHashString(HashAlgorithmName.SHA256);

    /// <summary>The DER bytes of the certificate alone (no key).</summary>
    public byte[] Der => Certificate.RawData;

    /// <summary>Writes <c>{name}.crt</c> (chain) and <c>{name}.key</c> into <paramref name="directory"/> and returns both paths.</summary>
    public (string CertFile, string KeyFile) WriteFiles(string directory, string name = "server")
    {
        Directory.CreateDirectory(directory);
        var certFile = Path.Combine(directory, name + ".crt");
        var keyFile = Path.Combine(directory, name + ".key");
        File.WriteAllText(certFile, ChainPem);
        File.WriteAllText(keyFile, PrivateKeyPem);
        return (certFile, keyFile);
    }

    public void Dispose() => Certificate.Dispose();
}

/// <summary>
/// A certificate authority for tests and local development: self-signed root or intermediate, issuing server and client certificates
/// with proper basicConstraints, keyUsage, EKU (serverAuth / clientAuth), SAN, SKI and AKI. This is the logic behind the later
/// <c>ekmmock certs</c> command and the console's "generate test root CA + server certificate" action.
/// </summary>
public sealed class CertificateAuthority : IDisposable
{
    /// <summary>serverAuth EKU.</summary>
    public const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    /// <summary>clientAuth EKU.</summary>
    public const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

    private readonly IssuedCertificate _identity;
    private readonly PkiKeyAlgorithm _algorithm;
    private readonly bool _isRoot;

    private CertificateAuthority(IssuedCertificate identity, PkiKeyAlgorithm algorithm, bool isRoot)
    {
        _identity = identity;
        _algorithm = algorithm;
        _isRoot = isRoot;
    }

    /// <summary>The certificates a TLS server sends for something this CA issues: this CA and the CAs above it, never the root itself.</summary>
    private List<string> ChainForIssued() => _isRoot ? [] : [_identity.CertificatePem, .. _identity.IntermediatePems];

    /// <summary>The CA certificate with its private key.</summary>
    public X509Certificate2 Certificate => _identity.Certificate;

    public string CertificatePem => _identity.CertificatePem;

    /// <summary>The CA's private key as PKCS#8 PEM. Only the <c>ekmmock certs</c> command writes it (to a file only its owner can read); treat it as a secret.</summary>
    public string PrivateKeyPem => _identity.PrivateKeyPem;

    public byte[] Der => _identity.Der;

    public string Subject => _identity.Certificate.Subject;

    /// <summary>The DER of this CA, base64, as it appears in <c>caCertificatesDerBase64</c> of a namespace trust.</summary>
    public string DerBase64 => Convert.ToBase64String(_identity.Der);

    /// <summary>PEM of the CAs above this one (empty for a root).</summary>
    public IReadOnlyList<string> IntermediatePems => _identity.IntermediatePems;

    /// <summary>
    /// Loads a CA that was written to disk earlier (<c>ekmmock certs ca</c>): the CA certificate and its PKCS#8 private key, both PEM. Throws <see cref="ArgumentException"/> (never echoing the
    /// key) when the input is not a CA certificate, the key is not valid PEM or the key does not belong to the certificate. A self-signed certificate is treated as a root, anything else as
    /// an intermediate whose own chain is unknown (certificates it issues then carry only this CA as their intermediate).
    /// </summary>
    public static CertificateAuthority Load(string certificatePem, string privateKeyPem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificatePem);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPem);

        X509Certificate2 certificate;
        try
        {
            certificate = X509Certificate2.CreateFromPem(certificatePem);
        }
        catch (CryptographicException)
        {
            throw new ArgumentException("The CA certificate is not valid PEM.", nameof(certificatePem));
        }

        using (certificate)
        {
            if (certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is not { CertificateAuthority: true })
            {
                throw new ArgumentException("The certificate is not a CA certificate (basicConstraints CA:true is missing).", nameof(certificatePem));
            }

            AsymmetricAlgorithm key;
            PkiKeyAlgorithm algorithm;
            using (var rsaPublic = certificate.GetRSAPublicKey())
            using (var ecdsaPublic = certificate.GetECDsaPublicKey())
            {
                algorithm = rsaPublic is not null
                    ? PkiKeyAlgorithm.Rsa2048
                    : ecdsaPublic is not null
                        ? PkiKeyAlgorithm.EcdsaP256
                        : throw new ArgumentException("Only RSA and ECDSA CA certificates are supported.", nameof(certificatePem));
            }

            try
            {
                if (algorithm == PkiKeyAlgorithm.Rsa2048)
                {
                    var rsa = RSA.Create();
                    rsa.ImportFromPem(privateKeyPem);
                    key = rsa;
                }
                else
                {
                    var ecdsa = ECDsa.Create();
                    ecdsa.ImportFromPem(privateKeyPem);
                    key = ecdsa;
                }
            }
            catch (Exception exception) when (exception is CryptographicException or ArgumentException)
            {
                throw new ArgumentException("The CA private key is not valid PKCS#8 PEM.", nameof(privateKeyPem));
            }

            using (key)
            {
                IssuedCertificate identity;
                try
                {
                    identity = Materialize(certificate, key, [], persistKey: false);
                }
                catch (Exception exception) when (exception is CryptographicException or ArgumentException)
                {
                    throw new ArgumentException("The CA private key does not belong to the CA certificate.", nameof(privateKeyPem));
                }

                var isRoot = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
                return new CertificateAuthority(identity, algorithm, isRoot);
            }
        }
    }

    /// <summary>Creates a self-signed root CA (pathLenConstraint 2).</summary>
    /// <param name="commonName">Becomes <c>CN=</c> of the subject.</param>
    /// <param name="validity">Default 10 years; the certificate starts 30 days in the past so test certificates may be backdated.</param>
    public static CertificateAuthority CreateRoot(
        string commonName,
        PkiKeyAlgorithm algorithm = PkiKeyAlgorithm.Rsa2048,
        TimeSpan? validity = null,
        DateTimeOffset? notBefore = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);
        var start = notBefore ?? DateTimeOffset.UtcNow.AddDays(-30);
        var end = start + (validity ?? TimeSpan.FromDays(3650));

        using var key = NewKey(algorithm, out var request, new X500DistinguishedName($"CN={Escape(commonName)}"));
        AddCaExtensions(request, pathLength: 2);
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        using var selfSigned = request.CreateSelfSigned(start, end);
        var issued = Materialize(selfSigned, key, [], persistKey: false);
        return new CertificateAuthority(issued, algorithm, isRoot: true);
    }

    /// <summary>Issues a subordinate CA (pathLenConstraint 0) signed by this CA.</summary>
    public CertificateAuthority IssueIntermediate(string commonName, TimeSpan? validity = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);
        var (start, end) = Window(validity, notBefore: null);
        using var key = NewKey(_algorithm, out var request, new X500DistinguishedName($"CN={Escape(commonName)}"));
        AddCaExtensions(request, pathLength: 0);
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Certificate, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        return new CertificateAuthority(Sign(request, key, start, end, persistKey: false), _algorithm, isRoot: false);
    }

    /// <summary>
    /// Issues a TLS server certificate with <c>serverAuth</c> EKU. <paramref name="hostNames"/> become the SAN (DNS names or IP
    /// addresses); the first one is also the subject CN.
    /// </summary>
    public IssuedCertificate IssueServer(string[] hostNames, TimeSpan? validity = null, DateTimeOffset? notBefore = null)
    {
        ArgumentNullException.ThrowIfNull(hostNames);
        if (hostNames.Length == 0)
        {
            throw new ArgumentException("At least one host name is required", nameof(hostNames));
        }

        var (start, end) = Window(validity, notBefore);
        using var key = NewKey(_algorithm, out var request, new X500DistinguishedName($"CN={Escape(hostNames[0])}"));
        var usage = _algorithm == PkiKeyAlgorithm.Rsa2048
            ? X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment
            : X509KeyUsageFlags.DigitalSignature;
        AddLeafExtensions(request, usage, ServerAuthOid);

        var san = new SubjectAlternativeNameBuilder();
        foreach (var host in hostNames)
        {
            if (IPAddress.TryParse(host, out var ip))
            {
                san.AddIpAddress(ip);
            }
            else
            {
                san.AddDnsName(host);
            }
        }

        request.CertificateExtensions.Add(san.Build());
        return Sign(request, key, start, end);
    }

    /// <summary>
    /// Issues a client certificate with <c>clientAuth</c> EKU and the given subject CN. Pass <paramref name="notBefore"/> and
    /// <paramref name="validity"/> to create expired or not-yet-valid certificates (the window is clipped to the CA's own validity).
    /// </summary>
    public IssuedCertificate IssueClient(string commonName, TimeSpan? validity = null, DateTimeOffset? notBefore = null)
        => IssueClientWithSubject(new X500DistinguishedName($"CN={Escape(commonName)}"), validity, notBefore);

    /// <summary>Issues a client certificate with an arbitrary subject, for tests of multi-RDN and escaped subjects.</summary>
    public IssuedCertificate IssueClientWithSubject(X500DistinguishedName subject, TimeSpan? validity = null, DateTimeOffset? notBefore = null)
    {
        ArgumentNullException.ThrowIfNull(subject);
        var (start, end) = Window(validity, notBefore);
        using var key = NewKey(_algorithm, out var request, subject);
        AddLeafExtensions(request, X509KeyUsageFlags.DigitalSignature, ClientAuthOid);
        return Sign(request, key, start, end);
    }

    /// <summary>Issues a client certificate whose only EKU is <paramref name="ekuOid"/> (for example serverAuth, to test usage enforcement).</summary>
    public IssuedCertificate IssueClientWithEku(string commonName, string ekuOid, TimeSpan? validity = null)
    {
        var (start, end) = Window(validity, notBefore: null);
        using var key = NewKey(_algorithm, out var request, new X500DistinguishedName($"CN={Escape(commonName)}"));
        AddLeafExtensions(request, X509KeyUsageFlags.DigitalSignature, ekuOid);
        return Sign(request, key, start, end);
    }

    /// <summary>Issues a client certificate without any EKU extension (valid for every purpose by X.509 rules).</summary>
    public IssuedCertificate IssueClientWithoutEku(string commonName, TimeSpan? validity = null)
    {
        var (start, end) = Window(validity, notBefore: null);
        using var key = NewKey(_algorithm, out var request, new X500DistinguishedName($"CN={Escape(commonName)}"));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Certificate, includeKeyIdentifier: true, includeIssuerAndSerial: false));
        return Sign(request, key, start, end);
    }

    public void Dispose() => _identity.Dispose();

    private static string Escape(string commonName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);

        // Quote the value (RFC 4514 allows it, and both the Windows and the managed X.500 parsers accept it) so that commas, plus signs,
        // equals signs and the like stay part of the value instead of changing the structure of the name.
        return '"' + commonName.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
    }

    private (DateTimeOffset Start, DateTimeOffset End) Window(TimeSpan? validity, DateTimeOffset? notBefore)
    {
        var start = notBefore ?? DateTimeOffset.UtcNow.AddMinutes(-5);
        var end = start + (validity ?? TimeSpan.FromDays(365));
        var issuerStart = new DateTimeOffset(Certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero);
        var issuerEnd = new DateTimeOffset(Certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);

        // Certificates never outlive their issuer (CertificateRequest.Create would throw otherwise).
        return (start < issuerStart ? issuerStart : start, end > issuerEnd ? issuerEnd : end);
    }

    private IssuedCertificate Sign(CertificateRequest request, AsymmetricAlgorithm key, DateTimeOffset start, DateTimeOffset end, bool persistKey = true)
    {
        using var signed = request.Create(Certificate, start, end, NewSerial());
        return Materialize(signed, key, ChainForIssued(), persistKey);
    }

    private static AsymmetricAlgorithm NewKey(PkiKeyAlgorithm algorithm, out CertificateRequest request, X500DistinguishedName subject)
    {
        if (algorithm == PkiKeyAlgorithm.Rsa2048)
        {
            var rsa = RSA.Create(2048);
            request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return rsa;
        }

        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
        return ecdsa;
    }

    private void AddLeafExtensions(CertificateRequest request, X509KeyUsageFlags usage, string ekuOid)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ekuOid)], false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Certificate, includeKeyIdentifier: true, includeIssuerAndSerial: false));
    }

    private static void AddCaExtensions(CertificateRequest request, int pathLength)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
    }

    private static byte[] NewSerial()
    {
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F; // positive
        serial[0] |= 0x01; // never a leading zero byte
        return serial;
    }

    private static X509Certificate2 AttachKey(X509Certificate2 certificate, AsymmetricAlgorithm key) => key switch
    {
        RSA rsa => certificate.CopyWithPrivateKey(rsa),
        ECDsa ecdsa => certificate.CopyWithPrivateKey(ecdsa),
        _ => throw new InvalidOperationException("Unsupported key type"),
    };

    /// <summary>
    /// Attaches the key and re-imports the certificate from PFX bytes. <paramref name="persistKey"/> decides where the key lives (see DECISIONS.md "M7: Windows key container leak"):
    /// <list type="bullet">
    /// <item><c>true</c> (certificates a TLS stack will use, server and client leaves): a regular key container. SChannel cannot use ephemeral keys for TLS ("the platform does not
    /// support ephemeral keys"), so on Windows this creates a key file in the user's CNG store that is deleted when the certificate is <em>disposed</em> (and only then: a process that
    /// exits without disposing leaves it behind). Always dispose issued leaf certificates.</item>
    /// <item><c>false</c> (CA certificates, which only sign): an ephemeral, in-memory key. No file is ever created.</item>
    /// </list>
    /// </summary>
    private static IssuedCertificate Materialize(X509Certificate2 certificate, AsymmetricAlgorithm key, IReadOnlyList<string> intermediatePems, bool persistKey = true)
    {
        var privateKeyPem = key.ExportPkcs8PrivateKeyPem();

        // A self-signed certificate already carries its key; start from the public part so every certificate takes the same path.
        using var publicPart = X509CertificateLoader.LoadCertificate(certificate.RawData);
        using var withKey = AttachKey(publicPart, key);

        var pfx = withKey.Export(X509ContentType.Pfx);
        var usable = X509CertificateLoader.LoadPkcs12(pfx, null, persistKey ? X509KeyStorageFlags.Exportable : X509KeyStorageFlags.EphemeralKeySet);
        CryptographicOperations.ZeroMemory(pfx);
        return new IssuedCertificate(usable, privateKeyPem, intermediatePems);
    }
}
