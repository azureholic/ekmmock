using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Pki;
using EkmMock.Server.Tls;
using EkmMock.TestSupport;

namespace EkmMock.Server.Tests;

/// <summary>The certificate generator behind the test PKI, the dev certificate and (M8) <c>ekmmock certs</c>: proper extensions on every certificate.</summary>
public sealed class PkiTests
{
    private static X509Extension? Extension(X509Certificate2 certificate, string oid)
        => certificate.Extensions.Cast<X509Extension>().FirstOrDefault(e => e.Oid?.Value == oid);

    private static X509BasicConstraintsExtension BasicConstraints(X509Certificate2 c) => new(Extension(c, "2.5.29.19")!, Extension(c, "2.5.29.19")!.Critical);

    private static X509KeyUsageFlags KeyUsage(X509Certificate2 c) => new X509KeyUsageExtension(Extension(c, "2.5.29.15")!, true).KeyUsages;

    private static string[] Ekus(X509Certificate2 c)
        => new X509EnhancedKeyUsageExtension(Extension(c, "2.5.29.37")!, false).EnhancedKeyUsages.Cast<Oid>().Select(static o => o.Value!).ToArray();

    [Theory]
    [InlineData(PkiKeyAlgorithm.Rsa2048)]
    [InlineData(PkiKeyAlgorithm.EcdsaP256)]
    public void ARootCa_IsSelfSignedWithCaBasicConstraints_AndCertSignKeyUsage(PkiKeyAlgorithm algorithm)
    {
        using var root = CertificateAuthority.CreateRoot("Test Root " + algorithm, algorithm);

        root.Certificate.Subject.ShouldBe(root.Certificate.Issuer);
        root.Certificate.HasPrivateKey.ShouldBeTrue();
        var basic = BasicConstraints(root.Certificate);
        basic.CertificateAuthority.ShouldBeTrue();
        basic.Critical.ShouldBeTrue();
        basic.HasPathLengthConstraint.ShouldBeTrue();
        KeyUsage(root.Certificate).HasFlag(X509KeyUsageFlags.KeyCertSign).ShouldBeTrue();
        Extension(root.Certificate, "2.5.29.14").ShouldNotBeNull(); // subject key identifier
        root.IntermediatePems.ShouldBeEmpty();
        root.CertificatePem.ShouldStartWith("-----BEGIN CERTIFICATE-----");
        Convert.FromBase64String(root.DerBase64).ShouldBe(root.Der);
    }

    [Theory]
    [InlineData(PkiKeyAlgorithm.Rsa2048)]
    [InlineData(PkiKeyAlgorithm.EcdsaP256)]
    public void AServerCertificate_HasServerAuthEku_SanForEveryName_AndANonCaLeaf(PkiKeyAlgorithm algorithm)
    {
        using var root = CertificateAuthority.CreateRoot("Test Root S " + algorithm, algorithm);
        using var server = root.IssueServer(["ekm.example.test", "10.1.2.3", "::1"]);

        Ekus(server.Certificate).ShouldBe([CertificateAuthority.ServerAuthOid]);
        ServerCertificateSnapshot.SubjectAlternativeNames(server.Certificate).ShouldBe(["DNS:ekm.example.test", "IP:10.1.2.3", "IP:::1"]);
        BasicConstraints(server.Certificate).CertificateAuthority.ShouldBeFalse();
        KeyUsage(server.Certificate).HasFlag(X509KeyUsageFlags.DigitalSignature).ShouldBeTrue();
        KeyUsage(server.Certificate).HasFlag(X509KeyUsageFlags.KeyCertSign).ShouldBeFalse();
        Extension(server.Certificate, "2.5.29.35").ShouldNotBeNull(); // authority key identifier
        server.Certificate.GetNameInfo(X509NameType.SimpleName, false).ShouldBe("ekm.example.test");
        server.IntermediatePems.ShouldBeEmpty(); // the root is never part of the chain a server sends
        server.ChainPem.Split("BEGIN CERTIFICATE").Length.ShouldBe(2);
    }

    [Fact]
    public void AClientCertificate_HasClientAuthEku_NoSan_AndTheRequestedCommonName()
    {
        using var root = CertificateAuthority.CreateRoot("Test Root C");
        using var client = root.IssueClient("pool-1.managedhsmclient.test");

        Ekus(client.Certificate).ShouldBe([CertificateAuthority.ClientAuthOid]);
        Extension(client.Certificate, "2.5.29.17").ShouldBeNull();
        CommonNameReader.TryGetSingleCommonName(client.Certificate.SubjectName, out var cn).ShouldBeTrue();
        cn.ShouldBe("pool-1.managedhsmclient.test");
    }

    [Theory]
    [InlineData("a, b")]
    [InlineData("x+y=z")]
    [InlineData("quote\"inside")]
    [InlineData("back\\slash")]
    [InlineData("semi;colon<angle>")]
    public void SpecialCharactersInACommonName_SurviveTheRoundTrip(string commonName)
    {
        using var root = CertificateAuthority.CreateRoot("Test Root E");
        using var client = root.IssueClient(commonName);

        CommonNameReader.TryGetSingleCommonName(client.Certificate.SubjectName, out var cn).ShouldBeTrue();
        cn.ShouldBe(commonName);
    }

    [Fact]
    public void AnIntermediate_IsACaWithPathLengthZero_AndItsLeavesCarryItInTheChainButNotTheRoot()
    {
        using var root = CertificateAuthority.CreateRoot("Test Root I");
        using var intermediate = root.IssueIntermediate("Test Issuing CA");
        using var leaf = intermediate.IssueServer(["localhost"]);

        var basic = BasicConstraints(intermediate.Certificate);
        basic.CertificateAuthority.ShouldBeTrue();
        basic.PathLengthConstraint.ShouldBe(0);
        intermediate.IntermediatePems.ShouldBeEmpty();
        leaf.IntermediatePems.Count.ShouldBe(1);
        leaf.IntermediatePems[0].ShouldBe(intermediate.CertificatePem);
        leaf.ChainPem.Split("BEGIN CERTIFICATE").Length.ShouldBe(3);

        // Chain to the root with only the root trusted and the intermediate supplied.
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root.Certificate);
        chain.ChainPolicy.ExtraStore.Add(intermediate.Certificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.Build(leaf.Certificate).ShouldBeTrue(string.Join(",", chain.ChainStatus.Select(static s => s.Status)));
        chain.ChainElements.Count.ShouldBe(3);
    }

    [Fact]
    public void SerialNumbers_ArePositiveRandomAndUnique()
    {
        using var root = CertificateAuthority.CreateRoot("Test Root N");
        var serials = Enumerable.Range(0, 20).Select(_ => { using var c = root.IssueClient("n"); return c.Certificate.SerialNumber; }).ToList();

        serials.Distinct().Count().ShouldBe(20);
        serials.ShouldAllBe(static s => s.Length >= 30 && !s.StartsWith("00", StringComparison.Ordinal) && !s.StartsWith('8') && !s.StartsWith('9') && !char.IsLetter(s[0]));
    }

    [Fact]
    public void ValidityCanBeBackdatedOrFuture_ButIsClippedToTheIssuer()
    {
        using var root = CertificateAuthority.CreateRoot("Test Root V", validity: TimeSpan.FromDays(100));
        using var expired = root.IssueClient("v", TimeSpan.FromDays(1), DateTimeOffset.UtcNow.AddDays(-5));
        using var future = root.IssueClient("v", TimeSpan.FromDays(2), DateTimeOffset.UtcNow.AddDays(3));
        using var tooLong = root.IssueClient("v", TimeSpan.FromDays(10_000));

        expired.Certificate.NotAfter.ShouldBeLessThan(DateTime.Now);
        future.Certificate.NotBefore.ShouldBeGreaterThan(DateTime.Now);
        tooLong.Certificate.NotAfter.ShouldBeLessThanOrEqualTo(root.Certificate.NotAfter);
    }

    [Theory]
    [InlineData(PkiKeyAlgorithm.Rsa2048)]
    [InlineData(PkiKeyAlgorithm.EcdsaP256)]
    public void TheWrittenFiles_LoadBackAsAServableCertificate_WithItsKey(PkiKeyAlgorithm algorithm)
    {
        using var folder = new TempFolder();
        using var root = CertificateAuthority.CreateRoot("Test Root F " + algorithm, algorithm);
        using var server = root.IssueServer(["localhost", "127.0.0.1"]);
        var (certFile, keyFile) = server.WriteFiles(folder.Path);

        using var loaded = ServerCertificateLoader.Load(File.ReadAllText(certFile), File.ReadAllText(keyFile), ServerCertificateSource.File, DateTimeOffset.UtcNow);

        loaded.Certificate.HasPrivateKey.ShouldBeTrue();
        loaded.Thumbprint.ShouldBe(server.Thumbprint);
        File.ReadAllText(keyFile).ShouldContain("BEGIN PRIVATE KEY"); // PKCS#8
    }

    [Fact]
    public void TheTestPki_GivesEveryInstanceUniqueCaNames_AndTheNamesAreVisibleInTheSubjects()
    {
        using var a = new TestPki();
        using var b = new TestPki();

        a.ServerCa.Subject.ShouldNotBe(b.ServerCa.Subject);
        a.ClientCaA.Subject.ShouldContain("Client Root CA A");
        a.UntrustedClientCa.Subject.ShouldContain("UNTRUSTED");
        a.ClientCaA.Certificate.Thumbprint.ShouldNotBe(a.ClientCaB.Certificate.Thumbprint);
    }
}
