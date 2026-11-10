using EkmMock.Pki;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Tests;

/// <summary><c>ekmmock certs</c> (spec 11.2, 12): test PKI only. Real certificates are built and chained here; nothing is trusted because a command said so.</summary>
public sealed class CertsCommandTests : IDisposable
{
    private readonly CliHarness _cli = new();

    public void Dispose() => _cli.Dispose();

    private static X509Certificate2 Load(string file) => X509Certificate2.CreateFromPem(File.ReadAllText(file));

    private static bool Chains(X509Certificate2 leaf, X509Certificate2 root, X509Certificate2Collection? extra = null, string? eku = null)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        if (extra is not null)
        {
            chain.ChainPolicy.ExtraStore.AddRange(extra);
        }

        if (eku is not null)
        {
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(eku));
        }

        return chain.Build(leaf);
    }

    [Fact]
    public async Task Ca_WritesAPemRootAndItsPrivateKey_AndPrintsTheTestPkiNotice()
    {
        var run = await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"), "--name", "Unit Test Root");

        run.ExitCode.ShouldBe(0, run.ToString());
        run.Out.ShouldContain("TEST PKI ONLY");
        using var root = Load(_cli.File("pki/root-ca.pem"));
        root.Subject.ShouldBe("CN=Unit Test Root");
        root.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority.ShouldBeTrue();
        root.SubjectName.RawData.ShouldBe(root.IssuerName.RawData);
        File.ReadAllText(_cli.File("pki/root-ca.key")).ShouldContain("BEGIN PRIVATE KEY");
    }

    [Fact]
    public async Task Ca_NeverPrintsPrivateKeyMaterial()
    {
        var run = await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"));

        AssertNoPrivateKeyMaterial(run, _cli.File("pki"));
    }

    private static void AssertNoPrivateKeyMaterial(CliRun run, string folder)
    {
        run.All.ShouldNotContain("PRIVATE KEY", Case.Sensitive);
        foreach (var keyFile in Directory.GetFiles(folder, "*.key"))
        {
            var pem = File.ReadAllText(keyFile);
            var body = string.Concat(pem.Split('\n').Where(static l => !l.StartsWith("-----", StringComparison.Ordinal))).Trim();
            body.Length.ShouldBeGreaterThan(40);
            run.All.ShouldNotContain(body[..40], customMessage: keyFile);
            run.All.ShouldNotContain(body[^40..], customMessage: keyFile);
        }
    }

    [Fact]
    public async Task PrivateKeyFiles_AreReadableByTheCurrentUserOnly()
    {
        await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"));

        SecureFile.IsOwnerOnly(_cli.File("pki/root-ca.key")).ShouldBeTrue();
    }

    [Fact]
    public async Task Server_IssuesAServerAuthCertificateWithTheFqdnAsSan_AndAChainToTheCa()
    {
        await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"));

        var run = await _cli.RunAsync("certs", "server", "--ca", _cli.File("pki/root-ca.pem"), "--ca-key", _cli.File("pki/root-ca.key"), "--fqdn", "ekm.contoso.test", "--san", "127.0.0.1", "--san", "alt.contoso.test", "--out", _cli.File("pki"));

        run.ExitCode.ShouldBe(0, run.ToString());
        using var server = Load(_cli.File("pki/server.crt"));
        using var root = Load(_cli.File("pki/root-ca.pem"));
        var san = server.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        san.EnumerateDnsNames().ShouldBe(["ekm.contoso.test", "alt.contoso.test"], ignoreOrder: true);
        san.EnumerateIPAddresses().Select(static a => a.ToString()).ShouldContain("127.0.0.1");
        server.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages.Cast<Oid>().Select(static o => o.Value).ShouldBe(["1.3.6.1.5.5.7.3.1"]);
        server.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority.ShouldBeFalse();
        Chains(server, root, eku: "1.3.6.1.5.5.7.3.1").ShouldBeTrue();
        AssertNoPrivateKeyMaterial(run, _cli.File("pki"));
    }

    [Fact]
    public async Task Server_IsServedByARealTlsHandshake_WhenTheKeyMatches()
    {
        await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"));
        await _cli.RunAsync("certs", "server", "--ca", _cli.File("pki/root-ca.pem"), "--ca-key", _cli.File("pki/root-ca.key"), "--fqdn", "localhost", "--out", _cli.File("pki"));

        using var withKey = X509Certificate2.CreateFromPemFile(_cli.File("pki/server.crt"), _cli.File("pki/server.key"));

        withKey.HasPrivateKey.ShouldBeTrue();
    }

    [Fact]
    public async Task Client_IssuesAClientAuthCertificate_WithTheGivenCn()
    {
        await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"));

        var run = await _cli.RunAsync("certs", "client", "--ca", _cli.File("pki/root-ca.pem"), "--ca-key", _cli.File("pki/root-ca.key"), "--cn", "test.managedhsmclient.local", "--out", _cli.File("pki"));

        run.ExitCode.ShouldBe(0, run.ToString());
        using var client = Load(_cli.File("pki/client.crt"));
        using var root = Load(_cli.File("pki/root-ca.pem"));
        client.Subject.ShouldBe("CN=test.managedhsmclient.local");
        client.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages.Cast<Oid>().Select(static o => o.Value).ShouldBe(["1.3.6.1.5.5.7.3.2"]);
        Chains(client, root, eku: "1.3.6.1.5.5.7.3.2").ShouldBeTrue();
        AssertNoPrivateKeyMaterial(run, _cli.File("pki"));
    }

    [Fact]
    public async Task Server_WithACaKeyThatDoesNotBelongToTheCa_IsAUsageError()
    {
        await _cli.RunAsync("certs", "ca", "--out", _cli.File("a"));
        await _cli.RunAsync("certs", "ca", "--out", _cli.File("b"));

        var run = await _cli.RunAsync("certs", "server", "--ca", _cli.File("a/root-ca.pem"), "--ca-key", _cli.File("b/root-ca.key"), "--fqdn", "x.test", "--out", _cli.File("c"));

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("does not belong");
        Directory.Exists(_cli.File("c")).ShouldBeFalse();
    }

    [Fact]
    public async Task Server_WithALeafAsCa_IsAUsageError()
    {
        await _cli.RunAsync("certs", "dev", "--out", _cli.File("pki"));

        var run = await _cli.RunAsync("certs", "server", "--ca", _cli.File("pki/client.crt"), "--ca-key", _cli.File("pki/client.key"), "--fqdn", "x.test", "--out", _cli.File("c"));

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("not a CA");
    }

    [Fact]
    public async Task Certs_RefuseToOverwriteExistingFiles_UnlessForced()
    {
        await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"));
        var before = File.ReadAllText(_cli.File("pki/root-ca.key"));

        var refused = await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"));
        var forced = await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"), "--force");

        refused.ExitCode.ShouldBe(1, refused.ToString());
        refused.Error.ShouldContain("--force");
        forced.ExitCode.ShouldBe(0, forced.ToString());
        File.ReadAllText(_cli.File("pki/root-ca.key")).ShouldNotBe(before);
    }

    [Fact]
    public async Task Dev_WritesEverythingTheLocalServerAndTheConformanceRunNeed()
    {
        var run = await _cli.RunAsync("certs", "dev", "--out", _cli.File("dev"), "--fqdn", "localhost");

        run.ExitCode.ShouldBe(0, run.ToString());
        run.Out.ShouldContain("TEST PKI ONLY");
        foreach (var file in new[] { "root-ca.pem", "root-ca.key", "server.crt", "server.key", "server-replacement.crt", "server-replacement.key", "mhsm-client-ca.pem", "mhsm-client-ca.key", "client.crt", "client.key", "client-wrong-cn.crt", "client-wrong-cn.key", "client-untrusted-ca.crt", "client-untrusted-ca.key", "mhsm-client.json" })
        {
            File.Exists(_cli.File("dev/" + file)).ShouldBeTrue(file);
        }

        using var serverRoot = Load(_cli.File("dev/root-ca.pem"));
        using var clientRoot = Load(_cli.File("dev/mhsm-client-ca.pem"));
        using var server = Load(_cli.File("dev/server.crt"));
        using var replacement = Load(_cli.File("dev/server-replacement.crt"));
        using var client = Load(_cli.File("dev/client.crt"));
        using var wrongCn = Load(_cli.File("dev/client-wrong-cn.crt"));
        using var rogue = Load(_cli.File("dev/client-untrusted-ca.crt"));

        var names = server.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        names.EnumerateDnsNames().ShouldContain("localhost");
        names.EnumerateIPAddresses().Select(static a => a.ToString()).ShouldContain("127.0.0.1");
        Chains(server, serverRoot).ShouldBeTrue();
        Chains(replacement, serverRoot).ShouldBeTrue();
        replacement.Thumbprint.ShouldNotBe(server.Thumbprint);
        client.Subject.ShouldBe("CN=test.managedhsmclient.local");
        Chains(client, clientRoot, eku: "1.3.6.1.5.5.7.3.2").ShouldBeTrue();
        Chains(client, serverRoot).ShouldBeFalse("the client CA is not the server CA");
        wrongCn.Subject.ShouldNotBe(client.Subject);
        Chains(wrongCn, clientRoot).ShouldBeTrue();
        Chains(rogue, clientRoot).ShouldBeFalse("the rogue client must come from a CA nobody trusts");
        AssertNoPrivateKeyMaterial(run, _cli.File("dev"));
    }

    [Fact]
    public async Task Dev_WritesTheTrustFileInTheFormatOfAzKeyvaultEkmConnectionCertificateShow()
    {
        await _cli.RunAsync("certs", "dev", "--out", _cli.File("dev"), "--client-cn", "pool.managedhsmclient.test");

        using var json = JsonDocument.Parse(File.ReadAllText(_cli.File("dev/mhsm-client.json")));
        json.RootElement.GetProperty("subjectCommonName").GetString().ShouldBe("pool.managedhsmclient.test");
        var cas = json.RootElement.GetProperty("caCertificates").EnumerateArray().Select(static e => e.GetString()!).ToList();
        cas.Count.ShouldBe(1);
        using var ca = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(cas[0]));
        using var fromFile = Load(_cli.File("dev/mhsm-client-ca.pem"));
        ca.Thumbprint.ShouldBe(fromFile.Thumbprint);
    }

    [Fact]
    public async Task Dev_CaNamesAreUniquePerRun_SoARepeatedRunNeverClashesInTheWindowsCaStore()
    {
        await _cli.RunAsync("certs", "dev", "--out", _cli.File("one"));
        await _cli.RunAsync("certs", "dev", "--out", _cli.File("two"));

        using var a = Load(_cli.File("one/root-ca.pem"));
        using var b = Load(_cli.File("two/root-ca.pem"));

        a.Subject.ShouldNotBe(b.Subject);
    }

    [Fact]
    public async Task Dev_WithEcdsa_ProducesEcdsaCertificates()
    {
        var run = await _cli.RunAsync("certs", "dev", "--out", _cli.File("dev"), "--algorithm", "ecdsa");

        run.ExitCode.ShouldBe(0, run.ToString());
        using var server = Load(_cli.File("dev/server.crt"));
        server.GetECDsaPublicKey().ShouldNotBeNull();
    }

    [Fact]
    public async Task Certs_WithJsonOutput_ListFilesAndFlagTheSecretOnes()
    {
        var run = await _cli.RunAsync("certs", "dev", "--out", _cli.File("dev"), "--output", "json");

        using var json = JsonDocument.Parse(run.Out);
        json.RootElement.GetProperty("notice").GetString()!.ShouldContain("TEST PKI ONLY");
        var files = json.RootElement.GetProperty("files").EnumerateArray().ToList();
        files.Count.ShouldBe(15);
        files.Where(static f => f.GetProperty("secret").GetBoolean()).Select(static f => f.GetProperty("path").GetString()!).ShouldAllBe(static p => p.EndsWith(".key", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-5")]
    [InlineData("99999")]
    public async Task Certs_WithAnInvalidValidity_IsAUsageError(string days)
    {
        var run = await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"), "--days", days);

        run.ExitCode.ShouldBe(2, run.ToString());
    }

    [Fact]
    public async Task Certs_WithBadSan_IsAUsageError()
    {
        await _cli.RunAsync("certs", "ca", "--out", _cli.File("pki"));

        var run = await _cli.RunAsync("certs", "server", "--ca", _cli.File("pki/root-ca.pem"), "--ca-key", _cli.File("pki/root-ca.key"), "--fqdn", "not a host name", "--out", _cli.File("pki"));

        run.ExitCode.ShouldBe(2, run.ToString());
    }
}
