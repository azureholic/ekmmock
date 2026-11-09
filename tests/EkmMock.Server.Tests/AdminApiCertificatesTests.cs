#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Pki;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.Server.Tls;
using EkmMock.TestSupport;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>
/// M6, spec 8.5.7, 5.3 and 14 test 15: the Certificates page through <c>/api/console/certificates</c>: current certificate facts, upload (valid and invalid), generated test PKI with a
/// public-only root download, the hot-reload effect on a live listener and the 30-day expiry warning.
/// </summary>
public sealed class AdminApiCertificatesTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;
    private AdminApi _api = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync();
        _api = new AdminApi(_host.Host.CreateConsoleClient());
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private IReadOnlyList<AuditEntry> Audit() => _host.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent();

    private static async Task<X509Certificate2> ServedCertificateAsync(RealEkmHost host)
    {
        X509Certificate2? served = null;
        var options = host.CreateClientSslOptions();
        options.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
        {
            served = X509CertificateLoader.LoadCertificate(certificate!.GetRawCertData());
            return true;
        };
        var (stream, tcp) = await host.ConnectTlsAsync(options);
        stream.Dispose();
        tcp.Dispose();
        return served!;
    }

    [Fact]
    public async Task TheCertificatePage_ShowsSanIssuerChainExpiryAndThePolicy_AndNoKeyMaterial()
    {
        var reply = await _api.GetAsync("/api/console/certificates");

        reply.StatusCode.ShouldBe(200, reply.Text);
        var cert = reply.Root.GetProperty("certificate");
        cert.GetProperty("subject_alternative_names").EnumerateArray().Select(static s => s.GetString()).ShouldContain("DNS:localhost");
        cert.GetProperty("subject_alternative_names").EnumerateArray().Select(static s => s.GetString()).ShouldContain("IP:127.0.0.1");
        cert.GetProperty("issuer").GetString()!.ShouldContain("EkmMock Test Server Root CA");
        cert.GetProperty("chain").GetArrayLength().ShouldBe(1);
        cert.GetProperty("thumbprint_sha256").GetString().ShouldBe(await _host.Host.ServedThumbprintAsync());
        cert.GetProperty("expires_soon").GetBoolean().ShouldBeFalse();
        reply.Root.GetProperty("tls").GetProperty("protocol").GetString().ShouldBe("TLS 1.3 only");
        reply.Root.GetProperty("tls").GetProperty("permitted_cipher_suites").GetArrayLength().ShouldBe(2);
        reply.Root.GetProperty("tls").TryGetProperty("enforcement", out _).ShouldBeTrue();
        reply.Text.ShouldNotContain("PRIVATE KEY");
    }

    [Fact]
    public async Task UploadingAValidCertificate_IsServedToNewConnections_WhileAKeepAliveConnectionIsUntouched()
    {
        using var identity = _host.Pki.ClientCaA.IssueClient(ConsoleTestHost.ClientCn);
        var ekm = _host.Host.CreateEkmClient(identity.Certificate, singleConnection: true);
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        var before = await _host.Host.ServedThumbprintAsync();
        using var replacement = _host.Pki.ServerCa.IssueServer(["localhost", "127.0.0.1", "::1"]);

        var reply = await _api.PostAsync("/api/console/certificates/upload", new { certificate_pem = replacement.ChainPem, private_key_pem = replacement.PrivateKeyPem });

        reply.StatusCode.ShouldBe(200, reply.Text);
        reply.Text.ShouldNotContain("PRIVATE KEY");
        reply.Text.ShouldNotContain(replacement.PrivateKeyPem.Split('\n')[1].Trim(), Case.Sensitive);
        reply.Root.GetProperty("thumbprint_sha256").GetString().ShouldBe(replacement.Thumbprint);
        (await _host.Host.ServedThumbprintAsync()).ShouldNotBe(before);
        (await _host.Host.ServedThumbprintAsync()).ShouldBe(replacement.Thumbprint);
        for (var i = 0; i < 5; i++)
        {
            (await ekm.InfoAsync()).StatusCode.ShouldBe(200, "the connection that was open during the swap keeps working");
        }

        (await File.ReadAllTextAsync(_host.Host.CertFile)).ShouldContain(replacement.CertificatePem.Split('\n')[1]);
        var entry = Audit().Single(e => e.Action == "certificate.upload");
        entry.User.ShouldBe("loopback");
        entry.Target.ShouldStartWith("certificate:");
        entry.ToString().ShouldNotContain("PRIVATE");
    }

    [Fact]
    public async Task AnInvalidUpload_IsRefused_KeepsTheServedCertificate_AndNeverEchoesTheKey()
    {
        var before = await _host.Host.ServedThumbprintAsync();
        using var good = _host.Pki.ServerCa.IssueServer(["localhost", "127.0.0.1"]);
        using var other = _host.Pki.ServerCa.IssueServer(["localhost", "127.0.0.1"]);
        using var client = _host.Pki.ClientCaA.IssueClient("not-a-server");
        using var expired = _host.Pki.ServerCa.IssueServer(["localhost"], TimeSpan.FromDays(1), DateTimeOffset.UtcNow.AddDays(-10));
        var noSan = SelfSignedWithoutSan();

        var cases = new (string Name, string Cert, string Key)[]
        {
            ("garbage certificate", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", good.PrivateKeyPem),
            ("not pem at all", "this is not a certificate", good.PrivateKeyPem),
            ("mismatched key", good.ChainPem, other.PrivateKeyPem),
            ("garbage key", good.ChainPem, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"),
            ("no key block", good.ChainPem, "not a key"),
            ("encrypted key", good.ChainPem, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"),
            ("client certificate (no serverAuth)", client.ChainPem, client.PrivateKeyPem),
            ("expired certificate", expired.ChainPem, expired.PrivateKeyPem),
            ("no SAN", noSan.CertificatePem, noSan.PrivateKeyPem),
        };

        foreach (var (name, cert, key) in cases)
        {
            var reply = await _api.PostAsync("/api/console/certificates/upload", new { certificate_pem = cert, private_key_pem = key });

            reply.StatusCode.ShouldBe(400, $"{name}: {reply.Text}");
            reply.ErrorCode.ShouldBe("InvalidRequest", name);
            reply.ErrorMessage.ShouldContain("still served", Case.Insensitive, name);
            reply.Text.ShouldNotContain("PRIVATE KEY", Case.Sensitive, name);
            reply.Text.ShouldNotContain("BEGIN", Case.Sensitive, name);
            (await _host.Host.ServedThumbprintAsync()).ShouldBe(before, name);
        }

        (await _api.PostAsync("/api/console/certificates/upload", new { })).StatusCode.ShouldBe(400);
        Audit().ShouldNotContain(static e => e.Action == "certificate.upload");
        var page = await _api.GetAsync("/api/console/certificates");
        page.Root.GetProperty("last_error").GetString()!.ShouldNotBeNullOrEmpty("the last reload error is shown (the last provider-level rejection)");
    }

    [Fact]
    public async Task GeneratedTestPki_IsInstalledAtOnce_AndOnlyThePublicRootCanBeDownloaded()
    {
        var reply = await _api.PostAsync("/api/console/certificates/generate", new { fqdn = "ekm.contoso.test" });

        reply.StatusCode.ShouldBe(200, reply.Text);
        reply.Text.ShouldNotContain("PRIVATE KEY");
        var rootPem = reply.Root.GetProperty("root_ca_pem").GetString()!;
        rootPem.ShouldContain("BEGIN CERTIFICATE");
        rootPem.ShouldNotContain("PRIVATE");
        reply.Root.GetProperty("certificate").GetProperty("subject_alternative_names").EnumerateArray().Select(static s => s.GetString()).ShouldBe(["DNS:ekm.contoso.test"]);

        // The listener serves it now, and it chains to exactly the root that was returned.
        using var served = await ServedCertificateAsync(_host.Host);
        served.GetNameInfo(X509NameType.DnsName, forIssuer: false).ShouldBe("ekm.contoso.test");
        using var root = X509Certificate2.CreateFromPem(rootPem);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.Build(served).ShouldBeTrue("the served certificate chains to the generated root CA");
        served.Issuer.ShouldBe(root.Subject);
        root.GetRSAPrivateKey().ShouldBeNull();

        var download = await _api.GetAsync("/api/console/certificates/root-ca.pem");
        download.StatusCode.ShouldBe(200);
        download.ContentType.ShouldBe("application/x-pem-file");
        download.Text.ShouldBe(rootPem);
        download.Text.ShouldNotContain("PRIVATE");

        // No private key of the CA exists anywhere on the volume: the only PEM the console wrote there is the public root certificate.
        var tlsFolder = Path.Combine(_host.Host.DataPath, "tls");
        Directory.Exists(tlsFolder).ShouldBeTrue();
        foreach (var file in Directory.EnumerateFiles(tlsFolder))
        {
            (await File.ReadAllTextAsync(file)).ShouldNotContain("PRIVATE KEY", Case.Sensitive, Path.GetFileName(file));
        }

        Audit().Single(e => e.Action == "certificate.generate").Target.ShouldBe("certificate:ekm.contoso.test");
    }

    [Fact]
    public async Task GeneratedTestPki_AcceptsSeveralNamesAndAnIpAddress_AndRefusesInvalidOnes()
    {
        var ok = await _api.PostAsync("/api/console/certificates/generate", new { fqdn = "ekm.a.test", host_names = new[] { "ekm.b.test", "127.0.0.1" } });
        ok.StatusCode.ShouldBe(200, ok.Text);
        ok.Root.GetProperty("certificate").GetProperty("subject_alternative_names").EnumerateArray().Select(static s => s.GetString())
            .ShouldBe(["DNS:ekm.a.test", "DNS:ekm.b.test", "IP:127.0.0.1"], ignoreOrder: true);

        foreach (var bad in new[] { "bad host!", "-bad.example.com", "under_score.example.com", "a..b.example.com", new string('a', 70) + ".example.com", "" })
        {
            var reply = await _api.PostAsync("/api/console/certificates/generate", new { fqdn = bad });
            reply.StatusCode.ShouldBe(400, bad);
        }

        (await _api.PostAsync("/api/console/certificates/generate", new { host_names = Enumerable.Range(0, 11).Select(static i => $"h{i}.example.test").ToArray() })).StatusCode.ShouldBe(400);
    }

    [Fact]
    public async Task TheRootCaDownload_IsNotAvailable_WhileACustomCertificateIsServed()
    {
        // The configured certificate of this host was issued by a CA the console does not hold: nothing to download until test PKI is generated.
        var reply = await _api.GetAsync("/api/console/certificates/root-ca.pem");

        reply.StatusCode.ShouldBe(404);
        reply.ErrorCode.ShouldBe("NotFound");
    }

    [Fact]
    public async Task AnUploadedCertificate_RemovesAStaleGeneratedRoot_SoTheDownloadNeverPointsAtTheWrongCa()
    {
        await _api.PostAsync("/api/console/certificates/generate", new { fqdn = "ekm.stale.test" });
        (await _api.GetAsync("/api/console/certificates/root-ca.pem")).StatusCode.ShouldBe(200);
        using var replacement = _host.Pki.ServerCa.IssueServer(["localhost", "127.0.0.1", "::1"]);

        (await _api.PostAsync("/api/console/certificates/upload", new { certificate_pem = replacement.ChainPem, private_key_pem = replacement.PrivateKeyPem })).StatusCode.ShouldBe(200);

        (await _api.GetAsync("/api/console/certificates/root-ca.pem")).StatusCode.ShouldBe(404);
    }

    [Fact]
    public async Task ACertificateThatExpiresWithin30Days_IsWarnedAbout_AndOneThatDoesNotIsNot()
    {
        using var pki = new TestPki();
        using var soon = pki.ServerCa.IssueServer(["localhost", "127.0.0.1", "::1"], TimeSpan.FromDays(12), DateTimeOffset.UtcNow.AddDays(-1));
        await using var host = await ConsoleTestHost.StartAsync();
        await using var expiring = await RealEkmHost.StartAsync(new RealEkmHostOptions { Pki = pki, ServerCertificate = soon });
        using var api = new HttpClientOwner(expiring.CreateConsoleClient());

        var reply = await new AdminApi(api.Client).GetAsync("/api/console/certificates");

        var cert = reply.Root.GetProperty("certificate");
        cert.GetProperty("expires_soon").GetBoolean().ShouldBeTrue();
        cert.GetProperty("is_expired").GetBoolean().ShouldBeFalse();
        cert.GetProperty("days_remaining").GetInt32().ShouldBeInRange(9, 12);
        reply.Root.GetProperty("warnings").EnumerateArray().Select(static w => w.GetString()).ShouldContain(static w => w!.Contains("expires in", StringComparison.Ordinal));

        var normal = await new AdminApi(host.Host.CreateConsoleClient()).GetAsync("/api/console/certificates");
        normal.Root.GetProperty("warnings").GetArrayLength().ShouldBe(0);
    }

    [Fact]
    public async Task AServerNameThatNoSanCovers_IsWarnedAbout()
    {
        await using var host = await ConsoleTestHost.StartAsync(configuration: new Dictionary<string, string?> { ["Tls:ServerName"] = "ekm.nowhere.test" });

        var reply = await new AdminApi(host.Host.CreateConsoleClient()).GetAsync("/api/console/certificates");

        reply.Root.GetProperty("warnings").EnumerateArray().Select(static w => w.GetString()).ShouldContain(static w => w!.Contains("ekm.nowhere.test", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithoutConfiguredFiles_AnUploadIsSavedOnTheDataVolume_AndLoadedAgainAfterARestart()
    {
        using var folder = new TempFolder("ekmmock-managed-cert");
        using var pki = new TestPki();
        using var first = pki.ServerCa.IssueServer(["localhost", "127.0.0.1", "::1"]);
        var options = Options.Create(new TlsOptions());
        var data = Options.Create(new DataOptions { Path = folder.Path });
        string thumbprint;
        using (var provider = new ServerCertificateProvider(options, Options.Create(new DevOptions { Enabled = true }), TimeProvider.System, NullLogger<ServerCertificateProvider>.Instance, data))
        {
            provider.Info.IsDevelopmentCertificate.ShouldBeTrue();
            thumbprint = (await provider.ReplaceAsync(first.ChainPem, first.PrivateKeyPem)).ThumbprintSha256;
        }

        File.Exists(Path.Combine(folder.Path, "tls", "server-cert.pem")).ShouldBeTrue();
        File.Exists(Path.Combine(folder.Path, "tls", "server-key.pem")).ShouldBeTrue();
        if (!OperatingSystem.IsWindows())
        {
            File.GetUnixFileMode(Path.Combine(folder.Path, "tls", "server-key.pem")).ShouldBe(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        // A new process (not even dev mode) serves the saved certificate: it survives a restart.
        using var restarted = new ServerCertificateProvider(options, Options.Create(new DevOptions()), TimeProvider.System, NullLogger<ServerCertificateProvider>.Instance, data);
        restarted.Info.ThumbprintSha256.ShouldBe(thumbprint);
        restarted.Info.IsDevelopmentCertificate.ShouldBeFalse();
    }

    private static (string CertificatePem, string PrivateKeyPem) SelfSignedWithoutSan()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=no-san.test", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return (cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem());
    }

    private sealed class HttpClientOwner : IDisposable
    {
        public HttpClientOwner(HttpClient client) => Client = client;

        public HttpClient Client { get; }

        public void Dispose() => Client.Dispose();
    }
}
