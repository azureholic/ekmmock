using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EkmMock.Crypto;
using EkmMock.Server.Connections;
using EkmMock.Server.Hosting;
using EkmMock.Server.Tls;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

// Cipher suite policies are only constructed inside explicit Linux branches below.
#pragma warning disable CA1416

namespace EkmMock.Server.Tests;

/// <summary>HttpContent of unknown length, so HTTP/1.1 sends it with Transfer-Encoding: chunked.</summary>
internal sealed class ChunkedContent : HttpContent
{
    private readonly byte[] _bytes;

    public ChunkedContent(byte[] bytes, string contentType = "application/json")
    {
        _bytes = bytes;
        Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(_bytes, 0, _bytes.Length);

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }
}

/// <summary>Kestrel limits of the EKM endpoint on a real listener (spec 4.1, 5.5) and the ProxyError answer to oversized bodies.</summary>
public sealed class KestrelLimitsTests : IClassFixture<MtlsFixture>
{
    private readonly MtlsFixture _fx;

    public KestrelLimitsTests(MtlsFixture fixture) => _fx = fixture;

    private RealEkmHost Host => _fx.Host;

    private static string WrapBodyOfExactSize(int totalBytes)
    {
        const string prefix = """{"request_context":{"request_id":"r"},"alg":"A256KWP","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","padding":" """;
        var json = prefix.TrimEnd() + new string('x', totalBytes - prefix.TrimEnd().Length - 2) + "\"}";
        Encoding.UTF8.GetByteCount(json).ShouldBe(totalBytes);
        return json;
    }

    [Fact]
    public void TheEkmEndpointLimits_AreThoseOfTheSpec()
    {
        var kestrel = Host.App.Services.GetRequiredService<IOptions<KestrelServerOptions>>().Value;

        kestrel.Limits.RequestHeadersTimeout.ShouldBe(TimeSpan.FromSeconds(2));
        kestrel.Limits.KeepAliveTimeout.ShouldBe(TimeSpan.FromSeconds(120));
        kestrel.Limits.MaxRequestBodySize.ShouldBe(16 * 1024);
        kestrel.AddServerHeader.ShouldBeFalse();
        EkmKestrelSetup.MaxRequestBodyBytes.ShouldBe(16384);
        Host.App.Services.GetRequiredService<IOptions<TlsOptions>>().Value.HandshakeTimeout.ShouldBe(TimeSpan.FromSeconds(3));
    }

    [Fact]
    public void TheDefaultHandshakeTimeout_IsTenSeconds() => new TlsOptions().HandshakeTimeout.ShouldBe(TimeSpan.FromSeconds(10));

    [Fact]
    public async Task AnOversizedBody_WithContentLength_IsOurProxyError400_NotKestrels413()
    {
        using var client = _fx.Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var ekm = Host.CreateEkmClient(client.Certificate);

        var reply = await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), WrapBodyOfExactSize(16385));

        reply.ShouldBeProxyError(400, "InvalidRequest");
        reply.Text.ShouldNotContain("413");
    }

    [Fact]
    public async Task ARequestAnnouncingAFiveMegabyteBody_IsAnsweredWithTheProxyError400_BeforeAnyBodyIsSent()
    {
        using var client = _fx.Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var (stream, tcp) = await Host.ConnectTlsAsync(clientCertificate: client.Certificate);
        using (stream)
        using (tcp)
        {
            var request = "POST /aes-key-1/wrapkey?api-version=0.1-preview HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 5242880\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request), TestContext.Current.CancellationToken);

            var received = new StringBuilder();
            var buffer = new byte[2048];
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            while (!received.ToString().Contains("\"message\"", StringComparison.Ordinal))
            {
                var read = await stream.ReadAsync(buffer, cts.Token);
                read.ShouldBeGreaterThan(0, "the connection closed without an answer");
                received.Append(Encoding.ASCII.GetString(buffer, 0, read));
            }

            var text = received.ToString();
            text.ShouldStartWith("HTTP/1.1 400");
            text.ShouldContain("\"code\":\"InvalidRequest\"");
            text.ShouldNotContain("413");
        }
    }
    [Fact]
    public async Task APercentEncodedSlashInTheKeyName_IsInvalidKeyName_OnRealKestrel()
    {
        // The in-process test host decodes %2F; real Kestrel keeps it, so the key name is "aes%2Fkey" (open question 16 of M2).
        using var client = _fx.Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var (stream, tcp) = await Host.ConnectTlsAsync(clientCertificate: client.Certificate);
        using (stream)
        using (tcp)
        {
            var body = EkmClient.Context;
            var request = $"POST /aes%2Fkey/metadata?api-version=0.1-preview HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\n\r\n{body}";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request), TestContext.Current.CancellationToken);

            var received = new StringBuilder();
            var buffer = new byte[2048];
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            while (!received.ToString().Contains("\"message\"", StringComparison.Ordinal))
            {
                var read = await stream.ReadAsync(buffer, cts.Token);
                read.ShouldBeGreaterThan(0);
                received.Append(Encoding.ASCII.GetString(buffer, 0, read));
            }

            received.ToString().ShouldStartWith("HTTP/1.1 400");
            received.ToString().ShouldContain("\"code\":\"InvalidKeyName\"");
        }
    }

    [Fact]
    public async Task AnOversizedChunkedBody_IsTheProxyError400_Too()
    {
        using var client = _fx.Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var ekm = Host.CreateEkmClient(client.Certificate);
        var body = new ChunkedContent(Encoding.UTF8.GetBytes(WrapBodyOfExactSize(20000)));

        var reply = await ekm.SendAsync(HttpMethod.Post, EkmClient.Path(null, "aes-key-1", "wrapkey"), body);

        reply.ShouldBeProxyError(400, "InvalidRequest");
    }

    [Fact]
    public async Task ABodyOfExactly16KiB_IsAccepted_AndOneByteMoreIsNot()
    {
        using var client = _fx.Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var ekm = Host.CreateEkmClient(client.Certificate);
        var path = EkmClient.Path(null, "aes-key-1", "wrapkey");

        (await ekm.PostAsync(path, WrapBodyOfExactSize(16384))).StatusCode.ShouldBe(200);
        (await ekm.SendAsync(HttpMethod.Post, path, new ChunkedContent(Encoding.UTF8.GetBytes(WrapBodyOfExactSize(16000))))).StatusCode.ShouldBe(200);

        // Kestrel counts chunk framing against its limit, so a chunked body of exactly 16384 bytes may be refused: it is then still our ProxyError 400, never a 413.
        var chunkedAtTheLimit = await ekm.SendAsync(HttpMethod.Post, path, new ChunkedContent(Encoding.UTF8.GetBytes(WrapBodyOfExactSize(16384))));
        if (chunkedAtTheLimit.StatusCode != 200)
        {
            chunkedAtTheLimit.ShouldBeProxyError(400, "InvalidRequest");
        }

        (await ekm.PostAsync(path, WrapBodyOfExactSize(16385))).ShouldBeProxyError(400, "InvalidRequest");
    }

    [Fact]
    public async Task TheServerHeader_IsNotSent()
    {
        using var client = _fx.Pki.ClientCaA.IssueClient(MtlsFixture.CnA);

        var reply = await Host.CreateEkmClient(client.Certificate).InfoAsync();

        reply.Message.Headers.Contains("Server").ShouldBeFalse();
    }

    [Fact]
    public async Task SlowRequestHeaders_GetTheConnectionClosed_AfterTheRequestHeadersTimeout()
    {
        using var client = _fx.Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var (stream, tcp) = await Host.ConnectTlsAsync(clientCertificate: client.Certificate);
        using (stream)
        using (tcp)
        {
            // Half a request: the headers never finish.
            await stream.WriteAsync(Encoding.ASCII.GetBytes("POST /info?api-version=0.1-preview HTTP/1.1\r\nHost: 127.0.0.1\r\n"), TestContext.Current.CancellationToken);
            var watch = Stopwatch.StartNew();
            var received = new StringBuilder();
            var buffer = new byte[1024];
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            try
            {
                int read;
                while ((read = await stream.ReadAsync(buffer, cts.Token)) > 0)
                {
                    received.Append(Encoding.ASCII.GetString(buffer, 0, read));
                }
            }
            catch (IOException)
            {
                // A reset instead of an orderly close is fine too.
            }

            watch.Elapsed.ShouldBeGreaterThan(TimeSpan.FromSeconds(1.5));
            watch.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(8));
            received.Length.ShouldBeLessThan(400, "no EKM answer is given to half a request");
        }
    }

    [Fact]
    public async Task AFullRequestOnAnIdleKeepAliveConnection_IsServedWithoutANewHandshake()
    {
        using var client = _fx.Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var mark = Host.Mark();
        using var http = Host.CreateHttpClient(client.Certificate, singleConnection: true);
        var ekm = new EkmClient(http);

        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        await Task.Delay(2500, TestContext.Current.CancellationToken); // longer than the 2 s header timeout: idle time is governed by KeepAliveTimeout
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);

        Host.Events.Snapshot().Count(e => e.Sequence > mark && e.Kind == ConnectionEventKind.HandshakeSucceeded).ShouldBe(1);
    }
}

/// <summary>Trust follows the namespace store at runtime: no restart, new and existing connections alike (spec 5.1).</summary>
public sealed class RuntimeTrustTests : IAsyncLifetime
{
    private const string Cn = "runtime-client.managedhsmclient.test";

    private TestPki _pki = null!;
    private RealEkmHost _host = null!;

    public async ValueTask InitializeAsync()
    {
        _pki = new TestPki();
        _host = await RealEkmHost.StartAsync(new RealEkmHostOptions { Pki = _pki, Namespaces = [TestNamespace.Default(_pki.ClientCaA, Cn)] });
        _host.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
    }

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        _pki.Dispose();
    }

    private static ClientTrust Trust(string[] commonNames, params EkmMock.Pki.CertificateAuthority[] cas)
        => new() { SubjectCommonNames = commonNames, CaCertificatesDerBase64 = [.. cas.Select(static c => c.DerBase64)] };

    [Fact]
    public async Task AddingANamespacesCa_LetsItsClientsInAtRuntime_AndRemovingItLocksThemOut()
    {
        using var newcomer = _pki.ClientCaB.IssueClient(Cn);
        var mark = _host.Mark();

        // Before: CA B is in no namespace, so the handshake itself is refused.
        using (var before = _host.CreateHttpClient(newcomer.Certificate))
        {
            await Should.ThrowAsync<HttpRequestException>(() => new EkmClient(before).InfoAsync());
        }

        (await _host.NextEventAsync(mark, ConnectionEventKind.HandshakeFailed))!.FailureReason.ShouldBe(HandshakeFailureReason.ClientCertificateNotTrusted);

        // Add CA B to the namespace: the very next connection works, no restart.
        _host.Namespaces.SetTrust("_default", Trust([Cn], _pki.ClientCaA, _pki.ClientCaB));
        using var after = _host.CreateHttpClient(newcomer.Certificate, singleConnection: true);
        var ekm = new EkmClient(after);
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);

        // Remove it again: the connection that is still open is judged per request against the current trust, so its next request is a 401 ...
        _host.Namespaces.SetTrust("_default", Trust([Cn], _pki.ClientCaA));
        (await ekm.InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");

        // ... and a new connection is refused at the handshake again.
        using var fresh = _host.CreateHttpClient(newcomer.Certificate);
        await Should.ThrowAsync<HttpRequestException>(() => new EkmClient(fresh).InfoAsync());
    }

    [Fact]
    public async Task ChangingTheAllowedCommonNames_TakesEffectOnTheNextRequest()
    {
        using var client = _pki.ClientCaA.IssueClient(Cn);
        using var http = _host.CreateHttpClient(client.Certificate, singleConnection: true);
        var ekm = new EkmClient(http);
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);

        _host.Namespaces.SetTrust("_default", Trust(["somebody-else.example"], _pki.ClientCaA));
        (await ekm.InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");

        _host.Namespaces.SetTrust("_default", Trust([Cn, "somebody-else.example"], _pki.ClientCaA));
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task ANewNamespaceWithItsOwnPrefixAndCa_WorksWithoutARestart()
    {
        using var client = _pki.ClientCaB.IssueClient("pool-b.example");
        _host.Namespaces.Add(new NamespaceDefinition { Name = "poolb", Prefix = "poolb", ClientTrust = Trust(["pool-b.example"], _pki.ClientCaB) });
        _host.Keys.Create("poolb", "aes-key-1", KeyType.Oct, 256);

        var reply = await _host.CreateEkmClient(client.Certificate).PostAsync(EkmClient.Path("poolb", "aes-key-1", "metadata"));

        reply.StatusCode.ShouldBe(200, reply.Text);
        // The default namespace still does not know this client.
        (await _host.CreateEkmClient(client.Certificate).InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");
    }

    [Fact]
    public async Task ANamespaceThatListsAnIssuingCaInsteadOfARoot_DoesNotAuthenticateItsClients()
    {
        // Characterisation of a limit, identical on Windows and Linux: custom root trust anchors only at self-signed roots. The Learn
        // reference says caCertificates are root certificates, which is what a namespace must list; an issuing CA there lets nobody in
        // (and never lets in more than the root would). The M6 trust import should warn about such an entry.
        using var issuing = _pki.ClientCaB.IssueIntermediate(_pki.Name("EkmMock Test Issuing CA"));
        using var client = issuing.IssueClient(Cn);
        _host.Namespaces.SetTrust("_default", Trust([Cn], issuing));

        var outcome = await TryAsync(_host.CreateEkmClient(client.Certificate, clientChain: new X509Certificate2Collection(issuing.Certificate)));

        outcome.ShouldNotBe(200);
    }
    private static async Task<int> TryAsync(EkmClient ekm)
    {
        try
        {
            return (await ekm.InfoAsync()).StatusCode;
        }
        catch (HttpRequestException)
        {
            return -1;
        }
    }

    [Fact]
    public async Task ANamespaceWithNoTrustConfigured_AuthenticatesNobody()
    {
        _host.Namespaces.SetTrust("_default", new ClientTrust());
        using var client = _pki.ClientCaA.IssueClient(Cn);

        // CA A is no longer in the union, so the handshake is refused; and without a certificate the answer is 401.
        using var http = _host.CreateHttpClient(client.Certificate);
        await Should.ThrowAsync<HttpRequestException>(() => new EkmClient(http).InfoAsync());
        (await _host.CreateEkmClient().InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");
    }
}

/// <summary>Cipher suite enforcement (spec 5.1). Enforced by the TLS stack on Linux; on Windows by a post-handshake check, with a warning.</summary>
public sealed class CipherPolicyTests : IClassFixture<MtlsFixture>
{
    private readonly MtlsFixture _fx;

    public CipherPolicyTests(MtlsFixture fixture) => _fx = fixture;

    private RealEkmHost Host => _fx.Host;

    private SslClientAuthenticationOptions Options(params TlsCipherSuite[] suites)
    {
        using var client = _fx.Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var options = Host.CreateClientSslOptions(client.Certificate);
        options.ClientCertificates = [X509CertificateLoader.LoadPkcs12(client.Certificate.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable)];
        options.CipherSuitesPolicy = new CipherSuitesPolicy(suites);
        return options;
    }

    [Fact]
    public void WhenTheTlsStackCannotRestrictSuites_TheStartupLogSaysSo_AndOtherwiseItDoesNot()
    {
        var warned = Host.Logs.Entries.Any(static e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning && e.Message.Contains("cipher suites cannot be restricted", StringComparison.Ordinal));
        var policy = Host.App.Services.GetRequiredService<TlsPolicy>();

        warned.ShouldBe(!policy.CanEnforceCipherSuites);
        (policy.CanEnforceCipherSuites).ShouldBe(OperatingSystem.IsLinux());
    }

    [Fact]
    public async Task TheNegotiatedSuite_IsAlwaysOneOfTheTwoPermitted_OnEveryOs()
    {
        using var client = _fx.Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var (stream, tcp) = await Host.ConnectTlsAsync(clientCertificate: client.Certificate);
        using (stream)
        using (tcp)
        {
            TlsPolicy.IsPermitted(stream.NegotiatedCipherSuite).ShouldBeTrue(stream.NegotiatedCipherSuite.ToString());
            stream.SslProtocol.ShouldBe(SslProtocols.Tls13);
        }
    }

    [Fact]
    public async Task Linux_AClientOfferingOnlyChaCha20_IsRefused_AndRecordedAsNoCommonCipherSuite()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "CipherSuitesPolicy is not supported on Windows/macOS clients or servers; this runs on Linux (OpenSSL) only");
        var mark = Host.Mark();
        var options = Options(TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256);

        await Should.ThrowAsync<Exception>(async () =>
        {
            var (stream, tcp) = await Host.ConnectTlsAsync(options);
            stream.Dispose();
            tcp.Dispose();
        });

        var failed = await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeFailed);
        failed.ShouldNotBeNull();
        failed.FailureReason.ShouldBe(HandshakeFailureReason.NoCommonCipherSuite);
        failed.FailureDetail.ShouldNotBeNull().ShouldContain("TLS_CHACHA20_POLY1305_SHA256");
    }

    [Fact]
    public async Task Linux_AClientOfferingChaCha20AndAes256_NegotiatesAes256()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "CipherSuitesPolicy is not supported on Windows/macOS clients or servers; this runs on Linux (OpenSSL) only");
        var options = Options(TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256, TlsCipherSuite.TLS_AES_256_GCM_SHA384);

        var (stream, tcp) = await Host.ConnectTlsAsync(options);
        using (stream)
        using (tcp)
        {
            stream.NegotiatedCipherSuite.ShouldBe(TlsCipherSuite.TLS_AES_256_GCM_SHA384);
        }
    }

    [Fact]
    public async Task Linux_AClientOfferingOnlyAes128_NegotiatesAes128_AndTheEventSaysSo()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "CipherSuitesPolicy is not supported on Windows/macOS clients or servers; this runs on Linux (OpenSSL) only");
        var mark = Host.Mark();
        var options = Options(TlsCipherSuite.TLS_AES_128_GCM_SHA256);

        var (stream, tcp) = await Host.ConnectTlsAsync(options);
        using (stream)
        using (tcp)
        {
            stream.NegotiatedCipherSuite.ShouldBe(TlsCipherSuite.TLS_AES_128_GCM_SHA256);
        }

        (await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeSucceeded))!.CipherSuite.ShouldBe("TLS_AES_128_GCM_SHA256");
    }

    [Fact]
    public async Task Linux_TheServerOnlyOffersThePermittedSuites_EvenToAClientThatOffersEverything()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "CipherSuitesPolicy is not supported on Windows/macOS clients or servers; this runs on Linux (OpenSSL) only");
        var options = Options(TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256, TlsCipherSuite.TLS_AES_128_GCM_SHA256, TlsCipherSuite.TLS_AES_256_GCM_SHA384);

        var (stream, tcp) = await Host.ConnectTlsAsync(options);
        using (stream)
        using (tcp)
        {
            TlsPolicy.IsPermitted(stream.NegotiatedCipherSuite).ShouldBeTrue();
        }
    }
}

/// <summary>The dev convenience: no certificate configured plus <c>--dev</c> gives a generated, clearly flagged localhost certificate.</summary>
public sealed class DevModeHostTests
{
    [Fact]
    public async Task DevModeHost_GeneratesALocalhostCertificate_ThatAClientCanTrustThroughItsRootCa()
    {
        using var pki = new TestPki();
        await using var host = await RealEkmHost.StartAsync(new RealEkmHostOptions { Pki = pki, DevMode = true, Namespaces = [TestNamespace.Default(pki.ClientCaA, "dev-client.example")] });
        var provider = host.Certificates;
        var rootPem = provider.DevelopmentRootCaPem.ShouldNotBeNull();
        using var root = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(string.Concat(rootPem.Split('\n').Where(static l => !l.StartsWith("-----", StringComparison.Ordinal)))));
        using var client = pki.ClientCaA.IssueClient("dev-client.example");

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
            ClientCertificates = [client.Certificate],
            RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
            {
                using var custom = new X509Chain();
                custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                custom.ChainPolicy.CustomTrustStore.Add(root);
                custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 && certificate is not null && custom.Build(X509CertificateLoader.LoadCertificate(certificate.GetRawCertData()));
            },
        };
        var (stream, tcp) = await host.ConnectTlsAsync(options);
        using (stream)
        using (tcp)
        {
            stream.IsAuthenticated.ShouldBeTrue();
        }

        provider.Info.IsDevelopmentCertificate.ShouldBeTrue();
        host.Logs.Entries.ShouldContain(static e => e.Message.Contains("DEV MODE", StringComparison.Ordinal) && e.Message.Contains("certificate", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithoutDevModeAndWithoutACertificate_TheHostRefusesToStart()
    {
        using var pki = new TestPki();
        using var folder = new TempFolder();
        var logs = new CapturingLoggerProvider();

        var ex = await Should.ThrowAsync<InvalidOperationException>(async () =>
        {
            var app = EkmServerServiceCollectionExtensions.BuildEkmMockApp([], builder =>
            {
                builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Data:Path"] = folder.Path, ["Endpoints:Ekm:Url"] = "https://127.0.0.1:0" });
                builder.Services.AddSingleton<IMasterKeyProvider>(new ExplicitMasterKeyProvider(EkmFactory.MasterKeyBytes("nodev")));
                builder.Logging.ClearProviders();
                builder.Logging.AddProvider(logs);
            });
            await app.DisposeAsync();
        });

        ex.Message.ShouldContain("--dev");
    }
}
