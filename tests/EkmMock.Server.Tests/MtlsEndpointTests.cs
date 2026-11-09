using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EkmMock.Crypto;
using EkmMock.Pki;
using EkmMock.Server.Connections;
using EkmMock.Server.Ekm;
using EkmMock.TestSupport;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>Shared real-Kestrel host for the mTLS tests (spec 14 tests 14 and 21, M3 "done when").</summary>
public sealed class MtlsFixture : IAsyncLifetime
{
    public const string CnA = "mhsm-a.managedhsmclient.test";
    public const string CnB = "mhsm-b.managedhsmclient.test";
    public const string CnEscaped = "pool, one+two";
    public const string PrefixB = "contoso/prod";
    public const string PrefixEscaped = "esc";

    internal RealEkmHost Host { get; private set; } = null!;

    internal TestPki Pki { get; private set; } = null!;

    public async ValueTask InitializeAsync()
    {
        Pki = new TestPki();
        Host = await RealEkmHost.StartAsync(new RealEkmHostOptions
        {
            Pki = Pki,
            AddPlainHttpListener = true,
            Configuration = new() { ["Tls:HandshakeTimeout"] = "00:00:03" },
            Namespaces =
            [
                TestNamespace.Default(Pki.ClientCaA, CnA),
                new TestNamespace("contoso", PrefixB, [CnB], [Pki.ClientCaB]),
                new TestNamespace("esc", PrefixEscaped, [CnEscaped], [Pki.ClientCaA]),
            ],
        });
        Host.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
        Host.Keys.Create("_default", "rsa-key-1", KeyType.Rsa, 2048);
        Host.Keys.Create("contoso", "aes-key-1", KeyType.Oct, 256);
        Host.Keys.Create("esc", "aes-key-1", KeyType.Oct, 256);
    }

    public async ValueTask DisposeAsync()
    {
        await Host.DisposeAsync();
        Pki.Dispose();
    }
}

/// <summary>The EKM endpoint on a real Kestrel listener with generated certificates: TLS 1.3, custom root trust, namespace authorization.</summary>
public sealed class MtlsEndpointTests : IClassFixture<MtlsFixture>
{
    private static readonly string[] PermittedSuites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"];

    private readonly MtlsFixture _fx;

    public MtlsEndpointTests(MtlsFixture fixture) => _fx = fixture;

    private RealEkmHost Host => _fx.Host;

    private TestPki Pki => _fx.Pki;

    private static string BPath(string key, string op) => EkmClient.Path(MtlsFixture.PrefixB, key, op);

    private static CapturedLog LastExchangeLog(RealEkmHost host, int skip) => host.Logs.Entries.Skip(skip).Last(static e => e.Category == "EkmMock.Exchange");

    // ---- valid caller: 200, TLS facts, round trips -----------------------------------------------------------------------------------

    [Fact]
    public async Task ValidClient_InfoReturns200_OverTls13AndHttp11_AndTheConnectionIsRecorded()
    {
        var mark = Host.Mark();
        using var client = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        string connectionId;
        using (var http = Host.CreateHttpClient(client.Certificate))
        {
            var ekm = new EkmClient(http);

            var first = await ekm.InfoAsync();
            var second = await ekm.InfoAsync();

            first.StatusCode.ShouldBe(200, first.Text);
            second.StatusCode.ShouldBe(200, second.Text);
            first.Message.Version.ShouldBe(HttpVersion.Version11);
            using var json = first.Json();
            json.RootElement.GetProperty("api_version").GetString().ShouldBe("0.1-preview");

            var opened = await Host.NextEventAsync(mark, ConnectionEventKind.Opened);
            var ok = await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeSucceeded);
            opened.ShouldNotBeNull();
            ok.ShouldNotBeNull();
            connectionId = ok.ConnectionId;
            opened.ConnectionId.ShouldBe(ok.ConnectionId);
            opened.RemoteEndPoint.ShouldNotBeNullOrEmpty();
            ok.TlsProtocol.ShouldBe("TLS 1.3");
            ok.CipherSuite.ShouldNotBeNull().ShouldBeOneOf(PermittedSuites);
            (ok.Alpn is null or "http/1.1").ShouldBeTrue($"ALPN was {ok.Alpn}"); // an HTTP/1.1-only client may not send ALPN at all
            ok.HandshakeTime.ShouldNotBeNull().ShouldBeGreaterThan(TimeSpan.Zero);
            ok.ClientCertificate.ShouldNotBeNull().Subject.ShouldContain(MtlsFixture.CnA);
            ok.ClientCertificate.ThumbprintSha256.ShouldBe(client.Thumbprint);
        }

        // Dropping the client closes the (kept-alive) connection: one connection served both requests.
        var closed = await Host.NextEventAsync(mark, ConnectionEventKind.Closed, e => e.ConnectionId == connectionId);
        closed.ShouldNotBeNull();
        closed.RequestCount.ShouldBe(2);
        closed.Duration.ShouldNotBeNull().ShouldBeGreaterThan(TimeSpan.Zero);
    }

    [Fact]
    public async Task ValidClient_WrapUnwrapRoundTrip_OverMtls_ForAesAndRsa()
    {
        using var client = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var ekm = Host.CreateEkmClient(client.Certificate);

        foreach (var (key, alg) in new[] { ("aes-key-1", "A256KWP"), ("aes-key-1", "A256KW"), ("rsa-key-1", "RSA-OAEP-256"), ("rsa-key-1", "RSA-OAEP") })
        {
            var dek = Fx.Random(32);
            var wrapped = await ekm.WrapAsync(key, alg, dek);
            wrapped.StatusCode.ShouldBe(200, wrapped.Text);
            var unwrapped = await ekm.UnwrapAsync(key, alg, wrapped.Value());
            unwrapped.StatusCode.ShouldBe(200, unwrapped.Text);
            Fx.Same(unwrapped.Value(), dek).ShouldBeTrue($"{key} {alg}");
        }

        (await ekm.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task ValidClient_OnEachNamespace_WithItsOwnCaAndCn_Works()
    {
        using var a = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        using var b = Pki.ClientCaB.IssueClient(MtlsFixture.CnB);

        (await Host.CreateEkmClient(a.Certificate).InfoAsync()).StatusCode.ShouldBe(200);
        (await Host.CreateEkmClient(b.Certificate).PostAsync(EkmClient.Path(MtlsFixture.PrefixB, null, "info"))).StatusCode.ShouldBe(200);
        (await Host.CreateEkmClient(b.Certificate).PostAsync(BPath("aes-key-1", "metadata"))).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task AClientWithoutACertificate_IsNeverServedAsAnEarlierClient_AcrossManyNewConnections()
    {
        // Regression for TLS session resumption: on Windows a resumed TLS 1.3 session used to carry the client certificate of the session it
        // came from, so a client that sent no certificate was occasionally authenticated as an earlier client of the same process.
        using var client = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);

        for (var i = 0; i < 25; i++)
        {
            (await Host.CreateEkmClient(client.Certificate).InfoAsync()).StatusCode.ShouldBe(200, $"iteration {i}, with the certificate");
            (await Host.CreateEkmClient().InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");
        }
    }

    [Fact]
    public async Task EveryNewConnection_GetsAFullHandshake_WithTheClientCertificateValidatedEachTime()
    {
        using var client = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var mark = Host.Mark();

        for (var i = 0; i < 4; i++)
        {
            var (stream, tcp) = await Host.ConnectTlsAsync(clientCertificate: client.Certificate);
            using (stream)
            using (tcp)
            {
                var local = ":" + ((IPEndPoint)tcp.Client.LocalEndPoint!).Port; // the client socket is dual-stack ([::ffff:127.0.0.1]:port), the server shows 127.0.0.1:port
                (await Wait.UntilAsync(() => Host.Connections.Snapshot().Any(c => c.RemoteEndPoint!.EndsWith(local, StringComparison.Ordinal) && c.ClientCertificateVerdict is { Accepted: true }), TimeSpan.FromSeconds(5)))
                    .ShouldBeTrue($"connection {i} ({local}) was not validated at its handshake (resumed?); open: " + string.Join("; ", Host.Connections.Snapshot().Select(c => $"{c.RemoteEndPoint} verdict={c.ClientCertificateVerdict?.Accepted} handshake={c.HandshakeCompleted} cert={c.ClientCertificate is not null}")));
            }
        }

        Host.Events.Snapshot().Where(e => e.Sequence > mark && e.Kind == ConnectionEventKind.HandshakeSucceeded).ShouldAllBe(static e => e.Resumed == false);
    }

    [Fact]
    public async Task ValidClient_ExchangeLogCarriesTheClientCommonName()
    {
        using var client = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var before = Host.Logs.Entries.Count;

        (await Host.CreateEkmClient(client.Certificate).InfoAsync()).StatusCode.ShouldBe(200);

        var line = LastExchangeLog(Host, before);
        line.Fields["client_cn"].ShouldBe(MtlsFixture.CnA);
        line.Fields["auth_failure"].ShouldBeNull();
    }

    // Diagnostics for an unexpected non-401 answer to a request that carried no certificate (it must never happen): what the server logged
    // for the exchange and which handshakes it saw, so a rare failure explains itself.
    private async Task<EkmReply> NoCertAsync(Func<EkmClient, Task<EkmReply>> send, long mark)
    {
        var logsBefore = Host.Logs.Entries.Count;
        var reply = await send(Host.CreateEkmClient());
        if (reply.StatusCode != 401)
        {
            var exchange = Host.Logs.Entries.Skip(logsBefore).Where(static e => e.Category == "EkmMock.Exchange").Select(static e => string.Join(",", e.Fields.Where(static f => f.Key is "client_cn" or "status" or "auth_failure" or "op").Select(static f => $"{f.Key}={f.Value}")));
            var events = Host.Events.Snapshot().Where(e => e.Sequence > mark).Select(static e => $"{e.Kind}:{e.RemoteEndPoint}:{e.ClientCertificate?.Subject}:{e.Resumed}");
            Assert.Fail($"A request without a client certificate got {reply.StatusCode} instead of 401. exchange=[{string.Join("; ", exchange)}] events=[{string.Join("; ", events)}]");
        }

        return reply;
    }
    // ---- 401 handling (spec 14 test 14) ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task TrustedCa_ButWrongCommonName_Is401Unauthenticated()
    {
        using var client = Pki.ClientCaA.IssueClient("some-other-client.example");
        var before = Host.Logs.Entries.Count;

        var reply = await Host.CreateEkmClient(client.Certificate).InfoAsync();

        reply.ShouldBeProxyError(401, "Unauthenticated");
        LastExchangeLog(Host, before).Fields["auth_failure"].ShouldBe(nameof(AuthFailure.CommonNameNotAllowed));
    }

    [Fact]
    public async Task NoClientCertificate_Is401JsonProxyError_NotATlsFailure_ForEveryOperation()
    {
        var mark = Host.Mark();

        (await NoCertAsync(static ekm => ekm.InfoAsync(), mark)).ShouldBeProxyError(401, "Unauthenticated");
        (await NoCertAsync(static ekm => ekm.MetadataAsync("aes-key-1"), mark)).ShouldBeProxyError(401, "Unauthenticated");
        (await NoCertAsync(static ekm => ekm.WrapAsync("aes-key-1", "A256KWP", new byte[32]), mark)).ShouldBeProxyError(401, "Unauthenticated");
        (await NoCertAsync(static ekm => ekm.UnwrapAsync("aes-key-1", "A256KWP", new byte[40]), mark)).ShouldBeProxyError(401, "Unauthenticated");

        // The TLS handshake itself succeeded (no certificate is allowed through, the middleware answers).
        var ok = await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeSucceeded);
        ok.ShouldNotBeNull().ClientCertificate.ShouldBeNull();
        Host.Events.Snapshot().ShouldNotContain(e => e.Sequence > mark && e.Kind == ConnectionEventKind.HandshakeFailed);
    }

    [Fact]
    public async Task NoClientCertificate_OnOneReusedKeepAliveConnection_IsA401EveryTime()
    {
        using var http = Host.CreateHttpClient(singleConnection: true);
        var ekm = new EkmClient(http);

        for (var i = 0; i < 5; i++)
        {
            (await ekm.InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");
            (await ekm.WrapAsync("aes-key-1", "A256KWP", new byte[32])).ShouldBeProxyError(401, "Unauthenticated");
        }
    }

    [Fact]
    public async Task Unauthenticated_BeatsEveryLaterCheck_SoNothingLeaksAboutKeysOrBodies()
    {
        var mark = Host.Mark();

        // Unknown key, bad api-version, bad content type and wrong method would each be a different 4xx for an authenticated caller.
        (await NoCertAsync(static ekm => ekm.WrapAsync("no-such-key", "A256KWP", new byte[32]), mark)).ShouldBeProxyError(401, "Unauthenticated");
        (await NoCertAsync(static ekm => ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey", "api-version=9.9"), "{"), mark)).ShouldBeProxyError(401, "Unauthenticated");
        (await NoCertAsync(static ekm => ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), "{", "text/plain"), mark)).ShouldBeProxyError(401, "Unauthenticated");
        (await NoCertAsync(static ekm => ekm.SendAsync(HttpMethod.Get, EkmClient.Path(null, "aes-key-1", "metadata")), mark)).ShouldBeProxyError(401, "Unauthenticated");
    }

    [Fact]
    public async Task UnroutablePath_IsStill404_BeforeAuthentication()
    {
        // Routing precedes auth (DECISIONS.md M2); a path no namespace claims never reaches authentication.
        var reply = await Host.CreateEkmClient().PostAsync("/nope/at/all/here?api-version=0.1-preview");

        reply.ShouldBeProxyError(404, "NotFound");
    }

    // ---- handshake failures: untrusted CA, TLS 1.2 -----------------------------------------------------------------------------------

    [Fact]
    public async Task UntrustedCa_FailsTheHandshake_AndAFailureEventWithAReasonIsRecorded()
    {
        var mark = Host.Mark();
        var failuresBefore = Host.Metrics.TotalHandshakeFailures;
        using var intruder = Pki.UntrustedClientCa.IssueClient(MtlsFixture.CnA);
        using var http = Host.CreateHttpClient(intruder.Certificate);

        await Should.ThrowAsync<HttpRequestException>(() => new EkmClient(http).InfoAsync());

        var failed = await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeFailed);
        failed.ShouldNotBeNull();
        failed.FailureReason.ShouldBe(HandshakeFailureReason.ClientCertificateNotTrusted);
        failed.FailureDetail.ShouldNotBeNull().ShouldContain("chain status");
        failed.RemoteEndPoint.ShouldNotBeNullOrEmpty();
        HandshakeFailureReasons.Describe(failed.FailureReason.ShouldNotBeNull()).ShouldNotBeNullOrWhiteSpace();
        Host.Metrics.HandshakeFailureCounts["client_cert_not_trusted"].ShouldBeGreaterThanOrEqualTo(1);
        Host.Metrics.TotalHandshakeFailures.ShouldBeGreaterThan(failuresBefore);

        // The connection is accounted for to the end (opened → failed → closed with zero requests).
        var closed = await Host.NextEventAsync(mark, ConnectionEventKind.Closed, e => e.ConnectionId == failed.ConnectionId);
        closed.ShouldNotBeNull().RequestCount.ShouldBe(0);
        Host.Events.Snapshot().ShouldNotContain(e => e.ConnectionId == failed.ConnectionId && e.Kind == ConnectionEventKind.HandshakeSucceeded);
    }

    [Fact]
    public async Task Tls12OnlyClient_IsRefused_AndTheVersionReasonIsRecorded()
    {
        var mark = Host.Mark();
        var options = Host.CreateClientSslOptions(protocols: SslProtocols.Tls12);

        // The TLS stack throws (AuthenticationException or IOException depending on the OS); either way there is no connection.
        await Should.ThrowAsync<Exception>(async () =>
        {
            var (stream, tcp) = await Host.ConnectTlsAsync(options);
            stream.Dispose();
            tcp.Dispose();
        });

        var failed = await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeFailed);
        failed.ShouldNotBeNull();
        failed.FailureReason.ShouldBe(HandshakeFailureReason.TlsVersionNotSupported);
        failed.FailureDetail.ShouldNotBeNull().ShouldContain("TLS 1.2");
        failed.FailureDetail.ShouldNotContain("TLS 1.3");
        Host.Metrics.HandshakeFailureCounts["tls_version_not_supported"].ShouldBeGreaterThanOrEqualTo(1);
    }

    [Fact]
    public async Task Tls12OnlyHttpClient_IsRefused()
    {
        var mark = Host.Mark();
        using var client = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        using var http = Host.CreateHttpClient(client.Certificate, protocols: SslProtocols.Tls12);

        await Should.ThrowAsync<HttpRequestException>(() => new EkmClient(http).InfoAsync());

        // Let the failure event land before the next test starts (events of one test must not leak into another's window).
        (await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeFailed))!.FailureReason.ShouldBe(HandshakeFailureReason.TlsVersionNotSupported);
    }

    [Fact]
    public async Task ClientOfferingTls12AndTls13_NegotiatesTls13()
    {
        using var client = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var options = Host.CreateClientSslOptions(client.Certificate, SslProtocols.Tls12 | SslProtocols.Tls13);

        var (stream, tcp) = await Host.ConnectTlsAsync(options);
        using (stream)
        using (tcp)
        {
            stream.SslProtocol.ShouldBe(SslProtocols.Tls13);
        }
    }

    [Fact]
    public async Task PlainHttpBytesOnTheTlsPort_AreClassifiedAsNotTls()
    {
        var mark = Host.Mark();
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, Host.Port, TestContext.Current.CancellationToken);
        var request = Encoding.ASCII.GetBytes("POST /info?api-version=0.1-preview HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
        await tcp.GetStream().WriteAsync(request, TestContext.Current.CancellationToken);

        var failed = await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeFailed);

        failed.ShouldNotBeNull().FailureReason.ShouldBe(HandshakeFailureReason.NotTls);
    }

    [Fact]
    public async Task ClientThatConnectsAndCloses_IsClassifiedAsClientClosed()
    {
        var mark = Host.Mark();
        using (var tcp = new TcpClient())
        {
            await tcp.ConnectAsync(IPAddress.Loopback, Host.Port, TestContext.Current.CancellationToken);
        }

        var failed = await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeFailed);

        failed.ShouldNotBeNull().FailureReason.ShouldBe(HandshakeFailureReason.ClientClosed);
    }

    [Fact]
    public async Task ClientThatStaysSilent_IsClassifiedAsHandshakeTimeout()
    {
        var mark = Host.Mark();
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, Host.Port, TestContext.Current.CancellationToken);

        // Tls:HandshakeTimeout is 3 s for this host.
        var failed = await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeFailed, timeout: TimeSpan.FromSeconds(15));

        failed.ShouldNotBeNull().FailureReason.ShouldBe(HandshakeFailureReason.HandshakeTimeout, $"after {failed.HandshakeTime}: {failed.FailureDetail}");
    }

    // ---- per-namespace authorization --------------------------------------------------------------------------------------------------

    [Fact]
    public async Task CertificateValidForNamespaceA_IsRejectedOnNamespaceB_AndTheOtherWayRound()
    {
        using var a = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        using var b = Pki.ClientCaB.IssueClient(MtlsFixture.CnB);
        var asA = Host.CreateEkmClient(a.Certificate);
        var asB = Host.CreateEkmClient(b.Certificate);

        (await asA.PostAsync(BPath("aes-key-1", "metadata"))).ShouldBeProxyError(401, "Unauthenticated");
        (await asB.MetadataAsync("aes-key-1")).ShouldBeProxyError(401, "Unauthenticated");
        (await asA.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);
        (await asB.PostAsync(BPath("aes-key-1", "metadata"))).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task CnAllowedOnA_ButSignedByBsCa_IsRejected_BecauseTheChainMustReachTheNamespacesOwnRoots()
    {
        // Passes the handshake (CA B is in the union) but is not a client of namespace _default.
        using var crossed = Pki.ClientCaB.IssueClient(MtlsFixture.CnA);

        (await Host.CreateEkmClient(crossed.Certificate).InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");
    }

    [Fact]
    public async Task CnAllowedOnB_ButSignedByAsCa_IsRejectedOnB()
    {
        using var crossed = Pki.ClientCaA.IssueClient(MtlsFixture.CnB);

        (await Host.CreateEkmClient(crossed.Certificate).PostAsync(EkmClient.Path(MtlsFixture.PrefixB, null, "info"))).ShouldBeProxyError(401, "Unauthenticated");
    }

    [Theory]
    [InlineData("MHSM-A.managedhsmclient.test")]
    [InlineData("Mhsm-A.managedhsmclient.test")]
    [InlineData("mhsm-a.managedhsmclient.test.evil")]
    [InlineData("evil.mhsm-a.managedhsmclient.test")]
    [InlineData("mhsm-a.managedhsmclient.tes")]
    [InlineData("*.managedhsmclient.test")]
    [InlineData("mhsm-a")]
    public async Task CommonName_MustMatchExactlyAndCaseSensitively_NoWildcardNoSubstring(string commonName)
    {
        using var client = Pki.ClientCaA.IssueClient(commonName);

        (await Host.CreateEkmClient(client.Certificate).InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");
    }

    [Fact]
    public async Task CommonNameWithEscapedCharacters_IsComparedAsTheParsedValue()
    {
        // The namespace allows the CN "pool, one+two": a comma and a plus sign inside one value.
        using var exact = Pki.ClientCaA.IssueClient(MtlsFixture.CnEscaped);
        using var splitTrick = Pki.ClientCaA.IssueClient("pool");
        var path = EkmClient.Path(MtlsFixture.PrefixEscaped, null, "info");

        (await Host.CreateEkmClient(exact.Certificate).PostAsync(path)).StatusCode.ShouldBe(200);
        (await Host.CreateEkmClient(splitTrick.Certificate).PostAsync(path)).ShouldBeProxyError(401, "Unauthenticated");
    }

    [Fact]
    public async Task SubjectWithTwoCommonNames_OrACnInAMultiValuedRdn_IsAmbiguousAndRejected()
    {
        var twoCn = new X500DistinguishedName("CN=intruder, CN=" + MtlsFixture.CnA);
        var multiValued = DistinguishedNames.MultiValuedRdn((DistinguishedNames.CommonNameOid, MtlsFixture.CnA), (DistinguishedNames.OrganizationalUnitOid, "extra"));
        using var first = Pki.ClientCaA.IssueClientWithSubject(twoCn);
        using var second = Pki.ClientCaA.IssueClientWithSubject(multiValued);

        (await Host.CreateEkmClient(first.Certificate).InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");
        (await Host.CreateEkmClient(second.Certificate).InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");
    }

    [Fact]
    public async Task SubjectWithOtherAttributes_StillMatchesOnItsSingleCommonName()
    {
        var subject = new X500DistinguishedName("CN=" + MtlsFixture.CnA + ", O=Managed HSM, C=NL");
        using var client = Pki.ClientCaA.IssueClientWithSubject(subject);

        (await Host.CreateEkmClient(client.Certificate).InfoAsync()).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task ExpiredClientCertificate_PassesTheHandshake_ButIs401_WithTheReasonLogged()
    {
        using var expired = Pki.ClientCaA.IssueClient(MtlsFixture.CnA, TimeSpan.FromDays(1), DateTimeOffset.UtcNow.AddDays(-5));
        var before = Host.Logs.Entries.Count;

        var reply = await Host.CreateEkmClient(expired.Certificate).InfoAsync();

        reply.ShouldBeProxyError(401, "Unauthenticated");
        LastExchangeLog(Host, before).Fields["auth_failure"].ShouldBe(nameof(AuthFailure.CertificateExpired));
    }

    [Fact]
    public async Task NotYetValidClientCertificate_Is401()
    {
        using var future = Pki.ClientCaA.IssueClient(MtlsFixture.CnA, TimeSpan.FromDays(2), DateTimeOffset.UtcNow.AddDays(1));
        var before = Host.Logs.Entries.Count;

        (await Host.CreateEkmClient(future.Certificate).InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");

        LastExchangeLog(Host, before).Fields["auth_failure"].ShouldBe(nameof(AuthFailure.CertificateNotYetValid));
    }

    [Fact]
    public async Task ClientCertificateWithoutClientAuthEku_Is401_ButOneWithNoEkuAtAllIsAccepted()
    {
        using var serverOnly = Pki.ClientCaA.IssueClientWithEku(MtlsFixture.CnA, CertificateAuthority.ServerAuthOid);
        using var noEku = Pki.ClientCaA.IssueClientWithoutEku(MtlsFixture.CnA);

        (await Host.CreateEkmClient(serverOnly.Certificate).InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");
        (await Host.CreateEkmClient(noEku.Certificate).InfoAsync()).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task ClientCertificateIssuedByAnIntermediate_IsAcceptedWhenTheNamespaceTrustsTheRoot_AndTheClientSendsTheChain()
    {
        using var intermediate = Pki.ClientCaA.IssueIntermediate(Pki.Name("EkmMock Test Client Issuing CA"));
        using var client = intermediate.IssueClient(MtlsFixture.CnA);
        var chain = new X509Certificate2Collection(intermediate.Certificate);

        var reply = await Host.CreateEkmClient(client.Certificate, clientChain: chain).InfoAsync();

        reply.StatusCode.ShouldBe(200, reply.Text);
    }

    [Fact]
    public async Task ClientCertificateIssuedByAnIntermediate_IsNeverAccepted_WhenTheClientDoesNotSendTheChain()
    {
        using var intermediate = Pki.ClientCaA.IssueIntermediate(Pki.Name("EkmMock Test Client Issuing CA 2"));
        using var client = intermediate.IssueClient(MtlsFixture.CnA);

        // Without the intermediate the chain is incomplete: the handshake (or the namespace check) must refuse it, never accept it.
        var mark = Host.Mark();
        var outcome = await TryInfoAsync(Host.CreateEkmClient(client.Certificate));

        outcome.ShouldNotBe(200);
        if (outcome == -1)
        {
            // Refused in the handshake: let the failure event land before the next test starts.
            (await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeFailed)).ShouldNotBeNull();
        }
    }

    // ---- the exchange links to its connection and TLS facts ---------------------------------------------------------------------------

    [Fact]
    public async Task KeepAlive_TheNextRequestsReuseTheConnection()
    {
        using var client = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var before = Host.Logs.Entries.Count;
        var mark = Host.Mark();
        using (var http = Host.CreateHttpClient(client.Certificate, singleConnection: true))
        {
            var ekm = new EkmClient(http);
            (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
            (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
            (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        }

        var handshakes = Host.Events.Snapshot().Where(e => e.Sequence > mark && e.Kind == ConnectionEventKind.HandshakeSucceeded).ToList();
        handshakes.Count.ShouldBe(1);
        var closed = await Host.NextEventAsync(mark, ConnectionEventKind.Closed, e => e.ConnectionId == handshakes[0].ConnectionId);
        closed.ShouldNotBeNull().RequestCount.ShouldBe(3);
        Host.Logs.Entries.Skip(before).Count(static e => e.Category == "EkmMock.Exchange").ShouldBe(3);
    }

    [Fact]
    public async Task Http2_CanBeNegotiatedViaAlpn_AndAuthorizationStillApplies()
    {
        using var client = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        using var wrong = Pki.ClientCaA.IssueClient("not-allowed.example");
        var mark = Host.Mark();
        using var http = Host.CreateHttpClient(client.Certificate, version: HttpVersion.Version20);
        using var httpWrong = Host.CreateHttpClient(wrong.Certificate, version: HttpVersion.Version20);

        var ok = await new EkmClient(http) { RequestVersion = HttpVersion.Version20 }.InfoAsync();
        var denied = await new EkmClient(httpWrong) { RequestVersion = HttpVersion.Version20 }.InfoAsync();

        ok.StatusCode.ShouldBe(200, ok.Text);
        ok.Message.Version.ShouldBe(HttpVersion.Version20);
        denied.ShouldBeProxyError(401, "Unauthenticated");
        var handshake = await Host.NextEventAsync(mark, ConnectionEventKind.HandshakeSucceeded);
        handshake.ShouldNotBeNull().Alpn.ShouldBe("h2");
    }

    // ---- port separation (spec 5.4, 14 test 16) ---------------------------------------------------------------------------------------

    [Fact]
    public async Task EkmRoutes_OnANonEkmPort_Are404_AndNeverReachTheHandlers()
    {
        Host.PlainHttpPort.ShouldNotBeNull();
        var key = new KeyRef("_default", "aes-key-1");
        var usageBefore = Host.Keys.Get(key)!.WrapCount;
        var exchangeLogsBefore = Host.Logs.Entries.Count(static e => e.Category == "EkmMock.Exchange");
        using var plain = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{Host.PlainHttpPort}/") };
        var body = EkmClient.WrapBody("A256KWP", Base64UrlOf(new byte[32]));

        foreach (var path in new[] { EkmClient.Path(null, null, "info"), EkmClient.Path(null, "aes-key-1", "wrapkey"), EkmClient.Path(null, "aes-key-1", "metadata"), BPath("aes-key-1", "wrapkey") })
        {
            var response = await plain.PostAsync(path, EkmClient.JsonBody(body), TestContext.Current.CancellationToken);
            response.StatusCode.ShouldBe(HttpStatusCode.NotFound, path);
        }

        Host.Keys.Get(key)!.WrapCount.ShouldBe(usageBefore);
        Host.Logs.Entries.Count(static e => e.Category == "EkmMock.Exchange").ShouldBe(exchangeLogsBefore);
    }

    [Theory]
    [InlineData("/api/console/keys")]
    [InlineData("/metrics")]
    [InlineData("/healthz")]
    [InlineData("/readyz")]
    [InlineData("/")]
    [InlineData("/_blazor")]
    public async Task ConsoleAndAdminPaths_OnTheEkmPort_Are404_InTheEkmErrorFormat(string path)
    {
        using var client = Pki.ClientCaA.IssueClient(MtlsFixture.CnA);
        var ekm = Host.CreateEkmClient(client.Certificate);

        (await ekm.SendAsync(HttpMethod.Get, path)).ShouldBeProxyError(404, "NotFound");
        (await ekm.PostAsync(path)).ShouldBeProxyError(404, "NotFound");
    }

    [Fact]
    public void EkmPortsAreLearnedFromTheEkmListener_AndNotFromAnyOtherListener()
    {
        var ports = Host.App.Services.GetRequiredService<EkmListenerPorts>();

        ports.IsEkmPort(Host.Port).ShouldBeTrue();
        ports.IsEkmPort(Host.PlainHttpPort!.Value).ShouldBeFalse();
        ports.IsEkmPort(0).ShouldBeFalse();
    }

    // ---- helpers ------------------------------------------------------------------------------------------------------------------------

    private static string Base64UrlOf(byte[] bytes) => Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static async Task<int> TryInfoAsync(EkmClient ekm)
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
}
