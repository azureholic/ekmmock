using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Crypto;
using EkmMock.Server.Connections;
using EkmMock.Server.Ekm;
using EkmMock.Server.Tls;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace EkmMock.Server.Tests;

/// <summary>
/// M8: the authorizer remembers successful chain verdicts (building an X509Chain cost 12 ms per request on Windows). The cache must never let through a request that a fresh build would refuse.
/// </summary>
public sealed class MtlsChainVerdictCacheTests : IDisposable
{
    private const string Cn = "cache-client.managedhsmclient.test";

    private readonly TestPki _pki = new();
    private readonly TempFolder _folder = new();
    private readonly ManualClock _clock = new(DateTimeOffset.UtcNow);

    public void Dispose()
    {
        _pki.Dispose();
        _folder.Dispose();
    }

    private sealed class ManualClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public void Advance(TimeSpan by) => _now += by;

        public override DateTimeOffset GetUtcNow() => _now;
    }

#pragma warning disable SYSLIB0058
    private sealed class FakeTls : ITlsHandshakeFeature, ITlsConnectionFeature
    {
        public SslProtocols Protocol => SslProtocols.Tls13;

        public System.Net.Security.TlsCipherSuite? NegotiatedCipherSuite => System.Net.Security.TlsCipherSuite.TLS_AES_256_GCM_SHA384;

        public string HostName => string.Empty;

        public CipherAlgorithmType CipherAlgorithm => CipherAlgorithmType.Aes256;

        public int CipherStrength => 256;

        public HashAlgorithmType HashAlgorithm => HashAlgorithmType.None;

        public int HashStrength => 0;

        public ExchangeAlgorithmType KeyExchangeAlgorithm => ExchangeAlgorithmType.None;

        public int KeyExchangeStrength => 0;

        public X509Certificate2? ClientCertificate { get; set; }

        public Task<X509Certificate2?> GetClientCertificateAsync(CancellationToken cancellationToken) => Task.FromResult(ClientCertificate);
    }
#pragma warning restore SYSLIB0058

    private sealed record Setup(MtlsCallerAuthorizer Authorizer, ConnectionRegistry Registry, NamespaceStore Store);

    private Setup Create(params NamespaceDefinition[] namespaces)
    {
        var store = NamespaceStore.Open(_folder.Path, namespaces);
        var registry = new ConnectionRegistry(_clock);
        return new Setup(new MtlsCallerAuthorizer(new ClientTrustProvider(store), registry, _clock), registry, store);
    }

    private NamespaceDefinition Namespace(string name, params X509Certificate2[] roots) => new()
    {
        Name = name,
        Prefix = name == "_default" ? string.Empty : "/" + name,
        ClientTrust = new ClientTrust { SubjectCommonNames = [Cn], CaCertificatesDerBase64 = roots.Select(static r => Convert.ToBase64String(r.RawData)).ToList() },
    };

    private static EkmAuthResult Authorize(Setup setup, string connectionId, X509Certificate2 client, NamespaceDefinition ns)
    {
        var context = new DefaultHttpContext();
        context.Features.Set<IHttpConnectionFeature>(new HttpConnectionFeature { ConnectionId = connectionId });
        var feature = new FakeTls { ClientCertificate = client };
        context.Features.Set<ITlsHandshakeFeature>(feature);
        context.Features.Set<ITlsConnectionFeature>(feature);

        var state = setup.Registry.Open(new DefaultConnectionContext(connectionId));
        state.SetClientCertificateVerdict(new HandshakeVerdict(true, "NoError", [], ClientCertificateSummary.From(client).ThumbprintSha256));
        state.CompleteHandshake("TLS 1.3", "TLS_AES_256_GCM_SHA384", null, null, ClientCertificateSummary.From(client), TimeSpan.FromMilliseconds(1));
        return setup.Authorizer.Authorize(context, ns);
    }

    [Fact]
    public void ARepeatedAuthorization_BuildsTheChainOnlyOnce()
    {
        var ns = Namespace("_default", _pki.ClientCaA.Certificate);
        var setup = Create(ns);
        using var client = _pki.ClientCaA.IssueClient(Cn);

        for (var i = 0; i < 5; i++)
        {
            Authorize(setup, "c" + i, client.Certificate, ns).Succeeded.ShouldBeTrue();
        }

        setup.Authorizer.ChainBuilds.ShouldBe(1);
    }

    [Fact]
    public void AFailedVerdict_IsNeverCached()
    {
        var ns = Namespace("_default", _pki.ClientCaA.Certificate);
        var setup = Create(ns);
        using var untrusted = _pki.UntrustedClientCa.IssueClient(Cn);

        for (var i = 0; i < 3; i++)
        {
            Authorize(setup, "c" + i, untrusted.Certificate, ns).Succeeded.ShouldBeFalse();
        }

        setup.Authorizer.ChainBuilds.ShouldBe(3);
    }

    [Fact]
    public void ChangingTheTrust_InvalidatesEveryCachedVerdict()
    {
        var ns = Namespace("_default", _pki.ClientCaA.Certificate);
        var setup = Create(ns);
        using var client = _pki.ClientCaA.IssueClient(Cn);
        Authorize(setup, "c1", client.Certificate, ns).Succeeded.ShouldBeTrue();

        // The operator replaces the trusted CA with another one: the certificate that was fine a moment ago must now be refused.
        var changed = Namespace("_default", _pki.ClientCaB.Certificate);
        setup.Store.Update(changed);
        var result = Authorize(setup, "c2", client.Certificate, changed);

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldBe(AuthFailure.ChainNotTrusted);
        setup.Authorizer.ChainBuilds.ShouldBe(2);
    }

    [Fact]
    public void AVerdict_IsNotServedAfterTheCertificateExpires()
    {
        var ns = Namespace("_default", _pki.ClientCaA.Certificate);
        var setup = Create(ns);
        using var client = _pki.ClientCaA.IssueClient(Cn, validity: TimeSpan.FromHours(1), notBefore: _clock.GetUtcNow().AddMinutes(-10));
        Authorize(setup, "c1", client.Certificate, ns).Succeeded.ShouldBeTrue();

        _clock.Advance(TimeSpan.FromHours(2));
        var result = Authorize(setup, "c2", client.Certificate, ns);

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldBe(AuthFailure.CertificateExpired);
    }

    [Fact]
    public void TheVerdictOfOneNamespace_DoesNotApplyToAnother()
    {
        var first = Namespace("_default", _pki.ClientCaA.Certificate);
        var second = Namespace("other", _pki.ClientCaB.Certificate);
        var setup = Create(first, second);
        using var client = _pki.ClientCaA.IssueClient(Cn);

        Authorize(setup, "c1", client.Certificate, first).Succeeded.ShouldBeTrue();
        var result = Authorize(setup, "c2", client.Certificate, second);

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldBe(AuthFailure.ChainNotTrusted);
    }

    [Fact]
    public void ACachedVerdict_StillEnforcesTheCommonNameList()
    {
        var ns = Namespace("_default", _pki.ClientCaA.Certificate);
        var setup = Create(ns);
        using var allowed = _pki.ClientCaA.IssueClient(Cn);
        using var otherName = _pki.ClientCaA.IssueClient("someone-else.local");

        Authorize(setup, "c1", allowed.Certificate, ns).Succeeded.ShouldBeTrue();
        var result = Authorize(setup, "c2", otherName.Certificate, ns);

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldBe(AuthFailure.CommonNameNotAllowed);
    }
}
