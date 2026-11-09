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

/// <summary>The authorizer on its own, with hand-made connection features (no listener): the rules that do not need a real handshake.</summary>
public sealed class MtlsCallerAuthorizerUnitTests : IDisposable
{
    private const string Cn = "unit-client.managedhsmclient.test";

    private readonly TestPki _pki = new();
    private readonly TempFolder _folder = new();

    public void Dispose()
    {
        _pki.Dispose();
        _folder.Dispose();
    }

    // ITlsHandshakeFeature still declares the obsolete algorithm/strength members, so a fake must implement them.
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

    private (MtlsCallerAuthorizer Authorizer, ConnectionRegistry Registry, NamespaceDefinition Ns) Create()
    {
        var ns = new NamespaceDefinition
        {
            Name = "_default",
            ClientTrust = new ClientTrust { SubjectCommonNames = [Cn], CaCertificatesDerBase64 = [_pki.ClientCaA.DerBase64] },
        };
        var store = NamespaceStore.Open(_folder.Path, [ns]);
        var registry = new ConnectionRegistry(TimeProvider.System);
        return (new MtlsCallerAuthorizer(new ClientTrustProvider(store), registry, TimeProvider.System), registry, ns);
    }

    private static DefaultHttpContext Context(string connectionId, X509Certificate2? presented, bool tls = true)
    {
        var context = new DefaultHttpContext();
        context.Features.Set<IHttpConnectionFeature>(new HttpConnectionFeature { ConnectionId = connectionId });
        if (tls)
        {
            var feature = new FakeTls { ClientCertificate = presented };
            context.Features.Set<ITlsHandshakeFeature>(feature);
            context.Features.Set<ITlsConnectionFeature>(feature);
        }

        return context;
    }

    private static ConnectionState RecordHandshake(ConnectionRegistry registry, string connectionId, X509Certificate2? certificate)
    {
        var state = registry.Open(new DefaultConnectionContext(connectionId));
        state.CompleteHandshake("TLS 1.3", "TLS_AES_256_GCM_SHA384", null, null, certificate is null ? null : ClientCertificateSummary.From(certificate), TimeSpan.FromMilliseconds(1));
        return state;
    }

    [Fact]
    public void ACertificateThatMatchesTheHandshakesRecord_IsAuthorized()
    {
        var (authorizer, registry, ns) = Create();
        using var client = _pki.ClientCaA.IssueClient(Cn);
        RecordHandshake(registry, "c1", client.Certificate);

        var result = authorizer.Authorize(Context("c1", client.Certificate), ns);

        result.Succeeded.ShouldBeTrue(result.Failure.ToString());
    }

    [Fact]
    public void ACertificateThatDiffersFromTheHandshakesRecord_IsRejected()
    {
        var (authorizer, registry, ns) = Create();
        using var recorded = _pki.ClientCaA.IssueClient(Cn);
        using var other = _pki.ClientCaA.IssueClient(Cn);
        RecordHandshake(registry, "c1", recorded.Certificate);

        var result = authorizer.Authorize(Context("c1", other.Certificate), ns);

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldBe(AuthFailure.ClientCertificateChanged);
    }

    [Fact]
    public void ACertificateOnARequestWhoseHandshakeSawNone_IsRejected()
    {
        var (authorizer, registry, ns) = Create();
        using var client = _pki.ClientCaA.IssueClient(Cn);
        RecordHandshake(registry, "c1", certificate: null);

        var result = authorizer.Authorize(Context("c1", client.Certificate), ns);

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldBe(AuthFailure.ClientCertificateChanged);
    }

    [Fact]
    public void ARequestWithoutTransportSecurity_IsNeverAuthorized_EvenWithACertificateOnTheContext()
    {
        var (authorizer, _, ns) = Create();
        using var client = _pki.ClientCaA.IssueClient(Cn);

        var result = authorizer.Authorize(Context("c1", client.Certificate, tls: false), ns);

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldBe(AuthFailure.NoTransportSecurity);
    }

    [Fact]
    public void ARequestWithoutACertificate_IsNeverAuthorized()
    {
        var (authorizer, registry, ns) = Create();
        RecordHandshake(registry, "c1", certificate: null);

        var result = authorizer.Authorize(Context("c1", presented: null), ns);

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldBe(AuthFailure.NoClientCertificate);
    }

    [Fact]
    public void ANamespaceTheTrustSnapshotDoesNotKnow_IsNeverAuthorized()
    {
        var (authorizer, registry, _) = Create();
        using var client = _pki.ClientCaA.IssueClient(Cn);
        RecordHandshake(registry, "c1", client.Certificate);

        var result = authorizer.Authorize(Context("c1", client.Certificate), new NamespaceDefinition { Name = "ghost" });

        result.Succeeded.ShouldBeFalse();
    }
}
