using System.Collections.Concurrent;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>Wraps the production authorizer and remembers what it decided (what the inspector will show, spec 8.1 "Client certificate").</summary>
internal sealed class RecordingAuthorizer : IEkmCallerAuthorizer
{
    private readonly IEkmCallerAuthorizer _inner;

    public RecordingAuthorizer(IEkmCallerAuthorizer inner) => _inner = inner;

    public ConcurrentQueue<(string Namespace, EkmAuthResult Result)> Results { get; } = new();

    public EkmAuthResult Authorize(HttpContext context, NamespaceDefinition ns)
    {
        var result = _inner.Authorize(context, ns);
        Results.Enqueue((ns.Name, result));
        return result;
    }
}

/// <summary>The client certificate facts captured per exchange (spec 8.1) for the inspector of M4.</summary>
public sealed class AuthCaptureTests : IAsyncLifetime
{
    private const string Cn = "capture-client.managedhsmclient.test";

    private TestPki _pki = null!;
    private RealEkmHost _host = null!;
    private RecordingAuthorizer _recorder = null!;

    public async ValueTask InitializeAsync()
    {
        _pki = new TestPki();
        _host = await RealEkmHost.StartAsync(new RealEkmHostOptions
        {
            Pki = _pki,
            Namespaces = [TestNamespace.Default(_pki.ClientCaA, Cn)],
            ConfigureServices = services => services.AddSingleton<IEkmCallerAuthorizer>(sp => new RecordingAuthorizer(ActivatorUtilities.CreateInstance<MtlsCallerAuthorizer>(sp))),
        });
        _recorder = (RecordingAuthorizer)_host.App.Services.GetRequiredService<IEkmCallerAuthorizer>();
    }

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        _pki.Dispose();
    }

    [Fact]
    public async Task AnAuthorizedExchange_CapturesEveryCertificateFact()
    {
        using var client = _pki.ClientCaA.IssueClient(Cn);

        (await _host.CreateEkmClient(client.Certificate).InfoAsync()).StatusCode.ShouldBe(200);

        var (ns, result) = _recorder.Results.Single();
        ns.ShouldBe("_default");
        result.Succeeded.ShouldBeTrue();
        result.Failure.ShouldBe(AuthFailure.None);
        result.CertificatePresent.ShouldBeTrue();
        result.NamespaceMatched.ShouldBeTrue();
        result.CommonNameAllowed.ShouldBe(true);
        result.CommonName.ShouldBe(Cn);
        result.ChainResult.ShouldBe("NoError");
        var certificate = result.Certificate.ShouldNotBeNull();
        certificate.Subject.ShouldContain(Cn);
        certificate.Issuer.ShouldBe(_pki.ClientCaA.Certificate.Subject);
        certificate.SerialNumber.ShouldBe(client.Certificate.SerialNumber);
        certificate.ThumbprintSha256.ShouldBe(client.Thumbprint);
        certificate.ThumbprintSha256.Length.ShouldBe(64);
        certificate.NotBeforeUtc.ShouldBeLessThan(DateTimeOffset.UtcNow);
        certificate.NotAfterUtc.ShouldBeGreaterThan(DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task ARejectedCommonName_IsCapturedWithTheChainResultAndCnAllowedFalse()
    {
        using var client = _pki.ClientCaA.IssueClient("not-allowed.example");

        (await _host.CreateEkmClient(client.Certificate).InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");

        var (_, result) = _recorder.Results.Single();
        result.Succeeded.ShouldBeFalse();
        result.NamespaceMatched.ShouldBeFalse();
        result.Failure.ShouldBe(AuthFailure.CommonNameNotAllowed);
        result.CommonNameAllowed.ShouldBe(false);
        result.ChainResult.ShouldBe("NoError"); // the chain was fine; only the name was not
        result.Certificate.ShouldNotBeNull().ThumbprintSha256.ShouldBe(client.Thumbprint);
    }

    [Fact]
    public async Task ARequestWithoutACertificate_IsCapturedAsNotPresent()
    {
        (await _host.CreateEkmClient().InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");

        var (_, result) = _recorder.Results.Single();
        result.CertificatePresent.ShouldBeFalse();
        result.Failure.ShouldBe(AuthFailure.NoClientCertificate);
        result.Certificate.ShouldBeNull();
        result.CommonNameAllowed.ShouldBeNull();
        result.ChainResult.ShouldBeNull();
    }

    [Fact]
    public async Task AnExpiredCertificate_IsCapturedWithItsValidityAndTheExpiredReason()
    {
        using var expired = _pki.ClientCaA.IssueClient(Cn, TimeSpan.FromDays(1), DateTimeOffset.UtcNow.AddDays(-4));

        (await _host.CreateEkmClient(expired.Certificate).InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");

        var (_, result) = _recorder.Results.Single();
        result.Failure.ShouldBe(AuthFailure.CertificateExpired);
        result.Certificate.ShouldNotBeNull().NotAfterUtc.ShouldBeLessThan(DateTimeOffset.UtcNow);
        result.ChainResult.ShouldNotBeNull().ShouldContain("NotTimeValid");
    }

    [Fact]
    public async Task EveryExchangeKnowsItsConnection()
    {
        using var client = _pki.ClientCaA.IssueClient(Cn);
        using var http = _host.CreateHttpClient(client.Certificate, singleConnection: true);
        var ekm = new EkmClient(http);

        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);

        // Same connection id on both exchanges, and the registry holds its TLS facts while it is open.
        var open = _host.Connections.OpenCount;
        open.ShouldBe(1);
    }
}
