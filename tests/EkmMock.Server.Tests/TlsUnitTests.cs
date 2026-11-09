using System.Net;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Crypto;
using EkmMock.Pki;
using EkmMock.Server.Hosting;
using EkmMock.Server.Tls;
using EkmMock.TestSupport;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

// The TlsPolicy tests read CipherSuitesPolicy inside explicit OS branches (the whole point is to prove what each OS supports).
#pragma warning disable CA1416

namespace EkmMock.Server.Tests;

/// <summary>The common-name rule of spec 5.1: the parsed CN attribute, exactly one, never a substring of the formatted subject.</summary>
public sealed class CommonNameReaderTests
{
    private static string? Cn(string subject) => CommonNameReader.TryGetSingleCommonName(new X500DistinguishedName(subject), out var cn) ? cn : null;

    [Theory]
    [InlineData("CN=host.example", "host.example")]
    [InlineData("O=Contoso, CN=host.example, C=NL", "host.example")]
    [InlineData("CN=\"a, b\"", "a, b")]
    [InlineData("CN=\"x+y=z\"", "x+y=z")]
    [InlineData("CN=Zoë", "Zoë")]
    [InlineData("CN=\"quo\"\"te\"", "quo\"te")]
    public void ASingleCommonName_IsReadAsItsParsedValue(string subject, string expected) => Cn(subject).ShouldBe(expected);

    [Theory]
    [InlineData("O=Contoso, C=NL")]
    [InlineData("CN=one, CN=two")]
    [InlineData("CN=\"\"")]
    public void NoCommonName_SeveralCommonNames_OrAMultiValuedRdn_AreAmbiguousAndYieldNothing(string subject) => Cn(subject).ShouldBeNull();

    [Fact]
    public void ACommonNameInAMultiValuedRdn_IsAmbiguousAndYieldsNothing()
    {
        // Real ASN.1 multi-valued RDNs (CN=one+OU=multi), in either order.
        foreach (var dn in new[]
        {
            DistinguishedNames.MultiValuedRdn((DistinguishedNames.CommonNameOid, "one"), (DistinguishedNames.OrganizationalUnitOid, "multi")),
            DistinguishedNames.MultiValuedRdn((DistinguishedNames.OrganizationalUnitOid, "multi"), (DistinguishedNames.CommonNameOid, "one")),
        })
        {
            CommonNameReader.TryGetSingleCommonName(dn, out var cn).ShouldBeFalse();
            cn.ShouldBeNull();
        }
    }

    [Fact]
    public void AnEmptySubject_YieldsNothing() => Cn(string.Empty).ShouldBeNull();
}

/// <summary>The endpoint URL rules: https only, with a port, and an address Kestrel can bind.</summary>
public sealed class EkmEndpointAddressTests
{
    [Fact]
    public void TheDefaultUrl_IsHttpsOnAllIPv4AddressesPort8443()
    {
        var address = EkmEndpointAddress.Parse(new EkmEndpointOptions().Url);

        address.Address.ShouldBe(IPAddress.Any);
        address.Port.ShouldBe(8443);
    }

    [Theory]
    [InlineData("https://127.0.0.1:0", "127.0.0.1", 0)]
    [InlineData("https://[::]:443", "::", 443)]
    [InlineData("HTTPS://10.1.2.3:8443/", "10.1.2.3", 8443)]
    public void IpAddressUrls_AreParsed(string url, string ip, int port)
    {
        var address = EkmEndpointAddress.Parse(url);

        address.Address.ShouldBe(IPAddress.Parse(ip));
        address.Port.ShouldBe(port);
    }

    [Fact]
    public void WildcardAndLocalhost_AreSupported()
    {
        EkmEndpointAddress.Parse("https://*:8443").IsAnyAddress.ShouldBeTrue();
        EkmEndpointAddress.Parse("https://+:8443").IsAnyAddress.ShouldBeTrue();
        EkmEndpointAddress.Parse("https://localhost:9000").IsLocalhost.ShouldBeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("http://0.0.0.0:8443")]
    [InlineData("0.0.0.0:8443")]
    [InlineData("https://0.0.0.0")]
    [InlineData("https://0.0.0.0:99999")]
    [InlineData("https://ekm.example.com:8443")]
    public void AnythingElse_IsRefused_NotEvenAPlainHttpSchemeIsAccepted(string url)
        => Should.Throw<InvalidOperationException>(() => EkmEndpointAddress.Parse(url));
}

/// <summary>The union trust snapshot follows the namespace store without a restart, atomically (spec 5.1).</summary>
public sealed class ClientTrustProviderTests : IDisposable
{
    private readonly TempFolder _folder = new();
    private readonly TestPki _pki = new();

    public void Dispose()
    {
        _folder.Dispose();
        _pki.Dispose();
    }

    private static NamespaceDefinition Ns(string name, string prefix, string[] cns, params CertificateAuthority[] cas) => new()
    {
        Name = name,
        Prefix = prefix,
        ClientTrust = new ClientTrust { SubjectCommonNames = cns, CaCertificatesDerBase64 = [.. cas.Select(static c => c.DerBase64)] },
    };

    [Fact]
    public void TheUnionContainsEveryNamespacesRoots_OnceEach_AndEachNamespaceKeepsItsOwn()
    {
        var store = NamespaceStore.Open(_folder.Path, [Ns("_default", "", ["a"], _pki.ClientCaA), Ns("other", "other", ["b"], _pki.ClientCaA, _pki.ClientCaB)]);
        using var provider = new ClientTrustProvider(store);

        var snapshot = provider.Current;

        snapshot.UnionRoots.Count.ShouldBe(2);
        snapshot.ByNamespace["_default"].Roots.Count.ShouldBe(1);
        snapshot.ByNamespace["other"].Roots.Count.ShouldBe(2);
        snapshot.ByNamespace["_default"].CommonNames.ShouldBe(["a"]);
    }

    [Fact]
    public void ChangingTheStore_ShowsUpInTheNextSnapshot_WithoutARestart()
    {
        var store = NamespaceStore.Open(_folder.Path, [Ns("_default", "", ["a"], _pki.ClientCaA)]);
        using var provider = new ClientTrustProvider(store);
        var before = provider.Current;
        provider.Current.ShouldBeSameAs(before); // unchanged store: the same snapshot, nothing rebuilt

        store.SetTrust("_default", new ClientTrust { SubjectCommonNames = ["a", "c"], CaCertificatesDerBase64 = [_pki.ClientCaA.DerBase64, _pki.ClientCaB.DerBase64] });
        var after = provider.Current;

        after.ShouldNotBeSameAs(before);
        after.UnionRoots.Count.ShouldBe(2);
        after.ByNamespace["_default"].CommonNames.ShouldBe(["a", "c"]);
        before.UnionRoots.Count.ShouldBe(1); // the old snapshot is immutable and still usable by a validation that started before the swap
        before.UnionRoots[0].Subject.ShouldContain("Client Root CA A");

        store.Add(Ns("new", "new", ["n"], _pki.UntrustedClientCa));
        provider.Current.UnionRoots.Count.ShouldBe(3);
        store.Remove("new");
        provider.Current.UnionRoots.Count.ShouldBe(2);
    }

    [Fact]
    public void ANamespaceWithoutCas_ContributesNothingToTheUnion()
    {
        var store = NamespaceStore.Open(_folder.Path, [Ns("_default", "", ["a"])]);
        using var provider = new ClientTrustProvider(store);

        provider.Current.UnionRoots.Count.ShouldBe(0);
        provider.Current.ByNamespace["_default"].Roots.Count.ShouldBe(0);
    }

    [Fact]
    public async Task ConcurrentReadersDuringChanges_AlwaysGetAUsableConsistentSnapshot()
    {
        var store = NamespaceStore.Open(_folder.Path, [Ns("_default", "", ["a"], _pki.ClientCaA)]);
        using var provider = new ClientTrustProvider(store);
        using var stop = new CancellationTokenSource();

        var readers = Enumerable.Range(0, 6).Select(_ => Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                var snapshot = provider.Current;
                var thumbprints = snapshot.UnionRoots.Select(static c => c.Thumbprint).ToList(); // would throw if a certificate were disposed
                thumbprints.Count.ShouldBe(snapshot.UnionRoots.Count);
                snapshot.ByNamespace.ContainsKey("_default").ShouldBeTrue();
            }
        })).ToList();

        for (var i = 0; i < 60; i++)
        {
            store.SetTrust("_default", new ClientTrust { SubjectCommonNames = ["a"], CaCertificatesDerBase64 = i % 2 == 0 ? [_pki.ClientCaA.DerBase64, _pki.ClientCaB.DerBase64] : [_pki.ClientCaA.DerBase64] });
        }

        await stop.CancelAsync();
        await Task.WhenAll(readers);
    }
}

/// <summary>The hot-reloadable certificate provider without Kestrel: loading, validation, dev mode, flags (spec 5.3).</summary>
public sealed class ServerCertificateProviderTests : IDisposable
{
    private readonly TempFolder _folder = new();
    private readonly TestPki _pki = new();
    private readonly CapturingLoggerProvider _logs = new();

    public void Dispose()
    {
        _folder.Dispose();
        _pki.Dispose();
    }

    private ServerCertificateProvider Create(TlsOptions? tls = null, bool dev = false)
    {
        var factory = LoggerFactory.Create(builder => builder.AddProvider(_logs).SetMinimumLevel(LogLevel.Information));
        return new ServerCertificateProvider(
            Options.Create(tls ?? new TlsOptions()),
            Options.Create(new DevOptions { Enabled = dev }),
            TimeProvider.System,
            factory.CreateLogger<ServerCertificateProvider>());
    }

    private TlsOptions Files(IssuedCertificate certificate)
    {
        var (certFile, keyFile) = certificate.WriteFiles(_folder.Path);
        return new TlsOptions { CertFile = certFile, KeyFile = keyFile, PollInterval = TimeSpan.FromHours(1), Debounce = TimeSpan.FromHours(1), RetiredCertificateGrace = TimeSpan.FromMinutes(5) };
    }

    [Fact]
    public void WithoutAConfiguredCertificate_AndNotInDevMode_TheProviderRefusesToStart()
    {
        var ex = Should.Throw<InvalidOperationException>(() => Create());

        ex.Message.ShouldContain("Tls:CertFile");
        ex.Message.ShouldContain("--dev");
    }

    [Fact]
    public void InDevMode_AThrowAwayLocalhostCertificateIsGenerated_AndClearlyFlagged()
    {
        using var provider = Create(dev: true);

        var info = provider.Info;
        info.IsDevelopmentCertificate.ShouldBeTrue();
        info.Source.ShouldBe(ServerCertificateSource.DevelopmentGenerated);
        info.SubjectAlternativeNames.ShouldContain("DNS:localhost");
        info.SubjectAlternativeNames.ShouldContain("IP:127.0.0.1");
        provider.DevelopmentRootCaPem.ShouldNotBeNull().ShouldStartWith("-----BEGIN CERTIFICATE-----");
        _logs.Entries.ShouldContain(static e => e.Level == LogLevel.Warning && e.Message.Contains("DEV MODE", StringComparison.Ordinal));
    }

    [Fact]
    public void ConfiguredFiles_WinOverDevMode_AndAreNotFlagged()
    {
        using var server = _pki.IssueServer();
        using var provider = Create(Files(server), dev: true);

        provider.Info.IsDevelopmentCertificate.ShouldBeFalse();
        provider.Info.Source.ShouldBe(ServerCertificateSource.File);
        provider.DevelopmentRootCaPem.ShouldBeNull();
    }

    [Fact]
    public void OnlyOneOfCertFileAndKeyFile_IsAConfigurationError()
    {
        var ex = Should.Throw<InvalidOperationException>(() => Create(new TlsOptions { CertFile = "x.crt" }));

        ex.Message.ShouldContain("together");
    }

    [Fact]
    public void MissingFiles_FailStartup_WithAClearMessage()
    {
        var ex = Should.Throw<InvalidOperationException>(() => Create(new TlsOptions { CertFile = Path.Combine(_folder.Path, "no.crt"), KeyFile = Path.Combine(_folder.Path, "no.key") }));

        ex.Message.ShouldContain("cannot be read");
    }

    [Fact]
    public void ABrokenCertificateAtStartup_FailsStartup_WithoutLeakingTheKey()
    {
        using var server = _pki.IssueServer();
        var options = Files(server);
        File.WriteAllText(options.CertFile!, "not pem");

        var ex = Should.Throw<InvalidOperationException>(() => Create(options));

        ex.Message.ShouldNotContain("PRIVATE KEY");
        ex.ToString().ShouldNotContain(server.PrivateKeyPem.Split('\n')[1]);
    }

    [Fact]
    public void TheCertificateKeyMustBelongToTheCertificate()
    {
        using var a = _pki.IssueServer();
        using var b = _pki.IssueServer();
        var options = Files(a);
        File.WriteAllText(options.KeyFile!, b.PrivateKeyPem);

        Should.Throw<InvalidOperationException>(() => Create(options)).Message.ShouldContain("cannot be used");
    }

    [Fact]
    public void ACertificateExpiringWithin30Days_IsFlagged_AndWarnedAbout()
    {
        using var soon = _pki.ServerCa.IssueServer(["localhost"], TimeSpan.FromDays(10));
        using var later = _pki.ServerCa.IssueServer(["localhost"], TimeSpan.FromDays(60));

        using (var provider = Create(Files(soon)))
        {
            provider.Info.ExpiresSoon.ShouldBeTrue();
            provider.Info.IsExpired.ShouldBeFalse();
            _logs.Entries.ShouldContain(static e => e.Level == LogLevel.Warning && e.Message.Contains("expires within 30 days", StringComparison.Ordinal));
        }

        using var second = Create(Files(later));
        second.Info.ExpiresSoon.ShouldBeFalse();
    }

    [Fact]
    public void AnAlreadyExpiredCertificateAtStartup_Loads_ButIsFlaggedExpired()
    {
        // The operator must be able to start the process and see the problem in the console rather than not get a console at all.
        using var expired = _pki.ServerCa.IssueServer(["localhost"], TimeSpan.FromDays(1), DateTimeOffset.UtcNow.AddDays(-5));

        using var provider = Create(Files(expired));

        provider.Info.IsExpired.ShouldBeTrue();
        _logs.Entries.ShouldContain(static e => e.Level == LogLevel.Error && e.Message.Contains("EXPIRED", StringComparison.Ordinal));
    }

    [Fact]
    public void AnIntermediateInTheCertFile_IsPartOfTheChain()
    {
        using var intermediate = _pki.ServerCa.IssueIntermediate(_pki.Name("Issuing CA"));
        using var leaf = intermediate.IssueServer(["localhost"]);

        using var provider = Create(Files(leaf));

        provider.Info.ChainLength.ShouldBe(2);
        provider.Current.Context.IntermediateCertificates.Count.ShouldBe(1);
    }

    [Fact]
    public void ReloadFromFiles_SwapsAtomically_RaisesChangedOnce_AndIgnoresUnchangedContent()
    {
        using var first = _pki.IssueServer();
        using var second = _pki.IssueServer();
        var options = Files(first);
        using var provider = Create(options);
        var changes = new List<string>();
        provider.Changed += snapshot => changes.Add(snapshot.Thumbprint);

        provider.ReloadFromFiles("unchanged");
        changes.ShouldBeEmpty();

        second.WriteFiles(_folder.Path);
        provider.ReloadFromFiles("test");
        provider.ReloadFromFiles("test again");

        provider.Current.Thumbprint.ShouldBe(second.Thumbprint);
        changes.ShouldBe([second.Thumbprint]);
        provider.LastError.ShouldBeNull();
    }

    [Fact]
    public void AFailedReload_IsLoggedOncePerBadContent_NotOnEveryPoll()
    {
        using var server = _pki.IssueServer();
        var options = Files(server);
        using var provider = Create(options);
        File.WriteAllText(options.CertFile!, "garbage");

        provider.ReloadFromFiles("poll");
        provider.ReloadFromFiles("poll");
        provider.ReloadFromFiles("poll");

        provider.LastError.ShouldNotBeNull();
        _logs.Entries.Count(static e => e.Level == LogLevel.Warning && e.Message.Contains("reload", StringComparison.Ordinal)).ShouldBe(1);
        provider.Current.Thumbprint.ShouldBe(server.Thumbprint);
    }

    [Fact]
    public async Task ReadersNeverSeeANullOrDisposedCertificate_WhileItIsSwappedRepeatedly()
    {
        using var first = _pki.IssueServer();
        var options = Files(first);
        using var provider = Create(options);
        using var stop = new CancellationTokenSource();
        var replacements = Enumerable.Range(0, 12).Select(_ => _pki.IssueServer()).ToList();

        var readers = Enumerable.Range(0, 6).Select(_ => Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                var snapshot = provider.Current;
                snapshot.Certificate.Thumbprint.ShouldNotBeNullOrEmpty();
                snapshot.Certificate.HasPrivateKey.ShouldBeTrue();
            }
        })).ToList();

        foreach (var replacement in replacements)
        {
            await provider.ReplaceAsync(replacement.ChainPem, replacement.PrivateKeyPem, TestContext.Current.CancellationToken);
        }

        await stop.CancelAsync();
        await Task.WhenAll(readers);
        provider.Current.Thumbprint.ShouldBe(replacements[^1].Thumbprint);
        replacements.ForEach(static r => r.Dispose());
    }

    [Fact]
    public async Task AfterDispose_ReplaceIsRefused()
    {
        using var first = _pki.IssueServer();
        var provider = Create(Files(first));
        provider.Dispose();

        await Should.ThrowAsync<ObjectDisposedException>(() => provider.ReplaceAsync(first.ChainPem, first.PrivateKeyPem, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void TheUploadSeam_IsAnInterfaceMemberSoTheConsoleCanUseIt()
        => typeof(IServerCertificateProvider).GetMethod(nameof(IServerCertificateProvider.ReplaceAsync)).ShouldNotBeNull();

    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    public void TheTlsOptionsRejectNonsense(int pollMilliseconds)
        => new TlsOptions { PollInterval = TimeSpan.FromMilliseconds(pollMilliseconds) }.Validate().ShouldNotBeNull();
}

/// <summary>The effective TLS policy the About page shows, and what this OS can actually enforce.</summary>
public sealed class TlsPolicyTests
{
    [Fact]
    public void TheEffectivePolicy_NamesTls13AndTheTwoPermittedSuites()
    {
        var policy = new TlsPolicy();

        policy.Effective.Protocol.ShouldBe("TLS 1.3 only");
        policy.Effective.PermittedCipherSuites.ShouldBe(["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]);
        policy.Effective.CipherSuiteSummary.ShouldNotBeNullOrWhiteSpace();
        policy.Effective.OperatingSystem.ShouldNotBeNullOrWhiteSpace();
        TlsPolicy.RequiredProtocols.ShouldBe(System.Security.Authentication.SslProtocols.Tls13);
    }

    [Fact]
    public void EnforcementCapability_IsProbed_AndMatchesWhatThePlatformSupports()
    {
        var policy = new TlsPolicy();

        if (OperatingSystem.IsWindows())
        {
            policy.CanEnforceCipherSuites.ShouldBeFalse("CipherSuitesPolicy is not supported on Windows");
            policy.Effective.CipherSuiteEnforcement.ShouldBe(CipherSuiteEnforcement.NotEnforceableByTlsStack);
            policy.Effective.CipherSuiteSummary.ShouldContain("not enforceable");
            policy.CipherSuitesPolicy.ShouldBeNull();
        }
        else if (OperatingSystem.IsLinux())
        {
            policy.CanEnforceCipherSuites.ShouldBeTrue("Linux/OpenSSL supports CipherSuitesPolicy");
            policy.Effective.CipherSuiteEnforcement.ShouldBe(CipherSuiteEnforcement.EnforcedByTlsStack);
            policy.CipherSuitesPolicy.ShouldNotBeNull().AllowedCipherSuites.ShouldBe(TlsPolicy.PermittedSuites);
        }

        (policy.CipherSuitesPolicy is not null).ShouldBe(policy.CanEnforceCipherSuites);
    }

    [Fact]
    public void OnlyTheTwoAesGcmSuitesArePermitted()
    {
        TlsPolicy.IsPermitted(System.Net.Security.TlsCipherSuite.TLS_AES_256_GCM_SHA384).ShouldBeTrue();
        TlsPolicy.IsPermitted(System.Net.Security.TlsCipherSuite.TLS_AES_128_GCM_SHA256).ShouldBeTrue();
        TlsPolicy.IsPermitted(System.Net.Security.TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256).ShouldBeFalse();
        TlsPolicy.IsPermitted(System.Net.Security.TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).ShouldBeFalse();
    }
}
