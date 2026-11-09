using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Pki;
using EkmMock.Server.Hosting;
using EkmMock.Server.Tls;
using EkmMock.TestSupport;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>
/// Hygiene guard (M7, open question 46): on Windows a certificate whose private key was imported into a regular key container leaves a file in the user's CNG key store
/// unless the certificate is disposed. These tests look at the <em>named key</em> of each certificate (not at a directory count, which would be disturbed by other test processes
/// running at the same time) and prove: CA certificates have ephemeral keys and create nothing; leaf certificates delete their container on dispose; the certificate provider
/// releases the certificate it retired at a hot reload when it is disposed, instead of leaving it to a grace-period task that a stopping host never runs. Skipped off Windows.
/// </summary>
public sealed class WindowsKeyContainerTests
{
    private static string? PersistedKeyName(X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa is RSACng rsaCng)
        {
            return rsaCng.Key.KeyName;
        }

        using var ecdsa = certificate.GetECDsaPrivateKey();
        return ecdsa is ECDsaCng ecdsaCng ? ecdsaCng.Key.KeyName : null;
    }

    private static bool ContainerExists(string name)
        => OperatingSystem.IsWindows() && CngKey.Exists(name, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.UserKey);

    [Theory]
    [InlineData(PkiKeyAlgorithm.EcdsaP256)]
    [InlineData(PkiKeyAlgorithm.Rsa2048)]
    public void ACaCertificate_HasAnEphemeralKey_AndALeafCertificateDeletesItsContainerWhenDisposed(PkiKeyAlgorithm algorithm)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The key container behaviour under test is specific to the Windows CNG key store.");
        using var ca = CertificateAuthority.CreateRoot("EkmMock key container guard " + Guid.NewGuid().ToString("N")[..8], algorithm);
        PersistedKeyName(ca.Certificate).ShouldBeNull("a CA only signs: its key is ephemeral and no file is created");
        using var intermediate = ca.IssueIntermediate("EkmMock key container guard intermediate " + Guid.NewGuid().ToString("N")[..8]);
        PersistedKeyName(intermediate.Certificate).ShouldBeNull();

        var server = intermediate.IssueServer(["localhost"]);
        var client = ca.IssueClient("guard-client");
        var serverKey = PersistedKeyName(server.Certificate).ShouldNotBeNull("a TLS leaf needs a regular container (SChannel refuses ephemeral keys)");
        var clientKey = PersistedKeyName(client.Certificate).ShouldNotBeNull();
        ContainerExists(serverKey).ShouldBeTrue();
        ContainerExists(clientKey).ShouldBeTrue();

        server.Dispose();
        client.Dispose();

        ContainerExists(serverKey).ShouldBeFalse("disposing the certificate deletes its container");
        ContainerExists(clientKey).ShouldBeFalse();
    }

    [Fact]
    public void TheCertificateProvider_ReleasesTheCertificateItRetiredAtAReload_WhenItIsDisposed()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The key container behaviour under test is specific to the Windows CNG key store.");
        using var folder = new TempFolder();
        using var pki = new TestPki();
        using var first = pki.IssueServer();
        using var second = pki.IssueServer();
        var (certFile, keyFile) = first.WriteFiles(folder.Path);
        var provider = new ServerCertificateProvider(
            Options.Create(new TlsOptions { CertFile = certFile, KeyFile = keyFile, PollInterval = TimeSpan.FromHours(1), Debounce = TimeSpan.FromHours(1), RetiredCertificateGrace = TimeSpan.FromHours(1) }),
            Options.Create(new DevOptions()),
            TimeProvider.System,
            NullLogger<ServerCertificateProvider>.Instance);
        var firstKey = PersistedKeyName(provider.Current.Certificate).ShouldNotBeNull();
        File.WriteAllText(keyFile, second.PrivateKeyPem);
        File.WriteAllText(certFile, second.ChainPem);
        provider.ReloadFromFiles("test");
        provider.Current.Thumbprint.ShouldBe(second.Thumbprint);
        var secondKey = PersistedKeyName(provider.Current.Certificate).ShouldNotBeNull();
        ContainerExists(firstKey).ShouldBeTrue("the retired certificate lives on for the grace period (a handshake may still use it)");

        provider.Dispose();

        ContainerExists(firstKey).ShouldBeFalse("the retired certificate is released with the provider, not after an hour");
        ContainerExists(secondKey).ShouldBeFalse();
    }

    [Fact]
    public async Task ARealHost_LeavesNoKeyContainerOfItsServerCertificateBehind_OnceItIsDisposed()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "The key container behaviour under test is specific to the Windows CNG key store.");
        using var pki = new TestPki();
        string? serverKey;
        await using (var host = await RealEkmHost.StartAsync(new RealEkmHostOptions { Pki = pki }))
        {
            serverKey = PersistedKeyName(host.Certificates.Current.Certificate).ShouldNotBeNull();
            ContainerExists(serverKey).ShouldBeTrue();
        }

        ContainerExists(serverKey).ShouldBeFalse("the host's server certificate was disposed with the host");
    }
}
