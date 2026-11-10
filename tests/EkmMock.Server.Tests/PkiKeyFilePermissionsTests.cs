using EkmMock.Pki;
using EkmMock.TestSupport;

namespace EkmMock.Server.Tests;

/// <summary>Security review I8: <c>IssuedCertificate.WriteFiles</c> writes the private key readable by its owner only (Unix mode 0600, a current-user-only ACL on Windows).</summary>
public sealed class PkiKeyFilePermissionsTests
{
    [Fact]
    public void WriteFiles_CreatesThePrivateKeyOwnerOnly_AndTheCertificateAsPublicText()
    {
        using var folder = new TempFolder();
        using var pki = new TestPki();
        using var server = pki.IssueServer();

        var (certFile, keyFile) = server.WriteFiles(folder.Path);

        SecureFile.IsOwnerOnly(keyFile).ShouldBeTrue("the private key must not be readable by others");
        File.ReadAllText(keyFile).ShouldBe(server.PrivateKeyPem);
        File.ReadAllText(certFile).ShouldBe(server.ChainPem);
        File.ReadAllText(keyFile).ShouldNotStartWith("\uFEFF");
    }

    [Fact]
    public void WriteFiles_OverAnExistingKeyFile_ReplacesTheContent_AndStaysOwnerOnly()
    {
        using var folder = new TempFolder();
        using var pki = new TestPki();
        using var first = pki.IssueServer();
        using var second = pki.IssueServer();
        var (_, keyFile) = first.WriteFiles(folder.Path);

        second.WriteFiles(folder.Path);

        File.ReadAllText(keyFile).ShouldBe(second.PrivateKeyPem);
        SecureFile.IsOwnerOnly(keyFile).ShouldBeTrue();
    }

    [Fact]
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    public void WriteFiles_TightensAnExistingKeyFileThatWasCreatedWithWidePermissionsOnUnix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix file modes only.");
        using var folder = new TempFolder();
        using var pki = new TestPki();
        using var server = pki.IssueServer();
        var keyFile = Path.Combine(folder.Path, "server.key");
        File.WriteAllText(keyFile, "old");
        TightenOrWiden(keyFile);

        server.WriteFiles(folder.Path);

        SecureFile.IsOwnerOnly(keyFile).ShouldBeTrue();
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void TightenOrWiden(string path)
        => File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
}
