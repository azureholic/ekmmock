using EkmMock.Pki;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Pages;

namespace EkmMock.Console.Tests;

/// <summary>M6, spec 8.5.7 and 5.3: the Certificates page: the served certificate, the expiry warning, upload, generated test PKI, the root CA download and the TLS policy.</summary>
public sealed class CertificatesPageTests : AdminPageTestBase
{
    private IRenderedComponent<CertificatesPage> Open() => Render<CertificatesPage>();

    private static void Type(IRenderedComponent<CertificatesPage> cut, string role, string text)
    {
        var field = cut.Find($"[data-role='{role}']");
        field.Input(text);
        field.Change(text);
    }

    [Fact]
    public void TheCurrentCertificate_ShowsSanIssuerChainValidityAndThumbprint()
    {
        var cut = Open();

        Text(cut.Find("[data-role='cert-san']")).ShouldContain("DNS:localhost");
        Text(cut.Find("[data-role='cert-san']")).ShouldContain("IP:127.0.0.1");
        Text(cut.Find("[data-role='cert-issuer']")).ShouldContain("EkmMock Test Server Root CA");
        Text(cut.Find("[data-role='cert-chain']")).ShouldContain("The root CA is never sent");
        cut.Find("[data-role='cert-thumbprint']").TextContent.ShouldBe(Env.Certificates.Info.ThumbprintSha256);
        cut.Find("[data-role='cert-expiry']").ClassList.ShouldContain("status-ok");
        Text(cut.Find("[data-role='cert-source']")).ShouldContain("Configured files");
        cut.FindAll("[data-role='cert-warning']").ShouldBeEmpty();
        cut.Markup.ShouldNotContain("PRIVATE KEY-----", Case.Sensitive);
    }

    [Fact]
    public void TheTlsPolicy_IsShown_WithWhatTheOsCanEnforce()
    {
        var cut = Open();

        var policy = Text(cut.Find("[data-role='tls-policy']"));
        policy.ShouldContain("TLS 1.3 only");
        policy.ShouldContain("TLS_AES_256_GCM_SHA384");
        policy.ShouldContain("TLS_AES_128_GCM_SHA256");
        var enforcement = Text(cut.Find("[data-role='tls-enforcement']"));
        (enforcement.Contains("enforced by the TLS stack", StringComparison.Ordinal) || enforcement.Contains("not enforceable on this OS", StringComparison.Ordinal)).ShouldBeTrue(enforcement);
    }

    [Fact]
    public async Task ACertificateExpiringWithin30Days_IsWarnedAbout_WithTheDaysLeft()
    {
        using var soon = Env.Pki.ServerCa.IssueServer(["localhost", "127.0.0.1", "::1"], TimeSpan.FromDays(12), DateTimeOffset.UtcNow.AddDays(-1));
        await Env.Certificates.ReplaceAsync(soon.ChainPem, soon.PrivateKeyPem, Xunit.TestContext.Current.CancellationToken);

        var cut = Open();

        var warning = cut.Find("[data-role='cert-warning']");
        warning.ClassList.ShouldContain("intent-warning");
        Text(warning).ShouldContain("expires in");
        var expiry = Text(cut.Find("[data-role='cert-expiry']"));
        expiry.ShouldContain("renew soon");
        expiry.ShouldContain("⚠");
        cut.Find("[data-role='cert-expiry']").ClassList.ShouldContain("status-client");
    }

    [Fact]
    public void Upload_AValidCertificateAndKey_IsInstalled_AndTheKeyFieldIsClearedAtOnce()
    {
        using var fresh = Env.Pki.ServerCa.IssueServer(["localhost", "127.0.0.1", "::1"]);
        var cut = Open();
        cut.Find("[data-role='upload-cert']").Change(fresh.ChainPem);
        cut.Find("[data-role='upload-key']").Change(fresh.PrivateKeyPem);

        cut.Find("[data-role='upload-submit']").Click();

        cut.WaitForAssertion(() => Text(cut.Find("[data-role='action-result']")).ShouldContain("is installed and served to new connections"), Patience);
        Env.Certificates.Info.ThumbprintSha256.ShouldBe(fresh.Thumbprint);
        cut.Find("[data-role='cert-thumbprint']").TextContent.ShouldBe(fresh.Thumbprint);
        cut.Find("[data-role='upload-key']").GetAttribute("value").ShouldBeNullOrEmpty();
        cut.Markup.ShouldNotContain(fresh.PrivateKeyPem.Split('\n')[1].Trim());
        Env.Entries.Single(static e => e.Action == "certificate.upload").User.ShouldBe("loopback");
        Env.Entries.ShouldAllBe(static e => !(e.Detail ?? string.Empty).Contains("PRIVATE", StringComparison.Ordinal));
    }

    [Fact]
    public void Upload_AMismatchedKey_IsRefused_TheServedCertificateStays_AndTheReloadErrorIsShown()
    {
        var before = Env.Certificates.Info.ThumbprintSha256;
        using var cert = Env.Pki.ServerCa.IssueServer(["localhost"]);
        using var other = Env.Pki.ServerCa.IssueServer(["localhost"]);
        var cut = Open();
        cut.Find("[data-role='upload-cert']").Change(cert.ChainPem);
        cut.Find("[data-role='upload-key']").Change(other.PrivateKeyPem);

        cut.Find("[data-role='upload-submit']").Click();

        cut.WaitForAssertion(() => cut.Find("[data-role='action-result']").ClassList.ShouldContain("intent-error"), Patience);
        Text(cut.Find("[data-role='action-result']")).ShouldContain("previous certificate is still served");
        Env.Certificates.Info.ThumbprintSha256.ShouldBe(before);
        var reloadError = cut.Find("[data-role='reload-error']");
        reloadError.ClassList.ShouldContain("intent-error");
        Text(reloadError).ShouldContain("last reload or upload failed");
        cut.Markup.ShouldNotContain("PRIVATE KEY-----", Case.Sensitive);
        Env.Entries.ShouldNotContain(static e => e.Action == "certificate.upload");
    }

    [Fact]
    public void Generate_ValidatesTheFqdn_AndInstallsTestPki_WithAPublicRootDownload()
    {
        var cut = Open();
        cut.Find("[data-role='generate-submit']").HasAttribute("disabled").ShouldBeTrue();
        Type(cut, "fqdn", "bad host!");
        Text(cut.Find("[data-role='fqdn-message']")).ShouldContain("is not a valid DNS name or IP address");
        cut.Find("[data-role='generate-submit']").HasAttribute("disabled").ShouldBeTrue();
        cut.FindAll("[data-role='root-ca']").ShouldBeEmpty("no root CA until test PKI is generated");

        Type(cut, "fqdn", "ekm.contoso.test");
        cut.Find("[data-role='generate-submit']").HasAttribute("disabled").ShouldBeFalse();
        cut.Find("[data-role='generate-submit']").Click();

        cut.WaitForAssertion(() => Text(cut.Find("[data-role='action-result']")).ShouldContain("Test PKI generated and installed for DNS:ekm.contoso.test"), Patience);
        Text(cut.Find("[data-role='cert-san']")).ShouldBe("DNS:ekm.contoso.test");
        Text(cut.Find("[data-role='cert-source']")).ShouldContain("Generated test PKI");
        var rootPem = cut.Find("[data-role='root-ca-pem']").TextContent;
        rootPem.ShouldStartWith("-----BEGIN CERTIFICATE-----");
        rootPem.ShouldNotContain("PRIVATE");
        var link = cut.Find("[data-role='root-ca-download']");
        link.GetAttribute("href").ShouldBe("/api/console/certificates/root-ca.pem");
        link.HasAttribute("download").ShouldBeTrue();
        cut.Markup.ShouldNotContain("PRIVATE KEY-----", Case.Sensitive);
        Env.CertificateAdmin.GetRootCaPem().ShouldBe(rootPem);
        Env.Entries.Single(static e => e.Action == "certificate.generate").Target.ShouldBe("certificate:ekm.contoso.test");
    }
}
