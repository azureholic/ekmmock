using AngleSharp.Dom;
using EkmMock.Crypto;
using EkmMock.Pki;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FluentUI.AspNetCore.Components;

namespace EkmMock.Console.Tests;

/// <summary>M6, spec 8.5.6, 4.2 and 5.1: the Namespaces &amp; trust page: validation, the trust import with preview and warnings, runtime changes, the delete rules and the az command.</summary>
public sealed class NamespacesPageTests : AdminPageTestBase
{
    public NamespacesPageTests()
    {
        Env.AddNamespace("_default", string.Empty, ("aes-key-1", KeyType.Oct, 256));
        Env.AddNamespace("contoso", "contoso/prod");
    }

    private IRenderedComponent<NamespacesPage> Open() => Render<NamespacesPage>();

    private static void Type(IRenderedComponent<NamespacesPage> cut, string role, string text)
    {
        var field = cut.Find($"[data-role='{role}']");
        field.Input(text);
        field.Change(text);
    }

    private static void Manage(IRenderedComponent<NamespacesPage> cut, string ns) => cut.Find($"[data-role='ns-name'][data-ns='{ns}']").Click();

    private string AzureJson(CertificateAuthority ca, string cn) => Json(new { subjectCommonName = cn, caCertificates = new[] { ca.DerBase64 } });

    [Fact]
    public void TheNamespaces_AreListed_WithPrefixKeysAndTrustCounts()
    {
        var cut = Open();

        var rows = cut.FindAll("[data-role='ns-name']").Select(static e => e.GetAttribute("data-ns")).ToList();
        rows.ShouldBe(["_default", "contoso"]);
        var row = cut.Find("[data-ns='contoso'][data-role='ns-name']").Closest("tr")!;
        Text(row.QuerySelector("[data-role='ns-prefix']")!).ShouldBe("/contoso/prod");
        Text(cut.Find("[data-ns='_default'][data-role='ns-name']").Closest("tr")!.QuerySelector("[data-role='ns-keys']")!).ShouldBe("1");
        Text(cut.Find("[data-ns='_default'][data-role='ns-name']").Closest("tr")!.QuerySelector("[data-role='ns-prefix']")!).ShouldBe("(no prefix)");
    }

    [Fact]
    public void Create_ValidatesNameAndPrefixWhileTyping_AndCreatesTheNamespace()
    {
        var cut = Open();
        cut.Find("[data-role='create-toggle']").Click();

        Type(cut, "create-name", "bad name");
        Text(cut.Find("[data-role='create-name-message']")).ShouldContain("Use 1 to 64 letters");
        Type(cut, "create-name", "contoso");
        Text(cut.Find("[data-role='create-name-message']")).ShouldContain("already exists");
        Type(cut, "create-name", "fabrikam");
        Type(cut, "create-prefix", "bad prefix");
        Text(cut.Find("[data-role='create-prefix-message']")).ShouldContain("Prefix may only contain");
        Type(cut, "create-prefix", "contoso/prod");
        Text(cut.Find("[data-role='create-prefix-message']")).ShouldContain("already uses this prefix");
        cut.Find("[data-role='create-submit']").HasAttribute("disabled").ShouldBeTrue();
        Type(cut, "create-prefix", "");
        Text(cut.Find("[data-role='create-prefix-message']")).ShouldContain("Only _default may have an empty prefix");
        Type(cut, "create-prefix", "/fab/rikam/");
        Text(cut.Find("[data-role='create-prefix-message']")).ShouldContain("Normalised to /fab/rikam");
        cut.Find("[data-role='create-submit']").HasAttribute("disabled").ShouldBeFalse();

        cut.Find("[data-role='create-submit']").Click();

        cut.Find("[data-ns='fabrikam'][data-role='ns-name']").ShouldNotBeNull();
        Env.NamespaceStore.Get("fabrikam")!.Prefix.ShouldBe("fab/rikam");
        File.ReadAllText(Path.Combine(Env.DataPath, "namespaces.json")).ShouldContain("fab/rikam");
        Env.Entries.Single(static e => e.Action == "namespace.create" && e.Target == "namespace:fabrikam").User.ShouldBe("loopback");
    }

    [Fact]
    public void Create_AllowsAnOverlappingPrefix_ButNotTheSameOne()
    {
        var cut = Open();
        cut.Find("[data-role='create-toggle']").Click();
        Type(cut, "create-name", "deeper");
        Type(cut, "create-prefix", "contoso/prod/eu");

        cut.Find("[data-role='create-submit']").HasAttribute("disabled").ShouldBeFalse("longest-prefix routing makes overlapping prefixes fine");
        cut.Find("[data-role='create-submit']").Click();

        cut.FindAll("[data-role='ns-warning']").Select(static w => w.TextContent).ShouldContain(static w => w.Contains("overlaps with namespace 'contoso'", StringComparison.Ordinal));
    }

    [Fact]
    public void ATrustImport_ShowsTheCnAndEveryCa_BeforeSaving_ThenSaves()
    {
        var cut = Open();
        Manage(cut, "contoso");
        cut.Find("[data-role='import-text']").Change(AzureJson(Env.Pki.ClientCaA, "mhsm.managedhsmclient.test"));

        cut.Find("[data-role='import-preview']").Click();

        var preview = cut.Find("[data-role='import-preview-result']");
        Text(preview.QuerySelector("[data-role='preview-cns']")!).ShouldBe("mhsm.managedhsmclient.test");
        var ca = preview.QuerySelector("[data-role='preview-ca']")!;
        Text(ca).ShouldContain("EkmMock Test Client Root CA A");
        Text(ca).ShouldContain("root CA");
        Text(preview.QuerySelector("[data-role='preview-result']")!).ShouldBe("1 common name(s), 1 CA(s)");
        Env.NamespaceStore.Get("contoso")!.ClientTrust.SubjectCommonNames.ShouldBeEmpty("nothing is saved by the preview");
        Env.Entries.ShouldNotContain(static e => e.Action == "namespace.trust.import");

        cut.Find("[data-role='import-save']").Click();

        Env.NamespaceStore.Get("contoso")!.ClientTrust.SubjectCommonNames.ShouldBe(["mhsm.managedhsmclient.test"]);
        Env.NamespaceStore.Get("contoso")!.ClientTrust.CaCertificatesDerBase64.ShouldBe([Env.Pki.ClientCaA.DerBase64]);
        Text(cut.Find("[data-role='action-result']")).ShouldContain("Trust saved for contoso");
        cut.Find("[data-role='cn-list']").TextContent.ShouldContain("mhsm.managedhsmclient.test");
        Text(cut.Find("[data-role='ca-subject']")).ShouldContain("EkmMock Test Client Root CA A");
        Env.Entries.Single(static e => e.Action == "namespace.trust.import").Detail.ShouldBe("mode=merge format=json cns=1 cas=1");
        Env.Entries.ShouldAllBe(static e => !(e.Detail ?? string.Empty).Contains("MII", StringComparison.Ordinal), "no certificate content in the audit log");
    }

    [Fact]
    public void ThePreviewWarns_AboutALeafCertificate_AnIssuingCa_AndAnExpiredCa()
    {
        using var leaf = Env.Pki.ClientCaA.IssueClient("some-leaf");
        using var issuing = Env.Pki.ClientCaA.IssueIntermediate("EkmMock Test Issuing CA " + Guid.NewGuid().ToString("N")[..6]);
        using var expired = CertificateAuthority.CreateRoot("EkmMock Expired CA " + Guid.NewGuid().ToString("N")[..6], PkiKeyAlgorithm.EcdsaP256, TimeSpan.FromDays(2), DateTimeOffset.UtcNow.AddDays(-30));
        var cut = Open();
        Manage(cut, "contoso");
        var input = Json(new { subjectCommonName = "x", caCertificates = new[] { Convert.ToBase64String(leaf.Der), issuing.DerBase64, expired.DerBase64 } });
        cut.Find("[data-role='import-text']").Change(input);

        cut.Find("[data-role='import-preview']").Click();

        var warnings = cut.FindAll("[data-role='preview-warning']").Select(static w => w.TextContent).ToList();
        warnings.ShouldContain(static w => w.Contains("not a CA certificate", StringComparison.Ordinal) && w.Contains("leaf", StringComparison.Ordinal));
        warnings.ShouldContain(static w => w.Contains("issuing CA, not a self-signed root", StringComparison.Ordinal));
        warnings.ShouldContain(static w => w.Contains("expired", StringComparison.Ordinal));
        cut.FindAll("[data-role='preview-warning']").ShouldAllBe(static w => w.ClassList.Contains("intent-warning"));
        Text(cut.Find("[data-role='preview-cas']")).ShouldContain("(expired)");
        Text(cut.Find("[data-role='preview-cas']")).ShouldContain("not a CA (leaf?)");
    }

    [Fact]
    public void BadTrustInput_IsReportedInWords_AndNothingIsSaved()
    {
        var cut = Open();
        Manage(cut, "contoso");

        foreach (var bad in new[] { "this is not trust", "{\"subjectCommonName\":\"x\"}" })
        {
            cut.Find("[data-role='import-text']").Change(bad);
            cut.Find("[data-role='import-preview']").Click();
            cut.Find("[data-role='action-result']").ClassList.ShouldContain("intent-error");
            cut.FindAll("[data-role='import-preview-result']").ShouldBeEmpty();
        }

        cut.Find("[data-role='import-save']").HasAttribute("disabled").ShouldBeTrue("save is only possible after a good preview");
        Env.NamespaceStore.Get("contoso")!.ClientTrust.CaCertificatesDerBase64.ShouldBeEmpty();
    }

    [Fact]
    public void ThePemInput_NeedsTheCommonNameSeparately()
    {
        var cut = Open();
        Manage(cut, "contoso");
        cut.Find("[data-role='import-text']").Change(Env.Pki.ClientCaB.CertificatePem);
        Type(cut, "import-cns", "pem.cn, second.cn");

        cut.Find("[data-role='import-preview']").Click();

        Text(cut.Find("[data-role='preview-cns']")).ShouldBe("pem.cn, second.cn");
        cut.Find("[data-role='import-preview-result']").TextContent.ShouldContain("PEM");
    }

    [Fact]
    public void TheCommonNameAllowList_CanBeEditedByHand_AndCasAreRemovable()
    {
        Env.Namespaces.Import("seed", "contoso", AzureJson(Env.Pki.ClientCaA, "first.cn"));
        var cut = Open();
        Manage(cut, "contoso");

        Type(cut, "cn-input", "second.cn");
        cut.Find("[data-role='cn-add']").Click();
        Env.NamespaceStore.Get("contoso")!.ClientTrust.SubjectCommonNames.ShouldBe(["first.cn", "second.cn"]);

        cut.FindAll("[data-role='cn-remove']")[0].Click();
        Env.NamespaceStore.Get("contoso")!.ClientTrust.SubjectCommonNames.ShouldBe(["second.cn"]);

        cut.Find("[data-role='ca-remove']").Click();
        Env.NamespaceStore.Get("contoso")!.ClientTrust.CaCertificatesDerBase64.ShouldBeEmpty();
        cut.Find("[data-role='no-cas']").ShouldNotBeNull();
        cut.FindAll("[data-role='ns-warning']").Select(static w => w.TextContent).ShouldContain(static w => w.Contains("No trusted CA", StringComparison.Ordinal));
        Env.Entries.Count(static e => e.Action == "namespace.update").ShouldBe(3);
    }

    [Fact]
    public void TheAzCommand_ForANamespaceWithAPrefix_IsRenderedWithThePrefixAndTheTypedHsm()
    {
        var cut = Open();
        Manage(cut, "contoso");

        Type(cut, "hsm-input", "my-hsm");

        var command = Text(cut.Find("[data-role='az-command']"));
        command.ShouldStartWith("az keyvault ekm-connection create --hsm-name my-hsm --host ");
        command.ShouldContain("--server-ca-certificate root-ca.pem");
        command.ShouldEndWith("--path-prefix /contoso/prod");
        Manage(cut, "_default");
        Text(cut.Find("[data-role='az-command']")).ShouldNotContain("--path-prefix");
    }

    [Fact]
    public void TheConsoleTestCa_CanBeTrustedWithOneClick_AndIsReplacedNotPiledUp()
    {
        var cut = Open();
        Manage(cut, "contoso");
        Text(cut.Find("[data-role='test-client-state']")).ShouldContain("does not trust");

        cut.Find("[data-role='trust-test-client']").Click();

        Text(cut.Find("[data-role='test-client-state']")).ShouldContain("Trusted");
        Env.NamespaceStore.Get("contoso")!.ClientTrust.SubjectCommonNames.ShouldContain(ConsoleTestIdentity.CommonName);
        cut.FindAll("[data-role='ca-kind']").Select(static k => k.TextContent).ShouldContain("console test CA");
        Env.Entries.Single(static e => e.Action == "namespace.trust.test-client").Target.ShouldBe("namespace:contoso");
    }

    [Fact]
    public void ChangingThePrefix_IsValidated_AndSaved()
    {
        var cut = Open();
        Manage(cut, "contoso");

        Type(cut, "edit-prefix", "contoso/prod");
        cut.Find("[data-role='edit-prefix-save']").Click(); // unchanged is fine
        Type(cut, "edit-prefix", "bad prefix");
        Text(cut.Find("[data-role='edit-prefix-message']")).ShouldContain("Prefix may only contain");
        cut.Find("[data-role='edit-prefix-save']").HasAttribute("disabled").ShouldBeTrue();
        Type(cut, "edit-prefix", "contoso/test");
        cut.Find("[data-role='edit-prefix-save']").Click();

        Env.NamespaceStore.Get("contoso")!.Prefix.ShouldBe("contoso/test");
        cut.Find("[data-role='edit-prefix']").HasAttribute("disabled").ShouldBeFalse();
        Manage(cut, "_default");
        cut.Find("[data-role='edit-prefix']").HasAttribute("disabled").ShouldBeTrue("_default has no prefix to edit");
    }

    [Fact]
    public void Delete_AnEmptyNamespace_NeedsTheTypedName()
    {
        var dialogs = Render<FluentDialogProvider>();
        var cut = Open();

        cut.Find("[data-ns='contoso'][data-role='ns-name']").Closest("tr")!.QuerySelector("[data-role='delete']")!.Click();

        dialogs.WaitForElement("[data-role='confirm-dialog']", Patience);
        dialogs.FindAll("[data-role='confirm-option']").ShouldBeEmpty("there are no keys to destroy");
        dialogs.Find("[data-role='confirm-ok']").HasAttribute("disabled").ShouldBeTrue();
        dialogs.Find("[data-role='confirm-input']").Input("contoso");
        dialogs.Find("[data-role='confirm-ok']").Click();

        cut.WaitForAssertion(() => cut.FindAll("[data-ns='contoso'][data-role='ns-name']").ShouldBeEmpty(), Patience);
        Env.NamespaceStore.Get("contoso").ShouldBeNull();
        Env.Entries.Single(static e => e.Action == "namespace.delete").Detail.ShouldBe("destroyed_keys=0");
    }

    [Fact]
    public void Delete_ANamespaceWithKeys_IsRefusedUnlessAllKeysAreDestroyedOnPurpose()
    {
        var dialogs = Render<FluentDialogProvider>();
        var cut = Open();
        var delete = () => cut.Find("[data-ns='_default'][data-role='ns-name']").Closest("tr")!.QuerySelector("[data-role='delete']")!.Click();

        // First attempt: the name is typed but the destroy-all box is not ticked: refused, nothing changes.
        delete();
        dialogs.WaitForElement("[data-role='confirm-dialog']", Patience);
        Text(dialogs.Find("[data-role='confirm-consequences']")).ShouldContain("1 key(s)");
        dialogs.Find("[data-role='confirm-input']").Input("_default");
        dialogs.Find("[data-role='confirm-ok']").Click();
        cut.WaitForAssertion(() => Text(cut.Find("[data-role='action-result']")).ShouldContain("still has 1 key(s)"), Patience);
        Env.NamespaceStore.Get("_default").ShouldNotBeNull();
        Env.Keys.Get("_default", "aes-key-1").Key.State.ShouldBe("Enabled");

        // Second attempt: ticking the box destroys the key first (irreversibly), then deletes the namespace.
        delete();
        dialogs.WaitForElement("[data-role='confirm-dialog']", Patience);
        var option = dialogs.FindComponents<FluentCheckbox>().Single(static c => c.Markup.Contains("data-role=\"confirm-option\"", StringComparison.Ordinal));
        dialogs.InvokeAsync(() => option.Instance.ValueChanged.InvokeAsync(true));
        dialogs.Find("[data-role='confirm-input']").Input("_default");
        dialogs.Find("[data-role='confirm-ok']").Click();

        cut.WaitForAssertion(() => Env.NamespaceStore.Get("_default").ShouldBeNull(), Patience);
        Env.Keys.Get("_default", "aes-key-1").Key.State.ShouldBe("Destroyed");
        Env.Entries.Select(static e => e.Action).ShouldContain("key.destroy");
        Env.Entries.Single(static e => e.Action == "namespace.delete").Detail.ShouldBe("destroyed_keys=1");
    }
}
