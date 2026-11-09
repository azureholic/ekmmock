using System.Security.Cryptography;
using System.Text.Json;
using AngleSharp.Dom;
using EkmMock.Crypto;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FluentUI.AspNetCore.Components;

namespace EkmMock.Console.Tests;

/// <summary>M6, spec 8.5.5, 6.2 and 14 test 19 (console part): the Keys page lists, creates, enables, disables, expires, destroys and shows keys without ever showing secret material.</summary>
public sealed class KeysPageTests : AdminPageTestBase
{
    public KeysPageTests()
        : base(
            allowImport: true,
            seed: backend =>
            {
                backend.Create("_default", "aes-key-1", KeyType.Oct, 256);
                backend.Create("_default", "rsa-key-1", KeyType.Rsa, 2048);
            })
    {
        Env.Namespaces.Create("seed", new NamespaceChange("_default", string.Empty, null, null));
        Env.Namespaces.Create("seed", new NamespaceChange("contoso", "contoso/prod", null, null));
    }

        private IRenderedComponent<KeysPage> Open() => Render<KeysPage>();

    private static IElement Row(IRenderedComponent<KeysPage> cut, string key) => cut.Find($"[data-key='{key}'][data-role='key-name']").Closest("tr")!;

    private static void Type(IRenderedComponent<KeysPage> cut, string role, string text)
    {
        var field = cut.Find($"[data-role='{role}']");
        field.Input(text);
        field.Change(text);
    }

    [Fact]
    public void TheKeysAreListedPerNamespace_WithTypeStateOriginAndUsage()
    {
        var cut = Open();

        var section = cut.Find("section[data-namespace='_default']");
        Text(section).ShouldContain("2 keys");
        var aes = Row(cut, "aes-key-1");
        Text(aes).ShouldContain("AES-256");
        Text(aes).ShouldContain("Enabled");
        Text(aes).ShouldContain("Generated");
        Text(aes).ShouldContain("no expiry");
        Text(aes).ShouldContain("never");
        aes.QuerySelector("[data-role='wrap-count']")!.TextContent.ShouldBe("0");
        Text(Row(cut, "rsa-key-1")).ShouldContain("RSA-2048");
        cut.FindAll("[data-namespace='contoso']").ShouldBeEmpty("a namespace without keys has no table");
    }

    [Fact]
    public void ACorruptKey_IsShownRed_WithAnExplanation()
    {
        // The key store of this environment is tampered with before it is opened: one byte of the blob is flipped (spec 14 test 19).
        using var env = AdminEnvironment.Create(
            InspectorFake,
            seed: backend => backend.Create("_default", "victim", KeyType.Oct, 256),
            prepareKeyStore: data =>
            {
                var path = Path.Combine(data, "keystore.json");
                var json = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(path))!;
                var entry = json["keys"]![0]!;
                var blob = Convert.FromBase64String((string)entry["ciphertext"]!);
                blob[3] ^= 0x01;
                entry["ciphertext"] = Convert.ToBase64String(blob);
                File.WriteAllText(path, json.ToJsonString());
            });
        env.Namespaces.Create("seed", new NamespaceChange("_default", string.Empty, null, null));
        Services.AddSingleton(env.Keys);
        Services.AddSingleton(env.Namespaces);

        var cut = Open();

        var row = Row(cut, "victim");
        row.QuerySelector("[data-role='key-state']")!.GetAttribute("data-state").ShouldBe("Corrupt");
        row.QuerySelector("[data-role='key-state']")!.ClassList.ShouldContain("state-corrupt");
        Text(row).ShouldContain("Corrupt");
        var alert = cut.Find("[data-role='key-problem']");
        alert.ClassList.ShouldContain("intent-error");
        Text(alert).ShouldContain("failed authentication");
        Text(alert).ShouldContain("503 HsmUnavailable");
        Text(alert).ShouldContain("master key");
    }

    [Fact]
    public void CreateKey_ValidatesTheNameWhileTyping_AndCreatesTheKey()
    {
        var cut = Open();
        cut.Find("[data-role='create-toggle']").Click();

        cut.Find("[data-role='create-submit']").HasAttribute("disabled").ShouldBeTrue("an empty name is invalid");
        Type(cut, "create-name", "bad_name");
        Text(cut.Find("[data-role='create-name-message']")).ShouldContain("Only letters, digits and '-'");
        cut.Find("[data-role='create-name-message']").ClassList.ShouldContain("field-invalid");
        cut.Find("[data-role='create-submit']").HasAttribute("disabled").ShouldBeTrue();
        Type(cut, "create-name", new string('a', 65));
        Text(cut.Find("[data-role='create-name-message']")).ShouldContain("at most 64");

        Type(cut, "create-name", "new-key-1");
        cut.Find("[data-role='create-name-message']").ClassList.ShouldNotContain("field-invalid");
        cut.Find("[data-role='create-submit']").HasAttribute("disabled").ShouldBeFalse();
        cut.Find("[data-role='create-submit']").Click();

        Text(cut.Find("[data-role='action-result']")).ShouldContain("Key new-key-1 created in _default");
        Text(Row(cut, "new-key-1")).ShouldContain("AES-256");
        Env.Keys.Get("_default", "new-key-1").Key.Size.ShouldBe(256);
        var entry = Env.Entries.Single(static e => e.Action == "key.create" && e.Target == "key:_default/new-key-1");
        entry.User.ShouldBe("loopback");
    }

    [Fact]
    public void CreateKey_AnEngineErrorIsShownInPlainWords_WithoutInternals()
    {
        var cut = Open();
        cut.Find("[data-role='create-toggle']").Click();
        Type(cut, "create-name", "aes-key-1");

        cut.Find("[data-role='create-submit']").Click();

        var message = Text(cut.Find("[data-role='action-result']"));
        message.ShouldNotBeEmpty();
        cut.Find("[data-role='action-result']").ClassList.ShouldContain("intent-error");
        message.ShouldNotContain("Exception");
        message.ShouldNotContain("   at ");
        Env.Entries.ShouldNotContain(static e => e.Action == "key.create", "a refused action is not an audited change");
    }

    [Fact]
    public void DisableAndEnable_FromTheRow_ChangeTheStateAndAreAudited()
    {
        var cut = Open();

        Row(cut, "aes-key-1").QuerySelector("[data-role='toggle-enabled']")!.Click();
        cut.Find("[data-key='aes-key-1'][data-role='key-name']").Closest("tr")!.QuerySelector("[data-role='key-state']")!.GetAttribute("data-state").ShouldBe("Disabled");
        Text(Row(cut, "aes-key-1").QuerySelector("[data-role='toggle-enabled']")!).ShouldBe("Enable");

        Row(cut, "aes-key-1").QuerySelector("[data-role='toggle-enabled']")!.Click();
        Row(cut, "aes-key-1").QuerySelector("[data-role='key-state']")!.GetAttribute("data-state").ShouldBe("Enabled");
        Env.Entries.Where(static e => e.Target == "key:_default/aes-key-1").Select(static e => e.Action).ShouldBe(["key.disable", "key.enable"]);
    }

    [Fact]
    public void Destroy_NeedsTheKeyNameTyped_InTheDialog_AndLeavesAVisibleTombstone()
    {
        var dialogs = Render<FluentDialogProvider>();
        var cut = Open();

        Row(cut, "aes-key-1").QuerySelector("[data-role='destroy']")!.Click();

        dialogs.WaitForElement("[data-role='confirm-dialog']", Patience);
        Text(dialogs.Find("[data-role='confirm-message']")).ShouldContain("irreversible crypto-shred");
        Text(dialogs.Find("[data-role='confirm-consequences']")).ShouldContain("404 KeyNotFound");
        dialogs.Find("[data-role='confirm-ok']").HasAttribute("disabled").ShouldBeTrue("nothing typed yet");

        var input = dialogs.Find("[data-role='confirm-input']");
        input.Input("AES-KEY-1");
        dialogs.Find("[data-role='confirm-ok']").HasAttribute("disabled").ShouldBeTrue("the name is case-sensitive");
        input.Input("aes-key-1");
        dialogs.Find("[data-role='confirm-ok']").HasAttribute("disabled").ShouldBeFalse();
        dialogs.Find("[data-role='confirm-ok']").Click();

        cut.WaitForAssertion(() => Text(cut.Find("[data-role='action-result']")).ShouldContain("destroyed"), Patience);
        var row = Row(cut, "aes-key-1");
        row.QuerySelector("[data-role='key-state']")!.GetAttribute("data-state").ShouldBe("Destroyed");
        Text(row.QuerySelector("[data-role='destroyed-note']")!).ShouldContain("by loopback");
        row.QuerySelector("[data-role='destroy']").ShouldBeNull("a destroyed key has no further actions");
        Env.Keys.Get("_default", "aes-key-1").Key.State.ShouldBe("Destroyed");
        Env.Entries.Single(static e => e.Action == "key.destroy").Target.ShouldBe("key:_default/aes-key-1");
    }

    [Fact]
    public void Destroy_Cancel_ChangesNothing()
    {
        var dialogs = Render<FluentDialogProvider>();
        var cut = Open();
        Row(cut, "rsa-key-1").QuerySelector("[data-role='destroy']")!.Click();
        dialogs.WaitForElement("[data-role='confirm-dialog']", Patience);

        dialogs.Find("[data-role='confirm-cancel']").Click();

        Env.Keys.Get("_default", "rsa-key-1").Key.State.ShouldBe("Enabled");
        Env.Entries.ShouldNotContain(static e => e.Action == "key.destroy");
    }

    [Fact]
    public void ADestroyedName_CannotBeReusedByAccident_OnlyWithAnExplicitOverride()
    {
        Env.Keys.Destroy("seed", "_default", "rsa-key-1", "rsa-key-1");
        var cut = Open();
        cut.Find("[data-role='create-toggle']").Click();
        Type(cut, "create-name", "rsa-key-1");

        cut.Find("[data-role='create-submit']").Click();

        Text(cut.Find("[data-role='action-result']")).ShouldContain("destroyed");
        Env.Keys.Get("_default", "rsa-key-1").Key.State.ShouldBe("Destroyed");
        var reuse = cut.FindComponents<FluentCheckbox>().Single(static c => c.Markup.Contains("data-role=\"create-reuse\"", StringComparison.Ordinal));
        cut.InvokeAsync(() => reuse.Instance.ValueChanged.InvokeAsync(true)); // the explicit override is offered after the refusal
        cut.Find("[data-role='create-submit']").Click();

        Env.Keys.Get("_default", "rsa-key-1").Key.State.ShouldBe("Enabled");
        Env.Entries.Single(static e => e.Action == "key.create" && e.Target == "key:_default/rsa-key-1" && e.Detail!.Contains("reuse_destroyed_name=true", StringComparison.Ordinal));
    }

    [Fact]
    public void TheRsaKeyDetail_ShowsThePublicKeyAsPemAndJwk_AndTheRegistrationCommand()
    {
        var cut = Open();

        cut.Find("[data-key='rsa-key-1'][data-role='key-name']").Click();

        var detail = cut.Find("[data-role='key-detail']");
        var pem = detail.QuerySelector("[data-role='public-pem']")!.TextContent;
        pem.ShouldStartWith("-----BEGIN PUBLIC KEY-----");
        pem.ShouldNotContain("PRIVATE");
        var n = detail.QuerySelector("[data-role='jwk-n']")!.TextContent;
        var e = detail.QuerySelector("[data-role='jwk-e']")!.TextContent;
        e.ShouldBe("AQAB");
        System.Buffers.Text.Base64Url.DecodeFromChars(n).Length.ShouldBe(256);

        // Independent check: the PEM on the page is the key the engine publishes for the EKM metadata call.
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        var published = Env.Backend.GetMetadata(new KeyRef("_default", "rsa-key-1"))!.PublicKey!;
        rsa.ExportParameters(false).Modulus!.ShouldBe(published.Modulus.ToArray());
        System.Buffers.Text.Base64Url.EncodeToString(published.Modulus.Span).ShouldBe(n);

        detail.QuerySelectorAll("[data-role='copy']").Length.ShouldBeGreaterThanOrEqualTo(4);
        Text(detail.QuerySelector("[data-role='az-command']")!).ShouldBe("az keyvault key create --hsm-name <hsm> --name <ref-name> --external-key-id rsa-key-1");
        Text(detail).ShouldContain("Reached on the connection without --path-prefix");
    }

    [Fact]
    public void TheAzCommand_TakesTheHsmAndReferenceNameTheUserTypes_WithoutStoringThem()
    {
        var cut = Open();
        cut.Find("[data-key='aes-key-1'][data-role='key-name']").Click();

        Type(cut, "hsm-input", "my-hsm");
        Type(cut, "refname-input", "ekm-aes");

        Text(cut.Find("[data-role='az-command']")).ShouldBe("az keyvault key create --hsm-name my-hsm --name ekm-aes --external-key-id aes-key-1");
        cut.Find("[data-role='key-detail']").QuerySelector("[data-role='public-pem']").ShouldBeNull("an AES key has no public key");
        Env.Entries.ShouldNotContain(static e => e.Detail != null && e.Detail.Contains("my-hsm", StringComparison.Ordinal));
    }

    [Fact]
    public void Expiry_CanBeSetAndCleared_AndAPastDateMakesTheKeyExpired()
    {
        var cut = Open();
        cut.Find("[data-key='aes-key-1'][data-role='key-name']").Click();

        Type(cut, "expiry-input", "2020-01-01 00:00");
        cut.Find("[data-role='expiry-set']").Click();

        Row(cut, "aes-key-1").QuerySelector("[data-role='key-state']")!.GetAttribute("data-state").ShouldBe("Expired");
        Text(Row(cut, "aes-key-1").QuerySelector("[data-role='not-after']")!).ShouldBe("2020-01-01");

        cut.Find("[data-role='expiry-clear']").Click();
        Row(cut, "aes-key-1").QuerySelector("[data-role='key-state']")!.GetAttribute("data-state").ShouldBe("Enabled");
        Env.Entries.Where(static e => e.Target == "key:_default/aes-key-1").Select(static e => e.Action).ShouldBe(["key.expiry.set", "key.expiry.clear"]);

        Type(cut, "expiry-input", "not a date");
        cut.Find("[data-role='expiry-set']").Click();
        cut.Find("[data-role='action-result']").ClassList.ShouldContain("intent-error");
    }

    [Fact]
    public void TheImportDialog_IsVisibleOnlyWhenImportIsEnabled_AndImportedKeysCarryTheBadge()
    {
        var cut = Open();
        cut.Find("[data-role='import-toggle']").Click();
        var aes = SecretScanner.RandomDek(32);

        cut.Find("[data-role='import-name']").Change("imported-aes");
        Type(cut, "import-name", "imported-aes");
        cut.Find("[data-role='import-material']").Change(Convert.ToHexString(aes));
        cut.Find("[data-role='import-submit']").Click();

        var row = Row(cut, "imported-aes");
        row.QuerySelector("[data-role='origin-badge']")!.TextContent.ShouldBe("Imported");
        Env.Keys.Get("_default", "imported-aes").Key.Origin.ShouldBe("Imported");
        cut.Find("[data-role='import-material']").GetAttribute("value").ShouldBeNullOrEmpty("the key material is cleared from the page at once");
        Env.Entries.Single(static e => e.Action == "key.import").Detail.ShouldBe("type=AES-256 origin=Imported");
        SecretScanner.LeaksInText(cut.Markup + string.Join('\n', Env.Entries.Select(static e => e.ToString())), aes).ShouldBeFalse();
    }

    [Fact]
    public void ImportIsHidden_WhenItIsNotEnabled()
    {
        using var disabled = new DisabledImportContext();

        var cut = disabled.Render<KeysPage>();

        cut.FindAll("[data-role='import-toggle']").ShouldBeEmpty();
        cut.FindAll("[data-role='import-form']").ShouldBeEmpty();
    }

    [Fact]
    public void ABadImport_IsRefusedWithoutEchoingTheValue()
    {
        var cut = Open();
        cut.Find("[data-role='import-toggle']").Click();
        Type(cut, "import-name", "bad-import");
        cut.Find("[data-role='import-material']").Change("SECRET-LOOKING-BUT-NOT-A-KEY");

        cut.Find("[data-role='import-submit']").Click();

        cut.Find("[data-role='action-result']").ClassList.ShouldContain("intent-error");
        Text(cut.Find("[data-role='action-result']")).ShouldNotBeEmpty();
        cut.Markup.ShouldNotContain("SECRET-LOOKING-BUT-NOT-A-KEY");
        Env.Keys.List("_default").ShouldNotContain(static k => k.Name == "bad-import");
    }

    [Fact]
    public void NoSecretMaterial_AppearsInTheRenderedPage_NotEvenForAnImportedKnownKey()
    {
        var aes = SecretScanner.RandomDek(32);
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(true);
        Env.Keys.Import("seed", "_default", "known-aes", KeyType.Oct, aes);
        Env.Keys.Import("seed", "_default", "known-rsa", KeyType.Rsa, rsa.ExportPkcs8PrivateKey());
        var cut = Open();
        cut.Find("[data-key='known-rsa'][data-role='key-name']").Click();
        var rsaMarkup = cut.Markup;
        cut.Find("[data-key='known-aes'][data-role='key-name']").Click();
        var aesMarkup = cut.Markup;

        foreach (var markup in new[] { rsaMarkup, aesMarkup })
        {
            SecretScanner.LeaksInText(markup, aes).ShouldBeFalse();
            foreach (var part in new[] { parameters.D!, parameters.P!, parameters.Q!, parameters.DP!, parameters.DQ!, parameters.InverseQ! })
            {
                SecretScanner.LeaksInText(markup, part).ShouldBeFalse();
            }
        }

        rsaMarkup.ShouldContain(System.Buffers.Text.Base64Url.EncodeToString(parameters.Modulus!), Case.Sensitive); // the public modulus is the one thing that may be shown
    }

    private sealed class DisabledImportContext : AdminPageTestBase
    {
        public DisabledImportContext()
            : base(allowImport: false)
        {
            Env.Namespaces.Create("seed", new NamespaceChange("_default", string.Empty, null, null));
        }
    }
}
