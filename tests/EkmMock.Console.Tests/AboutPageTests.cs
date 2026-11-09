using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Console.Tests;

/// <summary>A scripted <see cref="IAboutService"/> so the About page can be shown in every state (dev mode, failing self-test) without a host.</summary>
internal sealed class FakeAbout : IAboutService
{
    public AboutInfo Info { get; set; } = Make();

    public AboutInfo Get() => Info;

    public SelfTestView SelfTest() => Info.SelfTest;

    public static AboutInfo Make(bool dev = false, bool selfTestFails = false)
    {
        var cases = new List<SelfTestCaseView>
        {
            new("aes-kw/rfc3394-4.6", "Passed", 2.3, null),
            new("rsa-oaep/roundtrip", selfTestFails ? "Failed" : "Passed", 3.1, selfTestFails ? "round trip mismatch" : null),
            new("key:_default/aes-key-1", "Passed", 0.4, null),
        };
        return new AboutInfo(
            "1.2.3",
            "LoopbackOnly",
            dev,
            KeyImportEnabled: false,
            RevealAllowed: false,
            new MasterKeyView(true, dev, dev ? "dev mode" : "EKMMOCK_MASTER_KEY", dev ? "A throw-away master key that exists only in memory." : "Loaded. The value is never shown."),
            new SelfTestView(!selfTestFails, false, DateTimeOffset.UtcNow, cases, selfTestFails ? ["rsa-oaep/roundtrip"] : []),
            new DataVolumeView("/data", [new DataFileView("keystore.json", true, 2048, 1), new DataFileView("namespaces.json", true, 512, 1), new DataFileView("audit.jsonl", false, 0, 0)]),
            new TlsPolicyView("TLS 1.3 only", ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"], "NotEnforceableByTlsStack", "not enforceable on this OS", false),
            [new ListenerView("EKM endpoint (mTLS)", "https://0.0.0.0:8443", [8443]), new ListenerView("Console", "https://127.0.0.1:8080", [8080])],
            new InspectorStatus(10000, 12, 0, 0, 0, 3, 8192, 15, 0, false, null, SecretDisplayMode.Masked, false, 1),
            new RuntimeView(".NET 10.0.14", "Linux 6.1", "X64", InContainer: true),
            [
                new ConfigEntry("Data", "Path", "/data", false),
                new ConfigEntry("Secrets", "Master key (EKMMOCK_MASTER_KEY / EKMMOCK_MASTER_KEY_FILE)", "set - value hidden", true),
            ],
            [new DocLink("Specification", "https://example.test/spec")]);
    }
}

/// <summary>M6, spec 8.5.11: the About page: version, runtime, master-key status, the self-test (failures flagged), data volume, listeners, TLS policy and the redacted configuration.</summary>
public sealed class AboutPageTests : ConsoleTestBase
{
    private readonly FakeAbout _about = new();

    public AboutPageTests()
    {
        Services.AddSingleton<IAboutService>(_about);
    }

    private static string Text(AngleSharp.Dom.IElement element) => Dom.Text(element);

    [Fact]
    public void ThePage_ShowsVersionRuntimeListenersPolicyAndTheDataVolume()
    {
        var cut = Render<AboutPage>();

        Text(cut.Find("[data-role='version']")).ShouldBe("1.2.3");
        Text(cut.Find("[data-role='auth-mode']")).ShouldBe("LoopbackOnly");
        Text(cut.Find("[data-role='runtime-dotnet']")).ShouldBe(".NET 10.0.14");
        Text(cut.Find("[data-role='runtime-os']")).ShouldContain("Linux 6.1");
        cut.FindAll("[data-role='listener']").Select(static l => Text(l)).ShouldBe(["https://0.0.0.0:8443 (bound: 8443)", "https://127.0.0.1:8080 (bound: 8080)"]);
        Text(cut.Find("[data-role='tls-enforcement']")).ShouldContain("not enforceable on this OS");
        cut.Find("[data-role='tls-enforcement']").ClassList.ShouldContain("status-client");
        Text(cut.Find("[data-role='data-path']")).ShouldBe("/data");
        Text(cut.Find("[data-entry='keystore.json']")).ShouldContain("2.0 KiB");
        Text(cut.Find("[data-entry='audit.jsonl']")).ShouldContain("not present");
        Text(cut.Find("[data-role='ring']")).ShouldBe("12 of 10000");
        cut.Find("[data-role='docs'] a").GetAttribute("rel").ShouldBe("noopener noreferrer");
    }

    [Fact]
    public void TheSelfTest_ShowsEveryCaseWithDuration_AndAPassingRunIsGreen()
    {
        var cut = Render<AboutPage>();

        Text(cut.Find("[data-role='self-test-summary']")).ShouldContain("All checks passed");
        cut.Find("[data-role='self-test-summary']").ClassList.ShouldContain("status-ok");
        var rows = cut.FindAll("[data-role='self-test-table'] tbody tr");
        rows.Count.ShouldBe(3);
        Text(rows[0]).ShouldContain("aes-kw/rfc3394-4.6");
        Text(rows[0]).ShouldContain("✔ Passed");
        Text(rows[0]).ShouldContain("2.30 ms");
        cut.FindAll("[data-role='self-test-failures']").ShouldBeEmpty();
    }

    [Fact]
    public void AFailingSelfTest_FlagsTheFailingAlgorithmOrKey_InRedWithTheWordFailed()
    {
        _about.Info = FakeAbout.Make(selfTestFails: true);

        var cut = Render<AboutPage>();

        Text(cut.Find("[data-role='self-test-summary']")).ShouldContain("1 check(s) FAILED");
        cut.Find("[data-role='self-test-summary']").ClassList.ShouldContain("status-server");
        var failed = cut.Find("tr[data-case='rsa-oaep/roundtrip']");
        failed.ClassList.ShouldContain("row-failed");
        Text(failed).ShouldContain("✖ Failed");
        Text(failed).ShouldContain("round trip mismatch");
        var alert = cut.Find("[data-role='self-test-failures']");
        alert.ClassList.ShouldContain("intent-error");
        Text(alert).ShouldContain("rsa-oaep/roundtrip");
    }

    [Fact]
    public void TheMasterKey_IsLoaded_OrAThrowAwayDevKeyWithTheRedBanner()
    {
        var normal = Render<AboutPage>();
        Text(normal.Find("[data-role='master-key-state']")).ShouldContain("Loaded");
        normal.FindAll("[data-role='master-key-dev']").ShouldBeEmpty();

        _about.Info = FakeAbout.Make(dev: true);
        var dev = Render<AboutPage>();

        var alert = dev.Find("[data-role='master-key-dev']");
        alert.ClassList.ShouldContain("intent-error");
        Text(alert).ShouldContain("DEV MODE: throw-away master key");
        Text(alert).ShouldContain("exists only in memory");
        Text(dev.Find("[data-role='dev-mode']")).ShouldBe("on");
    }

    [Fact]
    public void Secrets_AreShownOnlyAsSetOrNotSet_NeverAsAValue()
    {
        var cut = Render<AboutPage>();

        var secret = cut.Find("tr[data-redacted='true']");
        Text(secret).ShouldContain("Master key");
        Text(secret).ShouldContain("●●●●");
        Text(secret).ShouldContain("set - value hidden");
        cut.FindAll("tr[data-redacted='false']").ShouldNotBeEmpty();
    }
}

/// <summary>M6, spec 8.5.11: with a real host the About page never shows a secret, whatever the environment holds.</summary>
[Collection(ProcessEnvironmentCollection.Name)]
public sealed class AboutPageRealHostTests : ConsoleTestBase, IAsyncLifetime
{
    private const string FakeClientSecret = "FAKE-ENTRA-SECRET-ABOUT-PAGE-77aa31";
    private const string FakeMasterKey = "FAKE-MASTER-KEY-ABOUT-PAGE-90bb44";
    private RealConsoleHost _host = null!;
    private string? _oldClientSecret;
    private string? _oldMasterKey;

    public async ValueTask InitializeAsync()
    {
        _oldClientSecret = Environment.GetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable);
        _oldMasterKey = Environment.GetEnvironmentVariable("EKMMOCK_MASTER_KEY");
        _host = await RealConsoleHost.StartAsync();
        Environment.SetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable, FakeClientSecret);
        Environment.SetEnvironmentVariable("EKMMOCK_MASTER_KEY", FakeMasterKey);
        Services.AddSingleton(_host.App.Services.GetRequiredService<IAboutService>());
    }

    public new async ValueTask DisposeAsync()
    {
        Environment.SetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable, _oldClientSecret);
        Environment.SetEnvironmentVariable("EKMMOCK_MASTER_KEY", _oldMasterKey);
        await _host.DisposeAsync();
        await base.DisposeAsync();
    }

    [Fact]
    public void NoSecretConfigurationValue_IsShownOnThePage()
    {
        var cut = Render<AboutPage>();

        var markup = cut.Markup;
        markup.ShouldNotContain(FakeClientSecret);
        markup.ShouldNotContain(FakeMasterKey);
        var masterKey = System.Security.Cryptography.SHA256.HashData("ekmmock-console-tests"u8.ToArray()); // the master key of RealConsoleHost
        markup.ShouldNotContain(Convert.ToBase64String(masterKey));
        markup.ShouldNotContain(Convert.ToHexString(masterKey), Case.Insensitive);
        SecretScanner.LeaksInText(markup, masterKey).ShouldBeFalse();
        var secretRows = cut.FindAll("tr[data-redacted='true']");
        secretRows.Count.ShouldBe(3);
        secretRows.ShouldAllBe(static r => r.TextContent.Contains("value hidden", StringComparison.Ordinal));
        Dom.Text(cut.Find("[data-role='self-test-summary']")).ShouldContain("All checks passed");
    }
}
