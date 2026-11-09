using System.Security.Cryptography;
using EkmMock.Crypto;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.Server.WebConsole.Pages;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FluentUI.AspNetCore.Components;

namespace EkmMock.Console.Tests;

internal static class PlaygroundTestHelpers
{
    public static void Pick(IRenderedComponent<PlaygroundPage> cut, string role, string value) => cut.Find($"[data-role='{role}'] fluent-option[value='{value}']").Click();

    public static void SetMode(IRenderedComponent<PlaygroundPage> cut, string mode)
    {
        var group = cut.FindComponent<FluentRadioGroup<string>>();
        cut.InvokeAsync(() => group.Instance.ValueChanged.InvokeAsync(mode));
    }

    public static string Fingerprint(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes))[..12];
}

/// <summary>M6, spec 8.5.8: the Playground page in direct mode against the real engine: algorithms per key type, inputs, fingerprints, the round-trip proof and the reveal gate.</summary>
public sealed class PlaygroundPageDirectTests : AdminPageTestBase
{
    public PlaygroundPageDirectTests()
    {
        Env.AddNamespace("_default", string.Empty, ("aes-key-1", KeyType.Oct, 256), ("rsa-key-1", KeyType.Rsa, 2048));
        Env.AddNamespace("contoso", "contoso/prod");
    }

    private IRenderedComponent<PlaygroundPage> Open() => Render<PlaygroundPage>();

    private static void Type(IRenderedComponent<PlaygroundPage> cut, string role, string text)
    {
        var field = cut.Find($"[data-role='{role}']");
        field.Input(text);
        field.Change(text);
    }

    [Fact]
    public void TheAlgorithms_AreFilteredByTheKeyType()
    {
        var cut = Open();

        cut.FindAll("[data-role='algorithm'] fluent-option").Select(static o => o.GetAttribute("value")).ShouldBe(["A256KWP", "A256KW"]);
        PlaygroundTestHelpers.Pick(cut, "key", "rsa-key-1");
        cut.FindAll("[data-role='algorithm'] fluent-option").Select(static o => o.GetAttribute("value")).ShouldBe(["RSA-OAEP-256", "RSA-OAEP"]);
        PlaygroundTestHelpers.Pick(cut, "key", "aes-key-1");
        cut.FindAll("[data-role='algorithm'] fluent-option").Select(static o => o.GetAttribute("value")).ShouldBe(["A256KWP", "A256KW"]);
    }

    [Fact]
    public void ANamespaceWithoutKeys_SaysSo()
    {
        var cut = Open();

        PlaygroundTestHelpers.Pick(cut, "namespace", "contoso");

        cut.Find("[data-role='no-keys']").ShouldNotBeNull();
        cut.Find("[data-role='wrap']").HasAttribute("disabled").ShouldBeTrue();
    }

    [Fact]
    public void ARandomDek_IsWrapped_ShowingLengthFingerprintAndTimeOnly_AndUnwrapProvesTheRoundTrip()
    {
        var cut = Open();

        cut.Find("[data-role='wrap']").Click();

        cut.WaitForAssertion(() => cut.Find("[data-role='result']").GetAttribute("data-ok").ShouldBe("true"), Patience);
        var wrappedText = cut.Find("[data-role='wrapped-value']").TextContent;
        var fingerprint = Text(cut.Find("[data-role='input-fingerprint']"));
        fingerprint.ShouldMatch(@"^32 bytes · fp [0-9a-f]{12}$");
        Text(cut.Find("[data-role='elapsed']")).ShouldEndWith("ms");
        System.Buffers.Text.Base64Url.DecodeFromChars(wrappedText).Length.ShouldBe(40, "A256KWP adds 8 bytes");
        cut.FindAll("[data-role='exchange-link']").ShouldBeEmpty("a direct call is not EKM traffic");
        cut.FindAll("[data-role='ekm-ids']").ShouldBeEmpty();

        cut.Find("[data-role='unwrap-result']").Click();

        cut.WaitForAssertion(() => cut.Find("[data-role='result']").GetAttribute("data-operation").ShouldBe("unwrap"), Patience);
        Text(cut.Find("[data-role='result-fingerprint']")).ShouldBe(fingerprint.Replace("32 bytes · fp ", "32 bytes · fp ", StringComparison.Ordinal));
        var roundTrip = cut.Find("[data-role='roundtrip']");
        roundTrip.ClassList.ShouldContain("intent-success");
        Text(roundTrip).ShouldContain("Round trip proven");
        cut.FindAll("[data-role='reveal']").ShouldBeEmpty("masked by default: no reveal without the gate");
        Env.Entries.Where(static e => e.Action.StartsWith("playground.", StringComparison.Ordinal)).Select(static e => (e.Action, e.Detail)).ShouldBe(
            [("playground.wrap", "mode=direct alg=A256KWP ok"), ("playground.unwrap", "mode=direct alg=A256KWP ok")]);
    }

    [Fact]
    public void ATypedHexDek_IsUsed_ClearedFromThePageAfterSubmission_AndNeverShown()
    {
        var dek = SecretScanner.RandomDek(32);
        var cut = Open();
        PlaygroundTestHelpers.Pick(cut, "input-kind", "hex");
        cut.Find("[data-role='input']").Change(Convert.ToHexString(dek));

        cut.Find("[data-role='wrap']").Click();

        cut.WaitForAssertion(() => Text(cut.Find("[data-role='input-fingerprint']")).ShouldBe($"32 bytes · fp {PlaygroundTestHelpers.Fingerprint(dek)}"), Patience);
        cut.Find("[data-role='input']").GetAttribute("value").ShouldBeNullOrEmpty("the typed DEK is cleared from the component after it was sent");
        SecretScanner.LeaksInText(cut.Markup, dek).ShouldBeFalse();
        SecretScanner.LeaksInText(string.Join('\n', Env.Entries.Select(static e => e.ToString())), dek).ShouldBeFalse();
    }

    [Fact]
    public void AnInvalidDek_IsRefusedInWords_WithoutEchoingIt()
    {
        var cut = Open();
        PlaygroundTestHelpers.Pick(cut, "input-kind", "base64url");
        cut.Find("[data-role='input']").Change("not+valid/base64url");

        cut.Find("[data-role='wrap']").Click();

        cut.WaitForAssertion(() => cut.Find("[data-role='action-result']").ClassList.ShouldContain("intent-error"), Patience);
        Text(cut.Find("[data-role='action-result']")).ShouldContain("base64url");
        cut.Markup.ShouldNotContain("not+valid/base64url");
        cut.FindAll("[data-role='result']").ShouldBeEmpty();
    }

    [Fact]
    public void AnEngineError_IsShownWithItsCode_NotAsAnException()
    {
        var cut = Open();
        cut.Find("[data-role='wrapped-input']").Change(System.Buffers.Text.Base64Url.EncodeToString(SecretScanner.RandomDek(40)));

        cut.Find("[data-role='unwrap']").Click();

        cut.WaitForAssertion(() => cut.Find("[data-role='result-error']").ShouldNotBeNull(), Patience);
        var error = cut.Find("[data-role='result-error']");
        error.ClassList.ShouldContain("intent-error");
        Text(error).ShouldContain("InvalidCiphertext");
        Text(error).ShouldNotContain("Exception");
        cut.Find("[data-role='result']").GetAttribute("data-ok").ShouldBe("false");
    }

    [Fact]
    public void ViaEkm_WithoutTrust_OffersTheAuditedOneClickFix_AndSendsNothing()
    {
        var cut = Open();
        PlaygroundTestHelpers.SetMode(cut, "ekm");

        cut.Find("[data-role='wrap']").Click();

        cut.WaitForAssertion(() => cut.Find("[data-role='trust-hint']").ShouldNotBeNull(), Patience);
        Text(cut.Find("[data-role='trust-hint']")).ShouldContain(ConsoleTestIdentity.CommonName);
        Text(cut.Find("[data-role='result-error']")).ShouldContain("TestClientNotTrusted");
        Env.Namespaces.TrustsConsoleTestClient("_default").ShouldBeFalse();

        cut.Find("[data-role='trust-test-client']").Click();

        Env.Namespaces.TrustsConsoleTestClient("_default").ShouldBeTrue();
        cut.FindAll("[data-role='trust-hint']").ShouldBeEmpty();
        Env.Entries.Single(static e => e.Action == "namespace.trust.test-client").User.ShouldBe("loopback");
    }

    [Fact]
    public void Reveal_IsOfferedOnlyWhenAllowed_IsAudited_AndShownBriefly()
    {
        InspectorFake.RevealEnabled = true;
        var cut = Open();
        cut.Find("[data-role='wrap']").Click();
        cut.WaitForAssertion(() => cut.Find("[data-role='unwrap-result']").ShouldNotBeNull(), Patience);
        cut.Find("[data-role='unwrap-result']").Click();
        cut.WaitForAssertion(() => cut.Find("[data-role='reveal']").ShouldNotBeNull(), Patience);
        cut.FindAll("[data-role='revealed']").ShouldBeEmpty("nothing is shown before the click");

        cut.Find("[data-role='reveal']").Click();

        var revealed = cut.Find("[data-role='revealed']");
        var hex = revealed.QuerySelector("[data-role='revealed-hex']")!.TextContent;
        hex.Length.ShouldBe(64);
        PlaygroundTestHelpers.Fingerprint(Convert.FromHexString(hex)).ShouldBe(Text(cut.Find("[data-role='result-fingerprint']")).Split(' ')[^1]);
        Env.Entries.Single(static e => e.Action == "playground.reveal").Detail.ShouldBe("32 bytes");
        SecretScanner.LeaksInText(string.Join('\n', Env.Entries.Select(static e => e.ToString())), Convert.FromHexString(hex)).ShouldBeFalse();

        ManualTime.Advance(TimeSpan.FromSeconds(PlaygroundPage.RevealSeconds + 1));
        cut.WaitForAssertion(() => cut.FindAll("[data-role='revealed']").ShouldBeEmpty(), Patience);
        cut.Markup.ShouldNotContain(hex, Case.Insensitive);
    }
}

/// <summary>
/// M6 "done when" at page level: the Playground page's "via EKM endpoint" round trip is a real mutual-TLS request to the real listener, and the exchanges show up in the Live
/// traffic page like any Managed HSM call. Also Replay from the Exchange detail.
/// </summary>
public sealed class PlaygroundPageViaEkmTests : ConsoleTestBase, IAsyncLifetime
{
    private RealConsoleHost _host = null!;

    public PlaygroundPageViaEkmTests()
        : base(realTime: true)
    {
    }

    public async ValueTask InitializeAsync()
    {
        _host = await RealConsoleHost.StartAsync();
        var services = _host.App.Services;
        Services.AddSingleton<IInspector>(services.GetRequiredService<IInspector>());
        Services.AddSingleton<IInspectorQuery>(services.GetRequiredService<IInspector>());
        Services.AddSingleton(services.GetRequiredService<PlaygroundService>());
        Services.AddSingleton(services.GetRequiredService<KeyAdminService>());
        Services.AddSingleton(services.GetRequiredService<NamespaceAdminService>());
        Services.AddSingleton(services.GetRequiredService<AuditRecorder>());
    }

    public new async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        await base.DisposeAsync();
    }

    private IAuditLog Audit => _host.App.Services.GetRequiredService<IAuditLog>();

    [Fact]
    public async Task ARoundTripViaTheEkmEndpoint_AppearsInLiveTraffic_AndProvesTheFingerprint()
    {
        var live = Render<LiveTraffic>();
        var cut = Render<PlaygroundPage>();
        PlaygroundTestHelpers.SetMode(cut, "ekm");

        cut.Find("[data-role='wrap']").Click();
        cut.WaitForAssertion(() => cut.Find("[data-role='trust-hint']").ShouldNotBeNull(), Patience); // the real namespace does not trust the console test CA yet
        cut.Find("[data-role='trust-test-client']").Click();
        cut.Find("[data-role='wrap']").Click();

        cut.WaitForAssertion(() => cut.Find("[data-role='result']").GetAttribute("data-ok").ShouldBe("true"), Patience);
        Text(cut.Find("[data-role='http-status']")).ShouldBe("200 OK");
        var correlation = cut.Find("[data-role='correlation-id']").TextContent;
        Guid.TryParse(correlation, out _).ShouldBeTrue();
        cut.Find("[data-role='exchange-link']").GetAttribute("href").ShouldStartWith("/exchange/");
        var fingerprint = Text(cut.Find("[data-role='input-fingerprint']"));

        cut.Find("[data-role='unwrap-result']").Click();
        cut.WaitForAssertion(() => cut.Find("[data-role='roundtrip']").ShouldNotBeNull(), Patience);
        Text(cut.Find("[data-role='roundtrip']")).ShouldContain("Round trip proven");
        Text(cut.Find("[data-role='result-fingerprint']")).ShouldBe(fingerprint);

        // Live traffic shows both calls: operation, client CN and the playground's pool name / correlation id.
        live.WaitForAssertion(() => live.FindAll("[data-row='exchange']").Count.ShouldBe(2), Patience);
        var rows = live.FindAll("[data-row='exchange']").Select(static r => Text(r)).ToList();
        rows.ShouldContain(static r => r.Contains("unwrapkey", StringComparison.Ordinal));
        rows.ShouldContain(static r => r.Contains("wrapkey", StringComparison.Ordinal));
        rows.ShouldAllBe(static r => r.Contains(ConsoleTestIdentity.CommonName, StringComparison.Ordinal));
        var exchanges = _host.Inspector.Query(new ExchangeFilter { Text = PlaygroundService.PoolName }).Items;
        exchanges.Count.ShouldBe(2);
        exchanges.Select(static e => e.Context.PoolName).Distinct().ShouldBe([PlaygroundService.PoolName]);
        exchanges.Select(static e => e.Context.CorrelationId).ShouldContain(correlation);
    }

    [Fact]
    public async Task Replay_IsDisabledWithItsReason_WhenTheRawBodyWasNotKept()
    {
        using (var client = _host.CreateEkmHttpClient())
        {
            (await RealConsoleHost.WrapAsync(client, SecretScanner.RandomDek(32))).StatusCode.ShouldBe(System.Net.HttpStatusCode.OK);
        }

        (await Poll.UntilAsync(() => _host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items.Count == 1)).ShouldBeTrue();
        var original = _host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items[0];

        var detail = Render<EkmMock.Server.WebConsole.Components.ExchangeDetailView>(p => p.Add(static c => c.ExchangeId, original.Id));

        detail.Find("[data-role='replay']").HasAttribute("disabled").ShouldBeTrue("replay stays disabled without the raw body");
        Text(detail.Find("[data-role='replay-hint']")).ShouldContain("kept only when reveal is allowed");
    }

    private static string Text(AngleSharp.Dom.IElement element) => Dom.Text(element);
}

/// <summary>M6, spec 8.5.2: with the reveal gate open the raw request body is kept and the Replay button of the Exchange detail really sends the request again through the EKM endpoint.</summary>
public sealed class ReplayPageTests : ConsoleTestBase, IAsyncLifetime
{
    private RealConsoleHost _host = null!;

    public ReplayPageTests()
        : base(realTime: true)
    {
    }

    public async ValueTask InitializeAsync()
    {
        _host = await RealConsoleHost.StartAsync(allowReveal: true);
        var services = _host.App.Services;
        Services.AddSingleton<IInspector>(services.GetRequiredService<IInspector>());
        Services.AddSingleton<IInspectorQuery>(services.GetRequiredService<IInspector>());
        StatusFake.RevealAllowed = true;
    }

    public new async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        await base.DisposeAsync();
    }

    private static string Text(AngleSharp.Dom.IElement element) => Dom.Text(element);

    [Fact]
    public async Task Replay_SendsTheSameRequestAgain_ShowsTheOutcome_AndLinksToTheNewExchangeInLiveTraffic()
    {
        var dek = SecretScanner.RandomDek(32);
        using (var client = _host.CreateEkmHttpClient())
        {
            (await RealConsoleHost.WrapAsync(client, dek, correlationId: "replay-original")).StatusCode.ShouldBe(System.Net.HttpStatusCode.OK);
        }

        (await Poll.UntilAsync(() => _host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items.Count == 1)).ShouldBeTrue();
        var original = _host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items[0];
        _host.App.Services.GetRequiredService<NamespaceAdminService>().TrustConsoleTestClient("loopback", "_default");
        var detail = Render<EkmMock.Server.WebConsole.Components.ExchangeDetailView>(p => p.Add(static c => c.ExchangeId, original.Id));
        detail.Find("[data-role='replay']").HasAttribute("disabled").ShouldBeFalse();

        detail.Find("[data-role='replay']").Click();

        detail.WaitForAssertion(() => Text(detail.Find("[data-role='replay-message']")).ShouldContain("Replayed: the EKM endpoint answered 200"), Patience);
        var link = detail.Find("[data-role='replay-link']");
        var newId = long.Parse(link.GetAttribute("href")!["/exchange/".Length..], System.Globalization.CultureInfo.InvariantCulture);
        newId.ShouldBeGreaterThan(original.Id);
        var replayed = _host.Inspector.Get(newId)!;
        replayed.ClientCertificate.CommonName.ShouldBe(ConsoleTestIdentity.CommonName);
        replayed.Context.CorrelationId.ShouldBe("replay-original");
        replayed.Response.Status.ShouldBe(200);
        var audit = _host.App.Services.GetRequiredService<IAuditLog>().ReadRecent().Single(static e => e.Action == "inspector.replay");
        audit.User.ShouldBe("loopback");
        audit.Target.ShouldBe($"exchange:{original.Id}");
        SecretScanner.LeaksInText(detail.Markup, dek).ShouldBeFalse();
    }
}