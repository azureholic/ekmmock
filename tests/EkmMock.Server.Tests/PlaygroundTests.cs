#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// M6, spec 8.5.8 and the "done when" of the milestone: the Playground's "via EKM endpoint" round trip is a real mutual-TLS request that shows up in Live traffic, the direct mode
/// does not, the missing-trust helper works, the loopback self-call is pinned to the served certificate, and every run is audited without the data.
/// </summary>
public sealed class PlaygroundTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;
    private PlaygroundService _playground = null!;
    private NamespaceAdminService _namespaces = null!;
    private IInspector _inspector = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync(allowReveal: false);
        var services = _host.Host.App.Services;
        _playground = services.GetRequiredService<PlaygroundService>();
        _namespaces = services.GetRequiredService<NamespaceAdminService>();
        _inspector = services.GetRequiredService<IInspector>();
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private IReadOnlyList<AuditEntry> Audit() => _host.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent();

    private static PlaygroundTarget Ekm(string key = "aes-key-1", string alg = "A256KWP", string ns = "_default") => new(PlaygroundMode.ViaEkm, ns, key, alg);

    private static PlaygroundTarget Direct(string key = "aes-key-1", string alg = "A256KWP") => new(PlaygroundMode.Direct, "_default", key, alg);

    private ExchangePage Playground() => _inspector.Query(new ExchangeFilter { Text = PlaygroundService.PoolName }, new ExchangePaging { Limit = 100 });

    [Fact]
    public async Task ViaEkm_ARealRoundTrip_ShowsUpInLiveTraffic_WithTheFingerprintsEqual()
    {
        _namespaces.TrustConsoleTestClient("loopback", "_default");
        var dek = Fx.Random(32);

        using var wrapped = await _playground.WrapAsync("loopback", Ekm(), dek);
        wrapped.Ok.ShouldBeTrue(wrapped.Message);
        wrapped.HttpStatus.ShouldBe(200);
        wrapped.WrappedValue.ShouldNotBeNull();
        wrapped.InputFingerprint.ShouldBe(SecretFingerprint.Compute(dek));
        using var unwrapped = await _playground.UnwrapAsync("loopback", Ekm(), wrapped.WrappedValue!, wrapped.InputBytes, wrapped.InputFingerprint);

        unwrapped.Ok.ShouldBeTrue(unwrapped.Message);
        unwrapped.ResultFingerprint.ShouldBe(wrapped.InputFingerprint);
        unwrapped.RoundTripMatches.ShouldBe(true);
        unwrapped.ResultBytes.ShouldBe(32);

        // The M6 done-when: both calls are in the inspector like any other EKM call, identifiable by pool_name and the test client certificate.
        (await Wait.UntilAsync(() => Playground().Items.Count >= 2)).ShouldBeTrue("the exchanges did not reach Live traffic");
        var exchanges = Playground().Items.OrderBy(static e => e.Id).ToList();
        exchanges.Select(static e => e.Request.Operation).ShouldBe(["wrapkey", "unwrapkey"]);
        exchanges.ShouldAllBe(static e => e.Context.PoolName == PlaygroundService.PoolName);
        exchanges.ShouldAllBe(static e => e.Response.Status == 200);
        exchanges.ShouldAllBe(static e => e.ClientCertificate.CommonName == ConsoleTestIdentity.CommonName);
        exchanges.ShouldAllBe(static e => e.Tls!.Protocol == "TLS 1.3");
        exchanges[0].Context.CorrelationId.ShouldBe(wrapped.CorrelationId);
        exchanges[1].Context.CorrelationId.ShouldBe(unwrapped.CorrelationId);
        wrapped.ExchangeId.ShouldBe(exchanges[0].Id);
        unwrapped.ExchangeId.ShouldBe(exchanges[1].Id);
        wrapped.CorrelationId.ShouldNotBe(unwrapped.CorrelationId, "every request gets a fresh correlation_id");

        // Masked like all inspector data: the fingerprint of the wrapped DEK is in the record, the DEK is not.
        exchanges[0].Request.Body!.MaskedFields.Single().Display.ShouldContain(wrapped.InputFingerprint!);
        SecretScanner.LeaksInText(string.Join('\n', exchanges.Select(static e => e.Request.Body!.Text + e.Response.Body!.Text)), dek).ShouldBeFalse();
    }

    [Fact]
    public async Task ViaEkm_AnRsaKey_RoundTripsToo()
    {
        _namespaces.TrustConsoleTestClient("loopback", "_default");
        var dek = Fx.Random(32);

        using var wrapped = await _playground.WrapAsync("loopback", Ekm("rsa-key-1", "RSA-OAEP-256"), dek);
        using var unwrapped = await _playground.UnwrapAsync("loopback", Ekm("rsa-key-1", "RSA-OAEP-256"), wrapped.WrappedValue!, 32, wrapped.InputFingerprint);

        wrapped.Ok.ShouldBeTrue(wrapped.Message);
        wrapped.WrappedValue!.Length.ShouldBe(256);
        unwrapped.RoundTripMatches.ShouldBe(true);
    }

    [Fact]
    public async Task DirectMode_CallsTheEngine_ButIsNotEkmTraffic()
    {
        _namespaces.TrustConsoleTestClient("loopback", "_default");
        var before = _inspector.Status().ExchangesCaptured;
        var dek = Fx.Random(32);

        using var wrapped = await _playground.WrapAsync("loopback", Direct(), dek);
        using var unwrapped = await _playground.UnwrapAsync("loopback", Direct(), wrapped.WrappedValue!, wrapped.InputBytes, wrapped.InputFingerprint);

        wrapped.Ok.ShouldBeTrue(wrapped.Message);
        unwrapped.RoundTripMatches.ShouldBe(true);
        wrapped.CorrelationId.ShouldBeNull();
        wrapped.ExchangeId.ShouldBeNull();
        await Task.Delay(300);
        _inspector.Status().ExchangesCaptured.ShouldBe(before, "a direct call is not an EKM exchange");
        Playground().Items.ShouldBeEmpty();
        var key = _host.Host.Keys.Get(new KeyRef("_default", "aes-key-1"))!;
        key.WrapCount.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task ViaEkm_WhenTheNamespaceDoesNotTrustTheTestCa_NothingIsSent_AndTheHelperFixesIt()
    {
        var before = _inspector.Status().ExchangesCaptured;

        using var refused = await _playground.WrapAsync("loopback", Ekm(), Fx.Random(32));

        refused.Ok.ShouldBeFalse();
        refused.NeedsTestClientTrust.ShouldBeTrue();
        refused.ErrorCode.ShouldBe("TestClientNotTrusted");
        refused.Message!.ShouldContain(ConsoleTestIdentity.CommonName);
        await Task.Delay(200);
        _inspector.Status().ExchangesCaptured.ShouldBe(before, "no request was sent");

        var view = _namespaces.TrustConsoleTestClient("alice", "_default");
        view.TrustsConsoleTestClient.ShouldBeTrue();
        view.SubjectCommonNames.ShouldContain(ConsoleTestIdentity.CommonName);
        view.SubjectCommonNames.ShouldContain(ConsoleTestHost.ClientCn, "existing trust is kept");
        view.CaCertificates.Count(static c => c.IsConsoleTestCa).ShouldBe(1);
        Audit().Single(static e => e.Action == "namespace.trust.test-client").User.ShouldBe("alice");

        using var ok = await _playground.WrapAsync("loopback", Ekm(), Fx.Random(32));
        ok.Ok.ShouldBeTrue(ok.Message);

        // A second click does not pile up CAs.
        _namespaces.TrustConsoleTestClient("alice", "_default").CaCertificates.Count(static c => c.IsConsoleTestCa).ShouldBe(1);
    }

    [Fact]
    public async Task ViaEkm_ErrorsOfTheEndpoint_AreShownWithTheirCode_AndTheExchangeIsStillInLiveTraffic()
    {
        _namespaces.TrustConsoleTestClient("loopback", "_default");
        _host.Host.Keys.SetEnabled(new KeyRef("_default", "aes-key-1"), false);
        try
        {
            using var result = await _playground.WrapAsync("loopback", Ekm(), Fx.Random(32));

            result.Ok.ShouldBeFalse();
            result.HttpStatus.ShouldBe(403);
            result.ErrorCode.ShouldBe("KeyDisabled");
            result.ExchangeId.ShouldNotBeNull();
            _inspector.Get(result.ExchangeId!.Value)!.Response.Status.ShouldBe(403);
        }
        finally
        {
            _host.Host.Keys.SetEnabled(new KeyRef("_default", "aes-key-1"), true);
        }
    }

    [Fact]
    public async Task Direct_EngineErrors_AreShownWithoutInternals()
    {
        var mismatch = await Should.ThrowAsync<ConsoleActionException>(async () => await _playground.WrapAsync("loopback", Direct("aes-key-1", "RSA-OAEP-256"), Fx.Random(16)));
        mismatch.Code.ShouldBe(ConsoleErrorCode.InvalidRequest);

        using var tampered = await _playground.UnwrapAsync("loopback", Direct(), Fx.Random(40));

        tampered.Ok.ShouldBeFalse();
        tampered.ErrorCode.ShouldBe("InvalidCiphertext");
        tampered.Message!.ShouldNotContain("Exception");
        tampered.Message!.ShouldNotContain(" at ");
    }

    [Fact]
    public async Task TheSelfCall_IsPinnedToTheServedCertificate_AndRefusesAnyOther()
    {
        _namespaces.TrustConsoleTestClient("loopback", "_default");
        var services = _host.Host.App.Services;
        var identity = services.GetRequiredService<ConsoleTestIdentity>();
        var listeners = services.GetRequiredService<ListenerRegistry>();
        var served = _host.Host.Certificates.Current.Thumbprint;
        const string wrongPin = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
        var body = """{"request_context":{"request_id":"r","correlation_id":"pin-test","pool_name":"ekmmock-playground"}}"""u8.ToArray();

        using var pinned = new EkmSelfClient(identity, () => served, () => listeners.EndpointsOf(ListenerRegistry.EkmName));
        using var impostor = new EkmSelfClient(identity, () => wrongPin, () => listeners.EndpointsOf(ListenerRegistry.EkmName));
        using var unpinned = new EkmSelfClient(identity, () => null, () => listeners.EndpointsOf(ListenerRegistry.EkmName));

        (await pinned.SendAsync("POST", "/info?api-version=0.1-preview", "application/json", body)).Status.ShouldBe(200);
        foreach (var client in new[] { impostor, unpinned })
        {
            var refused = await Should.ThrowAsync<ConsoleActionException>(async () => await client.SendAsync("POST", "/info?api-version=0.1-preview", "application/json", body));
            refused.Code.ShouldBe(ConsoleErrorCode.Unavailable);
            refused.Message.ShouldNotContain(served);
        }
    }

    [Fact]
    public void ThePin_MatchesTheExactCertificateOnly()
    {
        using var pki = new EkmMock.TestSupport.TestPki();
        using var a = pki.IssueServer();
        using var b = pki.IssueServer();
        var pinA = a.Thumbprint;

        PinnedServerCertificate.Matches(a.Certificate, pinA).ShouldBeTrue();
        PinnedServerCertificate.Matches(a.Certificate, pinA.ToLowerInvariant()).ShouldBeTrue();
        PinnedServerCertificate.Matches(b.Certificate, pinA).ShouldBeFalse();
        PinnedServerCertificate.Matches(null, pinA).ShouldBeFalse();
        PinnedServerCertificate.Matches(a.Certificate, null).ShouldBeFalse();
        PinnedServerCertificate.Matches(a.Certificate, string.Empty).ShouldBeFalse();
    }

    [Theory]
    [InlineData("//evil.example/info")]
    [InlineData("http://evil.example/")]
    [InlineData("evil.example/info")]
    [InlineData("/\\evil.example")]
    [InlineData("")]
    public async Task TheSelfClient_CanOnlyReachItsOwnEkmEndpoint(string target)
    {
        var client = _host.Host.App.Services.GetRequiredService<EkmSelfClient>();

        var refused = await Should.ThrowAsync<ConsoleActionException>(async () => await client.SendAsync("POST", target, "application/json", "{}"u8.ToArray()));

        refused.Code.ShouldBe(ConsoleErrorCode.InvalidRequest);
    }

    [Fact]
    public async Task EveryRun_IsAudited_WithModeAlgorithmAndOutcome_ButNeverTheData()
    {
        _namespaces.TrustConsoleTestClient("loopback", "_default");
        var dek = Fx.Random(32);

        using var a = await _playground.WrapAsync("alice", Direct(), dek);
        using var b = await _playground.WrapAsync("alice", Ekm(), dek);
        using var c = await _playground.UnwrapAsync("alice", Direct(), a.WrappedValue!);

        var entries = Audit().Where(static e => e.Action.StartsWith("playground.", StringComparison.Ordinal)).ToList();
        entries.Select(static e => (e.Action, e.Detail)).ShouldBe(
        [
            ("playground.wrap", "mode=direct alg=A256KWP ok"),
            ("playground.wrap", "mode=ekm alg=A256KWP ok"),
            ("playground.unwrap", "mode=direct alg=A256KWP ok"),
        ]);
        entries.ShouldAllBe(static e => e.User == "alice" && e.Target == "key:_default/aes-key-1");
        SecretScanner.LeaksInText(string.Join('\n', Audit().Select(static e => e.ToString())), dek).ShouldBeFalse();
        SecretScanner.LeaksInText(_host.Host.Logs.AllText, dek).ShouldBeFalse();
    }

    [Fact]
    public async Task Reveal_IsRefused_WhenTheGateIsClosed_AndTheDeniedAttemptIsAudited()
    {
        using var unwrapped = await RoundTripAsync(Direct());

        var refused = Should.Throw<ConsoleActionException>(() => _playground.Reveal("alice", unwrapped));

        refused.Code.ShouldBe(ConsoleErrorCode.Forbidden);
        _playground.RevealAllowed.ShouldBeFalse();
        Audit().Single(static e => e.Action == "playground.reveal.denied").User.ShouldBe("alice");
        Audit().ShouldNotContain(static e => e.Action == "playground.reveal");
    }

    [Theory]
    [InlineData("00ff10", "hex", 3)]
    [InlineData("00 FF 10", "hex", 3)]
    [InlineData("AP8Q", "base64url", 3)]
    [InlineData("AP8Q=", "base64url", -1)]
    [InlineData("AP+/", "base64url", -1)]
    [InlineData("zz", "hex", -1)]
    [InlineData("abc", "hex", -1)]
    [InlineData("", "hex", -1)]
    [InlineData("", "base64url", -1)]
    public void TheDekInput_IsParsedStrictly_AndNeverEchoedInAnError(string text, string kindName, int expectedLength)
    {
        var kind = kindName == "hex" ? DekInputKind.Hex : DekInputKind.Base64Url;
        if (expectedLength < 0)
        {
            var failure = Should.Throw<ConsoleActionException>(() => PlaygroundInput.Parse(kind, text));
            failure.Code.ShouldBe(ConsoleErrorCode.InvalidRequest);
            if (text.Length > 0)
            {
                failure.Message.ShouldNotContain(text);
            }

            return;
        }

        PlaygroundInput.Parse(kind, text).Length.ShouldBe(expectedLength);
    }

    [Fact]
    public void DisposingAResult_ZeroesThePlaintextDek()
    {
        var secret = Fx.Random(32);
        var result = new PlaygroundResult { Target = Direct(), Operation = "unwrap", Ok = true, SecretValue = secret };

        result.Dispose();

        secret.ShouldAllBe(static b => b == 0);
    }

    [Fact]
    public void TheRandomDek_HasTheRequestedLength_AndIsDifferentEveryTime()
    {
        var a = PlaygroundInput.Parse(DekInputKind.Random, null, 32);
        var b = PlaygroundInput.Parse(DekInputKind.Random, null, 32);

        a.Length.ShouldBe(32);
        a.ShouldNotBe(b);
        Should.Throw<ConsoleActionException>(() => PlaygroundInput.Parse(DekInputKind.Random, null, 0));
        Should.Throw<ConsoleActionException>(() => PlaygroundInput.Parse(DekInputKind.Random, null, PlaygroundInput.MaxBytes + 1));
    }

    [Fact]
    public void TheOfferedAlgorithms_AreFilteredByTheKeyType()
    {
        PlaygroundInput.AlgorithmsFor(KeyType.Oct).Select(static a => a.ToWireName()).ShouldBe(["A256KWP", "A256KW"]);
        PlaygroundInput.AlgorithmsFor(KeyType.Rsa).Select(static a => a.ToWireName()).ShouldBe(["RSA-OAEP-256", "RSA-OAEP"]);
    }

    private async Task<PlaygroundResult> RoundTripAsync(PlaygroundTarget target)
    {
        using var wrapped = await _playground.WrapAsync("alice", target, Fx.Random(32));
        return await _playground.UnwrapAsync("alice", target, wrapped.WrappedValue!, wrapped.InputBytes, wrapped.InputFingerprint);
    }
}

/// <summary>The Reveal gate of the Playground follows the inspector's: only with the environment flag and Inspector:SecretDisplay=Reveal, audited first.</summary>
public sealed class PlaygroundRevealTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await ConsoleTestHost.StartAsync(allowReveal: true);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    [Fact]
    public async Task Reveal_ReturnsTheDek_OnlyWhenAllowed_AuditsFirst_AndTheAuditNeverHoldsIt()
    {
        var playground = _host.Host.App.Services.GetRequiredService<PlaygroundService>();
        var audit = _host.Host.App.Services.GetRequiredService<IAuditLog>();
        var dek = Fx.Random(32);
        var target = new PlaygroundTarget(PlaygroundMode.Direct, "_default", "aes-key-1", "A256KWP");
        using var wrapped = await playground.WrapAsync("alice", target, dek);
        using var unwrapped = await playground.UnwrapAsync("alice", target, wrapped.WrappedValue!, 32, wrapped.InputFingerprint);

        playground.RevealAllowed.ShouldBeTrue();
        var (base64Url, hex) = playground.Reveal("alice", unwrapped);

        Convert.FromHexString(hex).ShouldBe(dek);
        System.Buffers.Text.Base64Url.DecodeFromChars(base64Url).ShouldBe(dek);
        var entry = audit.ReadRecent().Single(static e => e.Action == "playground.reveal");
        entry.User.ShouldBe("alice");
        entry.Target.ShouldBe("key:_default/aes-key-1");
        entry.Detail.ShouldBe("32 bytes");
        SecretScanner.LeaksInText(string.Join('\n', audit.ReadRecent().Select(static e => e.ToString())), dek).ShouldBeFalse();
        Should.Throw<ConsoleActionException>(() => playground.Reveal("alice", wrapped)).Code.ShouldBe(ConsoleErrorCode.Conflict); // a wrap result holds no plaintext
    }
}
