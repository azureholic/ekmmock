#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using EkmMock.Crypto;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// M6, spec 8.5.2: the Replay seam of M4 is now complete. A replay is a real mutual-TLS request with the console test client certificate, audited, visible in Live traffic,
/// and only possible when the raw request body is retained (reveal allowed).
/// </summary>
public sealed class ReplayTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await ConsoleTestHost.StartAsync(allowReveal: true);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private IInspector Inspector => _host.Inspector;

    private IReadOnlyList<AuditEntry> Audit() => _host.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent();

    private async Task<long> SendOriginalWrapAsync(byte[] dek)
    {
        var (ekm, _, owner) = _host.CreateTrustedEkmClient();
        using (owner)
        {
            (await ekm.WrapAsync("aes-key-1", "A256KWP", dek)).StatusCode.ShouldBe(200);
        }

        (await Wait.UntilAsync(() => Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items.Count >= 1)).ShouldBeTrue();
        return Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items[0].Id;
    }

    [Fact]
    public async Task ReplayingAnExchange_SendsTheSameRequestAgain_WithTheTestClientCertificate_AndItAppearsInLiveTraffic()
    {
        var dek = Fx.Random(32);
        var originalId = await SendOriginalWrapAsync(dek);
        _host.Host.App.Services.GetRequiredService<NamespaceAdminService>().TrustConsoleTestClient("loopback", "_default");
        Inspector.CanReplay(originalId).Possible.ShouldBeTrue();

        var outcome = await Inspector.ReplayAsync(originalId, "alice", TestContext.Current.CancellationToken);

        outcome.Sent.ShouldBeTrue(outcome.Note);
        outcome.Status.ShouldBe(200);
        (await Wait.UntilAsync(() => Inspector.Query(new ExchangeFilter { ClientCommonName = ConsoleTestIdentity.CommonName }).Items.Count == 1)).ShouldBeTrue("the replay is not in Live traffic");
        var replayed = Inspector.Query(new ExchangeFilter { ClientCommonName = ConsoleTestIdentity.CommonName }).Items.Single();
        var original = Inspector.Get(originalId)!;
        replayed.Id.ShouldBeGreaterThan(originalId);
        replayed.Request.Operation.ShouldBe("wrapkey");
        replayed.Request.Key.ShouldBe(original.Request.Key);
        replayed.Request.RawTarget.ShouldBe(original.Request.RawTarget);
        replayed.Context.CorrelationId.ShouldBe(original.Context.CorrelationId, "the same body, so the same ids");
        replayed.Request.Body!.MaskedFields.Single().Display.ShouldBe(original.Request.Body!.MaskedFields.Single().Display, "the same DEK, so the same fingerprint");
        replayed.Response.Status.ShouldBe(200);
        replayed.ClientCertificate.CommonName.ShouldBe(ConsoleTestIdentity.CommonName);

        var entry = Audit().Single(static e => e.Action == "inspector.replay");
        entry.User.ShouldBe("alice");
        entry.Target.ShouldBe($"exchange:{originalId}");
        SecretScanner.LeaksInText(string.Join('\n', Audit().Select(static e => e.ToString())), dek).ShouldBeFalse();
    }

        [Fact]
    public async Task AReplay_WhenNoNamespaceTrustsTheTestCa_FailsTheHandshake_AndSaysWhatToDo()
    {
        var originalId = await SendOriginalWrapAsync(Fx.Random(32));

        var outcome = await Inspector.ReplayAsync(originalId, "alice", TestContext.Current.CancellationToken);

        outcome.Sent.ShouldBeFalse();
        outcome.Status.ShouldBeNull();
        outcome.Note.ShouldNotBeNull().ShouldContain("namespace trusts the console test CA");
        outcome.Note.ShouldNotContain("BEGIN");
    }

    [Fact]
    public async Task AReplay_ToANamespaceThatDoesNotTrustTheTestCa_ButAnotherOneDoes_Reports401AndSaysWhy()
    {
        var originalId = await SendOriginalWrapAsync(Fx.Random(32));
        var admin = _host.Host.App.Services.GetRequiredService<NamespaceAdminService>();
        admin.Create("loopback", new NamespaceChange("elsewhere", "elsewhere", null, null));
        admin.TrustConsoleTestClient("loopback", "elsewhere"); // the CA is known to the listener now, but _default does not allow the test client

        var outcome = await Inspector.ReplayAsync(originalId, "alice", TestContext.Current.CancellationToken);

        outcome.Sent.ShouldBeTrue(outcome.Note);
        outcome.Status.ShouldBe(401);
        outcome.Note.ShouldNotBeNull().ShouldContain("does not trust the console test CA");
    }
    [Fact]
    public async Task ReplayIsRefused_WhenTheExchangeIsUnknown_AndNothingIsSent()
    {
        Inspector.CanReplay(424242).ShouldBe(new ReplayCheck(false, ReplayBlockReason.ExchangeNotFound));
        var exception = await Should.ThrowAsync<InspectorReplayException>(async () => await Inspector.ReplayAsync(424242, "alice", TestContext.Current.CancellationToken));
        exception.Reason.ShouldBe(ReplayBlockReason.ExchangeNotFound);
        Audit().ShouldNotContain(static e => e.Action == "inspector.replay");
    }
}

/// <summary>Without the reveal gate the raw body is never kept, so there is nothing to replay and the button stays disabled with its reason (spec 8.4, 8.5.2).</summary>
public sealed class ReplayWithoutRevealTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await ConsoleTestHost.StartAsync(allowReveal: false);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    [Fact]
    public async Task ReplayIsNotPossible_WithoutRevealAllowed()
    {
        await _host.SendSampleTrafficAsync();
        var id = _host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items[0].Id;

        _host.Inspector.CanReplay(id).ShouldBe(new ReplayCheck(false, ReplayBlockReason.RevealNotAllowed));
        var exception = await Should.ThrowAsync<InspectorReplayException>(async () => await _host.Inspector.ReplayAsync(id, "alice", TestContext.Current.CancellationToken));
        exception.Reason.ShouldBe(ReplayBlockReason.RevealNotAllowed);
    }
}
