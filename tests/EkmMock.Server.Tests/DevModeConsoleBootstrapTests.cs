#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using EkmMock.Crypto;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.TestSupport;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// M6, spec 11.2: with <c>--dev</c> the <c>_default</c> namespace exists and trusts the console test CA (CN test.managedhsmclient.local), so the Playground "via EKM endpoint" and
/// Replay work at once. Without <c>--dev</c> nothing is trusted automatically.
/// </summary>
public sealed class DevModeConsoleBootstrapTests
{
    [Fact]
    public async Task InDevMode_DefaultExists_TrustsTheConsoleTestCa_AndThePlaygroundWorksImmediately()
    {
        using var pki = new TestPki();
        await using var host = await RealEkmHost.StartAsync(new RealEkmHostOptions { Pki = pki, DevMode = true });
        var services = host.App.Services;
        var namespaces = services.GetRequiredService<NamespaceAdminService>();

        var view = namespaces.Get("_default");
        view.TrustsConsoleTestClient.ShouldBeTrue();
        view.SubjectCommonNames.ShouldBe([ConsoleTestIdentity.CommonName]);
        view.CaCertificates.Single().IsConsoleTestCa.ShouldBeTrue();
        var audit = services.GetRequiredService<IAuditLog>().ReadRecent();
        // (The shipped appsettings.json already seeds _default; the bootstrap only adds the trust of the console test CA, as the user "system".)
        audit.Select(static e => (e.User, e.Action)).ShouldBe([("system", "namespace.trust.test-client")]);

        host.Keys.Create("_default", "dev-key", KeyType.Oct, 256);
        using var wrapped = await services.GetRequiredService<PlaygroundService>().WrapAsync("alice", new PlaygroundTarget(PlaygroundMode.ViaEkm, "_default", "dev-key", "A256KWP"), Fx.Random(32));
        wrapped.Ok.ShouldBeTrue(wrapped.Message);
        wrapped.HttpStatus.ShouldBe(200);
    }

    [Fact]
    public async Task WithoutDevMode_NothingIsTrustedAutomatically()
    {
        using var pki = new TestPki();
        await using var host = await RealEkmHost.StartAsync(new RealEkmHostOptions { Pki = pki, Namespaces = [TestNamespace.Default(pki.ClientCaA, "some.client")] });

        host.App.Services.GetRequiredService<NamespaceAdminService>().Get("_default").TrustsConsoleTestClient.ShouldBeFalse();
        host.App.Services.GetRequiredService<IAuditLog>().ReadRecent().ShouldBeEmpty();
    }
}
