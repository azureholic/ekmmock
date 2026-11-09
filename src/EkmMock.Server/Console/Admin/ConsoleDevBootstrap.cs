using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.WebConsole;

/// <summary>
/// Dev mode convenience (spec 11.2): with <c>--dev</c> the <c>_default</c> namespace exists and trusts the console test CA (CN <see cref="ConsoleTestIdentity.CommonName"/>),
/// so the Playground and Replay work immediately. The test CA is per process (see <see cref="ConsoleTestIdentity"/>), so an older test CA in <c>namespaces.json</c> is
/// replaced, not accumulated. Both changes are written to the audit log as the user <c>system</c>. Outside dev mode nothing happens: trust is always an explicit action.
/// </summary>
internal sealed class ConsoleDevBootstrap : IHostedService
{
    public const string SystemUser = "system";

    private readonly IOptions<DevOptions> _dev;
    private readonly NamespaceStore _namespaces;
    private readonly IServiceProvider _services;

    public ConsoleDevBootstrap(IOptions<DevOptions> dev, NamespaceStore namespaces, IServiceProvider services)
    {
        _dev = dev;
        _namespaces = namespaces;
        _services = services;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_dev.Value.Enabled)
        {
            return Task.CompletedTask;
        }

        // Resolved here, not injected: outside dev mode this service (and the certificate provider behind it) is never created by the bootstrap.
        var admin = _services.GetRequiredService<NamespaceAdminService>();
        if (_namespaces.Get(EkmNames.DefaultNamespace) is null)
        {
            admin.Create(SystemUser, new NamespaceChange(EkmNames.DefaultNamespace, string.Empty, null, null));
        }

        if (!admin.TrustsConsoleTestClient(EkmNames.DefaultNamespace))
        {
            admin.TrustConsoleTestClient(SystemUser, EkmNames.DefaultNamespace);
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
