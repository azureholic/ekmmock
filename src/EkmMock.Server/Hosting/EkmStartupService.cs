using EkmMock.Crypto;
using EkmMock.Crypto.SelfTest;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Hosting;

/// <summary>
/// Runs before the server accepts traffic (hosted services start before the web server): checks the listener
/// guard, opens the key store and namespaces, seeds optional sample keys, runs the startup self-test (spec 6.5) and
/// only then marks the engine ready. A missing master key, an unreadable store or a failed strict self-test throws
/// and the host does not start.
/// </summary>
internal sealed class EkmStartupService : IHostedService
{
    internal const string SampleAesKeyName = "aes-key-1";
    internal const string SampleRsaKeyName = "rsa-key-1";

    private readonly IServiceProvider _services;
    private readonly ILogger<EkmStartupService> _logger;

    public EkmStartupService(IServiceProvider services, ILogger<EkmStartupService> logger)
    {
        _services = services;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var dev = _services.GetRequiredService<IOptions<DevOptions>>().Value;
        PlainHttpGuard.Check(_services.GetService<IServer>(), dev.Enabled);

        // Constructing the backend loads the key store and throws without a master key (spec 6.2).
        var backend = _services.GetRequiredService<SoftwareCryptoBackend>();
        _ = _services.GetRequiredService<NamespaceStore>();

        if (backend.IsMasterKeyThrowAway)
        {
            _logger.LogWarning("DEV MODE: using a throw-away master key. Keys created now cannot be read after a restart.");
        }

        if (dev.SeedSampleKeys)
        {
            SeedSampleKeys(_services.GetRequiredService<IKeyManager>());
        }

        var strict = _services.GetRequiredService<IOptions<SelfTestSettings>>().Value.Strict;
        var result = backend.RunSelfTest(new SelfTestOptions { Strict = strict });
        if (result.RefuseToStart)
        {
            throw new InvalidOperationException(
                "Startup self-test failed and SelfTest:Strict is on: " + string.Join(", ", result.Failures.Select(static f => f.Name)));
        }

        _services.GetRequiredService<EkmStartupState>().MarkReady(result);
        _logger.LogInformation(
            "EkmMock engine ready: keys={Keys} corrupt_keys={CorruptKeys} self_test_passed={SelfTestPassed} dev_mode={DevMode}",
            _services.GetRequiredService<IKeyManager>().List().Count(static k => k.State != KeyState.Destroyed),
            backend.LoadReport.CorruptKeys,
            result.Passed,
            dev.Enabled);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static void SeedSampleKeys(IKeyManager keys)
    {
        var aes = new KeyRef(EkmNames.DefaultNamespace, SampleAesKeyName);
        if (keys.Get(aes) is null)
        {
            keys.Create(aes.Namespace, aes.Name, KeyType.Oct, 256);
        }

        var rsa = new KeyRef(EkmNames.DefaultNamespace, SampleRsaKeyName);
        if (keys.Get(rsa) is null)
        {
            keys.Create(rsa.Namespace, rsa.Name, KeyType.Rsa, 2048);
        }
    }
}

/// <summary>
/// M2 has no TLS: the EKM handlers must never answer on a real plain-HTTP port outside tests and <c>--dev</c>.
/// Real listeners (TLS 1.3 + mTLS) arrive with M3, which replaces this guard.
/// </summary>
internal static class PlainHttpGuard
{
    public static void Check(IServer? server, bool devMode)
    {
        if (devMode || server is null || IsInProcessTestServer(server))
        {
            return;
        }

        throw new InvalidOperationException(
            "EKM over plain HTTP is only available in dev mode (--dev) until mTLS is implemented (milestone M3).");
    }

    // The in-process test host has no network listener. Matched by namespace so the server needs no test or Kestrel reference.
    internal static bool IsInProcessTestServer(IServer server)
        => server.GetType().Namespace?.StartsWith("Microsoft.AspNetCore.TestHost", StringComparison.Ordinal) == true;
}
