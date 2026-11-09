using System.Reflection;
using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.Server.Tls;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.WebConsole;

/// <summary>
/// Whether fault injection is switched on and a fault rule is active (spec 10.2: "a banner at the top of every console page says faults are active").
/// <see cref="Active"/> is true while at least one enabled, unexpired rule exists (an HSM-offline rule included); <see cref="Enabled"/> says the process allows faults at all.
/// </summary>
internal interface IFaultStatus
{
    /// <summary>The process was started with <c>EKMMOCK_ENABLE_FAULTS=true</c>.</summary>
    bool Enabled { get; }

    bool Active { get; }

    /// <summary>How many rules are active (enabled and not expired).</summary>
    int ActiveRules { get; }

    /// <summary>An "HSM offline" rule is active.</summary>
    bool HsmOffline { get; }

    /// <summary>Raised when the active state may have changed (a rule was created, changed, removed or expired), so the banner of every open console updates.</summary>
    event Action? Changed;
}

internal sealed class NoFaultStatus : IFaultStatus
{
    public bool Enabled => false;

    public bool Active => false;

    public int ActiveRules => 0;

    public bool HsmOffline => false;

    public event Action? Changed
    {
        add { }
        remove { }
    }
}

/// <summary>The real <see cref="IFaultStatus"/>: reads the rule store and forwards its change notifications.</summary>
internal sealed class FaultStatus : IFaultStatus
{
    private readonly Faults.FaultRuleStore _rules;

    public FaultStatus(Faults.FaultRuleStore rules)
    {
        _rules = rules;
        _rules.Changed += OnChanged;
    }

    public bool Enabled => _rules.Enabled;

    public bool Active => _rules.ActiveCount > 0;

    public int ActiveRules => _rules.ActiveCount;

    public bool HsmOffline => _rules.IsHsmOffline;

    public event Action? Changed;

    private void OnChanged() => Changed?.Invoke();
}

/// <summary>What the console shell, the banners and <c>/api/console/status</c> need to know. Contains no secret, no path and no key material.</summary>
internal sealed record ConsoleStatus(
    string Version,
    string AuthMode,
    bool DevMode,
    bool DevMasterKey,
    bool Ready,
    bool SelfTestPassed,
    bool FaultsActive,
    bool RevealAllowed,
    string SecretDisplay,
    int LatencyBudgetMs,
    int LatencyWarningMs,
    bool FaultsEnabled = false,
    bool HsmOfflineFault = false);

/// <summary>The answer of <c>/readyz</c>: ready, or the short names of what is not (never details).</summary>
internal sealed record ReadinessResult(bool Ready, IReadOnlyList<string> NotReady);

internal interface IConsoleStatusProvider
{
    ConsoleStatus Get();

    ReadinessResult CheckReadiness();
}

internal sealed class ConsoleStatusProvider : IConsoleStatusProvider
{
    public const string KeyStoreNotReady = "key_store";
    public const string SelfTestFailed = "self_test";
    public const string EkmListenerDown = "ekm_listener";

    private static readonly string VersionText = typeof(ConsoleStatusProvider).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    private readonly EkmStartupState _startup;
    private readonly SoftwareCryptoBackend _backend;
    private readonly IOptions<DevOptions> _dev;
    private readonly IOptions<ConsoleOptions> _console;
    private readonly IOptions<LimitsOptions> _limits;
    private readonly IFaultStatus _faults;
    private readonly IInspectorQuery _inspector;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ListenerRegistry _listeners;
    private readonly IServerCertificateProvider _certificates;

    public ConsoleStatusProvider(
        EkmStartupState startup,
        SoftwareCryptoBackend backend,
        IOptions<DevOptions> dev,
        IOptions<ConsoleOptions> console,
        IOptions<LimitsOptions> limits,
        IFaultStatus faults,
        IInspectorQuery inspector,
        IHostApplicationLifetime lifetime,
        ListenerRegistry listeners,
        IServerCertificateProvider certificates)
    {
        _startup = startup;
        _backend = backend;
        _dev = dev;
        _console = console;
        _limits = limits;
        _faults = faults;
        _inspector = inspector;
        _lifetime = lifetime;
        _listeners = listeners;
        _certificates = certificates;
    }

    public ConsoleStatus Get()
    {
        var inspector = _inspector.Status();
        return new ConsoleStatus(
            VersionText,
            _console.Value.Auth.ToString(),
            _dev.Value.Enabled,
            _backend.IsMasterKeyThrowAway,
            _startup.IsReady,
            _startup.SelfTest?.Passed ?? false,
            _faults.Active,
            inspector.RevealAllowed,
            inspector.SecretDisplay.ToString(),
            _limits.Value.LatencyBudgetMs,
            _limits.Value.LatencyWarningMs,
            _faults.Enabled,
            _faults.HsmOffline);
    }

    public ReadinessResult CheckReadiness()
    {
        var notReady = new List<string>(3);
        if (!_startup.IsReady || !_backend.IsAvailable)
        {
            notReady.Add(KeyStoreNotReady);
        }

        if (_startup.SelfTest is not { Passed: true })
        {
            notReady.Add(SelfTestFailed);
        }

        // All Kestrel endpoints bind together when the application starts, so "started" plus a bound EKM port plus a loaded certificate is "the EKM listener is up".
        if (!_lifetime.ApplicationStarted.IsCancellationRequested || _listeners.PortsOf(ListenerRegistry.EkmName).Count == 0 || _certificates.Current is null)
        {
            notReady.Add(EkmListenerDown);
        }

        return new ReadinessResult(notReady.Count == 0, notReady);
    }
}
