using System.Reflection;
using System.Runtime.InteropServices;
using EkmMock.Crypto;
using EkmMock.Server.Connections;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.Server.Tls;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.WebConsole;

internal sealed record ConfigEntry(string Section, string Name, string Value, bool Redacted);

internal sealed record SelfTestCaseView(string Name, string Outcome, double DurationMs, string? Error);

internal sealed record SelfTestView(bool Passed, bool Strict, DateTimeOffset? RanAt, IReadOnlyList<SelfTestCaseView> Cases, IReadOnlyList<string> Failing);

internal sealed record MasterKeyView(bool Loaded, bool DevMode, string Source, string Description);

internal sealed record DataFileView(string Name, bool Exists, long Bytes, int Files);

internal sealed record DataVolumeView(string Path, IReadOnlyList<DataFileView> Entries);

internal sealed record ListenerView(string Name, string Configured, IReadOnlyList<int> BoundPorts);

internal sealed record RuntimeView(string Dotnet, string Os, string Architecture, bool InContainer);

internal sealed record DocLink(string Title, string Url);

internal sealed record AboutInfo(
    string Version,
    string AuthMode,
    bool DevMode,
    bool KeyImportEnabled,
    bool RevealAllowed,
    MasterKeyView MasterKey,
    SelfTestView SelfTest,
    DataVolumeView Data,
    TlsPolicyView Tls,
    IReadOnlyList<ListenerView> Listeners,
    InspectorStatus Inspector,
    RuntimeView Runtime,
    IReadOnlyList<ConfigEntry> Configuration,
    IReadOnlyList<DocLink> Links);

/// <summary>The About information as the page and the API consume it (a seam so the page can be tested with any combination of states).</summary>
internal interface IAboutService
{
    AboutInfo Get();

    SelfTestView SelfTest();
}

/// <summary>
/// What the About page and <c>GET /api/console/about</c> show (spec 8.5.11). <b>Redaction by construction:</b> the effective configuration is not a dump of
/// <c>IConfiguration</c> (which also holds every environment variable, including secrets); it is assembled from an explicit list of non-secret settings read from the typed
/// options, and every secret-bearing setting (master key, Entra client secret, uploaded keys) is represented only by a redacted "set / not set" line. A secret value
/// is never read into this type, so no redaction filter can miss it.
/// </summary>
internal sealed class AboutService : IAboutService
{
    public const string RepositoryUrl = "https://github.com/azureholic/ekmmock";

    private static readonly string VersionText = typeof(AboutService).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    private readonly IConsoleStatusProvider _status;
    private readonly EkmStartupState _startup;
    private readonly SoftwareCryptoBackend _backend;
    private readonly SoftwareCryptoBackendOptions _engine;
    private readonly CertificateAdminService _certificates;
    private readonly ListenerRegistry _listeners;
    private readonly IInspectorQuery _inspector;
    private readonly IOptions<DataOptions> _data;
    private readonly IOptions<DevOptions> _dev;
    private readonly IOptions<ProxyInfoOptions> _proxy;
    private readonly IOptions<SelfTestSettings> _selfTest;
    private readonly IOptions<EkmEndpointOptions> _ekmEndpoint;
    private readonly IOptions<ConsoleEndpointOptions> _consoleEndpoint;
    private readonly IOptions<ConsoleOptions> _console;
    private readonly IOptions<TlsOptions> _tls;
    private readonly IOptions<InspectorOptions> _inspectorOptions;
    private readonly IOptions<LimitsOptions> _limits;

    public AboutService(
        IConsoleStatusProvider status,
        EkmStartupState startup,
        SoftwareCryptoBackend backend,
        SoftwareCryptoBackendOptions engine,
        CertificateAdminService certificates,
        ListenerRegistry listeners,
        IInspectorQuery inspector,
        IOptions<DataOptions> data,
        IOptions<DevOptions> dev,
        IOptions<ProxyInfoOptions> proxy,
        IOptions<SelfTestSettings> selfTest,
        IOptions<EkmEndpointOptions> ekmEndpoint,
        IOptions<ConsoleEndpointOptions> consoleEndpoint,
        IOptions<ConsoleOptions> console,
        IOptions<TlsOptions> tls,
        IOptions<InspectorOptions> inspectorOptions,
        IOptions<LimitsOptions> limits)
    {
        _status = status;
        _startup = startup;
        _backend = backend;
        _engine = engine;
        _certificates = certificates;
        _listeners = listeners;
        _inspector = inspector;
        _data = data;
        _dev = dev;
        _proxy = proxy;
        _selfTest = selfTest;
        _ekmEndpoint = ekmEndpoint;
        _consoleEndpoint = consoleEndpoint;
        _console = console;
        _tls = tls;
        _inspectorOptions = inspectorOptions;
        _limits = limits;
    }

    public AboutInfo Get()
    {
        var status = _status.Get();
        var inspector = _inspector.Status();
        return new AboutInfo(
            VersionText,
            status.AuthMode,
            _dev.Value.Enabled,
            _engine.AllowKeyImport,
            inspector.RevealAllowed,
            MasterKey(),
            SelfTest(),
            DataVolume(),
            _certificates.TlsPolicyView(),
            [
                new ListenerView("EKM endpoint (mTLS)", _ekmEndpoint.Value.Url, _listeners.PortsOf(ListenerRegistry.EkmName)),
                new ListenerView("Console", _consoleEndpoint.Value.Url, _listeners.PortsOf(ListenerRegistry.ConsoleName)),
            ],
            inspector,
            new RuntimeView(RuntimeInformation.FrameworkDescription, RuntimeInformation.OSDescription, RuntimeInformation.OSArchitecture.ToString(), InContainer()),
            Configuration(),
            Links());
    }

    public SelfTestView SelfTest()
    {
        var result = _startup.SelfTest;
        if (result is null)
        {
            return new SelfTestView(false, _selfTest.Value.Strict, null, [], []);
        }

        return new SelfTestView(
            result.Passed,
            result.Strict,
            result.RanAt,
            [.. result.Cases.Select(static c => new SelfTestCaseView(c.Name, c.Outcome.ToString(), c.Duration.TotalMilliseconds, c.Error))],
            [.. result.Failures.Select(static f => f.Name)]);
    }

    private MasterKeyView MasterKey() => _backend.IsMasterKeyThrowAway
        ? new MasterKeyView(true, true, "dev mode", "A throw-away master key that exists only in memory. Keys created now are unreadable after a restart. Never protect real data with this instance.")
        : new MasterKeyView(true, false, _backend.MasterKeySource, "Loaded. The value is never shown.");

    private DataVolumeView DataVolume()
    {
        var root = Path.GetFullPath(_data.Value.Path);
        return new DataVolumeView(
            root,
            [
                FileEntry(root, "keystore.json"),
                FileEntry(root, "namespaces.json"),
                FileEntry(root, FileAuditLog.FileName),
                FolderEntry(root, string.IsNullOrWhiteSpace(_inspectorOptions.Value.PersistPath) ? "inspector" : null, _inspectorOptions.Value.PersistPath, "inspector (JSONL)"),
                FolderEntry(root, ServerCertificateProvider.ManagedFolderName, null, "tls (uploaded or generated certificate)"),
                FolderEntry(root, "dataprotection", null, "dataprotection (console tokens)"),
            ]);
    }

    private static DataFileView FileEntry(string root, string name)
    {
        try
        {
            var file = new FileInfo(Path.Combine(root, name));
            return new DataFileView(name, file.Exists, file.Exists ? file.Length : 0, file.Exists ? 1 : 0);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new DataFileView(name, false, 0, 0);
        }
    }

    private static DataFileView FolderEntry(string root, string? relative, string? absolute, string label)
    {
        try
        {
            var path = absolute is { Length: > 0 } ? Path.GetFullPath(absolute) : Path.Combine(root, relative ?? string.Empty);
            if (!Directory.Exists(path))
            {
                return new DataFileView(label, false, 0, 0);
            }

            long bytes = 0;
            var files = 0;
            foreach (var file in new DirectoryInfo(path).EnumerateFiles("*", SearchOption.TopDirectoryOnly).Take(10_000))
            {
                bytes += file.Length;
                files++;
            }

            return new DataFileView(label, true, bytes, files);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new DataFileView(label, false, 0, 0);
        }
    }

    private IReadOnlyList<ConfigEntry> Configuration()
    {
        var entries = new List<ConfigEntry>();
        void Add(string section, string name, object? value) => entries.Add(new ConfigEntry(section, name, Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty, Redacted: false));
        void Secret(string section, string name, bool isSet, string? note = null)
            => entries.Add(new ConfigEntry(section, name, (isSet ? "set" : "not set") + (note is null ? string.Empty : $" ({note})") + " - value hidden", Redacted: true));

        var proxy = _proxy.Value;
        Add("ProxyInfo", "ApiVersion", proxy.ApiVersion);
        Add("ProxyInfo", "ProxyVendor", proxy.ProxyVendor);
        Add("ProxyInfo", "ProxyName", proxy.ProxyName);
        Add("ProxyInfo", "EkmVendor", proxy.EkmVendor);
        Add("ProxyInfo", "EkmProduct", proxy.EkmProduct);

        Add("Endpoints", "Ekm:Url", _ekmEndpoint.Value.Url);
        Add("Endpoints", "Console:Url", _consoleEndpoint.Value.Url);
        Add("Data", "Path", _data.Value.Path);
        Add("Dev", "Enabled", _dev.Value.Enabled);
        Add("Dev", "SeedSampleKeys", _dev.Value.SeedSampleKeys);
        Add("SelfTest", "Strict", _selfTest.Value.Strict);

        var tls = _tls.Value;
        Add("Tls", "ServerName", string.IsNullOrWhiteSpace(tls.ServerName) ? "(not set)" : tls.ServerName);
        Add("Tls", "CertFile", string.IsNullOrWhiteSpace(tls.CertFile) ? "(not set: data volume or dev certificate)" : tls.CertFile);
        Add("Tls", "KeyFile", string.IsNullOrWhiteSpace(tls.KeyFile) ? "(not set)" : tls.KeyFile + " (path only; the key itself is never shown)");
        Add("Tls", "PollInterval", tls.PollInterval);
        Add("Tls", "ExpiryWarningDays", tls.ExpiryWarningDays);
        Add("Tls", "HandshakeTimeout", tls.HandshakeTimeout);

        var console = _console.Value;
        Add("Console", "Auth", console.Auth);
        Add("Console", "EnforceLoopbackClient", console.EnforceLoopbackClient);
        if (console.Auth == ConsoleAuthMode.EntraId)
        {
            Add("Console", "EntraId:TenantId", console.EntraId.TenantId);
            Add("Console", "EntraId:ClientId", console.EntraId.ClientId);
            Add("Console", "EntraId:AllowedObjectIds", $"{console.EntraId.AllowedObjectIds.Count} configured");
            Add("Console", "EntraId:AllowedGroupId", console.EntraId.AllowedGroupId ?? "(not set)");
        }

        var inspector = _inspectorOptions.Value;
        Add("Inspector", "SecretDisplay", inspector.SecretDisplay);
        Add("Inspector", "RingBufferSize", inspector.RingBufferSize);
        Add("Inspector", "ChannelCapacity", inspector.ChannelCapacity);
        Add("Inspector", "Persist", inspector.Persist);
        Add("Inspector", "RetainDays", inspector.RetainDays);
        Add("Limits", "LatencyBudgetMs", _limits.Value.LatencyBudgetMs);
        Add("Limits", "LatencyWarningMs", _limits.Value.LatencyWarningMs);
        Add("Limits", "InternalDeadlineMs", _limits.Value.InternalDeadlineMs);
        Add("Limits", "MaxConcurrency", _limits.Value.MaxConcurrency);

        Add("Environment flags", "EKMMOCK_ALLOW_KEY_IMPORT", _engine.AllowKeyImport);
        Add("Environment flags", InspectorOptions.AllowRevealVariable, _inspector.Status().RevealAllowed || EnvironmentRevealGate.IsEnvironmentFlagSet());

        // Secrets: only whether they exist, never what they are.
        Secret("Secrets", "Master key (EKMMOCK_MASTER_KEY / EKMMOCK_MASTER_KEY_FILE)", !_backend.IsMasterKeyThrowAway, _backend.IsMasterKeyThrowAway ? "dev mode: throw-away key in memory" : null);
        Secret("Secrets", "Entra client secret (EKMMOCK_CONSOLE_CLIENT_SECRET)", ClientSecretConfigured());
        Secret("Secrets", "Uploaded private keys", false, "never kept by the console; the server key is written to its own file");
        return entries;
    }

    private static IReadOnlyList<DocLink> Links() =>
    [
        new("EkmMock specification", $"{RepositoryUrl}/blob/main/spec/ekm-proxy-mockhsm-spec.md"),
        new("Design decisions", $"{RepositoryUrl}/blob/main/docs/DECISIONS.md"),
        new("Open questions", $"{RepositoryUrl}/blob/main/docs/OPEN-QUESTIONS.md"),
        new("Microsoft Learn: Managed HSM external key management", "https://learn.microsoft.com/azure/key-vault/managed-hsm/external-key-manager-overview"),
    ];

    // Presence only: neither the secret nor the file it names is read here.
    private static bool ClientSecretConfigured()
        => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable))
            || !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(ConsoleSecrets.ClientSecretFileVariable));

    private static bool InContainer()
        => string.Equals(Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase) || File.Exists("/.dockerenv");
}

/// <summary>
/// Sends an exchange again through the EKM endpoint with the console test client certificate (spec 8.5.2). The request body arrives as a private copy that is zeroed by
/// <see cref="ReplayRequest.Dispose"/>. Nothing is logged and nothing is kept.
/// </summary>
internal sealed class ConsoleReplaySender : IReplaySender
{
    private readonly EkmSelfClient _client;

    public ConsoleReplaySender(EkmSelfClient client)
    {
        _client = client;
    }

    public async Task<ReplayOutcome> SendAsync(ReplayRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _client.SendAsync(request.Method, request.PathAndQuery, request.ContentType, request.Body, cancellationToken).ConfigureAwait(false);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(response.Body);
            return response.Status == StatusCodes.Status401Unauthorized
                ? new ReplayOutcome(true, response.Status, "The EKM endpoint answered 401: the namespace does not trust the console test CA. Trust it on the Namespaces & trust page and replay again.")
                : new ReplayOutcome(true, response.Status, null);
        }
        catch (ConsoleActionException exception)
        {
            return new ReplayOutcome(false, null, exception.Message);
        }
    }
}
