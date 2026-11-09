using System.Security.Cryptography;
using System.Text.Json;
using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.Server.Tls;
using EkmMock.Server.WebConsole;
using EkmMock.TestSupport;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace EkmMock.Console.Tests;

/// <summary>
/// The real M6 services (engine, namespace store, audit file, certificate provider, playground) on a temp folder, without a web host: what the page tests run against. Nothing in it is
/// faked except the EKM self client's endpoint (there is no listener); the tests that need the real endpoint use <see cref="RealConsoleHost"/>.
/// </summary>
internal sealed class AdminEnvironment : IDisposable
{
    private readonly TempFolder _folder;

    private AdminEnvironment(TempFolder folder, string dataPath)
    {
        _folder = folder;
        DataPath = dataPath;
    }

    public string DataPath { get; }

    public TestPki Pki { get; private set; } = null!;

    public SoftwareCryptoBackend Backend { get; private set; } = null!;

    public NamespaceStore NamespaceStore { get; private set; } = null!;

    public FileAuditLog AuditLog { get; private set; } = null!;

    public AuditRecorder Recorder { get; private set; } = null!;

    public ConsoleTestIdentity Identity { get; private set; } = null!;

    public KeyAdminService Keys { get; private set; } = null!;

    public NamespaceAdminService Namespaces { get; private set; } = null!;

    public ServerCertificateProvider Certificates { get; private set; } = null!;

    public CertificateAdminService CertificateAdmin { get; private set; } = null!;

    public EkmSelfClient SelfClient { get; private set; } = null!;

    public PlaygroundService Playground { get; private set; } = null!;

    public SoftwareCryptoBackendOptions EngineOptions { get; private set; } = null!;

    public static byte[] MasterKey => SHA256.HashData("ekmmock-console-page-tests"u8.ToArray());

    /// <param name="beforeOpen">Runs after the key store was created and closed, before it is opened for the services: the hook to tamper with <c>keystore.json</c>.</param>
    public static AdminEnvironment Create(IInspectorQuery inspector, bool allowImport = false, Action<string>? prepareKeyStore = null, Action<SoftwareCryptoBackend>? seed = null)
    {
        var folder = new TempFolder("ekmmock-page-tests");
        var data = Path.Combine(folder.Path, "data");
        Directory.CreateDirectory(data);
        var environment = new AdminEnvironment(folder, data) { Pki = new TestPki() };

        if (seed is not null)
        {
            using var first = environment.OpenBackend(allowImport);
            seed(first);
        }

        prepareKeyStore?.Invoke(data);
        environment.Build(allowImport, inspector);
        return environment;
    }

    private SoftwareCryptoBackend OpenBackend(bool allowImport)
        => new(new SoftwareCryptoBackendOptions
        {
            DataPath = DataPath,
            MasterKeyProvider = new ExplicitMasterKeyProvider(MasterKey),
            AllowKeyImport = allowImport,
            CounterFlushInterval = TimeSpan.Zero,
        });

    private void Build(bool allowImport, IInspectorQuery inspector)
    {
        EngineOptions = new SoftwareCryptoBackendOptions
        {
            DataPath = DataPath,
            MasterKeyProvider = new ExplicitMasterKeyProvider(MasterKey),
            AllowKeyImport = allowImport,
            CounterFlushInterval = TimeSpan.Zero,
        };
        Backend = new SoftwareCryptoBackend(EngineOptions);
        NamespaceStore = NamespaceStore.Open(DataPath);
        AuditLog = new FileAuditLog(Path.Combine(DataPath, FileAuditLog.FileName), TimeProvider.System);
        Recorder = new AuditRecorder(AuditLog, NullLogger<AuditRecorder>.Instance);
        Identity = new ConsoleTestIdentity();

        var serverCert = Pki.IssueServer();
        var (certFile, keyFile) = serverCert.WriteFiles(Path.Combine(_folder.Path, "tls"));
        var tls = Options.Create(new TlsOptions { CertFile = certFile, KeyFile = keyFile, PollInterval = TimeSpan.FromMinutes(5) });
        var dataOptions = Options.Create(new DataOptions { Path = DataPath });
        Certificates = new ServerCertificateProvider(tls, Options.Create(new DevOptions()), TimeProvider.System, NullLogger<ServerCertificateProvider>.Instance, dataOptions);
        serverCert.Dispose();

        Keys = new KeyAdminService(Backend, NamespaceStore, Recorder, EngineOptions);
        var services = new ServiceCollection().AddSingleton<IServerCertificateProvider>(Certificates).BuildServiceProvider();
        Namespaces = new NamespaceAdminService(NamespaceStore, Backend, Recorder, Identity, services, tls, TimeProvider.System);
        CertificateAdmin = new CertificateAdminService(Certificates, new TlsPolicy(), tls, dataOptions, Recorder, TimeProvider.System);

        // No EKM listener here: the self client has no endpoint, so "via EKM endpoint" reports it is not listening. The real-host tests cover the real round trip.
        SelfClient = new EkmSelfClient(Identity, () => Certificates.Current.Thumbprint, () => []);
        Playground = new PlaygroundService(Backend, Backend, NamespaceStore, Namespaces, SelfClient, inspector, Recorder);
    }

    /// <summary>Adds a namespace with trust for <see cref="TestPki.ClientCaA"/> and optionally keys.</summary>
    public void AddNamespace(string name, string prefix, params (string Key, KeyType Type, int Size)[] keys)
    {
        Namespaces.Create("seed", new NamespaceChange(name, prefix, null, null));
        foreach (var (key, type, size) in keys)
        {
            Keys.Create("seed", new CreateKeyRequest(name, key, type == KeyType.Oct ? "oct" : "RSA", size));
        }
    }

    public IReadOnlyList<AuditEntry> Entries => AuditLog.ReadRecent(100_000);

    public void Dispose()
    {
        Identity.Dispose();
        SelfClient.Dispose();
        Certificates.Dispose();
        Backend.Dispose();
        Pki.Dispose();
        _folder.Dispose();
    }
}

/// <summary>The page-test base: the console's component context plus the real M6 services of an <see cref="AdminEnvironment"/>.</summary>
public abstract class AdminPageTestBase : ConsoleTestBase
{
    private protected AdminPageTestBase(bool allowImport = false, Action<string>? prepareKeyStore = null, Action<SoftwareCryptoBackend>? seed = null)
    {
        Env = AdminEnvironment.Create(InspectorFake, allowImport, prepareKeyStore, seed);
        Services.AddSingleton(Env.Keys);
        Services.AddSingleton(Env.Namespaces);
        Services.AddSingleton(Env.CertificateAdmin);
        Services.AddSingleton(Env.Playground);
        Services.AddSingleton<IAuditLog>(Env.AuditLog);
        Services.AddSingleton(Env.Recorder);
    }

    internal AdminEnvironment Env { get; }

    private bool _environmentDisposed;

    protected override void Dispose(bool disposing)
    {
        // bUnit's DisposeAsync (which xUnit calls) ends in Dispose(false), and only the synchronous path passes true: dispose the environment on both, once. It owns the server
        // certificate provider (a Windows key container per test environment that is deleted only on dispose: open question 46) and a temp folder.
        if (!_environmentDisposed)
        {
            _environmentDisposed = true;
            Env.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <summary>The visible text of an element (tags replaced by spaces, whitespace collapsed).</summary>
    protected static string Text(AngleSharp.Dom.IElement element) => Dom.Text(element);

    protected static string Json(object value) => JsonSerializer.Serialize(value);
}

/// <summary>Polls a condition until it holds or the time is up (the capture and the feed are asynchronous by design).</summary>
internal static class Poll
{
    public static async Task<bool> UntilAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(15));
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(25);
        }

        return condition();
    }
}
