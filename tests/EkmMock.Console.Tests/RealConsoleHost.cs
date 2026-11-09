using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EkmMock.Console.Tests;

/// <summary>
/// The production EKM server on real Kestrel listeners (mTLS EKM endpoint + HTTPS console, ephemeral ports) with generated certificates, built by the production host builder.
/// The live-update test sends a real mutual-TLS request to it and watches the console components render it.
/// </summary>
internal sealed class RealConsoleHost : IAsyncDisposable
{
    public const string ClientCn = "mhsm-live.managedhsmclient.test";

    private readonly TempFolder _folder;
    private readonly TestPki _pki;
    private readonly List<IDisposable> _disposables = [];

    private RealConsoleHost(WebApplication app, TestPki pki, TempFolder folder)
    {
        App = app;
        _pki = pki;
        _folder = folder;
    }

    public WebApplication App { get; }

    public int EkmPort { get; private set; }

    public int ConsolePort { get; private set; }

    public IInspector Inspector => App.Services.GetRequiredService<IInspector>();

    public static async Task<RealConsoleHost> StartAsync(bool allowReveal = false)
    {
        var pki = new TestPki();
        var folder = new TempFolder("ekmmock-console-host");
        var server = pki.IssueServer();
        var (certFile, keyFile) = server.WriteFiles(Path.Combine(folder.Path, "tls"));
        var dataPath = Path.Combine(folder.Path, "data");
        var masterKey = new ExplicitMasterKeyProvider(System.Security.Cryptography.SHA256.HashData("ekmmock-console-tests"u8.ToArray()));
        var configuration = new Dictionary<string, string?>
        {
            ["Data:Path"] = dataPath,
            ["Endpoints:Ekm:Url"] = "https://127.0.0.1:0",
            ["Endpoints:Console:Url"] = "https://127.0.0.1:0",
            ["Tls:CertFile"] = certFile,
            ["Tls:KeyFile"] = keyFile,
            ["SeedNamespaces:0:Name"] = "_default",
            ["SeedNamespaces:0:Prefix"] = string.Empty,
            ["SeedNamespaces:0:ClientTrust:SubjectCommonNames:0"] = ClientCn,
            ["SeedNamespaces:0:ClientTrust:CaCertificatesDerBase64:0"] = pki.ClientCaA.DerBase64,
        };

        var app = EkmServerServiceCollectionExtensions.BuildEkmMockApp([], builder =>
        {
            builder.Configuration.AddInMemoryCollection(configuration);
            builder.Logging.ClearProviders();
            builder.Logging.SetMinimumLevel(LogLevel.Warning);
            builder.Services.AddSingleton<IMasterKeyProvider>(masterKey);
            if (allowReveal)
            {
                // The test equivalent of EKMMOCK_INSPECTOR_ALLOW_REVEAL=true: raw request bodies are retained, so replay is possible.
                builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Inspector:SecretDisplay"] = "Reveal" });
                builder.Services.AddSingleton<IInspectorRevealGate>(new OpenRevealGate());
            }
            builder.Services.AddSingleton(new SoftwareCryptoBackendOptions
            {
                DataPath = dataPath,
                MasterKeyProvider = masterKey,
                CounterFlushInterval = TimeSpan.Zero,
                Info = new BackendInfo("EkmMock", "EkmMock Software HSM"),
            });
        });

        var host = new RealConsoleHost(app, pki, folder);
        host._disposables.Add(server);
        await app.StartAsync();
        var listeners = app.Services.GetRequiredService<ListenerRegistry>();
        host.EkmPort = listeners.PortsOf(ListenerRegistry.EkmName).Single();
        host.ConsolePort = listeners.PortsOf(ListenerRegistry.ConsoleName).Single();
        app.Services.GetRequiredService<IKeyManager>().Create("_default", "aes-key-1", KeyType.Oct, 256);
        return host;
    }

    /// <summary>An HttpClient for the EKM endpoint: TLS 1.3, trusts only the test server CA, presents the trusted client certificate.</summary>
    public HttpClient CreateEkmHttpClient()
    {
        var issued = _pki.ClientCaA.IssueClient(ClientCn);
        _disposables.Add(issued);
        var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = "127.0.0.1",
                EnabledSslProtocols = SslProtocols.Tls13,
                ClientCertificates = [issued.Certificate],
                RemoteCertificateValidationCallback = ValidateServer,
            },
        };
        var client = new HttpClient(handler, disposeHandler: true) { BaseAddress = new Uri($"https://127.0.0.1:{EkmPort}/"), Timeout = TimeSpan.FromSeconds(20) };
        _disposables.Add(client);
        return client;
    }

    /// <summary>One wrap request of a DEK through the EKM endpoint (a real mutual-TLS request).</summary>
    public static async Task<HttpResponseMessage> WrapAsync(HttpClient client, byte[] dek, string key = "aes-key-1", string correlationId = "live-correlation")
    {
        var body = $$"""{"request_context":{"request_id":"live-r","correlation_id":"{{correlationId}}","pool_name":"live-pool"},"alg":"A256KWP","value":"{{SecretScanner.Base64Url(dek)}}"}""";
        using var content = new StringContent(body);
        content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        return await client.PostAsync($"/{key}/wrapkey?api-version=0.1-preview", content);
    }

    private bool ValidateServer(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
        {
            return false;
        }

        using var custom = new X509Chain();
        custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        custom.ChainPolicy.CustomTrustStore.Add(_pki.ServerCa.Certificate);
        custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        using var leaf = new X509Certificate2(certificate);
        return custom.Build(leaf);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var disposable in _disposables)
        {
            disposable.Dispose();
        }

        try
        {
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await App.StopAsync(stop.Token);
        }
        catch (Exception)
        {
            // Best effort in tests.
        }

        await App.DisposeAsync();
        _folder.Dispose();
        _pki.Dispose();
    }
}

/// <summary>An open reveal gate (a stand-in for the environment flag), so that the raw request bodies are retained.</summary>
internal sealed class OpenRevealGate : IInspectorRevealGate
{
    public bool IsAllowed => true;
}
