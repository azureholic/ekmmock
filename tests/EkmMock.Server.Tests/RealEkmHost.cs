using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Crypto;
using EkmMock.Pki;
using EkmMock.Server.Connections;
using EkmMock.Server.Hosting;
using EkmMock.Server.Tls;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EkmMock.Server.Tests;

/// <summary>A namespace for a real-Kestrel test: prefix, allowed client CNs and the root CAs whose clients are trusted.</summary>
internal sealed record TestNamespace(string Name, string Prefix, string[] CommonNames, CertificateAuthority[] TrustedCas)
{
    public static TestNamespace Default(CertificateAuthority ca, params string[] commonNames) => new("_default", string.Empty, commonNames, [ca]);
}

internal sealed class RealEkmHostOptions
{
    public required TestPki Pki { get; init; }

    public TestNamespace[] Namespaces { get; init; } = [];

    /// <summary>The initial server certificate; null issues one from <see cref="TestPki.ServerCa"/> for localhost/127.0.0.1.</summary>
    public IssuedCertificate? ServerCertificate { get; init; }

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(200);

    public TimeSpan Debounce { get; init; } = TimeSpan.FromMilliseconds(50);

    /// <summary>Extra Kestrel listeners next to the EKM endpoint, to prove the port separation (plain HTTP on loopback, port 0).</summary>
    public bool AddPlainHttpListener { get; init; }

    /// <summary>Starts with <c>--dev</c> and no <c>Tls:CertFile</c>, so the host generates its own throw-away localhost certificate.</summary>
    public bool DevMode { get; init; }

    public Action<IServiceCollection>? ConfigureServices { get; init; }

    public Dictionary<string, string?> Configuration { get; init; } = [];
}

/// <summary>
/// The real EKM server on a real Kestrel listener (<c>https://127.0.0.1:0</c>), built by the production host builder, with
/// generated certificates in a temp folder. Nothing is bypassed: TLS 1.3, mTLS validation, authorization and connection capture all run.
/// </summary>
internal sealed class RealEkmHost : IAsyncDisposable
{
    private readonly TempFolder _folder;
    private readonly List<IDisposable> _disposables = [];

    private RealEkmHost(WebApplication app, TempFolder folder, TestPki pki, string certFile, string keyFile, CapturingLoggerProvider logs)
    {
        App = app;
        _folder = folder;
        Pki = pki;
        CertFile = certFile;
        KeyFile = keyFile;
        Logs = logs;
    }

    public WebApplication App { get; }

    public TestPki Pki { get; }

    public string CertFile { get; }

    public string KeyFile { get; }

    public string TlsFolder => Path.GetDirectoryName(CertFile)!;

    public CapturingLoggerProvider Logs { get; }

    public int Port { get; private set; }

    /// <summary>The console listener's port (M5); the EKM tests do not use it except to prove the port separation.</summary>
    public int ConsolePort { get; private set; }

    public int? PlainHttpPort { get; private set; }

    public Uri BaseAddress => new($"https://127.0.0.1:{Port}/");

    public ConnectionEventStore Events => App.Services.GetRequiredService<ConnectionEventStore>();

    public ConnectionEventSink EventSink => App.Services.GetRequiredService<ConnectionEventSink>();

    public EkmMetrics Metrics => App.Services.GetRequiredService<EkmMetrics>();

    public NamespaceStore Namespaces => App.Services.GetRequiredService<NamespaceStore>();

    public IKeyManager Keys => App.Services.GetRequiredService<IKeyManager>();

    public ICryptoBackend Backend => App.Services.GetRequiredService<ICryptoBackend>();

    public ServerCertificateProvider Certificates => App.Services.GetRequiredService<ServerCertificateProvider>();

    public ConnectionRegistry Connections => App.Services.GetRequiredService<ConnectionRegistry>();

    public static async Task<RealEkmHost> StartAsync(RealEkmHostOptions options)
    {
        var folder = new TempFolder("ekmmock-mtls");
        var certFile = string.Empty;
        var keyFile = string.Empty;
        if (!options.DevMode)
        {
            var server = options.ServerCertificate ?? options.Pki.IssueServer();
            (certFile, keyFile) = server.WriteFiles(Path.Combine(folder.Path, "tls"));
        }
        var logs = new CapturingLoggerProvider();
        var dataPath = Path.Combine(folder.Path, "data");

        var configuration = new Dictionary<string, string?>
        {
            ["Data:Path"] = dataPath,
            ["Endpoints:Ekm:Url"] = "https://127.0.0.1:0",
            ["Endpoints:Console:Url"] = "https://127.0.0.1:0",
            ["Tls:CertFile"] = options.DevMode ? null : certFile,
            ["Tls:KeyFile"] = options.DevMode ? null : keyFile,
            ["Tls:PollInterval"] = options.PollInterval.ToString("c"),
            ["Tls:Debounce"] = options.Debounce.ToString("c"),
            ["Tls:RetiredCertificateGrace"] = "00:00:10",
        };
        for (var i = 0; i < options.Namespaces.Length; i++)
        {
            var ns = options.Namespaces[i];
            configuration[$"SeedNamespaces:{i}:Name"] = ns.Name;
            configuration[$"SeedNamespaces:{i}:Prefix"] = ns.Prefix;
            for (var c = 0; c < ns.CommonNames.Length; c++)
            {
                configuration[$"SeedNamespaces:{i}:ClientTrust:SubjectCommonNames:{c}"] = ns.CommonNames[c];
            }

            for (var c = 0; c < ns.TrustedCas.Length; c++)
            {
                configuration[$"SeedNamespaces:{i}:ClientTrust:CaCertificatesDerBase64:{c}"] = ns.TrustedCas[c].DerBase64;
            }
        }

        foreach (var pair in options.Configuration)
        {
            configuration[pair.Key] = pair.Value;
        }

        var masterKey = new ExplicitMasterKeyProvider(EkmFactory.MasterKeyBytes("real-host"));
        var app = EkmServerServiceCollectionExtensions.BuildEkmMockApp(options.DevMode ? ["--dev"] : [], builder =>
        {
            builder.Configuration.AddInMemoryCollection(configuration);
            builder.Logging.ClearProviders();
            builder.Logging.AddProvider(logs);
            builder.Logging.SetMinimumLevel(Environment.GetEnvironmentVariable("EKMMOCK_TEST_DEBUG") == "1" ? LogLevel.Debug : LogLevel.Information);
            builder.Services.AddSingleton<IMasterKeyProvider>(masterKey);
            builder.Services.AddSingleton(new SoftwareCryptoBackendOptions
            {
                DataPath = dataPath,
                MasterKeyProvider = masterKey,
                CounterFlushInterval = TimeSpan.Zero,
                Info = new BackendInfo("EkmMock", "EkmMock Software HSM"),
            });
            if (options.AddPlainHttpListener)
            {
                builder.Services.Configure<KestrelServerOptions>(kestrel => kestrel.Listen(IPAddress.Loopback, 0));
            }

            options.ConfigureServices?.Invoke(builder.Services);
        });

        var host = new RealEkmHost(app, folder, options.Pki, certFile, keyFile, logs);
        try
        {
            await app.StartAsync();
        }
        catch
        {
            await host.DisposeAsync();
            throw;
        }

        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses
            .Select(static a => new Uri(a))
            .ToList();
        var listeners = app.Services.GetRequiredService<ListenerRegistry>();
        host.Port = listeners.PortsOf(ListenerRegistry.EkmName).Single();
        host.ConsolePort = listeners.PortsOf(ListenerRegistry.ConsoleName).Single();
        host.PlainHttpPort = addresses.SingleOrDefault(static a => a.Scheme == "http")?.Port;
        return host;
    }

    // ---- connection events ----

    /// <summary>The sequence number to pass to <see cref="NextEventAsync"/> so that only events published afterwards match.</summary>
    public long Mark() => EventSink.LastSequence;

    public Task<ConnectionEvent?> NextEventAsync(long after, ConnectionEventKind kind, Func<ConnectionEvent, bool>? filter = null, TimeSpan? timeout = null)
        => Events.WaitForAsync(e => e.Sequence > after && e.Kind == kind && (filter?.Invoke(e) ?? true), timeout ?? TimeSpan.FromSeconds(10));

    // ---- clients ----

    /// <summary>A real <see cref="HttpClient"/> over TLS 1.3 that trusts only the test server CA. Pass a certificate to present a client identity.</summary>
    public HttpClient CreateHttpClient(X509Certificate2? clientCertificate = null, bool singleConnection = false, SslProtocols protocols = SslProtocols.Tls13, Version? version = null, X509Certificate2Collection? clientChain = null)
    {
        var handler = new SocketsHttpHandler
        {
            SslOptions = CreateClientSslOptions(clientCertificate, protocols, clientChain),
            PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
            MaxConnectionsPerServer = singleConnection ? 1 : int.MaxValue,
        };
        var client = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = BaseAddress,
            Timeout = TimeSpan.FromSeconds(20),
            DefaultRequestVersion = version ?? HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };
        _disposables.Add(client);
        return client;
    }

    public EkmClient CreateEkmClient(X509Certificate2? clientCertificate = null, bool singleConnection = false, X509Certificate2Collection? clientChain = null)
        => new(CreateHttpClient(clientCertificate, singleConnection, clientChain: clientChain));

    public Uri ConsoleAddress => new($"https://127.0.0.1:{ConsolePort}/");

    /// <summary>
    /// A client of the console listener (no client certificate; the console shares the test server certificate, which this client verifies against the test server CA).
    /// Cookies are kept so that antiforgery tokens work; redirects are not followed.
    /// </summary>
    public HttpClient CreateConsoleClient(Action<HttpRequestHeaders>? defaultHeaders = null)
    {
        var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = "127.0.0.1",
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = ValidateServer,
            },
            UseCookies = true,
            CookieContainer = new System.Net.CookieContainer(),
            AllowAutoRedirect = false,
            PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
        };
        var client = new HttpClient(handler, disposeHandler: true) { BaseAddress = ConsoleAddress, Timeout = TimeSpan.FromSeconds(20) };
        defaultHeaders?.Invoke(client.DefaultRequestHeaders);
        _disposables.Add(client);
        return client;
    }

    /// <summary>Client TLS options that trust only <see cref="TestPki.ServerCa"/> (custom root trust, hostname checked, no OS trust).</summary>
    public SslClientAuthenticationOptions CreateClientSslOptions(X509Certificate2? clientCertificate = null, SslProtocols protocols = SslProtocols.Tls13, X509Certificate2Collection? clientChain = null)
    {
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = "127.0.0.1",
            EnabledSslProtocols = protocols,
            RemoteCertificateValidationCallback = ValidateServer,
        };
        if (clientCertificate is not null && clientChain is not null)
        {
            options.ClientCertificateContext = SslStreamCertificateContext.Create(clientCertificate, clientChain, offline: true);
        }
        else if (clientCertificate is not null)
        {
            options.ClientCertificates = [clientCertificate];
        }

        return options;
    }

    /// <summary>The server certificate validation of the test clients; also records the certificate the server actually presented.</summary>
    public bool ValidateServer(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 || (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
        {
            return false;
        }

        using var custom = new X509Chain();
        custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        custom.ChainPolicy.CustomTrustStore.Add(Pki.ServerCa.Certificate);
        custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        custom.ChainPolicy.DisableCertificateDownloads = true;

        // The intermediates the server sent (if it did not send them, the chain cannot be built: that is the point of the chain tests).
        if (chain is not null)
        {
            foreach (var extra in chain.ChainPolicy.ExtraStore)
            {
                custom.ChainPolicy.ExtraStore.Add(extra);
            }
        }

        using var leaf = new X509Certificate2(certificate);
        return custom.Build(leaf);
    }

    /// <summary>Opens a TCP connection and runs a TLS handshake by hand; the caller owns the stream. Throws what the TLS stack throws.</summary>
    public async Task<(SslStream Stream, TcpClient Tcp)> ConnectTlsAsync(SslClientAuthenticationOptions? options = null, X509Certificate2? clientCertificate = null)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, Port);
        var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await ssl.AuthenticateAsClientAsync(options ?? CreateClientSslOptions(clientCertificate), cts.Token);
        }
        catch
        {
            await ssl.DisposeAsync();
            tcp.Dispose();
            throw;
        }

        return (ssl, tcp);
    }

    /// <summary>The server certificate the listener serves right now, as a fresh TLS handshake sees it (SHA-256 thumbprint).</summary>
    public async Task<string> ServedThumbprintAsync()
    {
        string? thumbprint = null;
        var options = CreateClientSslOptions();
        options.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
        {
            thumbprint = new X509Certificate2(certificate!).GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
            return true;
        };
        var (stream, tcp) = await ConnectTlsAsync(options);
        stream.Dispose();
        tcp.Dispose();
        return thumbprint!;
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
            // Stop is best-effort in tests.
        }

        await App.DisposeAsync();
        _folder.Dispose();
    }
}

internal static class Wait
{
    /// <summary>Polls <paramref name="condition"/> until it is true or the timeout passes. Returns the final value.</summary>
    public static async Task<bool> UntilAsync(Func<bool> condition, TimeSpan? timeout = null, TimeSpan? interval = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(15));
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(interval ?? TimeSpan.FromMilliseconds(25));
        }

        return condition();
    }
}
