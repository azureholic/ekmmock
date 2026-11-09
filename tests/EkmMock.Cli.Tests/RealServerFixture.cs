using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Ekm;
using EkmMock.Cli.Infrastructure;
using EkmMock.TestSupport;

namespace EkmMock.Cli.Tests;

/// <summary>
/// The real server (<c>dotnet EkmMock.Server.dll</c>, as a user starts it) prepared <b>with the CLI itself</b>: <c>certs dev</c> makes the PKI, <c>init</c> the data folder and master key, the server
/// runs with key import and fault injection switched on (so the full conformance run has as few skips as possible), then <c>trust import</c> and <c>key create</c> make the sample keys.
/// This is the spec 11.2 "make dev" flow, end to end, on ephemeral ports.
/// </summary>
public sealed class RealServerFixture : IAsyncLifetime
{
    public const string ClientCn = "test.managedhsmclient.local";

    private readonly TempFolder _folder = new("ekmmock-cli-it");
    private readonly StringBuilder _serverOutput = new();
    private Process? _server;

    public string Pki => _folder.File("pki");

    public string Data => _folder.File("data");

    public int EkmPort { get; private set; }

    public int ConsolePort { get; private set; }

    public string ConsoleUrl => $"https://127.0.0.1:{ConsolePort}";

    public string EkmUrl => $"https://127.0.0.1:{EkmPort}";

    public string RootCa => Path.Combine(Pki, "root-ca.pem");

    public string ServerOutput
    {
        get
        {
            lock (_serverOutput)
            {
                return _serverOutput.ToString();
            }
        }
    }

    /// <summary>The console options every command needs: the console URL and the CA that issued its certificate (the dev PKI's root, so nothing is bypassed).</summary>
    public string[] ConsoleArgs => ["--console", ConsoleUrl, "--console-ca", RootCa];

    /// <summary>The options of the EKM endpoint for <c>test conformance</c> and <c>test bench</c>.</summary>
    public string[] EndpointArgs(string client = "client") =>
    [
        "--url", EkmUrl,
        "--server-name", "localhost",
        "--client-cert", Path.Combine(Pki, client + ".crt"),
        "--client-key", Path.Combine(Pki, client + ".key"),
        "--ca", RootCa,
    ];

    public string[] FullConformanceArgs(string reportFile) =>
    [
        .. EndpointArgs(),
        "--alt-client-cert", Path.Combine(Pki, "client-wrong-cn.crt"),
        "--alt-client-key", Path.Combine(Pki, "client-wrong-cn.key"),
        "--rogue-client-cert", Path.Combine(Pki, "client-untrusted-ca.crt"),
        "--rogue-client-key", Path.Combine(Pki, "client-untrusted-ca.key"),
        "--replacement-server-cert", Path.Combine(Pki, "server-replacement.crt"),
        "--replacement-server-key", Path.Combine(Pki, "server-replacement.key"),
        .. ConsoleArgs,
        "--allow-disruptive",
        "--report", reportFile,
    ];

    public async ValueTask InitializeAsync()
    {
        await using (var setup = new CliSession(_folder.Path))
        {
            (await setup.RunAsync("certs", "dev", "--out", Pki, "--fqdn", "localhost")).ExitCode.ShouldBe(0);
            (await setup.RunAsync("init", "--data", Data)).ExitCode.ShouldBe(0);
        }

        // The server writes an uploaded certificate over its configured files: give it its own copies, so the PKI folder stays what the CLI wrote.
        Directory.CreateDirectory(Path.Combine(Data, "tls"));
        File.Copy(Path.Combine(Pki, "server.crt"), Path.Combine(Data, "tls", "live.crt"));
        File.Copy(Path.Combine(Pki, "server.key"), Path.Combine(Data, "tls", "live.key"));

        EkmPort = FreePort();
        ConsolePort = FreePort();
        await StartServerAsync();

        var cli = new CliSession(_folder.Path);
        (await cli.RunAsync(["trust", "import", "--ns", "_default", "--json", Path.Combine(Pki, "mhsm-client.json"), .. ConsoleArgs])).ExitCode.ShouldBe(0);
        (await cli.RunAsync(["key", "create", "--ns", "_default", "--name", "aes-key-1", "--type", "aes", .. ConsoleArgs])).ExitCode.ShouldBe(0);
        (await cli.RunAsync(["key", "create", "--ns", "_default", "--name", "rsa-key-1", "--type", "rsa", "--size", "2048", .. ConsoleArgs])).ExitCode.ShouldBe(0);
    }

    internal Task<CliRun> RunAsync(params string[] args) => new CliSession(_folder.Path).RunAsync(args);

    /// <summary>Runs a command with the console options appended.</summary>
    internal Task<CliRun> RunOnConsoleAsync(params string[] args) => RunAsync([.. args, .. ConsoleArgs]);

    public async Task StartServerAsync()
    {
        var dll = ServerDll();
        var info = new ProcessStartInfo("dotnet", $"\"{dll}\"")
        {
            WorkingDirectory = Path.GetDirectoryName(dll)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        // Production-like (no --dev): the master key comes from the file `ekmmock init` wrote. Key import and fault injection are the test switches of spec 6.2 and 10.2.
        info.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        info.Environment["Data__Path"] = Data;
        info.Environment["EKMMOCK_MASTER_KEY_FILE"] = Path.Combine(Data, "master.key");
        info.Environment["Endpoints__Ekm__Url"] = $"https://127.0.0.1:{EkmPort}";
        info.Environment["Endpoints__Console__Url"] = $"https://127.0.0.1:{ConsolePort}";
        info.Environment["Tls__CertFile"] = Path.Combine(Data, "tls", "live.crt");
        info.Environment["Tls__KeyFile"] = Path.Combine(Data, "tls", "live.key");
        info.Environment["EKMMOCK_ALLOW_KEY_IMPORT"] = "true";
        info.Environment["EKMMOCK_ENABLE_FAULTS"] = "true";
        info.Environment["Logging__LogLevel__Default"] = "Warning";
        info.Environment.Remove("EKMMOCK_MASTER_KEY");
        info.Environment.Remove("EKMMOCK_INSPECTOR_ALLOW_REVEAL");

        _server = Process.Start(info) ?? throw new InvalidOperationException("The server process did not start.");
        _server.OutputDataReceived += (_, e) => Append(e.Data);
        _server.ErrorDataReceived += (_, e) => Append(e.Data);
        _server.BeginOutputReadLine();
        _server.BeginErrorReadLine();

        using var probe = new HttpClient(new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = static (_, _, _, _) => true } }) { Timeout = TimeSpan.FromSeconds(3) };
        var deadline = DateTime.UtcNow.AddSeconds(90);
        while (DateTime.UtcNow < deadline)
        {
            if (_server.HasExited)
            {
                throw new InvalidOperationException("The server exited during start-up: " + ServerOutput);
            }

            try
            {
                using var response = await probe.GetAsync($"{ConsoleUrl}/readyz");
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // not up yet
            }
            catch (TaskCanceledException)
            {
            }

            await Task.Delay(200);
        }

        throw new TimeoutException("The server did not become ready: " + ServerOutput);
    }

    public async Task StopServerAsync()
    {
        if (_server is { HasExited: false })
        {
            _server.Kill(entireProcessTree: true);
            await _server.WaitForExitAsync();
        }

        _server?.Dispose();
        _server = null;
    }

    public async Task RestartServerAsync()
    {
        await StopServerAsync();
        await StartServerAsync();
    }

    /// <summary>An EKM client of the real endpoint with the dev client certificate (the same code the CLI uses).</summary>
    internal (EkmClient Client, IDisposable Owner) CreateEkmClient(string client = "client")
    {
        var identity = ClientIdentity.Load(Path.Combine(Pki, client + ".crt"), Path.Combine(Pki, client + ".key"));
        var roots = new X509Certificate2Collection();
        roots.ImportFromPemFile(RootCa);
        var ekm = EkmClient.Create(EkmTarget.Parse(EkmUrl, "localhost"), identity, roots, "it");
        return (ekm, new Disposables(ekm, identity));
    }

    internal ConsoleApiClient CreateConsoleClient()
    {
        var settings = new ConsoleSettings(new Uri(ConsoleUrl), RootCa, null, false, ConsoleAuthMode.Auto, null, null);
        return ConsoleApiClient.Create(settings, new CliEnvironment { Out = TextWriter.Null, Error = TextWriter.Null });
    }

    /// <summary>The SHA-256 thumbprint of the certificate the console serves (the EKM endpoint serves the same one), for pinning tests.</summary>
    public string ServerCertificateThumbprint()
    {
        using var certificate = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(Data, "tls", "live.crt")));
        return certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
    }

    public async ValueTask DisposeAsync()
    {
        await StopServerAsync();
        RemoveCachedCertificates();
        _folder.Dispose();
    }

    private void Append(string? line)
    {
        if (line is not null)
        {
            lock (_serverOutput)
            {
                _serverOutput.AppendLine(line);
            }
        }
    }

    // Best effort, like TestPki: the Windows TLS stack caches the CA certificates it sees in the user's CA store; remove the ones of this run's PKI.
    private void RemoveCachedCertificates()
    {
        if (!OperatingSystem.IsWindows() || !Directory.Exists(Pki))
        {
            return;
        }

        try
        {
            var names = new List<string>();
            foreach (var file in new[] { "root-ca.pem", "mhsm-client-ca.pem" })
            {
                var path = Path.Combine(Pki, file);
                if (File.Exists(path))
                {
                    using var certificate = X509Certificate2.CreateFromPem(File.ReadAllText(path));
                    names.Add(certificate.Subject);
                }
            }

            using var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            foreach (var certificate in store.Certificates)
            {
                if (names.Contains(certificate.Subject) || names.Contains(certificate.Issuer))
                {
                    store.Remove(certificate);
                }

                certificate.Dispose();
            }
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or UnauthorizedAccessException or IOException)
        {
            // Not worth failing a test run over.
        }
    }

    private static string ServerDll()
    {
        var baseDirectory = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var framework = baseDirectory.Name; // net10.0
        var configuration = baseDirectory.Parent!.Name; // Debug or Release
        var root = baseDirectory;
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "EkmMock.sln")))
        {
            root = root.Parent;
        }

        var dll = Path.Combine(root?.FullName ?? throw new InvalidOperationException("EkmMock.sln was not found above the test output."), "src", "EkmMock.Server", "bin", configuration, framework, "EkmMock.Server.dll");
        return File.Exists(dll) ? dll : throw new FileNotFoundException("The server build output was not found; build the solution first.", dll);
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private sealed class Disposables : IDisposable
    {
        private readonly IDisposable[] _items;

        public Disposables(params IDisposable[] items)
        {
            _items = items;
        }

        public void Dispose()
        {
            foreach (var item in _items)
            {
                item.Dispose();
            }
        }
    }
}

/// <summary>A CLI runner bound to a working directory (no environment variables set, so a stray <c>EKMMOCK_CONSOLE</c> of the developer's shell cannot change a test).</summary>
internal sealed class CliSession : IAsyncDisposable
{
    private readonly string _directory;

    public CliSession(string directory)
    {
        _directory = directory;
    }

    public async Task<CliRun> RunAsync(params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var env = new CliEnvironment { Out = output, Error = error, GetEnvironmentVariable = static _ => null, WorkingDirectory = _directory };
        var code = await CliApp.RunAsync(args, env);
        return new CliRun(code, output.ToString(), error.ToString());
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

[CollectionDefinition("real server")]
public sealed class RealServerCollection : ICollectionFixture<RealServerFixture>
{
}
