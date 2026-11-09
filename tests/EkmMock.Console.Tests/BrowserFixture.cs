#pragma warning disable xUnit1051 // The browser tests use explicit Playwright and HttpClient timeouts.

using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using EkmMock.Pki;
using EkmMock.TestSupport;
using Microsoft.Playwright;

namespace EkmMock.Console.Tests;

/// <summary>
/// The real server process (<c>dotnet EkmMock.Server.dll --dev</c>, the way a user starts it) with a real Chromium in front of it. Playwright's browser is installed on first use
/// (<c>playwright install chromium</c>); if the browser or the server cannot be started here, every browser test is <b>skipped with the reason</b> and says so: no test passes without
/// having looked at a real page. The tests carry the trait <c>Category=Browser</c> and can be excluded with <c>--filter-not-trait "Category=Browser"</c>.
/// </summary>
public sealed class BrowserFixture : IAsyncLifetime
{
    public const string ClientCn = "mhsm-browser.managedhsmclient.test";

    private readonly TempFolder _folder = new("ekmmock-browser");
    private TestPki? _pki;
    private Process? _server;
    private IPlaywright? _playwright;
    private HttpClient? _ekm;
    private System.Security.Cryptography.X509Certificates.X509Certificate2? _clientCertificate;
    private readonly StringBuilder _serverOutput = new();

    /// <summary>Non-null when the browser tests cannot run in this environment: the reason, for the skip message.</summary>
    public string? Unavailable { get; private set; }

    public IBrowser? Browser { get; private set; }

    public int ConsolePort { get; private set; }

    public int EkmPort { get; private set; }

    public string ConsoleUrl => $"https://127.0.0.1:{ConsolePort}";

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

    /// <summary>Where the screenshots of the visual check go.</summary>
    public static string ScreenshotFolder { get; } = Path.Combine(Path.GetTempPath(), "ekmmock-m5-screens");

    public async ValueTask InitializeAsync()
    {
        try
        {
            Directory.CreateDirectory(ScreenshotFolder);
            await StartServerAsync();
            await StartBrowserAsync();
        }
        catch (Exception exception)
        {
            Unavailable = $"{exception.GetType().Name}: {exception.Message}";
        }
    }

    private async Task StartServerAsync()
    {
        _pki = new TestPki();
        string certFile, keyFile;
        using (var server = _pki.IssueServer())
        {
            (certFile, keyFile) = server.WriteFiles(Path.Combine(_folder.Path, "tls"));
        }
        ConsolePort = FreePort();
        EkmPort = FreePort();

        var dll = typeof(Program).Assembly.Location;
        var info = new ProcessStartInfo("dotnet", $"\"{dll}\" --dev")
        {
            WorkingDirectory = Path.GetDirectoryName(dll)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        // Development, like `dotnet run`: that is the environment that serves the static web assets (Blazor, Fluent UI, console.css) straight from the build output.
        info.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        info.Environment["Data__Path"] = Path.Combine(_folder.Path, "data");
        info.Environment["Endpoints__Ekm__Url"] = $"https://127.0.0.1:{EkmPort}";
        info.Environment["Endpoints__Console__Url"] = $"https://127.0.0.1:{ConsolePort}";
        info.Environment["Tls__CertFile"] = certFile;
        info.Environment["Tls__KeyFile"] = keyFile;
        info.Environment["Dev__SeedSampleKeys"] = "true";
        info.Environment["SeedNamespaces__0__Name"] = "_default";
        info.Environment["SeedNamespaces__0__Prefix"] = string.Empty;
        info.Environment["SeedNamespaces__0__ClientTrust__SubjectCommonNames__0"] = ClientCn;
        info.Environment["SeedNamespaces__0__ClientTrust__CaCertificatesDerBase64__0"] = _pki.ClientCaA.DerBase64;
        info.Environment["Logging__LogLevel__Default"] = "Warning";

        _server = Process.Start(info) ?? throw new InvalidOperationException("The server process did not start.");
        _server.OutputDataReceived += (_, e) => Append(e.Data);
        _server.ErrorDataReceived += (_, e) => Append(e.Data);
        _server.BeginOutputReadLine();
        _server.BeginErrorReadLine();

        using var probe = new HttpClient(new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = static (_, _, _, _) => true } }) { Timeout = TimeSpan.FromSeconds(3) };
        var deadline = DateTime.UtcNow.AddSeconds(60);
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
                    break;
                }
            }
            catch (HttpRequestException)
            {
                // Not up yet.
            }
            catch (TaskCanceledException)
            {
            }

            await Task.Delay(250);
        }

        if (DateTime.UtcNow >= deadline)
        {
            throw new TimeoutException("The server did not become ready: " + ServerOutput);
        }

        // The mTLS client for the EKM endpoint (trusts only the test server CA).
        _clientCertificate = _pki.ClientCaA.IssueClient(ClientCn).Certificate;
        var handler = new SocketsHttpHandler
        {
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                TargetHost = "127.0.0.1",
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13,
                ClientCertificates = [_clientCertificate],
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                {
                    if (certificate is null || (errors & System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                    {
                        return false;
                    }

                    using var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
                    chain.ChainPolicy.TrustMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(_pki.ServerCa.Certificate);
                    chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                    using var leaf = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate);
                    return chain.Build(leaf);
                },
            },
        };
        _ekm = new HttpClient(handler) { BaseAddress = new Uri($"https://127.0.0.1:{EkmPort}/"), Timeout = TimeSpan.FromSeconds(20) };
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

    private async Task StartBrowserAsync()
    {
        // Installs the browser Playwright 1.64 expects when it is missing (a no-op when it is already there). The download happens once per machine.
        var exit = await Task.Run(() => Microsoft.Playwright.Program.Main(["install", "chromium"]));
        if (exit != 0)
        {
            throw new InvalidOperationException($"'playwright install chromium' exited with code {exit}.");
        }

        _playwright = await Playwright.CreateAsync();
        Browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
    }

    /// <summary>Sends one wrap request (a real mutual-TLS request) for a random DEK through the EKM endpoint; returns the status and the DEK (so tests can prove it never reaches the page).</summary>
    public async Task<(HttpStatusCode Status, byte[] Dek)> SendWrapAsync(string correlationId = "browser-correlation-id-0001", string key = "aes-key-1")
    {
        var dek = SecretScanner.RandomDek();
        var body = $$"""{"request_context":{"request_id":"b-r","correlation_id":"{{correlationId}}","pool_name":"browser-pool"},"alg":"A256KWP","value":"{{SecretScanner.Base64Url(dek)}}"}""";
        using var content = new StringContent(body);
        content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        using var response = await _ekm!.PostAsync($"/{key}/wrapkey?api-version=0.1-preview", content);
        return (response.StatusCode, dek);
    }

    public async Task<HttpStatusCode> SendInfoAsync()
    {
        using var content = new StringContent("""{"request_context":{"request_id":"b-i","correlation_id":"browser-info","pool_name":"browser-pool"}}""");
        content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        using var response = await _ekm!.PostAsync("/info?api-version=0.1-preview", content);
        return response.StatusCode;
    }

    public async Task<HttpStatusCode> SendNotFoundAsync()
    {
        using var content = new StringContent("""{"request_context":{"request_id":"b-n","correlation_id":"browser-404","pool_name":"browser-pool"}}""");
        content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        using var response = await _ekm!.PostAsync("/no-such-key/metadata?api-version=0.1-preview", content);
        return response.StatusCode;
    }

    public async ValueTask DisposeAsync()
    {
        if (Browser is not null)
        {
            await Browser.CloseAsync();
        }

        _playwright?.Dispose();
        _ekm?.Dispose();
        if (_server is { HasExited: false })
        {
            _server.Kill(entireProcessTree: true);
        }

        _server?.Dispose();
        _clientCertificate?.Dispose();
        _pki?.Dispose();
        _folder.Dispose();
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
