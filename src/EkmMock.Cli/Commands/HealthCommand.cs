using System.CommandLine;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Commands;

/// <summary>
/// <c>ekmmock health</c>: the container health probe (spec 11.1: "healthcheck hits /healthz on the console port"). The runtime image has no <c>curl</c>, so the image's <c>HEALTHCHECK</c> runs this
/// command. It asks the console's anonymous <c>/healthz</c> (or <c>/readyz</c> with <c>--ready</c>), exits 0 when the answer is 200 and the body says <c>alive</c> / <c>ready</c>, and 1 for everything else
/// (connection refused, TLS failure, timeout, any other status): Docker treats 1 as "unhealthy" and reserves 2. It prints one short line and never anything secret.
/// TLS trust is the same as for every console call (<see cref="TlsTrust"/>): <c>--console-ca</c> (only roots trusted, host name checked), <c>--console-pin</c> (one exact certificate) or
/// <c>--insecure-console-cert</c>, which is accepted for a loopback URL only. The image uses the last one: the probe talks to 127.0.0.1 inside its own container's network namespace, so nothing
/// can sit in the middle, and the answer carries no information beyond "alive" (see DECISIONS "M9: Health check").
/// </summary>
internal static class HealthCommand
{
    public static Command Create(CliEnvironment env, GlobalOptions global)
    {
        var console = new Option<string>("--console") { Description = $"Console base URL (https only). Default: ${ConsoleSettings.UrlVariable} or {ConsoleSettings.DefaultUrl}." };
        var ca = new Option<string>("--console-ca") { Description = "PEM file with the root CA(s) that issued the console's certificate (the only roots trusted; host name is checked)." };
        var pin = new Option<string>("--console-pin") { Description = "SHA-256 thumbprint (hex) of the console's certificate: trust exactly that certificate." };
        var insecure = new Option<bool>("--insecure-console-cert") { Description = "Do not verify the console's certificate. Only accepted for a loopback console URL (127.0.0.1, ::1, localhost)." };
        var ready = new Option<bool>("--ready") { Description = "Ask /readyz (key store loaded, self-test passed, EKM listener up) instead of /healthz (process alive)." };
        var timeout = new Option<string>("--timeout") { Description = "Give up after this long, for example 3s or 500ms. Default 3s.", DefaultValueFactory = _ => "3s" };

        var command = new Command("health", "Check that a running EkmMock console answers /healthz (the container health probe).\n\n" +
            "Examples:\n" +
            "  ekmmock health --insecure-console-cert                 inside the container (loopback, the image's HEALTHCHECK)\n" +
            "  ekmmock health --ready --console https://127.0.0.1:8080 --console-ca ./dev-pki/root-ca.pem\n\n" +
            "Prints one line. Exit code 0 healthy; 1 unhealthy (cannot connect, TLS failure, timeout or a bad answer); 2 usage error. Docker reads 0 as healthy and 1 as unhealthy.");
        command.Options.Add(console);
        command.Options.Add(ca);
        command.Options.Add(pin);
        command.Options.Add(insecure);
        command.Options.Add(ready);
        command.Options.Add(timeout);

        command.SetAction(async (result, cancellationToken) =>
        {
            var wait = TimeSpan.FromSeconds(3);
            var urlText = result.GetValue(console) ?? env.GetEnvironmentVariable(ConsoleSettings.UrlVariable) ?? ConsoleSettings.DefaultUrl;
            try
            {
                if (!Duration.TryParse(result.GetValue(timeout), out wait) || wait <= TimeSpan.Zero)
                {
                    throw CliException.Usage("--timeout must be a positive duration such as 3s or 500ms.");
                }

                if (!Uri.TryCreate(urlText, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
                {
                    throw CliException.Usage($"--console must be an absolute https URL (for example {ConsoleSettings.DefaultUrl}), not '{urlText}'. The console only speaks HTTPS.");
                }

                if (result.GetValue(insecure) && !ConsoleSettings.IsLoopbackHost(url))
                {
                    throw CliException.Usage("--insecure-console-cert is only allowed for a loopback console URL (127.0.0.1, ::1, localhost). Use --console-ca or --console-pin for any other host.");
                }

                var path = result.GetValue(ready) ? "/readyz" : "/healthz";
                var expected = result.GetValue(ready) ? "ready" : "alive";
                var verdict = await ProbeAsync(env, url, path, expected, wait, result.GetValue(ca), result.GetValue(pin), result.GetValue(insecure), cancellationToken).ConfigureAwait(false);
                if (verdict is null)
                {
                    env.Out.WriteLine($"healthy: {path} {expected}");
                    return ExitCodes.Success;
                }

                env.Error.WriteLine($"unhealthy: {path} {verdict}");
                return ExitCodes.Failure;
            }
            catch (CliException exception) when (exception.ExitCode == ExitCodes.Usage)
            {
                env.Error.WriteLine("error: " + exception.Message);
                return ExitCodes.Usage;
            }
            catch (CliException exception)
            {
                env.Error.WriteLine("unhealthy: " + exception.Message);
                return ExitCodes.Failure;
            }
        });
        return command;
    }

    /// <summary>Null when healthy, otherwise a short secret-free reason.</summary>
    private static async Task<string?> ProbeAsync(
        CliEnvironment env,
        Uri url,
        string path,
        string expected,
        TimeSpan timeout,
        string? caFile,
        string? pin,
        bool insecure,
        CancellationToken cancellationToken)
    {
        X509Certificate2Collection? roots = caFile is null ? null : TlsTrust.LoadRoots(env.ResolvePath(caFile), "--console-ca");
        try
        {
            HttpMessageHandler handler = env.ConsoleHandlerFactory is { } factory
                ? factory()
                : new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    UseCookies = false,
                    ConnectTimeout = timeout,
                    SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = TlsTrust.CreateCallback(roots, pin, insecure) },
                };
            using var http = new HttpClient(handler, disposeHandler: true) { Timeout = timeout, BaseAddress = new Uri(url.GetLeftPart(UriPartial.Authority) + "/") };
            http.DefaultRequestHeaders.UserAgent.ParseAdd(ConsoleApiClient.UserAgent);
            try
            {
                using var response = await http.GetAsync(path.TrimStart('/'), cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    return $"answered HTTP {(int)response.StatusCode}";
                }

                var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                return StatusOf(body) == expected ? null : "answered 200 but not with the expected status";
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return $"no answer within {Duration.Format(timeout)}";
            }
            catch (HttpRequestException exception)
            {
                return "cannot reach the console (" + (exception.InnerException?.GetType().Name ?? exception.HttpRequestError.ToString()) + ")";
            }
        }
        finally
        {
            if (roots is not null)
            {
                foreach (var root in roots)
                {
                    root.Dispose();
                }
            }
        }
    }

    private static string? StatusOf(string body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            return document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.String
                ? status.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
