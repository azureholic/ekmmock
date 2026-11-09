using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.ConsoleApi;

/// <summary>Where and how to reach the console API.</summary>
internal sealed record ConsoleSettings(
    Uri Url,
    string? CaFile,
    string? PinSha256,
    bool InsecureConsoleCert,
    ConsoleAuthMode Auth,
    EntraSettings? Entra,
    string? Token)
{
    public const string DefaultUrl = "https://127.0.0.1:8080";
    public const string UrlVariable = "EKMMOCK_CONSOLE";
    public const string TokenVariable = "EKMMOCK_CONSOLE_TOKEN";
    public const string TenantVariable = "EKMMOCK_TENANT_ID";
    public const string ClientIdVariable = "EKMMOCK_CLIENT_ID";
    public const string ScopeVariable = "EKMMOCK_CONSOLE_SCOPE";

    public bool IsLoopback => IsLoopbackHost(Url);

    public static bool IsLoopbackHost(Uri url)
    {
        if (string.Equals(url.Host, "localhost", StringComparison.OrdinalIgnoreCase) || url.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(url.Host.Trim('[', ']'), out var address) && IPAddress.IsLoopback(address);
    }
}

/// <summary>An error answer of the console API (<c>{"code":"...","message":"..."}</c>) with its HTTP status.</summary>
internal sealed class ConsoleApiException : Exception
{
    public ConsoleApiException(int status, string code, string message)
        : base(message)
    {
        Status = status;
        Code = code;
    }

    public int Status { get; }

    public string Code { get; }
}

/// <summary>
/// The CLI's client of <c>/api/console/*</c>. Every call carries <c>X-EkmMock-Client</c> (the CSRF proof of a non-browser client, M6) and never an <c>Origin</c> header; with a token it also
/// carries <c>Authorization: Bearer</c>. Redirects are not followed, so the token can never be sent to another host. Failures become <see cref="CliException"/> with exit code 3 (cannot connect,
/// not signed in, not allowed) or 1 (the server refused the action, message from the server).
/// </summary>
internal sealed class ConsoleApiClient : IDisposable
{
    public const string ClientHeader = "X-EkmMock-Client";

    private readonly HttpClient _http;
    private readonly ITokenSource? _tokens;
    private readonly bool _ownsHttp;

    public ConsoleApiClient(HttpClient http, ITokenSource? tokens, bool ownsHttp = false)
    {
        _http = http;
        _tokens = tokens;
        _ownsHttp = ownsHttp;
        Settings = null;
    }

    public ConsoleSettings? Settings { get; private init; }

    public Uri BaseAddress => _http.BaseAddress!;

    public static string UserAgent => "ekmmock-cli/" + CliVersion.Current;

    public static ConsoleApiClient Create(ConsoleSettings settings, CliEnvironment env, bool useCookies = false)
    {
        HttpMessageHandler handler;
        if (env.ConsoleHandlerFactory is { } factory)
        {
            handler = factory();
        }
        else
        {
            if (settings.InsecureConsoleCert && !settings.IsLoopback)
            {
                throw CliException.Usage("--insecure-console-cert is only allowed for a loopback console URL (127.0.0.1, ::1, localhost). Use --console-ca <root-ca.pem> or --console-pin <sha256> for any other host.");
            }

            X509Certificate2Collection? roots = settings.CaFile is null ? null : TlsTrust.LoadRoots(env.ResolvePath(settings.CaFile), "--console-ca");
            var sockets = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = useCookies,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                ConnectTimeout = TimeSpan.FromSeconds(10),
                SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = TlsTrust.CreateCallback(roots, settings.PinSha256, settings.InsecureConsoleCert) },
            };
            if (settings.InsecureConsoleCert)
            {
                env.Error.WriteLine("warning: --insecure-console-cert: the console certificate is not verified (loopback only).");
            }

            handler = sockets;
        }

        var http = new HttpClient(handler, disposeHandler: true) { BaseAddress = new Uri(settings.Url.GetLeftPart(UriPartial.Authority) + "/"), Timeout = TimeSpan.FromSeconds(120) };
        return new ConsoleApiClient(http, CreateTokenSource(settings, env), ownsHttp: true) { Settings = settings };
    }

    private static ITokenSource? CreateTokenSource(ConsoleSettings settings, CliEnvironment env)
    {
        if (settings.Token is { Length: > 0 } token)
        {
            return new StaticTokenSource(token);
        }

        if (settings.Entra is not { } entra || settings.Auth == ConsoleAuthMode.Loopback)
        {
            return null;
        }

        var prompt = (string message) => env.Error.WriteLine(message);
        var credential = (env.CredentialFactory ?? CredentialTokenSource.CreateDeviceCodeCredential)(entra, prompt);
        return new CredentialTokenSource(credential, entra.Scope, env.Time);
    }

    // ---- requests ----

    public async Task<T> GetAsync<T>(string path, JsonTypeInfo<T> type, CancellationToken cancellationToken)
    {
        var (_, body) = await SendAsync(HttpMethod.Get, path, null, cancellationToken).ConfigureAwait(false);
        return Deserialize(body, type);
    }

    public async Task<string> GetTextAsync(string path, CancellationToken cancellationToken)
    {
        var (_, body) = await SendAsync(HttpMethod.Get, path, null, cancellationToken).ConfigureAwait(false);
        return Encoding.UTF8.GetString(body);
    }

    public async Task<TResult> PostAsync<TBody, TResult>(string path, TBody? body, JsonTypeInfo<TBody> bodyType, JsonTypeInfo<TResult> resultType, CancellationToken cancellationToken)
        where TBody : class
    {
        var content = body is null ? null : JsonSerializer.SerializeToUtf8Bytes(body, bodyType);
        var (_, response) = await SendAsync(HttpMethod.Post, path, content ?? "{}"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        return Deserialize(response, resultType);
    }

    public async Task PostAsync(string path, CancellationToken cancellationToken)
        => await SendAsync(HttpMethod.Post, path, "{}"u8.ToArray(), cancellationToken).ConfigureAwait(false);

    public async Task DeleteAsync(string path, CancellationToken cancellationToken)
        => await SendAsync(HttpMethod.Delete, path, null, cancellationToken).ConfigureAwait(false);

    /// <summary>A raw call that never throws for an HTTP error status: the caller (a conformance check) decides what the status means.</summary>
    public async Task<(HttpStatusCode Status, byte[] Body)> TryAsync(HttpMethod method, string path, byte[]? json, CancellationToken cancellationToken, IReadOnlyDictionary<string, string>? headers = null)
    {
        using var request = await CreateRequestAsync(method, path, json, cancellationToken).ConfigureAwait(false);
        foreach (var header in headers ?? new Dictionary<string, string>())
        {
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        try
        {
            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            return (response.StatusCode, await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false));
        }
        catch (HttpRequestException exception)
        {
            throw Translate(exception);
        }
    }

    private async Task<(HttpStatusCode Status, byte[] Body)> SendAsync(HttpMethod method, string path, byte[]? json, CancellationToken cancellationToken)
    {
        var (status, body) = await TryAsync(method, path, json, cancellationToken).ConfigureAwait(false);
        if ((int)status is >= 200 and < 300)
        {
            return (status, body);
        }

        throw ToException(status, body);
    }

    private async Task<HttpRequestMessage> CreateRequestAsync(HttpMethod method, string path, byte[]? json, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(method, path.TrimStart('/'));
        request.Headers.Add(ClientHeader, UserAgent);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (_tokens is not null && await _tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false) is { } token)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        if (json is not null)
        {
            request.Content = new ByteArrayContent(json);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        }

        return request;
    }

    private static T Deserialize<T>(byte[] body, JsonTypeInfo<T> type)
    {
        try
        {
            return JsonSerializer.Deserialize(body, type) ?? throw CliException.Failure("The console answered with an empty body.");
        }
        catch (JsonException exception)
        {
            throw CliException.Failure("The console answered with something that is not the expected JSON. Is --console pointing at an EkmMock console?", exception);
        }
    }

    private Exception ToException(HttpStatusCode status, byte[] body)
    {
        ApiError? error = null;
        try
        {
            error = JsonSerializer.Deserialize(body, ConsoleApiJson.Default.ApiError);
        }
        catch (JsonException)
        {
            // Not an EkmMock error body (a proxy page, for example): fall through to the generic message.
        }

        var code = error?.Code ?? status.ToString();
        var message = error?.Message ?? $"HTTP {(int)status}";
        return (int)status switch
        {
            401 => CliException.Connection(_tokens is null
                ? "The console requires sign-in (401). For an EntraId console use --tenant and --client-id (device-code sign-in), or set EKMMOCK_CONSOLE_TOKEN to an access token."
                : "The console rejected the access token (401): it may be expired or for another app registration (--client-id / --scope)."),
            403 => CliException.Connection($"The console refused this caller (403): {message}"),
            _ => new ConsoleApiException((int)status, code, message),
        };
    }

    private CliException Translate(HttpRequestException exception)
    {
        var root = exception.GetBaseException().Message;
        var hint = exception.InnerException is System.Security.Authentication.AuthenticationException
            ? " The console's TLS certificate is not trusted: use --console-ca <root-ca.pem>, --console-pin <sha256 of the certificate>, or (loopback only) --insecure-console-cert."
            : string.Empty;
        return CliException.Connection($"Cannot reach the console at {BaseAddress}: {root}.{hint}", exception);
    }

    // ---- typed calls ----

    public Task<ConsoleStatus> StatusAsync(CancellationToken ct) => GetAsync("/api/console/status", ConsoleApiJson.Default.ConsoleStatus, ct);

    public Task<AboutInfo> AboutAsync(CancellationToken ct) => GetAsync("/api/console/about", ConsoleApiJson.Default.AboutInfo, ct);

    public async Task<List<KeyView>> ListKeysAsync(string? ns, CancellationToken ct)
        => (await GetAsync("/api/console/keys" + (string.IsNullOrEmpty(ns) ? string.Empty : "?namespace=" + Uri.EscapeDataString(ns)), ConsoleApiJson.Default.KeyList, ct).ConfigureAwait(false)).Keys;

    public Task<KeyDetail> GetKeyAsync(string ns, string name, CancellationToken ct)
        => GetAsync($"/api/console/keys/{Esc(ns)}/{Esc(name)}", ConsoleApiJson.Default.KeyDetail, ct);

    public Task<KeyView> CreateKeyAsync(CreateKeyBody body, CancellationToken ct)
        => PostAsync("/api/console/keys", body, ConsoleApiJson.Default.CreateKeyBody, ConsoleApiJson.Default.KeyView, ct);

    public Task<KeyView> ImportKeyAsync(ImportKeyBody body, CancellationToken ct)
        => PostAsync("/api/console/keys/import", body, ConsoleApiJson.Default.ImportKeyBody, ConsoleApiJson.Default.KeyView, ct);

    public Task<KeyView> SetEnabledAsync(string ns, string name, bool enabled, CancellationToken ct)
        => PostAsync<ExpiryBody, KeyView>($"/api/console/keys/{Esc(ns)}/{Esc(name)}/{(enabled ? "enable" : "disable")}", null, ConsoleApiJson.Default.ExpiryBody, ConsoleApiJson.Default.KeyView, ct);

    public Task<KeyView> SetExpiryAsync(string ns, string name, DateTimeOffset? notAfter, CancellationToken ct)
        => PostAsync($"/api/console/keys/{Esc(ns)}/{Esc(name)}/expiry", new ExpiryBody(notAfter), ConsoleApiJson.Default.ExpiryBody, ConsoleApiJson.Default.KeyView, ct);

    public Task<KeyView> DestroyKeyAsync(string ns, string name, string confirmName, CancellationToken ct)
        => PostAsync($"/api/console/keys/{Esc(ns)}/{Esc(name)}/destroy", new DestroyKeyBody(confirmName), ConsoleApiJson.Default.DestroyKeyBody, ConsoleApiJson.Default.KeyView, ct);

    public async Task<List<NamespaceView>> ListNamespacesAsync(CancellationToken ct)
        => (await GetAsync("/api/console/namespaces", ConsoleApiJson.Default.NamespaceList, ct).ConfigureAwait(false)).Namespaces;

    public Task<NamespaceView> GetNamespaceAsync(string name, CancellationToken ct)
        => GetAsync($"/api/console/namespaces/{Esc(name)}", ConsoleApiJson.Default.NamespaceView, ct);

    public Task<NamespaceView> CreateNamespaceAsync(NamespaceBody body, CancellationToken ct)
        => PostAsync("/api/console/namespaces", body, ConsoleApiJson.Default.NamespaceBody, ConsoleApiJson.Default.NamespaceView, ct);

    public Task<NamespaceDeleted> DeleteNamespaceAsync(string name, DeleteNamespaceBody body, CancellationToken ct)
        => PostAsync($"/api/console/namespaces/{Esc(name)}/delete", body, ConsoleApiJson.Default.DeleteNamespaceBody, ConsoleApiJson.Default.NamespaceDeleted, ct);

    public Task<TrustPreview> ImportTrustAsync(string ns, TrustImportBody body, CancellationToken ct)
        => PostAsync($"/api/console/namespaces/{Esc(ns)}/trust/import", body, ConsoleApiJson.Default.TrustImportBody, ConsoleApiJson.Default.TrustPreview, ct);

    /// <summary>Uploads a new EKM server certificate (chain and unencrypted key, PEM); the server reloads it without dropping connections.</summary>
    public async Task UploadCertificateAsync(UploadCertificateBody body, CancellationToken ct)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(body, ConsoleApiJson.Default.UploadCertificateBody);
        await SendAsync(HttpMethod.Post, "/api/console/certificates/upload", json, ct).ConfigureAwait(false);
    }

    public Task<FaultList> ListFaultsAsync(CancellationToken ct) => GetAsync("/api/console/faults", ConsoleApiJson.Default.FaultList, ct);

    public Task<FaultRuleView> ApplyFaultPresetAsync(string presetId, CancellationToken ct)
        => PostAsync<ExpiryBody, FaultRuleView>($"/api/console/faults/presets/{Esc(presetId)}", null, ConsoleApiJson.Default.ExpiryBody, ConsoleApiJson.Default.FaultRuleView, ct);

    public Task<FaultRuleView> CreateFaultAsync(FaultRuleBody body, CancellationToken ct)
        => PostAsync("/api/console/faults", body, ConsoleApiJson.Default.FaultRuleBody, ConsoleApiJson.Default.FaultRuleView, ct);

    public Task DeleteFaultAsync(string id, CancellationToken ct) => DeleteAsync($"/api/console/faults/{Esc(id)}", ct);

    public Task<FaultCleared> ClearFaultsAsync(CancellationToken ct)
        => PostAsync<ExpiryBody, FaultCleared>("/api/console/faults/clear", null, ConsoleApiJson.Default.ExpiryBody, ConsoleApiJson.Default.FaultCleared, ct);

    public Task<ExchangePage> ExchangesAsync(string query, CancellationToken ct)
        => GetAsync("/api/console/exchanges" + query, ConsoleApiJson.Default.ExchangePage, ct);

    public async Task<List<ConnectionEventView>> ConnectionsAsync(string query, CancellationToken ct)
        => (await GetAsync("/api/console/connections" + query, ConsoleApiJson.Default.ConnectionList, ct).ConfigureAwait(false)).Events;

    public Task<AuditPage> AuditAsync(string query, CancellationToken ct) => GetAsync("/api/console/audit" + query, ConsoleApiJson.Default.AuditPage, ct);

    private static string Esc(string value) => Uri.EscapeDataString(value);

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }
}
