using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Ekm;

/// <summary>Where the EKM endpoint is: <c>https://host[:port][/prefix]</c>.</summary>
internal sealed record EkmTarget(Uri Origin, string Prefix, string ServerName)
{
    public const string ApiVersion = "0.1-preview";

    public string DisplayUrl => Origin.GetLeftPart(UriPartial.Authority) + (Prefix.Length == 0 ? string.Empty : "/" + Prefix);

    /// <summary>Parses <c>--url</c>. The path is the namespace's path prefix (<c>[A-Za-z0-9/-]</c>, validated like the server does).</summary>
    public static EkmTarget Parse(string url, string? serverName)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw CliException.Usage($"--url must be an absolute https URL such as https://ekm.contoso.test[/prefix], not '{url}'. EkmMock only speaks TLS 1.3.");
        }

        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw CliException.Usage("--url must not carry a query or fragment.");
        }

        if (!EkmMock.Crypto.EkmNames.TryNormalizePrefix(Uri.UnescapeDataString(uri.AbsolutePath), out var prefix, out var problem))
        {
            throw CliException.Usage($"The path of --url is the path prefix and is invalid: {problem}.");
        }

        return new EkmTarget(new Uri(uri.GetLeftPart(UriPartial.Authority)), prefix, string.IsNullOrWhiteSpace(serverName) ? uri.Host : serverName.Trim());
    }
}

/// <summary>The answer of the EKM endpoint to one request, with the client-side time it took.</summary>
internal sealed class EkmReply
{
    public EkmReply(int status, string? contentType, byte[] body, TimeSpan elapsed, string correlationId)
    {
        Status = status;
        ContentType = contentType;
        Body = body;
        Elapsed = elapsed;
        CorrelationId = correlationId;
    }

    public int Status { get; }

    public string? ContentType { get; }

    public byte[] Body { get; }

    public TimeSpan Elapsed { get; }

    public string CorrelationId { get; }

    public string Text => Encoding.UTF8.GetString(Body);

    public JsonDocument? TryJson()
    {
        try
        {
            return JsonDocument.Parse(Body);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The <c>code</c> of a ProxyError body, or null.</summary>
    public string? ErrorCode
    {
        get
        {
            using var json = TryJson();
            return json is { RootElement.ValueKind: JsonValueKind.Object } && json.RootElement.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String ? code.GetString() : null;
        }
    }

    /// <summary>A string property of the JSON body, or null.</summary>
    public string? GetString(string property)
    {
        using var json = TryJson();
        return json is { RootElement.ValueKind: JsonValueKind.Object } && json.RootElement.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }
}

/// <summary>
/// The CLI acting as a fake Managed HSM: a plain HTTPS client over TLS 1.3 with a client certificate, trusting only the roots given with <c>--ca</c> (see <see cref="TlsTrust"/>). Requests carry a fresh
/// <c>request_context</c> (a <c>correlation_id</c> the suite can look up in the console's inspector). HTTP/1.1 with keep-alive; the connection is reused between calls like Managed HSM does.
/// </summary>
internal sealed class EkmClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _runId;
    private long _sequence;

    public EkmClient(HttpClient http, EkmTarget target, string runId)
    {
        _http = http;
        Target = target;
        _runId = runId;
    }

    public EkmTarget Target { get; }

    /// <summary>
    /// Creates a client. <paramref name="protocols"/> defaults to TLS 1.3 only (what the EKM endpoint requires); the conformance suite passes TLS 1.2 to prove that it is refused.
    /// <paramref name="identity"/> may be null (no client certificate). <paramref name="roots"/> null means the OS trust store.
    /// </summary>
    public static EkmClient Create(EkmTarget target, ClientIdentity? identity, X509Certificate2Collection? roots, string runId, SslProtocols protocols = SslProtocols.Tls13, int maxConnections = 4, TimeSpan? timeout = null)
    {
        var ssl = new SslClientAuthenticationOptions
        {
            TargetHost = target.ServerName,
            EnabledSslProtocols = protocols,
            RemoteCertificateValidationCallback = TlsTrust.CreateCallback(roots, pinSha256: null, insecureLoopback: false),
        };
        identity?.ApplyTo(ssl);
        var handler = new SocketsHttpHandler
        {
            SslOptions = ssl,
            MaxConnectionsPerServer = maxConnections,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            ConnectTimeout = TimeSpan.FromSeconds(10),
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
        };
        var http = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = target.Origin,
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };
        return new EkmClient(http, target, runId);
    }

    public string NewCorrelationId() => $"conf-{_runId}-{Interlocked.Increment(ref _sequence):D4}";

    public string Path(string? key, string operation, string? query = "api-version=" + EkmTarget.ApiVersion, string? prefixOverride = null)
    {
        var prefix = prefixOverride ?? Target.Prefix;
        var path = new StringBuilder("/");
        if (prefix.Length > 0)
        {
            path.Append(prefix).Append('/');
        }

        if (key is not null)
        {
            path.Append(key).Append('/');
        }

        path.Append(operation);
        if (!string.IsNullOrEmpty(query))
        {
            path.Append('?').Append(query);
        }

        return path.ToString();
    }

    public string BodyJson(string correlationId, string? alg = null, string? valueText = null)
    {
        var body = new StringBuilder();
        body.Append("{\"request_context\":{\"request_id\":\"").Append(Guid.NewGuid().ToString("D")).Append("\",\"correlation_id\":\"").Append(correlationId).Append("\",\"pool_name\":\"ekmmock-conformance\"}");
        if (alg is not null)
        {
            body.Append(",\"alg\":\"").Append(JsonEncodedText.Encode(alg)).Append('"');
        }

        if (valueText is not null)
        {
            body.Append(",\"value\":\"").Append(JsonEncodedText.Encode(valueText)).Append('"');
        }

        return body.Append('}').ToString();
    }

    public async Task<EkmReply> SendAsync(HttpMethod method, string pathAndQuery, string? json, string? contentType = "application/json", string? correlationId = null, CancellationToken cancellationToken = default)
    {
        correlationId ??= NewCorrelationId();
        using var request = new HttpRequestMessage(method, pathAndQuery);
        if (!string.Equals(Target.ServerName, Target.Origin.Host, StringComparison.OrdinalIgnoreCase))
        {
            // SocketsHttpHandler takes the SNI name and the name the server certificate is checked against from the request's Host header and ignores SslClientAuthenticationOptions.TargetHost,
            // so --server-name has to travel as the Host header.
            request.Headers.Host = Target.ServerName;
        }

        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8);
            request.Content.Headers.ContentType = contentType is null ? null : System.Net.Http.Headers.MediaTypeHeaderValue.Parse(contentType);
        }

        var started = Stopwatch.GetTimestamp();
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        return new EkmReply((int)response.StatusCode, response.Content.Headers.ContentType?.ToString(), body, Stopwatch.GetElapsedTime(started), correlationId);
    }

    public Task<EkmReply> PostAsync(string pathAndQuery, string? alg = null, string? valueText = null, CancellationToken cancellationToken = default)
    {
        var correlation = NewCorrelationId();
        return SendAsync(HttpMethod.Post, pathAndQuery, BodyJson(correlation, alg, valueText), correlationId: correlation, cancellationToken: cancellationToken);
    }

    public Task<EkmReply> InfoAsync(CancellationToken ct = default) => PostAsync(Path(null, "info"), cancellationToken: ct);

    public Task<EkmReply> MetadataAsync(string key, CancellationToken ct = default) => PostAsync(Path(key, "metadata"), cancellationToken: ct);

    public Task<EkmReply> WrapAsync(string key, string alg, ReadOnlySpan<byte> dek, CancellationToken ct = default)
        => PostAsync(Path(key, "wrapkey"), alg, Base64Url(dek), ct);

    public Task<EkmReply> UnwrapAsync(string key, string alg, ReadOnlySpan<byte> wrapped, CancellationToken ct = default)
        => PostAsync(Path(key, "unwrapkey"), alg, Base64Url(wrapped), ct);

    public Task<EkmReply> WrapTextAsync(string key, string alg, string valueText, CancellationToken ct = default) => PostAsync(Path(key, "wrapkey"), alg, valueText, ct);

    public Task<EkmReply> UnwrapTextAsync(string key, string alg, string valueText, CancellationToken ct = default) => PostAsync(Path(key, "unwrapkey"), alg, valueText, ct);

    public static string Base64Url(ReadOnlySpan<byte> bytes) => System.Buffers.Text.Base64Url.EncodeToString(bytes);

    public static byte[] FromBase64Url(string text) => System.Buffers.Text.Base64Url.DecodeFromChars(text);

    public void Dispose() => _http.Dispose();
}
