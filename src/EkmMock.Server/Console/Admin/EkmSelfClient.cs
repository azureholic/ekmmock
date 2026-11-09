using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Server.Hosting;
using EkmMock.Server.Tls;

namespace EkmMock.Server.WebConsole;

/// <summary>What the EKM endpoint answered to a console self-call. <see cref="Body"/> may hold a plaintext DEK (an unwrap answer): the caller zeroes it.</summary>
internal sealed record SelfResponse(int Status, byte[] Body, string? ContentType, double ElapsedMs);

/// <summary>
/// The server-certificate check of the console's loopback self-call: the presented certificate must be <em>exactly</em> the one the certificate provider serves
/// (compared by SHA-256 thumbprint of the whole certificate). Chain, name and trust results are ignored on purpose, because the throw-away or generated certificate
/// is not trusted by the OS and its name need not match <c>127.0.0.1</c>. This is a pin, not a blanket bypass: any other certificate (an impostor listening on the
/// port, a stale one) is refused.
/// </summary>
internal static class PinnedServerCertificate
{
    public static bool Matches(X509Certificate? presented, string? expectedThumbprintSha256)
    {
        if (presented is null || string.IsNullOrEmpty(expectedThumbprintSha256))
        {
            return false;
        }

        using var certificate = X509CertificateLoader.LoadCertificate(presented.GetRawCertData());
        var actual = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        return string.Equals(actual, expectedThumbprintSha256, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// The console's HTTPS client for the EKM endpoint (Playground "via EKM endpoint" and Replay). Design (DECISIONS "M6: Playground self-call"):
/// <list type="bullet">
/// <item>It makes a real TLS 1.3 mutual-TLS request to the real listener (<c>https://127.0.0.1:&lt;ekm port&gt;</c>), so the exchange runs through the whole pipeline and is captured like any other.</item>
/// <item>The client certificate is the console test certificate (<see cref="ConsoleTestIdentity"/>); a namespace must trust its CA.</item>
/// <item>The server certificate is <b>pinned</b> to the one the provider serves (<see cref="PinnedServerCertificate"/>); nothing else is accepted.</item>
/// <item>The client can only talk to the EKM listener's own loopback address and port: anything else is refused before a socket is opened.</item>
/// </list>
/// </summary>
internal sealed class EkmSelfClient : IDisposable
{
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(15);

    private readonly ConsoleTestIdentity _identity;
    private readonly Func<string?> _pinnedThumbprint;
    private readonly Func<IReadOnlyList<IPEndPoint>> _endpoints;
    private readonly Lazy<HttpClient> _http;

    public EkmSelfClient(ConsoleTestIdentity identity, Func<string?> pinnedThumbprint, Func<IReadOnlyList<IPEndPoint>> endpoints)
    {
        _identity = identity;
        _pinnedThumbprint = pinnedThumbprint;
        _endpoints = endpoints;
        _http = new Lazy<HttpClient>(CreateClient, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public static EkmSelfClient For(ConsoleTestIdentity identity, IServerCertificateProvider certificates, ListenerRegistry listeners)
        => new(identity, () => certificates.Current.Thumbprint, () => listeners.EndpointsOf(ListenerRegistry.EkmName));

    /// <summary>The origin of the EKM listener on loopback, or null while it is not bound.</summary>
    public Uri? Origin
    {
        get
        {
            var endpoint = _endpoints().FirstOrDefault();
            if (endpoint is null)
            {
                return null;
            }

            var address = endpoint.Address;
            var host = address.Equals(IPAddress.Any) ? "127.0.0.1"
                : address.Equals(IPAddress.IPv6Any) ? "127.0.0.1"
                : address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{address}]"
                : address.ToString();
            return new Uri($"https://{host}:{endpoint.Port}/");
        }
    }

    /// <summary>Sends one request to the EKM endpoint. <paramref name="pathAndQuery"/> must be an absolute path (<c>/prefix/key/wrapkey?api-version=...</c>).</summary>
    public async Task<SelfResponse> SendAsync(string method, string pathAndQuery, string? contentType, ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default)
    {
        var origin = Origin ?? throw new ConsoleActionException(ConsoleErrorCode.Unavailable, "The EKM endpoint is not listening yet.");
        if (string.IsNullOrEmpty(pathAndQuery) || pathAndQuery[0] != '/' || pathAndQuery.StartsWith("//", StringComparison.Ordinal) || pathAndQuery.Contains('\\', StringComparison.Ordinal))
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The request target must be an absolute path on the EKM endpoint.");
        }

        var uri = new Uri(origin, pathAndQuery);
        using var request = new HttpRequestMessage(new HttpMethod(method), uri) { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
        if (!body.IsEmpty)
        {
            request.Content = new ReadOnlyMemoryContent(body);
            request.Content.Headers.ContentType = contentType is not null && MediaTypeHeaderValue.TryParse(contentType, out var parsed) ? parsed : new MediaTypeHeaderValue("application/json");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        try
        {
            using var response = await _http.Value.SendAsync(request, HttpCompletionOption.ResponseContentRead, timeout.Token).ConfigureAwait(false);
            var bytes = await response.Content.ReadAsByteArrayAsync(timeout.Token).ConfigureAwait(false);
            return new SelfResponse((int)response.StatusCode, bytes, response.Content.Headers.ContentType?.MediaType, System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds);
        }
        catch (Exception exception) when (exception is HttpRequestException or AuthenticationException or TaskCanceledException or IOException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            // The reason (TLS error text) can name certificates; the console says what to check instead.
            throw new ConsoleActionException(
                ConsoleErrorCode.Unavailable,
                "The console could not complete a TLS 1.3 request to the EKM endpoint. Check that the endpoint is up, that it still serves the certificate the console expects, and that a namespace trusts the console test CA.");
        }
    }

    public void Dispose()
    {
        if (_http.IsValueCreated)
        {
            _http.Value.Dispose();
        }
    }

    private HttpClient CreateClient()
    {
        var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls13,
                ClientCertificates = [_identity.ClientCertificate],
                RemoteCertificateValidationCallback = (_, certificate, _, _) => PinnedServerCertificate.Matches(certificate, _pinnedThumbprint()),
            },
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
        };

        // Defence in depth: whatever builds the request, it can only ever reach the EKM listener's own loopback origin.
        var guard = new OriginGuardHandler(() => Origin, handler);
        return new HttpClient(guard, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    private sealed class OriginGuardHandler : DelegatingHandler
    {
        private readonly Func<Uri?> _origin;

        public OriginGuardHandler(Func<Uri?> origin, HttpMessageHandler inner)
            : base(inner)
        {
            _origin = origin;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var origin = _origin();
            if (origin is null || request.RequestUri is null
                || !string.Equals(request.RequestUri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
                || !string.Equals(request.RequestUri.Host, origin.Host, StringComparison.OrdinalIgnoreCase)
                || request.RequestUri.Port != origin.Port)
            {
                throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The console only sends requests to its own EKM endpoint.");
            }

            return base.SendAsync(request, cancellationToken);
        }
    }
}
