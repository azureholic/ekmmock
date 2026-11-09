using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Server.Connections;
using EkmMock.Server.Metrics;
using EkmMock.Server.Tls;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Hosting;

/// <summary>The <c>Endpoints:Ekm</c> configuration section (spec 7, 16). Must be an <c>https</c> URL: there is no plain-HTTP EKM endpoint.</summary>
internal sealed class EkmEndpointOptions
{
    public const string SectionName = "Endpoints:Ekm";

    public string Url { get; set; } = "https://0.0.0.0:8443";
}

/// <summary>Where the EKM listener binds, parsed from <c>Endpoints:Ekm:Url</c>. Port 0 asks the OS for a free port (tests).</summary>
internal sealed record EkmEndpointAddress(IPAddress? Address, bool IsLocalhost, bool IsAnyAddress, int Port)
{
    private const string HttpsPrefix = "https://";

    public static EkmEndpointAddress Parse(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !url.StartsWith(HttpsPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Endpoints:Ekm:Url must be an https URL such as https://0.0.0.0:8443. The EKM endpoint is TLS 1.3 with mutual authentication only; there is no plain-HTTP mode.");
        }

        var authority = url[HttpsPrefix.Length..].TrimEnd('/');
        var colon = authority.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(authority[(colon + 1)..], out var port) || port is < 0 or > 65535)
        {
            throw new InvalidOperationException("Endpoints:Ekm:Url must contain a host and a port, for example https://0.0.0.0:8443.");
        }

        var host = authority[..colon];
        if (host is "*" or "+")
        {
            return new EkmEndpointAddress(null, false, true, port);
        }

        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return new EkmEndpointAddress(null, true, false, port);
        }

        if (IPAddress.TryParse(host, out var address))
        {
            return new EkmEndpointAddress(address, false, false, port);
        }

        throw new InvalidOperationException("Endpoints:Ekm:Url host must be an IP address, localhost, or * (all addresses).");
    }
}

/// <summary>
/// Configures the EKM Kestrel endpoint (spec 5.1, 5.5, 7): TLS 1.3 only, the two permitted cipher suites where the platform can enforce them,
/// optional client certificates validated against the custom union of the namespaces' roots, the hot-reloadable server certificate,
/// the connection capture middleware before TLS, and the Kestrel limits of the EKM endpoint.
/// </summary>
internal sealed class EkmKestrelSetup : IConfigureOptions<KestrelServerOptions>
{
    /// <summary>Request header read timeout (spec 5.5).</summary>
    public static readonly TimeSpan RequestHeadersTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Idle keep-alive time (spec 5.5): Managed HSM reuses connections, a new handshake per call would eat the latency budget.</summary>
    public static readonly TimeSpan KeepAliveTimeout = TimeSpan.FromSeconds(120);

    /// <summary>Largest request body (spec 4.1). The handler enforces the same 16 KiB with its own ProxyError.</summary>
    public const long MaxRequestBodyBytes = 16 * 1024;

    private readonly EkmEndpointOptions _endpoint;
    private readonly TlsOptions _tls;
    private readonly IServerCertificateProvider _certificates;
    private readonly ClientCertificateValidator _validator;
    private readonly TlsPolicy _policy;
    private readonly ConnectionCapture _capture;
    private readonly ListenerRegistry _listeners;
    private readonly ILogger _logger;

    public EkmKestrelSetup(
        IOptions<EkmEndpointOptions> endpoint,
        IOptions<TlsOptions> tls,
        IServerCertificateProvider certificates,
        ClientCertificateValidator validator,
        TlsPolicy policy,
        ConnectionRegistry registry,
        IConnectionEventSink sink,
        EkmMetrics metrics,
        EkmListenerPorts ports,
        ListenerRegistry listeners,
        TimeProvider time,
        ILoggerFactory loggerFactory)
    {
        _endpoint = endpoint.Value;
        _tls = tls.Value;
        _certificates = certificates;
        _validator = validator;
        _policy = policy;
        _listeners = listeners;
        _capture = new ConnectionCapture(registry, sink, metrics, ports, time, loggerFactory, _tls.HandshakeTimeout);
        _logger = loggerFactory.CreateLogger("EkmMock.Tls");
    }

    public void Configure(KestrelServerOptions options)
    {
        var address = EkmEndpointAddress.Parse(_endpoint.Url);

        options.AddServerHeader = false;
        options.Limits.RequestHeadersTimeout = RequestHeadersTimeout;
        options.Limits.KeepAliveTimeout = KeepAliveTimeout;
        options.Limits.MaxRequestBodySize = MaxRequestBodyBytes;

        if (!_policy.CanEnforceCipherSuites)
        {
            _logger.LogWarning(
                "TLS cipher suites cannot be restricted by the TLS stack on this operating system ({Os}): CipherSuitesPolicy is not supported here. " +
                "TLS 1.3 only is enforced; connections that negotiate a suite other than TLS_AES_256_GCM_SHA384 or TLS_AES_128_GCM_SHA256 are closed right after the handshake. " +
                "Run on Linux (OpenSSL) for full enforcement.",
                _policy.Effective.OperatingSystem);
        }

        void ConfigureListener(ListenOptions listen)
        {
            listen.Protocols = HttpProtocols.Http1AndHttp2;
            if (address.Port != 0)
            {
                _capture.RegisterConfiguredPort(address.Port);
            }

            // Order matters: capture before TLS (sees failed handshakes), then TLS, then the post-handshake step.
            listen.Use(_capture.Outer);
            listen.UseHttps(CreateHttpsOptions());
            listen.Use(_capture.Inner);
            _listeners.Register(ListenerRegistry.EkmName, listen);
        }

        if (address.IsAnyAddress)
        {
            options.ListenAnyIP(address.Port, ConfigureListener);
        }
        else if (address.IsLocalhost)
        {
            options.ListenLocalhost(address.Port, ConfigureListener);
        }
        else
        {
            options.Listen(address.Address!, address.Port, ConfigureListener);
        }
    }

    private HttpsConnectionAdapterOptions CreateHttpsOptions() => new()
    {
        SslProtocols = TlsPolicy.RequiredProtocols,
        ClientCertificateMode = ClientCertificateMode.AllowCertificate,
        ClientCertificateValidation = _validator.Validate,
        ServerCertificateSelector = (_, _) => _certificates.Current.Certificate,
        HandshakeTimeout = _tls.HandshakeTimeout,
        OnAuthenticate = (connection, ssl) =>
        {
            // Every connection gets a full handshake. A resumed session skips the client certificate validation (and the capture of the
            // intermediates the client sent), and its client identity is whatever the original session authenticated, which is a class of
            // problems an access-control endpoint should not have. TLS 1.3 handshakes are one round trip either way, and Managed HSM reuses
            // its keep-alive connections. (DECISIONS.md "M3: TLS stack" records the intermittent test failure that prompted this.)
            ssl.AllowTlsResume = false;

            // Spec 5.1: restrict the TLS 1.3 suites. Not supported on Windows (probed in TlsPolicy); the post-handshake check covers it there.
            if (_policy.CipherSuitesPolicy is { } suites)
            {
                ssl.CipherSuitesPolicy = suites;
            }

            // Serve the whole chain (leaf + intermediates) built offline from the current certificate snapshot. The selector above is the
            // contract Kestrel requires and returns the same leaf; replacing the selection callback with the certificate context is what makes
            // the TLS stack send the intermediates too (on Windows it would otherwise look for them in the machine store).
            ssl.ServerCertificateSelectionCallback = null;
            ssl.ServerCertificateContext = _certificates.Current.Context;
        },
    };
}
