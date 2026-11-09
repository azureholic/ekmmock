using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using EkmMock.Server.Tls;
using EkmMock.Server.WebConsole;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Hosting;

/// <summary>
/// The certificate of the console listener (spec 5.4): <c>Console:Tls:CertFile/KeyFile</c> when configured (its own hot-reloading provider), otherwise the EKM server
/// certificate provider, which in <c>--dev</c> serves the generated, flagged throw-away <c>localhost</c> certificate.
/// </summary>
internal sealed class ConsoleCertificates : IDisposable
{
    private readonly ServerCertificateProvider? _own;

    public ConsoleCertificates(
        IOptions<ConsoleOptions> options,
        ServerCertificateProvider ekmCertificates,
        IOptions<DevOptions> dev,
        TimeProvider time,
        ILoggerFactory loggerFactory)
    {
        if (options.Value.Tls.HasFiles)
        {
            _own = new ServerCertificateProvider(
                Options.Create(new TlsOptions { CertFile = options.Value.Tls.CertFile, KeyFile = options.Value.Tls.KeyFile }),
                dev,
                time,
                loggerFactory.CreateLogger<ServerCertificateProvider>());
            Provider = _own;
            IsOwnCertificate = true;
        }
        else
        {
            Provider = ekmCertificates;
        }
    }

    public IServerCertificateProvider Provider { get; }

    /// <summary>True when the console has its own certificate; false when it shares the EKM server certificate.</summary>
    public bool IsOwnCertificate { get; }

    public void Dispose() => _own?.Dispose();
}

/// <summary>
/// Configures the console Kestrel endpoint (spec 5.4, 7): HTTPS, no client certificate, bound exactly where <c>Endpoints:Console:Url</c> says. It first runs the same start-up checks
/// as the host builder, so a <c>LoopbackOnly</c> console can never be bound to a non-loopback address, whatever path led here. Together with <see cref="EkmKestrelSetup"/>
/// this is the only place that configures listeners (an architecture test pins that).
/// </summary>
internal sealed class ConsoleKestrelSetup : IConfigureOptions<KestrelServerOptions>
{
    private readonly ConsoleEndpointOptions _endpoint;
    private readonly ConsoleOptions _console;
    private readonly EkmEndpointOptions _ekm;
    private readonly ConsoleCertificates _certificates;
    private readonly ConsoleListenerPorts _ports;
    private readonly ListenerRegistry _listeners;

    public ConsoleKestrelSetup(
        IOptions<ConsoleEndpointOptions> endpoint,
        IOptions<ConsoleOptions> console,
        IOptions<EkmEndpointOptions> ekm,
        ConsoleCertificates certificates,
        ConsoleListenerPorts ports,
        ListenerRegistry listeners)
    {
        _endpoint = endpoint.Value;
        _console = console.Value;
        _ekm = ekm.Value;
        _certificates = certificates;
        _ports = ports;
        _listeners = listeners;
    }

    public void Configure(KestrelServerOptions options)
    {
        ConsoleConfigurationValidator.EnsureValid(_console, _endpoint, _ekm.Url);
        var address = ConsoleEndpointAddress.Parse(_endpoint.Url);

        void ConfigureListener(ListenOptions listen)
        {
            listen.Protocols = HttpProtocols.Http1AndHttp2;
            if (address.Port != 0)
            {
                _ports.Add(address.Port);
            }

            // Registers the local port before any request is read, so the port separation holds for ephemeral listeners too.
            listen.Use(next => context =>
            {
                if (context.LocalEndPoint is IPEndPoint local)
                {
                    _ports.Add(local.Port);
                }

                return next(context);
            });
            listen.UseHttps(CreateHttpsOptions());
            _listeners.Register(ListenerRegistry.ConsoleName, listen);
        }

        if (address.IsAnyAddress)
        {
            options.ListenAnyIP(address.Port, ConfigureListener);
        }
        else if (address.IsLocalhost && address.Port != 0)
        {
            options.ListenLocalhost(address.Port, ConfigureListener);
        }
        else if (address.IsLocalhost)
        {
            // Kestrel cannot bind "localhost" to an ephemeral port (it would need two different ports); tests use 127.0.0.1.
            options.Listen(IPAddress.Loopback, 0, ConfigureListener);
        }
        else if (address.Address is { } ip)
        {
            options.Listen(ip, address.Port, ConfigureListener);
        }
        else
        {
            // A host name (only reachable with EntraId, or a name that resolves to loopback only): bind every address it resolves to.
            foreach (var resolved in Dns.GetHostAddresses(address.Host).Distinct())
            {
                options.Listen(resolved, address.Port, ConfigureListener);
            }
        }
    }

    private HttpsConnectionAdapterOptions CreateHttpsOptions()
    {
        var provider = _certificates.Provider;
        return new HttpsConnectionAdapterOptions
        {
            // Browsers: TLS 1.2 and 1.3 (the EKM endpoint is the one that is TLS 1.3 only). No client certificate on the console (spec 5.4).
            SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ClientCertificateMode = ClientCertificateMode.NoCertificate,
            ServerCertificateSelector = (_, _) => provider.Current.Certificate,
            OnAuthenticate = (_, ssl) =>
            {
                // Serve the whole chain, as the EKM listener does (see EkmKestrelSetup).
                ssl.ServerCertificateSelectionCallback = null;
                ssl.ServerCertificateContext = provider.Current.Context;
            },
        };
    }
}

/// <summary>Remembers the Kestrel <see cref="ListenOptions"/> of each endpoint so the host (and tests) can ask for the port the OS actually assigned to an ephemeral listener.</summary>
internal sealed class ListenerRegistry
{
    public const string EkmName = "ekm";
    public const string ConsoleName = "console";

    private readonly object _gate = new();
    private readonly List<(string Name, ListenOptions Options)> _listeners = [];

    public void Register(string name, ListenOptions options)
    {
        lock (_gate)
        {
            _listeners.Add((name, options));
        }
    }

    /// <summary>The bound ports of an endpoint. Available once the server started.</summary>
    public IReadOnlyList<int> PortsOf(string name)
    {
        lock (_gate)
        {
            return [.. _listeners.Where(l => l.Name == name).Select(static l => l.Options.IPEndPoint?.Port ?? 0).Where(static p => p > 0)];
        }
    }

    /// <summary>The bound addresses (with the port the OS actually assigned) of an endpoint.</summary>
    public IReadOnlyList<System.Net.IPEndPoint> EndpointsOf(string name)
    {
        lock (_gate)
        {
            return [.. _listeners.Where(l => l.Name == name).Select(static l => l.Options.IPEndPoint).Where(static e => e is { Port: > 0 })!];
        }
    }
}
