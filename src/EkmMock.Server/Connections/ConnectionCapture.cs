using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EkmMock.Server.Tls;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;

namespace EkmMock.Server.Connections;

/// <summary>
/// The Kestrel connection middleware pair of the EKM listener (spec 7, 8.2).
/// <para>
/// <see cref="Outer"/> is added <em>before</em> <c>UseHttps</c>, so it sees every connection including the ones whose TLS handshake
/// fails: it records "opened", wraps the transport with a <see cref="ClientHelloTap"/>, and when the connection ends without the
/// handshake having completed it classifies why and publishes "handshake failed" (and the metric), then "closed".
/// <see cref="Inner"/> is added <em>after</em> <c>UseHttps</c>: it only runs when the handshake succeeded, reads the negotiated TLS
/// facts, publishes "handshake succeeded" and enforces the cipher policy where the TLS stack cannot.
/// </para>
/// Why not catch the exception? Kestrel's HTTPS middleware swallows handshake exceptions (it logs them at debug and closes the
/// connection), so nothing propagates to a wrapper. "Closed without the inner middleware having run" is the reliable signal.
/// </summary>
internal sealed class ConnectionCapture
{
    private readonly ConnectionRegistry _registry;
    private readonly IConnectionEventSink _sink;
    private readonly EkmMetrics _metrics;
    private readonly EkmListenerPorts _ports;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly TimeSpan _handshakeTimeout;

    public ConnectionCapture(
        ConnectionRegistry registry,
        IConnectionEventSink sink,
        EkmMetrics metrics,
        EkmListenerPorts ports,
        TimeProvider time,
        ILoggerFactory loggerFactory,
        TimeSpan handshakeTimeout)
    {
        _registry = registry;
        _sink = sink;
        _metrics = metrics;
        _ports = ports;
        _time = time;
        _logger = loggerFactory.CreateLogger("EkmMock.Connections");
        _handshakeTimeout = handshakeTimeout;
    }

    /// <summary>Before <c>UseHttps</c>.</summary>
    public ConnectionDelegate Outer(ConnectionDelegate next) => async context =>
    {
        var state = _registry.Open(context);
        _ports.Add(state.LocalPort);
        Publish(new ConnectionEvent
        {
            ConnectionId = state.Id,
            Kind = ConnectionEventKind.Opened,
            AtUtc = state.OpenedAtUtc,
            RemoteEndPoint = state.RemoteEndPoint,
            LocalPort = state.LocalPort,
        });

        var original = context.Transport;
        context.Transport = new ClientHelloTap(original, state.SetClientHello);
        ConnectionState.Current = state;
        try
        {
            await next(context).ConfigureAwait(false);
        }
        finally
        {
            context.Transport = original;
            Close(state);
        }
    };

    /// <summary>After <c>UseHttps</c>: the TLS handshake has succeeded when this runs.</summary>
    public ConnectionDelegate Inner(ConnectionDelegate next) => context =>
    {
        var state = _registry.TryGet(context.ConnectionId);
        return state is null ? next(context) : AcceptAsync(context, state, next);
    };

    private async Task AcceptAsync(ConnectionContext context, ConnectionState state, ConnectionDelegate next)
    {
        var handshake = context.Features.Get<ITlsHandshakeFeature>();
        var protocol = handshake is null ? "unknown" : DescribeProtocol(handshake.Protocol);
        var suite = handshake?.NegotiatedCipherSuite;
        var suiteName = suite?.ToString();

        // The TLS stack negotiated these. Where it could not be told which suites to offer (Windows), hold it to the policy here.
        if (handshake is not null && EvaluatePolicy(handshake.Protocol, suite) is { } violation)
        {
            state.RejectByPolicy(violation, $"negotiated {protocol} {suiteName ?? "unknown suite"}", protocol, suiteName);
            context.Abort();
            return;
        }

        var certificate = context.Features.Get<ITlsConnectionFeature>()?.ClientCertificate;

        // Kestrel exposes the SslStream itself: its negotiated ALPN is what the HTTP layer will speak (h2 or http/1.1).
        var negotiated = context.Features.Get<ISslStreamFeature>()?.SslStream.NegotiatedApplicationProtocol.Protocol ?? default;
        var alpn = negotiated.IsEmpty ? null : Encoding.ASCII.GetString(negotiated.Span);
        var summary = certificate is null ? null : ClientCertificateSummary.From(certificate);
        var elapsed = state.Age;

        state.CompleteHandshake(protocol, suiteName, alpn, handshake?.HostName, summary, elapsed);
        Publish(new ConnectionEvent
        {
            ConnectionId = state.Id,
            Kind = ConnectionEventKind.HandshakeSucceeded,
            AtUtc = _time.GetUtcNow(),
            RemoteEndPoint = state.RemoteEndPoint,
            LocalPort = state.LocalPort,
            TlsProtocol = protocol,
            CipherSuite = suiteName,
            Alpn = alpn,
            Sni = state.Sni,

            // Session resumption is disabled on this endpoint (see EkmKestrel), so every handshake is a full one.
            Resumed = false,
            HandshakeTime = elapsed,
            ClientCertificate = summary,
        });

        await next(context).ConfigureAwait(false);
    }

    /// <summary>
    /// The post-handshake policy check: the negotiated protocol must be TLS 1.3 and the negotiated suite one of the two permitted ones.
    /// An unknown suite (the OS did not report it) is not a violation. Returns the failure reason, or null when the connection is fine.
    /// </summary>
    internal static HandshakeFailureReason? EvaluatePolicy(System.Security.Authentication.SslProtocols protocol, TlsCipherSuite? suite)
    {
        if (protocol != System.Security.Authentication.SslProtocols.Tls13)
        {
            return HandshakeFailureReason.TlsVersionNotSupported;
        }

        return suite is { } negotiated && !TlsPolicy.IsPermitted(negotiated) ? HandshakeFailureReason.CipherSuiteNotAllowed : null;
    }

    private void Close(ConnectionState state)
    {
        try
        {
            if (!state.HandshakeCompleted)
            {
                var (reason, detail) = Classify(state);
                _metrics.RecordHandshakeFailure(reason);
                Publish(new ConnectionEvent
                {
                    ConnectionId = state.Id,
                    Kind = ConnectionEventKind.HandshakeFailed,
                    AtUtc = _time.GetUtcNow(),
                    RemoteEndPoint = state.RemoteEndPoint,
                    LocalPort = state.LocalPort,
                    TlsProtocol = state.TlsProtocol,
                    CipherSuite = state.CipherSuite,
                    Sni = state.Sni ?? state.Hello?.ServerName,
                    Alpn = state.Hello is { Alpn.Count: > 0 } hello ? string.Join(',', hello.Alpn) : null,
                    HandshakeTime = state.Age,
                    FailureReason = reason,
                    FailureDetail = detail,
                });
                _logger.LogWarning(
                    "TLS handshake failed: reason={Reason} remote={Remote} detail={Detail}",
                    HandshakeFailureReasons.Label(reason),
                    state.RemoteEndPoint,
                    detail);
            }

            Publish(new ConnectionEvent
            {
                ConnectionId = state.Id,
                Kind = ConnectionEventKind.Closed,
                AtUtc = _time.GetUtcNow(),
                RemoteEndPoint = state.RemoteEndPoint,
                LocalPort = state.LocalPort,
                Duration = state.Age,
                RequestCount = state.RequestCount,
            });
        }
        finally
        {
            _registry.Remove(state.Id);
        }
    }

    /// <summary>
    /// Decides why a handshake did not complete, from facts that are the same on every OS: the policy check, the client certificate
    /// verdict and what the client offered in its ClientHello. The OS error text is never used (it differs between SChannel and OpenSSL).
    /// </summary>
    // Kestrel's handshake timer and the connection clock start a few microseconds apart, so allow a small tolerance (a client that gave up
    // within 250 ms of the timeout is indistinguishable from a timeout anyway).
    private bool TimedOut(ConnectionState state) => state.Age >= _handshakeTimeout - HandshakeTimeoutTolerance;

    private static readonly TimeSpan HandshakeTimeoutTolerance = TimeSpan.FromMilliseconds(250);

    internal (HandshakeFailureReason Reason, string Detail) Classify(ConnectionState state)
    {
        if (state.PolicyViolation is { } violation)
        {
            return (violation, state.PolicyViolationDetail ?? HandshakeFailureReasons.Describe(violation));
        }

        if (state.ClientCertificateVerdict is { Accepted: false } verdict)
        {
            return (HandshakeFailureReason.ClientCertificateNotTrusted, $"chain status: {verdict.ChainStatus}");
        }

        switch (state.HelloStatus)
        {
            case ClientHelloParseStatus.NotTls:
                return (HandshakeFailureReason.NotTls, "first bytes are not a TLS handshake record");
            case ClientHelloParseStatus.Parsed when state.Hello is { } hello:
                if (!hello.OffersTls13)
                {
                    return (HandshakeFailureReason.TlsVersionNotSupported, "client offered " + string.Join(", ", hello.OfferedVersions.Select(ClientHelloInfo.VersionName)));
                }

                if (!hello.OffersAnyOf(0x1301, 0x1302))
                {
                    var offered = hello.CipherSuites.Select(ClientHelloInfo.Tls13SuiteName).OfType<string>().ToList();
                    return (HandshakeFailureReason.NoCommonCipherSuite, "client offered TLS 1.3 suites: " + (offered.Count == 0 ? "none" : string.Join(", ", offered)));
                }

                break;
            case ClientHelloParseStatus.Malformed:
                return (HandshakeFailureReason.Other, "the ClientHello could not be read");
        }

        if (state.HelloStatus is null or ClientHelloParseStatus.NeedMoreData)
        {
            return TimedOut(state)
                ? (HandshakeFailureReason.HandshakeTimeout, "no complete ClientHello within the handshake timeout")
                : (HandshakeFailureReason.ClientClosed, "the client closed the connection before sending a complete ClientHello");
        }

        return TimedOut(state)
            ? (HandshakeFailureReason.HandshakeTimeout, "the handshake did not finish within the handshake timeout")
            : (HandshakeFailureReason.Other, "the client's hello was acceptable but the handshake did not complete");
    }

    /// <summary>Registers a configured (non-ephemeral) listener port as an EKM port before the first connection arrives.</summary>
    public void RegisterConfiguredPort(int port) => _ports.Add(port);

    private void Publish(ConnectionEvent connectionEvent)
    {
        try
        {
            _sink.Publish(connectionEvent);
        }
        catch (Exception)
        {
            // The capture path must never take a connection down.
        }
    }

    private static string DescribeProtocol(System.Security.Authentication.SslProtocols protocol) => protocol switch
    {
        System.Security.Authentication.SslProtocols.Tls13 => "TLS 1.3",
        System.Security.Authentication.SslProtocols.Tls12 => "TLS 1.2",
        _ => protocol.ToString(),
    };
}
