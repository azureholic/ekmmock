using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using EkmMock.Server.Tls;
using Microsoft.AspNetCore.Connections;

namespace EkmMock.Server.Connections;

/// <summary>
/// What EkmMock knows about one connection on the EKM endpoint: identity, what the client offered, the handshake outcome, TLS
/// details and a request counter. Created when the connection is accepted, found again by connection id from the HTTP layer
/// (so every exchange can link to its connection, M4), and removed when the connection closes.
/// </summary>
internal sealed class ConnectionState
{
    private readonly object _gate = new();
    private long _requestCount;

    public ConnectionState(string id, string? remoteEndPoint, int localPort, DateTimeOffset openedAtUtc, long openedTimestamp)
    {
        Id = id;
        RemoteEndPoint = remoteEndPoint;
        LocalPort = localPort;
        OpenedAtUtc = openedAtUtc;
        OpenedTimestamp = openedTimestamp;
    }

    public string Id { get; }

    // The connection whose handshake is running on this logical flow. Kestrel's client certificate validation callback is invoked
    // synchronously inside the handshake that the capture middleware awaits, so the async-local value set there reaches it (and
    // nothing else): that is how the verdict finds its connection without any change to Kestrel's own callback.
    private static readonly AsyncLocal<ConnectionState?> s_current = new();

    /// <summary>The connection being handled on the current logical flow, or null outside a captured connection.</summary>
    public static ConnectionState? Current
    {
        get => s_current.Value;
        set => s_current.Value = value;
    }

    public string? RemoteEndPoint { get; }

    public int LocalPort { get; }

    public DateTimeOffset OpenedAtUtc { get; }

    public long OpenedTimestamp { get; }

    public long RequestCount => Interlocked.Read(ref _requestCount);

    public void RequestStarted() => Interlocked.Increment(ref _requestCount);

    // ---- what the client offered (set by the tap) ----

    public ClientHelloParseStatus? HelloStatus { get; private set; }

    public ClientHelloInfo? Hello { get; private set; }

    public void SetClientHello(ClientHelloParseStatus status, ClientHelloInfo? info)
    {
        lock (_gate)
        {
            HelloStatus = status;
            Hello = info;
        }
    }

    // ---- client certificate verdict of the handshake (set by the validation wrapper) ----

    public HandshakeVerdict? ClientCertificateVerdict { get; private set; }

    public void SetClientCertificateVerdict(HandshakeVerdict verdict)
    {
        lock (_gate)
        {
            ClientCertificateVerdict = verdict;
        }
    }

    /// <summary>The server name the client asked for, as delivered to the certificate selector.</summary>
    public string? Sni { get; set; }

    // ---- handshake outcome ----

    public bool HandshakeCompleted { get; private set; }

    /// <summary>Set when the handshake finished but the negotiated parameters violate the policy and the connection was closed.</summary>
    public HandshakeFailureReason? PolicyViolation { get; private set; }

    public string? PolicyViolationDetail { get; private set; }

    public string? TlsProtocol { get; private set; }

    public string? CipherSuite { get; private set; }

    public string? Alpn { get; private set; }

    public ClientCertificateSummary? ClientCertificate { get; private set; }

    public TimeSpan? HandshakeTime { get; private set; }

    /// <summary>The intermediates the client sent, used to rebuild its chain against one namespace's roots.</summary>
    public IReadOnlyList<byte[]> PresentedIntermediates => ClientCertificateVerdict?.PresentedIntermediates ?? [];

    public void CompleteHandshake(string tlsProtocol, string? cipherSuite, string? alpn, string? sni, ClientCertificateSummary? certificate, TimeSpan handshakeTime)
    {
        lock (_gate)
        {
            HandshakeCompleted = true;
            TlsProtocol = tlsProtocol;
            CipherSuite = cipherSuite;
            Alpn = alpn;
            Sni = sni ?? Sni;
            ClientCertificate = certificate;
            HandshakeTime = handshakeTime;
        }
    }

    public void RejectByPolicy(HandshakeFailureReason reason, string detail, string tlsProtocol, string? cipherSuite)
    {
        lock (_gate)
        {
            PolicyViolation = reason;
            PolicyViolationDetail = detail;
            TlsProtocol = tlsProtocol;
            CipherSuite = cipherSuite;
        }
    }

    public TimeSpan Age => Stopwatch.GetElapsedTime(OpenedTimestamp);
}

/// <summary>The open connections of the EKM endpoint, by Kestrel connection id (also <c>HttpContext.Connection.Id</c>).</summary>
internal sealed class ConnectionRegistry
{
    private readonly ConcurrentDictionary<string, ConnectionState> _connections = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    public ConnectionRegistry(TimeProvider time) => _time = time;

    public int OpenCount => _connections.Count;

    /// <summary>The connections that are open right now (for the console's Connections tab and for tests).</summary>
    public IReadOnlyList<ConnectionState> Snapshot() => [.. _connections.Values];

    public ConnectionState Open(ConnectionContext context)
    {
        var local = (context.LocalEndPoint as IPEndPoint)?.Port ?? 0;
        var state = new ConnectionState(context.ConnectionId, FormatEndPoint(context.RemoteEndPoint), local, _time.GetUtcNow(), Stopwatch.GetTimestamp());
        _connections[state.Id] = state;
        return state;
    }

    public ConnectionState? TryGet(string? connectionId)
        => string.IsNullOrEmpty(connectionId) ? null : _connections.GetValueOrDefault(connectionId);

    public void Remove(string connectionId) => _connections.TryRemove(connectionId, out _);

    private static string? FormatEndPoint(EndPoint? endPoint) => endPoint switch
    {
        IPEndPoint ip => ip.ToString(),
        null => null,
        _ => endPoint.GetType().Name,
    };
}

/// <summary>
/// The ports that carry the EKM endpoint (spec 5.4). EKM routes answer <em>only</em> on these local ports, and only these ports
/// run the EKM pipeline: the console and any other listener get a plain 404 for EKM paths, whatever the Host header says.
/// A port is registered by the EKM listener's own connection middleware, so it is known even for ephemeral (port 0) listeners
/// and can never be claimed by another listener.
/// </summary>
internal interface IEkmPortPolicy
{
    bool IsEkmPort(int localPort);
}

internal sealed class EkmListenerPorts : IEkmPortPolicy
{
    private readonly ConcurrentDictionary<int, byte> _ports = new();

    public IReadOnlyCollection<int> Ports => [.. _ports.Keys];

    public void Add(int port)
    {
        if (port > 0)
        {
            _ports[port] = 0;
        }
    }

    public bool IsEkmPort(int localPort) => localPort > 0 && _ports.ContainsKey(localPort);
}
