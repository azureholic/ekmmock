using System.Threading.Channels;
using EkmMock.Server.Tls;

namespace EkmMock.Server.Connections;

internal enum ConnectionEventKind
{
    Opened,
    HandshakeSucceeded,
    HandshakeFailed,
    Closed,
}

/// <summary>
/// Why a TLS handshake did not complete (spec 8.2). The <see cref="HandshakeFailureReasons.Label"/> values are the
/// <c>reason</c> label of <c>ekmmock_tls_handshake_failures_total</c>.
/// </summary>
internal enum HandshakeFailureReason
{
    /// <summary>The client presented a certificate that does not chain to any namespace's root CA (unknown CA, partial chain, ...).</summary>
    ClientCertificateNotTrusted,

    /// <summary>The client did not offer TLS 1.3 (for example a TLS 1.2-only client).</summary>
    TlsVersionNotSupported,

    /// <summary>The client offered TLS 1.3 but none of the two permitted cipher suites.</summary>
    NoCommonCipherSuite,

    /// <summary>The first bytes were not a TLS handshake (plain HTTP to the TLS port, a port scan, ...).</summary>
    NotTls,

    /// <summary>The client closed the connection (or sent too little) before the handshake finished.</summary>
    ClientClosed,

    /// <summary>The handshake did not finish within the handshake timeout.</summary>
    HandshakeTimeout,

    /// <summary>The handshake finished with a cipher suite outside the permitted set; the connection was closed (non-enforcing TLS stacks).</summary>
    CipherSuiteNotAllowed,

    Other,
}

internal static class HandshakeFailureReasons
{
    /// <summary>Stable snake_case metric label.</summary>
    public static string Label(HandshakeFailureReason reason) => reason switch
    {
        HandshakeFailureReason.ClientCertificateNotTrusted => "client_cert_not_trusted",
        HandshakeFailureReason.TlsVersionNotSupported => "tls_version_not_supported",
        HandshakeFailureReason.NoCommonCipherSuite => "no_common_cipher_suite",
        HandshakeFailureReason.NotTls => "not_tls",
        HandshakeFailureReason.ClientClosed => "client_closed",
        HandshakeFailureReason.HandshakeTimeout => "handshake_timeout",
        HandshakeFailureReason.CipherSuiteNotAllowed => "cipher_suite_not_allowed",
        _ => "other",
    };

    /// <summary>A fixed, secret-free sentence for the console.</summary>
    public static string Describe(HandshakeFailureReason reason) => reason switch
    {
        HandshakeFailureReason.ClientCertificateNotTrusted => "The client certificate does not chain to a root CA trusted by any namespace.",
        HandshakeFailureReason.TlsVersionNotSupported => "The client did not offer TLS 1.3, which is the only protocol version accepted.",
        HandshakeFailureReason.NoCommonCipherSuite => "The client offered none of the permitted TLS 1.3 cipher suites (TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256).",
        HandshakeFailureReason.NotTls => "The connection did not start with a TLS handshake.",
        HandshakeFailureReason.ClientClosed => "The client closed the connection before the TLS handshake completed.",
        HandshakeFailureReason.HandshakeTimeout => "The TLS handshake did not complete in time.",
        HandshakeFailureReason.CipherSuiteNotAllowed => "The negotiated cipher suite is not one of the permitted TLS 1.3 cipher suites; the connection was closed.",
        _ => "The TLS handshake failed for a reason that is not classified.",
    };
}

/// <summary>
/// One connection event (spec 8.2). A flat record: which fields are set depends on <see cref="Kind"/>.
/// Contains no secrets: only names, endpoints, protocol facts and the public summary of a client certificate.
/// </summary>
internal sealed record ConnectionEvent
{
    /// <summary>Assigned by the sink, strictly increasing per process.</summary>
    public long Sequence { get; init; }

    public required string ConnectionId { get; init; }

    public required ConnectionEventKind Kind { get; init; }

    public required DateTimeOffset AtUtc { get; init; }

    public string? RemoteEndPoint { get; init; }

    public int LocalPort { get; init; }

    // HandshakeSucceeded
    public string? TlsProtocol { get; init; }

    public string? CipherSuite { get; init; }

    public string? Alpn { get; init; }

    public string? Sni { get; init; }

    /// <summary>Whether the session was resumed. EkmMock disables TLS session resumption on the EKM endpoint, so successful handshakes report <c>false</c>.</summary>
    public bool? Resumed { get; init; }

    public TimeSpan? HandshakeTime { get; init; }

    public ClientCertificateSummary? ClientCertificate { get; init; }

    // HandshakeFailed
    public HandshakeFailureReason? FailureReason { get; init; }

    /// <summary>Extra detail composed only from enumerations (offered versions, suites, chain status flags).</summary>
    public string? FailureDetail { get; init; }

    // Closed
    public TimeSpan? Duration { get; init; }

    public long? RequestCount { get; init; }
}

/// <summary>Where connection events are published. Publishing never blocks and never throws into the connection path.</summary>
internal interface IConnectionEventSink
{
    void Publish(ConnectionEvent connectionEvent);
}

/// <summary>
/// A bounded queue that never blocks the producer: when it is full the <em>oldest</em> item is dropped and counted
/// (spec 8.3). Reused by the inspector capture pipeline (M4).
/// </summary>
internal sealed class BoundedDropOldestQueue<T>
{
    private readonly Channel<T> _channel;
    private long _dropped;

    public BoundedDropOldestQueue(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        Capacity = capacity;
        _channel = Channel.CreateBounded<T>(
            new BoundedChannelOptions(capacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false,
            },
            _ => Interlocked.Increment(ref _dropped));
    }

    public int Capacity { get; }

    /// <summary>Items dropped because the queue was full when something newer arrived.</summary>
    public long Dropped => Interlocked.Read(ref _dropped);

    public ChannelReader<T> Reader => _channel.Reader;

    /// <summary>Always succeeds while the queue is open: a full queue drops its oldest item to make room.</summary>
    public bool TryEnqueue(T item) => _channel.Writer.TryWrite(item);

    public void Complete() => _channel.Writer.TryComplete();
}

/// <summary>
/// The in-process connection event sink: assigns sequence numbers and enqueues into a bounded drop-oldest queue.
/// A consumer (the in-memory <see cref="ConnectionEventStore"/> now, the inspector pipeline in M4) reads <see cref="Reader"/>.
/// </summary>
internal sealed class ConnectionEventSink : IConnectionEventSink
{
    public const int DefaultCapacity = 10_000;

    private readonly BoundedDropOldestQueue<ConnectionEvent> _queue;
    private long _sequence;

    public ConnectionEventSink(int capacity = DefaultCapacity) => _queue = new BoundedDropOldestQueue<ConnectionEvent>(capacity);

    public ChannelReader<ConnectionEvent> Reader => _queue.Reader;

    public long Dropped => _queue.Dropped;

    /// <summary>The sequence number of the most recently published event (0 before the first).</summary>
    public long LastSequence => Interlocked.Read(ref _sequence);

    public void Publish(ConnectionEvent connectionEvent)
    {
        ArgumentNullException.ThrowIfNull(connectionEvent);
        _queue.TryEnqueue(connectionEvent with { Sequence = Interlocked.Increment(ref _sequence) });
    }

    public void Complete() => _queue.Complete();
}
