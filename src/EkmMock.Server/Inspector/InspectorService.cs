using System.Text.Json;
using EkmMock.Server.Connections;
using EkmMock.Server.Ekm;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Inspector;

/// <summary>Connection counters for the Connections tab (spec 8.2, 8.5), maintained from the connection events by the pump.</summary>
internal sealed record ConnectionStatistics(
    int OpenNow,
    long Opened,
    long HandshakesSucceeded,
    long HandshakesFailed,
    IReadOnlyDictionary<string, long> FailuresByReason,
    long Closed,
    long ResumedHandshakes,
    double ResumptionRate,
    long RequestsOnClosedConnections,
    double AverageRequestsPerClosedConnection);

internal sealed class ConnectionStatsStage : IInspectorStage
{
    private readonly object _gate = new();
    private readonly Dictionary<string, long> _failures = new(StringComparer.Ordinal);
    private long _opened;
    private long _succeeded;
    private long _failed;
    private long _closed;
    private long _resumed;
    private long _requestsOnClosed;

    public void OnConnectionEvent(ConnectionEventRecord connectionEvent)
    {
        lock (_gate)
        {
            switch (connectionEvent.Kind)
            {
                case "opened":
                    _opened++;
                    break;
                case "handshake_succeeded":
                    _succeeded++;
                    if (connectionEvent.Resumed == true)
                    {
                        _resumed++;
                    }

                    break;
                case "handshake_failed":
                    _failed++;
                    var reason = connectionEvent.FailureReason ?? "other";
                    _failures[reason] = _failures.GetValueOrDefault(reason) + 1;
                    break;
                case "closed":
                    _closed++;
                    _requestsOnClosed += connectionEvent.RequestCount ?? 0;
                    break;
            }
        }
    }

    public ConnectionStatistics Snapshot(int openNow)
    {
        lock (_gate)
        {
            return new ConnectionStatistics(
                openNow,
                _opened,
                _succeeded,
                _failed,
                new Dictionary<string, long>(_failures),
                _closed,
                _resumed,
                _succeeded == 0 ? 0 : (double)_resumed / _succeeded,
                _requestsOnClosed,
                _closed == 0 ? 0 : (double)_requestsOnClosed / _closed);
        }
    }
}

internal sealed record ConnectionEventFilter
{
    /// <summary>opened, handshake_succeeded, handshake_failed or closed.</summary>
    public string? Kind { get; init; }

    public string? ConnectionId { get; init; }

    public bool FailuresOnly { get; init; }
}

internal sealed record InspectorStatus(
    int RingCapacity,
    int RingCount,
    long RingEvicted,
    long DroppedExchanges,
    long DroppedConnectionEvents,
    long DroppedCaptures,
    int CaptureQueueCapacity,
    long ExchangesCaptured,
    long CaptureFailures,
    bool PersistEnabled,
    string? PersistFolder,
    SecretDisplayMode SecretDisplay,
    bool RevealAllowed,
    int FeedSubscribers);

internal enum ExportFormat
{
    /// <summary>One JSON document: <c>{"exported_at_utc", "masked": true, "count", "exchanges": [...]}</c>.</summary>
    Json,

    /// <summary>One exchange per line, the same shape as the inspector JSONL files.</summary>
    Jsonl,
}

internal enum RevealFailure
{
    /// <summary>Reveal is not enabled for this process (no <c>EKMMOCK_INSPECTOR_ALLOW_REVEAL=true</c> or not <c>SecretDisplay=Reveal</c>).</summary>
    Disabled,

    /// <summary>Not a field that can be revealed (only <c>request.value</c> and <c>response.value</c>).</summary>
    UnknownField,

    ExchangeNotFound,

    /// <summary>The exchange is there but the raw value was not retained (nothing secret in that position, an oversize or unparseable body, or already evicted).</summary>
    NotRetained,

    /// <summary>The audit entry could not be written; nothing is revealed without an audit entry.</summary>
    AuditUnavailable,
}

internal sealed class InspectorRevealException : Exception
{
    public InspectorRevealException(RevealFailure reason)
        : base(Describe(reason))
    {
        Reason = reason;
    }

    public RevealFailure Reason { get; }

    private static string Describe(RevealFailure reason) => reason switch
    {
        RevealFailure.Disabled => "Reveal is not enabled for this process.",
        RevealFailure.UnknownField => "That field cannot be revealed.",
        RevealFailure.ExchangeNotFound => "The exchange is no longer in the inspector.",
        RevealFailure.NotRetained => "The raw value is not available for this exchange.",
        _ => "The reveal was not audited and is therefore refused.",
    };
}

/// <summary>A revealed DEK as it was sent or returned (base64url text) with its length and fingerprint. Shown to the console user who asked, never stored, never exported.</summary>
internal sealed record RevealedField(long ExchangeId, string Field, string Value, int? Bytes, string? Fingerprint);

internal enum ReplayBlockReason
{
    None,

    /// <summary>Replay needs the raw request body, which is only retained while reveal is allowed (spec 8.4).</summary>
    RevealNotAllowed,

    ExchangeNotFound,

    /// <summary>The exchange is in the buffer but its raw body was not retained (an oversize body) or has been evicted.</summary>
    BodyNotRetained,
}

internal readonly record struct ReplayCheck(bool Possible, ReplayBlockReason Reason);

/// <summary>What the console's test client needs to send an exchange again. The body is a private copy that the sender must zero (<see cref="Dispose"/>).</summary>
internal sealed class ReplayRequest : IDisposable
{
    public ReplayRequest(string method, string pathAndQuery, string? contentType, byte[] body)
    {
        Method = method;
        PathAndQuery = pathAndQuery;
        ContentType = contentType;
        Body = body;
    }

    public string Method { get; }

    public string PathAndQuery { get; }

    public string? ContentType { get; }

    public byte[] Body { get; }

    public void Dispose() => System.Security.Cryptography.CryptographicOperations.ZeroMemory(Body);
}

internal sealed record ReplayOutcome(bool Sent, int? Status, string? Note);

/// <summary>The seam for M6: sends a request through the EKM endpoint with the console's test client certificate. Not implemented in M4.</summary>
internal interface IReplaySender
{
    Task<ReplayOutcome> SendAsync(ReplayRequest request, CancellationToken cancellationToken);
}

internal sealed class InspectorReplayException : Exception
{
    public InspectorReplayException(ReplayBlockReason reason)
        : base($"Replay is not possible: {reason}.")
    {
        Reason = reason;
    }

    public ReplayBlockReason Reason { get; }
}

/// <summary>What the console pages read (spec 8.5). Everything returned is masked and immutable.</summary>
internal interface IInspectorQuery
{
    /// <summary>The Live traffic list: newest first, filtered and paged.</summary>
    ExchangePage Query(ExchangeFilter? filter = null, ExchangePaging? paging = null);

    /// <summary>One exchange for the detail panel (masked), or null when it is no longer in the ring buffer.</summary>
    ExchangeRecord? Get(long exchangeId);

    long Count(ExchangeFilter? filter = null);

    /// <summary>Connection events, newest first (spec 8.2).</summary>
    IReadOnlyList<ConnectionEventRecord> ConnectionEvents(ConnectionEventFilter? filter = null, int limit = 200);

    IReadOnlyList<OpenConnectionInfo> OpenConnections();

    ConnectionStatistics ConnectionStatistics();

    DashboardSnapshot Dashboard();

    InspectorStatus Status();

    /// <summary>The KQL for the Managed HSM side of an exchange (spec 8.5), or null when the exchange is unknown.</summary>
    KqlSnippet? Kql(long exchangeId);
}

/// <summary>The inspector as the console and the CLI use it: the query side plus live feed, reveal, replay and export.</summary>
internal interface IInspector : IInspectorQuery
{
    IInspectorFeed Feed { get; }

    /// <summary>
    /// Reveals one masked field. Only possible when reveal is allowed (spec 8.4); every successful reveal is written to the audit log <em>before</em> the value is returned.
    /// </summary>
    /// <exception cref="InspectorRevealException">Reveal is disabled, the field or exchange is unknown, the value was not retained, or the audit entry could not be written.</exception>
    RevealedField Reveal(long exchangeId, string field, string user);

    ReplayCheck CanReplay(long exchangeId);

    /// <summary>Sends the exchange again through the registered <see cref="IReplaySender"/> (M6). Audited.</summary>
    Task<ReplayOutcome> ReplayAsync(long exchangeId, string user, CancellationToken cancellationToken = default);

    /// <summary>Writes the matching exchanges (oldest first) in masked form. The export can never contain a raw secret: it is built from <see cref="ExchangeRecord"/> only.</summary>
    Task ExportAsync(Stream destination, ExportFormat format, ExchangeFilter? filter = null, CancellationToken cancellationToken = default);
}

internal sealed class InspectorService : IInspector
{
    private static readonly byte[] NewLine = [(byte)'\n'];

    private readonly ExchangeRingBuffer _ring;
    private readonly DashboardAggregator _dashboard;
    private readonly ConnectionStatsStage _connectionStats;
    private readonly ConnectionEventStore _connectionEvents;
    private readonly ConnectionRegistry _registry;
    private readonly InspectorPipeline _pipeline;
    private readonly ConnectionEventSink _connectionSink;
    private readonly InspectorFeed _feed;
    private readonly IInspectorRevealGate _revealGate;
    private readonly IAuditLog _audit;
    private readonly InspectorOptions _options;
    private readonly InspectorJsonlWriter _jsonl;
    private readonly CaptureDiagnostics _diagnostics;
    private readonly IReplaySender? _replaySender;

    public InspectorService(
        ExchangeRingBuffer ring,
        DashboardAggregator dashboard,
        ConnectionStatsStage connectionStats,
        ConnectionEventStore connectionEvents,
        ConnectionRegistry registry,
        InspectorPipeline pipeline,
        ConnectionEventSink connectionSink,
        InspectorFeed feed,
        IInspectorRevealGate revealGate,
        IAuditLog audit,
        IOptions<InspectorOptions> options,
        InspectorJsonlWriter jsonl,
        CaptureDiagnostics diagnostics,
        IEnumerable<IReplaySender> replaySenders)
    {
        _ring = ring;
        _dashboard = dashboard;
        _connectionStats = connectionStats;
        _connectionEvents = connectionEvents;
        _registry = registry;
        _pipeline = pipeline;
        _connectionSink = connectionSink;
        _feed = feed;
        _revealGate = revealGate;
        _audit = audit;
        _options = options.Value;
        _jsonl = jsonl;
        _diagnostics = diagnostics;
        _replaySender = replaySenders.LastOrDefault();
    }

    public IInspectorFeed Feed => _feed;

    public ExchangePage Query(ExchangeFilter? filter = null, ExchangePaging? paging = null) => _ring.Query(filter, paging);

    public ExchangeRecord? Get(long exchangeId) => _ring.Get(exchangeId);

    public long Count(ExchangeFilter? filter = null) => _ring.CountMatching(filter);

    public IReadOnlyList<ConnectionEventRecord> ConnectionEvents(ConnectionEventFilter? filter = null, int limit = 200)
    {
        var events = _connectionEvents.Snapshot();
        var result = new List<ConnectionEventRecord>(Math.Min(limit, events.Count));
        for (var i = events.Count - 1; i >= 0 && result.Count < limit; i--)
        {
            var e = events[i];
            if (filter is not null)
            {
                if (filter.ConnectionId is not null && e.ConnectionId != filter.ConnectionId)
                {
                    continue;
                }

                if (filter.FailuresOnly && e.Kind != ConnectionEventKind.HandshakeFailed)
                {
                    continue;
                }
            }

            var record = ConnectionEventRecords.From(e);
            if (filter?.Kind is { } kind && record.Kind != kind)
            {
                continue;
            }

            result.Add(record);
        }

        return result;
    }

    public IReadOnlyList<OpenConnectionInfo> OpenConnections()
        => [.. _registry.Snapshot()
            .OrderBy(static c => c.OpenedAtUtc)
            .Select(static c => new OpenConnectionInfo(
                c.Id,
                c.RemoteEndPoint,
                c.OpenedAtUtc,
                Math.Round(c.Age.TotalMilliseconds, 1),
                c.RequestCount,
                c.HandshakeCompleted,
                c.TlsProtocol,
                c.CipherSuite,
                c.Alpn,
                c.Sni,
                c.ClientCertificate?.Subject))];

    public ConnectionStatistics ConnectionStatistics() => _connectionStats.Snapshot(_registry.OpenCount);

    public DashboardSnapshot Dashboard() => _dashboard.Snapshot(DroppedCaptures());

    public InspectorStatus Status() => new(
        _ring.Capacity,
        _ring.Count,
        _ring.Evicted,
        _pipeline.Dropped,
        _connectionSink.Dropped,
        DroppedCaptures(),
        _pipeline.Capacity,
        _diagnostics.Captured,
        _diagnostics.Failures,
        _options.Persist,
        _options.Persist ? _jsonl.Folder : null,
        _options.SecretDisplay,
        _revealGate.IsAllowed,
        _feed.SubscriberCount);

    public KqlSnippet? Kql(long exchangeId) => _ring.Get(exchangeId) is { } record ? KqlSnippets.For(record) : null;

    private long DroppedCaptures() => _pipeline.Dropped + _connectionSink.Dropped;

    // ---- reveal (spec 8.4) ----

    public RevealedField Reveal(long exchangeId, string field, string user)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(user);
        var target = $"exchange:{exchangeId}/{field}";

        if (!_revealGate.IsAllowed)
        {
            TryAudit(user, "inspector.reveal.denied", target, "reveal is not enabled for this process");
            throw new InspectorRevealException(RevealFailure.Disabled);
        }

        if (!RevealFields.IsKnown(field))
        {
            throw new InspectorRevealException(RevealFailure.UnknownField);
        }

        // Read under the ring buffer's lock so that an eviction cannot zero the bytes mid-read.
        var value = _ring.WithSecrets(exchangeId, secrets => secrets.ReadValue(field));
        if (value is null)
        {
            throw new InspectorRevealException(_ring.Contains(exchangeId, out _) ? RevealFailure.NotRetained : RevealFailure.ExchangeNotFound);
        }

        try
        {
            _audit.Append(user, "inspector.reveal", target);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new InspectorRevealException(RevealFailure.AuditUnavailable);
        }

        var (bytes, fingerprint) = Describe(value);
        return new RevealedField(exchangeId, field, value, bytes, fingerprint);
    }

    private static (int? Bytes, string? Fingerprint) Describe(string value)
    {
        var utf8 = System.Text.Encoding.UTF8.GetBytes(value);
        var decoded = new byte[Math.Max(1, Base64UrlCodec.MaxDecodedLength(utf8.Length))];
        try
        {
            return Base64UrlCodec.TryDecode(utf8, decoded, out var length) ? (length, SecretFingerprint.Compute(decoded.AsSpan(0, length))) : (null, null);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(decoded);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(utf8);
        }
    }

    private void TryAudit(string user, string action, string target, string detail)
    {
        try
        {
            _audit.Append(user, action, target, detail);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Refusing already happened; a failed audit of a refusal changes nothing.
        }
    }

    // ---- replay seam (spec 8.5; sending is M6) ----

    public ReplayCheck CanReplay(long exchangeId)
    {
        if (!_revealGate.IsAllowed)
        {
            return new ReplayCheck(false, ReplayBlockReason.RevealNotAllowed);
        }

        if (!_ring.Contains(exchangeId, out _))
        {
            return new ReplayCheck(false, ReplayBlockReason.ExchangeNotFound);
        }

        // The raw request body is retained only while reveal is allowed, and not for an oversize body.
        return _ring.WithSecrets(exchangeId, static s => s.HasRequestBody ? s : null) is not null
            ? new ReplayCheck(true, ReplayBlockReason.None)
            : new ReplayCheck(false, ReplayBlockReason.BodyNotRetained);
    }

    public async Task<ReplayOutcome> ReplayAsync(long exchangeId, string user, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(user);
        var check = CanReplay(exchangeId);
        if (!check.Possible)
        {
            throw new InspectorReplayException(check.Reason);
        }

        if (_replaySender is null)
        {
            return new ReplayOutcome(false, null, "No replay sender is registered.");
        }

        var record = _ring.Get(exchangeId) ?? throw new InspectorReplayException(ReplayBlockReason.ExchangeNotFound);
        var body = _ring.WithSecrets(exchangeId, static s => s.CopyRequestBody()) ?? throw new InspectorReplayException(ReplayBlockReason.BodyNotRetained);
        using var request = new ReplayRequest(
            record.Request.Method,
            record.Request.RawTarget ?? "/",
            record.Request.Headers.FirstOrDefault(static h => string.Equals(h.Name, "Content-Type", StringComparison.OrdinalIgnoreCase))?.Value,
            body);

        _audit.Append(user, "inspector.replay", $"exchange:{exchangeId}");
        return await _replaySender.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    // ---- export ----

    public async Task ExportAsync(Stream destination, ExportFormat format, ExchangeFilter? filter = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        var records = _ring.Snapshot().Where(r => filter?.Matches(r) ?? true).ToList();

        if (format == ExportFormat.Jsonl)
        {
            foreach (var record in records)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await destination.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(record, InspectorJsonContext.Default.ExchangeRecord), cancellationToken).ConfigureAwait(false);
                // Async write: the destination can be an HTTP response body, which does not allow synchronous I/O.
                await destination.WriteAsync(NewLine, cancellationToken).ConfigureAwait(false);
            }

            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        await using var writer = new Utf8JsonWriter(destination, new JsonWriterOptions { Indented = false, SkipValidation = false });
        writer.WriteStartObject();
        writer.WriteString("exported_at_utc", DateTimeOffset.UtcNow);
        writer.WriteBoolean("masked", true);
        writer.WriteNumber("count", records.Count);
        writer.WriteStartArray("exchanges");
        foreach (var record in records)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Serialize to bytes first: the source-generated serializer may flush a Utf8JsonWriter synchronously, which an HTTP response body (the console export) does not allow.
            writer.WriteRawValue(JsonSerializer.SerializeToUtf8Bytes(record, InspectorJsonContext.Default.ExchangeRecord), skipInputValidation: true);
            await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
