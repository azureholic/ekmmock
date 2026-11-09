using System.Threading.Channels;
using EkmMock.Server.Connections;
using EkmMock.Server.Inspector;
using EkmMock.Server.Tls;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.Options;

namespace EkmMock.Console.Tests;

/// <summary>A clock (and timers) the test moves by hand: <see cref="Advance"/> fires the timers that are due, synchronously.</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly List<ManualTimer> _timers = [];
    private DateTimeOffset _now;

    public ManualTimeProvider(DateTimeOffset start) => _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state, dueTime, period);
        lock (_timers)
        {
            _timers.Add(timer);
        }

        return timer;
    }

    public int ActiveTimers
    {
        get
        {
            lock (_timers)
            {
                return _timers.Count(static t => !t.Disposed);
            }
        }
    }

    public void Set(DateTimeOffset now) => _now = now;

    public void Advance(TimeSpan by)
    {
        var target = _now + by;
        while (true)
        {
            ManualTimer? next;
            lock (_timers)
            {
                next = _timers.Where(static t => !t.Disposed && t.Due is not null).OrderBy(static t => t.Due).FirstOrDefault(t => t.Due <= target);
            }

            if (next is null)
            {
                break;
            }

            _now = next.Due!.Value;
            next.Fire();
        }

        _now = target;
    }

    private sealed class ManualTimer : ITimer
    {
        private readonly ManualTimeProvider _owner;
        private readonly TimerCallback _callback;
        private readonly object? _state;
        private TimeSpan _period;

        public ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            _owner = owner;
            _callback = callback;
            _state = state;
            Change(dueTime, period);
        }

        public DateTimeOffset? Due { get; private set; }

        public bool Disposed { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            _period = period;
            Due = dueTime == Timeout.InfiniteTimeSpan ? null : _owner._now + dueTime;
            return true;
        }

        public void Fire()
        {
            Due = _period == Timeout.InfiniteTimeSpan || _period == TimeSpan.Zero ? null : Due + _period;
            _callback(_state);
        }

        public void Dispose() => Disposed = true;

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>A test <see cref="IConsoleStatusProvider"/>: the banners and the layout read what the test sets.</summary>
internal sealed class FakeStatus : IConsoleStatusProvider
{
    public bool DevMasterKey { get; set; }

    public bool RevealAllowed { get; set; }

    public bool Ready { get; set; } = true;

    public ConsoleStatus Get() => new("0.0.0-test", "LoopbackOnly", DevMasterKey, DevMasterKey, Ready, true, false, RevealAllowed, RevealAllowed ? "Reveal" : "Masked", 250, 150);

    public ReadinessResult CheckReadiness() => new(Ready, Ready ? [] : ["key_store"]);
}

internal sealed class FakeFaults : IFaultStatus
{
    public bool Active { get; private set; }

    public event Action? Changed;

    public void Set(bool active)
    {
        Active = active;
        Changed?.Invoke();
    }
}

internal sealed class FakeUser : IConsoleUser
{
    public ConsoleUserInfo Info { get; set; } = new(ConsoleUserInfo.LoopbackName, ConsoleUserInfo.LoopbackName, ConsoleAuthMode.LoopbackOnly);

    public ValueTask<ConsoleUserInfo> GetAsync() => ValueTask.FromResult(Info);
}

/// <summary>
/// An in-memory <see cref="IInspector"/> built from the real M4 parts (ring buffer, live feed, dashboard aggregate, connection statistics), so the console components run against
/// the real filtering, paging, feed and aggregation without a host. <see cref="Publish(ExchangeRecord)"/> is what the capture consumer does: store, then push to the feed.
/// </summary>
internal sealed class FakeInspector : IInspector
{
    private readonly ExchangeRingBuffer _ring = new(10_000);
    private readonly InspectorFeed _feed;
    private readonly DashboardAggregator _dashboard;
    private readonly ConnectionStatsStage _connectionStats = new();
    private readonly List<ConnectionEventRecord> _events = [];
    private readonly Dictionary<(long, string), string> _revealable = [];
    private long _connectionSequence;

    public FakeInspector(TimeProvider time)
    {
        _feed = new InspectorFeed(Options.Create(new InspectorOptions { SubscriberCapacity = 1000 }));
        _dashboard = new DashboardAggregator(time);
    }

    public List<(long ExchangeId, string Field, string User)> Reveals { get; } = [];

    public IReadOnlyList<OpenConnectionInfo> Open { get; set; } = [];

    public bool RevealEnabled { get; set; }

    public ReplayCheck Replay { get; set; } = new(false, ReplayBlockReason.RevealNotAllowed);

    public ReplayOutcome ReplayResult { get; set; } = new(true, 200, null);

    public List<(long ExchangeId, string User)> Replays { get; } = [];

    public bool ThrowOnQuery { get; set; }

    public IInspectorFeed Feed => _feed;

    public void Publish(ExchangeRecord record)
    {
        _ring.Add(record);
        _dashboard.Add(record);
        ((IInspectorStage)_feed).OnExchange(new CapturedExchange(record, null));
    }

    public void Publish(ConnectionEventRecord connection)
    {
        lock (_events)
        {
            _events.Add(connection);
        }

        _connectionStats.OnConnectionEvent(connection);
        ((IInspectorStage)_feed).OnConnectionEvent(connection);
    }

    public ConnectionEventRecord NewConnectionEvent(string kind, string connectionId = "conn-1", DateTimeOffset? at = null, string? failureReason = null, string? failureDescription = null)
        => new()
        {
            Sequence = Interlocked.Increment(ref _connectionSequence),
            ConnectionId = connectionId,
            Kind = kind,
            AtUtc = at ?? Rec.Epoch,
            RemoteEndPoint = "127.0.0.1:50000",
            TlsProtocol = kind == "handshake_succeeded" ? "TLS 1.3" : null,
            CipherSuite = kind == "handshake_succeeded" ? "TLS_AES_256_GCM_SHA384" : null,
            FailureReason = failureReason,
            FailureDescription = failureDescription,
            DurationMs = kind == "closed" ? 1500 : null,
            RequestCount = kind == "closed" ? 3 : null,
        };

    /// <summary>Makes <c>Reveal</c> return this raw value for the exchange and field (the test controls what "raw" is).</summary>
    public void AllowReveal(long exchangeId, string field, string value) => _revealable[(exchangeId, field)] = value;

    public ExchangePage Query(ExchangeFilter? filter = null, ExchangePaging? paging = null)
        => ThrowOnQuery ? throw new InvalidOperationException("boom (test)") : _ring.Query(filter, paging);

    public ExchangeRecord? Get(long exchangeId) => _ring.Get(exchangeId);

    public long Count(ExchangeFilter? filter = null) => _ring.CountMatching(filter);

    public IReadOnlyList<ConnectionEventRecord> ConnectionEvents(ConnectionEventFilter? filter = null, int limit = 200)
    {
        lock (_events)
        {
            return [.. Enumerable.Reverse(_events)
                .Where(e => (filter?.Kind is null || e.Kind == filter.Kind)
                    && (filter?.ConnectionId is null || e.ConnectionId == filter.ConnectionId)
                    && (filter?.FailuresOnly != true || e.Kind == "handshake_failed"))
                .Take(limit)];
        }
    }

    public IReadOnlyList<OpenConnectionInfo> OpenConnections() => Open;

    public ConnectionStatistics ConnectionStatistics() => _connectionStats.Snapshot(Open.Count);

    public DashboardSnapshot Dashboard() => _dashboard.Snapshot(0);

    public InspectorStatus Status() => new(10_000, 0, 0, 0, 0, 0, 8192, 0, 0, false, null, RevealEnabled ? SecretDisplayMode.Reveal : SecretDisplayMode.Masked, RevealEnabled, _feed.SubscriberCount);

    public KqlSnippet? Kql(long exchangeId) => _ring.Get(exchangeId) is { } record ? KqlSnippets.For(record) : null;

    public RevealedField Reveal(long exchangeId, string field, string user)
    {
        if (!RevealEnabled)
        {
            throw new InspectorRevealException(RevealFailure.Disabled);
        }

        if (!_revealable.TryGetValue((exchangeId, field), out var value))
        {
            throw new InspectorRevealException(RevealFailure.NotRetained);
        }

        Reveals.Add((exchangeId, field, user));
        return new RevealedField(exchangeId, field, value, 32, "3f9a1c07b2e4");
    }

    public ReplayCheck CanReplay(long exchangeId) => Replay;

    public Task<ReplayOutcome> ReplayAsync(long exchangeId, string user, CancellationToken cancellationToken = default)
    {
        Replays.Add((exchangeId, user));
        return Task.FromResult(ReplayResult);
    }

    public Task ExportAsync(Stream destination, ExportFormat format, ExchangeFilter? filter = null, CancellationToken cancellationToken = default) => Task.CompletedTask;
}

/// <summary>DOM helpers for the component tests.</summary>
internal static class Dom
{
    /// <summary>The visible text of an element with a space at every tag boundary (AngleSharp's <c>TextContent</c> glues <c>dt</c> and <c>dd</c> together), whitespace collapsed.</summary>
    public static string Text(AngleSharp.Dom.IElement element)
    {
        var spaced = System.Text.RegularExpressions.Regex.Replace(element.InnerHtml, "<[^>]+>", " ");
        return System.Text.RegularExpressions.Regex.Replace(System.Net.WebUtility.HtmlDecode(spaced), @"\s+", " ").Trim();
    }
}

/// <summary>Builds <see cref="ExchangeRecord"/>s for component tests (the same shape the capture produces, with controllable facts).</summary>
internal static class Rec
{
    public static readonly DateTimeOffset Epoch = new(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);

    public static ExchangeRecord Make(
        long id,
        string? op = "wrapkey",
        int status = 200,
        double ms = 5,
        string? ns = "_default",
        string? key = "aes-key-1",
        string? cn = "client.test",
        string? correlationId = "aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85",
        string? poolName = "pool-1",
        string? requestId = null,
        DateTimeOffset? at = null,
        string? code = null,
        string bodyText = """{"request_context":{"correlation_id":"c"}}""",
        string responseText = "{}",
        string? alg = "A256KWP",
        IReadOnlyList<MaskedField>? requestMasked = null,
        IReadOnlyList<MaskedField>? responseMasked = null,
        FaultFacts? fault = null,
        double authMs = 0.4,
        double cryptoMs = 1.2,
        double delayMs = 0,
        double queueMs = 0)
        => new()
        {
            Identity = new ExchangeIdentity(id, "conn-1", at ?? Epoch.AddMilliseconds(id), "127.0.0.1:50000"),
            Tls = new TlsFacts("TLS 1.3", "TLS_AES_256_GCM_SHA384", "http/1.1", "ekm.test", false, id == 1 ? 2.5 : null, (int)id),
            ClientCertificate = new ClientCertFacts
            {
                Present = cn is not null,
                CommonName = cn,
                Subject = cn is null ? null : $"CN={cn}",
                Issuer = "CN=Test CA",
                Serial = "0A",
                ThumbprintSha256 = "AB12",
                NotBeforeUtc = Epoch.AddDays(-1),
                NotAfterUtc = Epoch.AddDays(30),
                AuthEvaluated = true,
                ChainResult = "NoError",
                CommonNameAllowed = status != 401,
                NamespaceMatched = true,
                AuthFailure = status == 401 ? "CommonNameNotAllowed" : null,
            },
            Request = new RequestFacts
            {
                Method = "POST",
                HttpVersion = "HTTP/1.1",
                Operation = op,
                Namespace = ns,
                Key = key,
                ApiVersion = "0.1-preview",
                RawTarget = $"/{key}/{op}?api-version=0.1-preview",
                Headers = [new HeaderEntry("Content-Type", "application/json"), new HeaderEntry("Authorization", "[redacted]")],
                Body = new CapturedBody { SizeBytes = bodyText.Length, Text = bodyText, MaskedFields = requestMasked ?? [] },
            },
            Context = new EkmContextFacts(requestId ?? "req-" + id, correlationId, poolName, alg),
            Response = new ResponseFacts
            {
                Status = status,
                Code = code ?? (status >= 400 ? "Error" : null),
                Headers = [new HeaderEntry("Content-Type", "application/json")],
                Body = new CapturedBody { SizeBytes = responseText.Length, Text = responseText, MaskedFields = responseMasked ?? [] },
            },
            Timing = new TimingFacts
            {
                TotalMs = ms,
                AuthMs = authMs,
                CryptoMs = cryptoMs,
                InjectedDelayMs = delayMs,
                QueueWaitMs = queueMs,
                Budget = LatencyBudget.Classify(ms, 150, 250),
            },
            Key = new KeyFacts("oct", 256, "Enabled", 1, 0),
            Faults = fault,
        };
}
