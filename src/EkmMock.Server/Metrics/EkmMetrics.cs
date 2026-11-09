using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using EkmMock.Server.Connections;
using EkmMock.Server.Ekm;

namespace EkmMock.Server.Metrics;

/// <summary>
/// The metrics of the EKM endpoint (spec 9). Every measurement is aggregated here with bounded label sets and rendered by <see cref="PrometheusExposition"/> for the
/// console's <c>/metrics</c> pull endpoint; the same numbers are also published through <see cref="System.Diagnostics.Metrics"/> instruments (meter <see cref="MeterName"/>)
/// so that <c>dotnet-counters</c> or an in-process listener sees them. There is no push exporter and no outbound telemetry (DECISIONS.md "M7: Metrics exporter").
/// <para>
/// <b>Cardinality rules.</b> Labels only ever take values from bounded sets, never client text: <c>op</c> is one of four wire names or <c>unrouted</c>; <c>status</c> is an HTTP
/// status the server itself produced (three digits, else <c>other</c>); <c>namespace</c> is a configured namespace name (at most <see cref="MaxNamespaceLabels"/> distinct
/// values, then <c>other</c>) or <c>unknown</c> for a path that no namespace claims; <c>alg</c> is one of the four supported names, <c>unsupported</c> or <c>none</c>;
/// <c>reason</c> is a <see cref="HandshakeFailureReason"/> label. Key names, client CNs and free text are never labels.
/// </para>
/// </summary>
internal sealed class EkmMetrics : IDisposable
{
    public const string MeterName = "EkmMock";
    public const string RequestsName = "ekmmock_requests_total";
    public const string RequestDurationName = "ekmmock_request_duration_seconds";
    public const string CryptoDurationName = "ekmmock_crypto_duration_seconds";
    public const string BudgetExceededName = "ekmmock_budget_exceeded_total";
    public const string HandshakeFailuresName = "ekmmock_tls_handshake_failures_total";
    public const string InspectorDroppedName = "ekmmock_inspector_dropped_total";
    public const string InFlightName = "ekmmock_inflight_requests";

    /// <summary>The label value for a request no namespace claimed (unknown prefix), and the overflow value beyond <see cref="MaxNamespaceLabels"/>.</summary>
    public const string UnknownNamespace = "unknown";
    public const string OtherLabel = "other";
    public const string UnroutedOperation = "unrouted";
    public const string NoAlgorithm = "none";
    public const string UnsupportedAlgorithm = "unsupported";
    public const int MaxNamespaceLabels = 256;

    /// <summary>Spec 9: the buckets of <c>ekmmock_request_duration_seconds</c>.</summary>
    public static readonly IReadOnlyList<double> RequestBuckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.25, 0.5, 1];

    /// <summary>
    /// The buckets of <c>ekmmock_crypto_duration_seconds</c>. The spec gives none for it; the request buckets start at 5 ms, far above a software HSM's microsecond
    /// wrap and unwrap, so these start at 0.1 ms (DECISIONS.md "M7: Metrics exporter").
    /// </summary>
    public static readonly IReadOnlyList<double> CryptoBuckets = [0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1];

    private static readonly HashSet<string> KnownAlgorithms = new(StringComparer.Ordinal) { "A256KW", "A256KWP", "RSA-OAEP-256", "RSA-OAEP" };

    private readonly Meter _meter;
    private readonly Counter<long> _requests;
    private readonly Histogram<double> _requestDuration;
    private readonly Histogram<double> _cryptoDuration;
    private readonly Counter<long> _budgetExceeded;
    private readonly Counter<long> _handshakeFailures;
    private readonly Counter<long> _inspectorDropped;
    private readonly ConcurrentDictionary<(string Op, string Status, string Namespace), Cell> _requestCounts = new();
    private readonly ConcurrentDictionary<string, HistogramData> _requestDurations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<(string Op, string Alg), HistogramData> _cryptoDurations = new();
    private readonly ConcurrentDictionary<string, Cell> _budgetExceededCounts = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, long> _failureCounts = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _namespaceLabels = new(StringComparer.Ordinal);
    private long _inspectorDroppedTotal;
    private Func<long> _inFlight = static () => 0;

    public EkmMetrics()
    {
        _meter = new Meter(MeterName);
        _requests = _meter.CreateCounter<long>(RequestsName, description: "EKM requests by operation, HTTP status and namespace.");
        _requestDuration = _meter.CreateHistogram(
            RequestDurationName,
            unit: "s",
            description: "Server time of EKM requests in seconds.",
            advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = [.. RequestBuckets] });
        _cryptoDuration = _meter.CreateHistogram(
            CryptoDurationName,
            unit: "s",
            description: "Time spent in the crypto engine in seconds, by operation and algorithm.",
            advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = [.. CryptoBuckets] });
        _budgetExceeded = _meter.CreateCounter<long>(BudgetExceededName, description: "Requests that missed the internal deadline (a crypto call that ended after it, or a request refused because it had passed).");
        _handshakeFailures = _meter.CreateCounter<long>(HandshakeFailuresName, description: "TLS handshakes on the EKM endpoint that did not complete, by reason.");
        _inspectorDropped = _meter.CreateCounter<long>(InspectorDroppedName, description: "Inspector capture records (exchanges and connection events) dropped because the bounded capture queue was full.");
        _meter.CreateObservableGauge(InFlightName, () => _inFlight(), description: "EKM requests currently holding a concurrency slot.");
    }

    /// <summary>Where the in-flight gauge reads from (the concurrency gate). Set once by the composition root.</summary>
    public void SetInFlightSource(Func<long> source) => _inFlight = source;

    public long InFlight => _inFlight();

    // ---- recording ----

    /// <summary>Counts one finished EKM exchange (any outcome) and its server time. Never blocks, never throws.</summary>
    public void RecordRequest(EkmOperation? operation, int status, string? namespaceName, TimeSpan duration)
    {
        var op = OperationLabel(operation);
        var statusLabel = StatusLabel(status);
        var ns = NamespaceLabel(namespaceName);
        _requestCounts.GetOrAdd((op, statusLabel, ns), static _ => new Cell()).Increment();
        _requestDurations.GetOrAdd(op, static _ => new HistogramData(RequestBuckets)).Record(duration);
        _requests.Add(1, new("op", op), new("status", statusLabel), new("namespace", ns));
        _requestDuration.Record(Math.Max(0, duration.TotalSeconds), new KeyValuePair<string, object?>("op", op));
    }

    /// <summary>Records the time of one crypto-engine call.</summary>
    public void RecordCrypto(EkmOperation? operation, string? algorithm, TimeSpan duration)
    {
        var op = OperationLabel(operation);
        var alg = AlgorithmLabel(algorithm);
        _cryptoDurations.GetOrAdd((op, alg), static _ => new HistogramData(CryptoBuckets)).Record(duration);
        _cryptoDuration.Record(Math.Max(0, duration.TotalSeconds), new("op", op), new("alg", alg));
    }

    /// <summary>Counts a request that missed the internal deadline (spec 10.1).</summary>
    public void RecordBudgetExceeded(EkmOperation? operation)
    {
        var op = OperationLabel(operation);
        _budgetExceededCounts.GetOrAdd(op, static _ => new Cell()).Increment();
        _budgetExceeded.Add(1, new KeyValuePair<string, object?>("op", op));
    }

    /// <summary>Counts one capture record that was dropped (spec 8.3). Never blocks, never throws.</summary>
    public void RecordInspectorDropped()
    {
        Interlocked.Increment(ref _inspectorDroppedTotal);
        _inspectorDropped.Add(1);
    }

    public void RecordHandshakeFailure(HandshakeFailureReason reason)
    {
        var label = HandshakeFailureReasons.Label(reason);
        _failureCounts.AddOrUpdate(label, 1, static (_, count) => count + 1);
        _handshakeFailures.Add(1, new KeyValuePair<string, object?>("reason", label));
    }

    // ---- reading (console, tests, exposition) ----

    /// <summary>Capture records dropped since the process started (the console shows it next to the dashboard).</summary>
    public long InspectorDroppedTotal => Interlocked.Read(ref _inspectorDroppedTotal);

    /// <summary>Total failures per <c>reason</c> label since the process started.</summary>
    public IReadOnlyDictionary<string, long> HandshakeFailureCounts => new Dictionary<string, long>(_failureCounts);

    public long TotalHandshakeFailures => _failureCounts.Values.Sum();

    internal IReadOnlyList<(string Op, string Status, string Namespace, long Count)> RequestCounts()
        => [.. _requestCounts.Select(static p => (p.Key.Op, p.Key.Status, p.Key.Namespace, p.Value.Value))];

    internal IReadOnlyList<(string Op, HistogramSnapshot Histogram)> RequestDurations()
        => [.. _requestDurations.Select(static p => (p.Key, p.Value.Snapshot()))];

    internal IReadOnlyList<(string Op, string Alg, HistogramSnapshot Histogram)> CryptoDurations()
        => [.. _cryptoDurations.Select(static p => (p.Key.Op, p.Key.Alg, p.Value.Snapshot()))];

    internal IReadOnlyList<(string Op, long Count)> BudgetExceeded()
        => [.. _budgetExceededCounts.Select(static p => (p.Key, p.Value.Value))];

    /// <summary>How many requests missed the internal deadline for an operation (tests and the console).</summary>
    public long BudgetExceededCount(EkmOperation? operation) => _budgetExceededCounts.TryGetValue(OperationLabel(operation), out var cell) ? cell.Value : 0;

    public long TotalBudgetExceeded => _budgetExceededCounts.Values.Sum(static c => c.Value);

    // ---- labels ----

    public static string OperationLabel(EkmOperation? operation) => operation?.WireName() ?? UnroutedOperation;

    public static string StatusLabel(int status) => status is >= 100 and <= 599 ? status.ToString(System.Globalization.CultureInfo.InvariantCulture) : OtherLabel;

    /// <summary>Only the four supported algorithm names (exact match, case-sensitive) are ever a label value; every other client string is <c>unsupported</c>.</summary>
    public static string AlgorithmLabel(string? algorithm)
        => algorithm is null ? NoAlgorithm : KnownAlgorithms.Contains(algorithm) ? algorithm : UnsupportedAlgorithm;

    private string NamespaceLabel(string? name)
    {
        if (name is null)
        {
            return UnknownNamespace;
        }

        if (_namespaceLabels.ContainsKey(name))
        {
            return name;
        }

        // Namespaces are created by the operator, so this bound is only a safety net; beyond it new names share one series instead of growing memory.
        if (_namespaceLabels.Count >= MaxNamespaceLabels)
        {
            return OtherLabel;
        }

        _namespaceLabels.TryAdd(name, 0);
        return name;
    }

    public void Dispose() => _meter.Dispose();

    private sealed class Cell
    {
        private long _value;

        public long Value => Interlocked.Read(ref _value);

        public void Increment() => Interlocked.Increment(ref _value);
    }
}

/// <summary>A cumulative histogram as Prometheus wants it: per upper bound the number of observations at or below it, plus the total count and the sum in seconds.</summary>
internal sealed record HistogramSnapshot(IReadOnlyList<double> Bounds, IReadOnlyList<long> Cumulative, long Count, double SumSeconds);

/// <summary>Lock-free histogram storage: one counter per bucket (the last one is <c>+Inf</c>) and the sum in 100 ns ticks.</summary>
internal sealed class HistogramData
{
    private readonly IReadOnlyList<double> _bounds;
    private readonly long[] _counts;
    private long _sumTicks;

    public HistogramData(IReadOnlyList<double> bounds)
    {
        _bounds = bounds;
        _counts = new long[bounds.Count + 1];
    }

    public void Record(TimeSpan duration)
    {
        var seconds = Math.Max(0, duration.TotalSeconds);
        var index = 0;
        while (index < _bounds.Count && seconds > _bounds[index])
        {
            index++;
        }

        Interlocked.Increment(ref _counts[index]);
        Interlocked.Add(ref _sumTicks, Math.Max(0, duration.Ticks));
    }

    public HistogramSnapshot Snapshot()
    {
        var cumulative = new long[_counts.Length];
        long running = 0;
        for (var i = 0; i < _counts.Length; i++)
        {
            running += Interlocked.Read(ref _counts[i]);
            cumulative[i] = running;
        }

        // The count is derived from the buckets so that +Inf and _count always agree, even while requests are being recorded during the scrape.
        return new HistogramSnapshot(_bounds, cumulative, running, Interlocked.Read(ref _sumTicks) / (double)TimeSpan.TicksPerSecond);
    }
}
