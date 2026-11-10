namespace EkmMock.Server.Inspector;

/// <summary>The status classes of the live traffic filter (spec 8.5).</summary>
internal enum StatusClass
{
    Success = 2,
    ClientError = 4,
    ServerError = 5,
}

/// <summary>
/// The filters of the Live traffic page (spec 8.5), all optional and combined with AND. <see cref="Operation"/>, <see cref="Namespace"/>, <see cref="Key"/> and
/// <see cref="ClientCommonName"/> are exact, case-sensitive matches (a CN is compared exactly everywhere else too); <see cref="Text"/> is a case-insensitive substring
/// over <c>correlation_id</c>, <c>pool_name</c> and <c>request_id</c>. "Over budget" means red (above the latency budget); "errors" means a status of 400 or more.
/// </summary>
internal sealed record ExchangeFilter
{
    public string? Operation { get; init; }

    public StatusClass? StatusClass { get; init; }

    public string? Namespace { get; init; }

    public string? Key { get; init; }

    public string? ClientCommonName { get; init; }

    public string? Text { get; init; }

    public bool OnlyErrors { get; init; }

    public bool OnlyOverBudget { get; init; }

    /// <summary>Hide the Managed HSM health probes (<c>info</c>).</summary>
    public bool HideInfo { get; init; }

    public bool Matches(ExchangeRecord record)
    {
        if (Operation is not null && !string.Equals(record.Request.Operation, Operation, StringComparison.Ordinal))
        {
            return false;
        }

        if (StatusClass is { } statusClass && record.Response.Status / 100 != (int)statusClass)
        {
            return false;
        }

        if (Namespace is not null && !string.Equals(record.Request.Namespace, Namespace, StringComparison.Ordinal))
        {
            return false;
        }

        if (Key is not null && !string.Equals(record.Request.Key, Key, StringComparison.Ordinal))
        {
            return false;
        }

        if (ClientCommonName is not null && !string.Equals(record.ClientCertificate.CommonName, ClientCommonName, StringComparison.Ordinal))
        {
            return false;
        }

        if (OnlyErrors && record.Response.Status < 400)
        {
            return false;
        }

        if (OnlyOverBudget && record.Timing.Budget != BudgetStatus.Red)
        {
            return false;
        }

        if (HideInfo && string.Equals(record.Request.Operation, "info", StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(Text))
        {
            var context = record.Context;
            if (!Contains(context.CorrelationId, Text) && !Contains(context.PoolName, Text) && !Contains(context.RequestId, Text))
            {
                return false;
            }
        }

        return true;
    }

    private static bool Contains(string? haystack, string needle) => haystack?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true;
}

/// <summary>
/// Paging over the newest-first list. Without a cursor the newest <see cref="Limit"/> matches are returned. <see cref="BeforeId"/> continues older (exchange ids below
/// it, for scrolling down); <see cref="AfterId"/> returns what is newer than a cursor (for catching up after a pause). Exchange ids are sequential, so cursors are stable
/// while the ring buffer evicts.
/// </summary>
internal sealed record ExchangePaging
{
    public const int MaxLimit = 1000;

    public int Limit { get; init; } = 100;

    public long? BeforeId { get; init; }

    public long? AfterId { get; init; }
}

/// <summary>One page of the newest-first list. <see cref="NextBeforeId"/> is the cursor for the next (older) page, null when there is none.</summary>
internal sealed record ExchangePage(IReadOnlyList<ExchangeRecord> Items, bool HasMore, long? NextBeforeId, int InBuffer, int Capacity);

/// <summary>
/// The in-memory ring buffer of exchanges (spec 8.3, default 10 000). One writer (the consumer) and any number of readers; every operation takes the same short lock, and
/// readers copy references out and filter outside the lock. The buffer is kept sorted by exchange id (records arrive in completion order, which can differ slightly from
/// start order under concurrency), so lookup by id is a binary search and "newest first" is simply the tail.
/// <para>
/// The slot of an exchange also holds its <see cref="RetainedSecrets"/> (only when reveal is allowed): they are evicted together with the record and zeroed on eviction and on <see cref="Clear"/>.
/// </para>
/// <para>
/// The buffer is bounded twice (security review M2): by record count (<see cref="Capacity"/>) and by an <em>estimated</em> number of retained bytes (<see cref="MaxBytes"/>). The estimate of a
/// record (<see cref="ExchangeRecordSize"/>) is computed once, when the record is added, and the oldest records are evicted (their raw secrets zeroed) until the total is under the cap. The newest
/// record is always kept, even when it alone is larger than the cap.
/// </para>
/// </summary>
internal sealed class ExchangeRingBuffer : IInspectorStage
{
    private readonly object _gate = new();
    private readonly Slot?[] _slots;
    private int _head;
    private int _count;
    private long _evicted;
    private long _retainedBytes;

    public ExchangeRingBuffer(int capacity, long maxBytes = InspectorOptions.DefaultMaxBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBytes, 1L);
        _slots = new Slot?[capacity];
        Capacity = capacity;
        MaxBytes = maxBytes;
    }

    public ExchangeRingBuffer(Microsoft.Extensions.Options.IOptions<InspectorOptions> options)
        : this(options.Value.RingBufferSize, options.Value.MaxBytes)
    {
    }

    public int Capacity { get; }

    /// <summary>The cap of <see cref="RetainedBytes"/> (<c>Inspector:MaxBytes</c>).</summary>
    public long MaxBytes { get; }

    /// <summary>The estimated memory the stored records retain right now (see <see cref="ExchangeRecordSize"/>).</summary>
    public long RetainedBytes
    {
        get
        {
            lock (_gate)
            {
                return _retainedBytes;
            }
        }
    }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _count;
            }
        }
    }

    /// <summary>Records pushed out by newer ones since the process started.</summary>
    public long Evicted => Interlocked.Read(ref _evicted);

    void IInspectorStage.OnExchange(CapturedExchange exchange) => Add(exchange.Record, exchange.Secrets);

    public void Add(ExchangeRecord record, RetainedSecrets? secrets = null)
    {
        lock (_gate)
        {
            if (_count == Capacity)
            {
                EvictOldest();
            }

            var bytes = ExchangeRecordSize.Estimate(record, secrets);
            _slots[Physical(_count)] = new Slot(record, secrets, bytes);
            _count++;
            _retainedBytes += bytes;

            // Keep the buffer ordered by id: a record that finished late moves back past the few that finished before it.
            for (var i = _count - 1; i > 0 && Logical(i - 1).Record.Id > Logical(i).Record.Id; i--)
            {
                (_slots[Physical(i - 1)], _slots[Physical(i)]) = (_slots[Physical(i)], _slots[Physical(i - 1)]);
            }

            // The byte cap: drop the oldest records until the estimate fits, but never the only one left.
            while (_retainedBytes > MaxBytes && _count > 1)
            {
                EvictOldest();
            }
        }
    }

    // Caller holds the lock and guarantees _count > 0.
    private void EvictOldest()
    {
        var oldest = _slots[_head];
        oldest?.Secrets?.Zero();
        _retainedBytes -= oldest?.Bytes ?? 0;
        _slots[_head] = null;
        _head = (_head + 1) % Capacity;
        _count--;
        Interlocked.Increment(ref _evicted);
    }

    public ExchangeRecord? Get(long id)
    {
        lock (_gate)
        {
            var index = IndexOf(id);
            return index < 0 ? null : Logical(index).Record;
        }
    }

    /// <summary>Runs <paramref name="read"/> under the buffer's lock with the secrets of an exchange (so they cannot be zeroed by an eviction meanwhile). Null when the exchange or its secrets are gone.</summary>
    public T? WithSecrets<T>(long id, Func<RetainedSecrets, T?> read)
        where T : class
    {
        lock (_gate)
        {
            var index = IndexOf(id);
            return index >= 0 && Logical(index).Secrets is { } secrets ? read(secrets) : null;
        }
    }

    /// <summary>True when the exchange is in the buffer; <paramref name="hasSecrets"/> tells whether raw bodies are retained for it.</summary>
    public bool Contains(long id, out bool hasSecrets)
    {
        lock (_gate)
        {
            var index = IndexOf(id);
            hasSecrets = index >= 0 && Logical(index).Secrets is { IsEmpty: false };
            return index >= 0;
        }
    }

    /// <summary>All records, oldest first.</summary>
    public IReadOnlyList<ExchangeRecord> Snapshot()
    {
        lock (_gate)
        {
            var list = new ExchangeRecord[_count];
            for (var i = 0; i < _count; i++)
            {
                list[i] = Logical(i).Record;
            }

            return list;
        }
    }

    public long CountMatching(ExchangeFilter? filter)
    {
        var snapshot = Snapshot();
        return filter is null ? snapshot.Count : snapshot.LongCount(filter.Matches);
    }

    public ExchangePage Query(ExchangeFilter? filter = null, ExchangePaging? paging = null)
    {
        paging ??= new ExchangePaging();
        var limit = Math.Clamp(paging.Limit, 1, ExchangePaging.MaxLimit);
        var snapshot = Snapshot();
        var matches = new List<ExchangeRecord>(Math.Min(limit, 128));
        var more = false;

        for (var i = snapshot.Count - 1; i >= 0; i--)
        {
            var record = snapshot[i];
            if (paging.BeforeId is { } before && record.Id >= before)
            {
                continue;
            }

            if (paging.AfterId is { } after && record.Id <= after)
            {
                break; // ids only get smaller from here
            }

            if (filter is not null && !filter.Matches(record))
            {
                continue;
            }

            if (matches.Count == limit)
            {
                more = true;
                break;
            }

            matches.Add(record);
        }

        return new ExchangePage(matches, more, more && matches.Count > 0 ? matches[^1].Id : null, snapshot.Count, Capacity);
    }

    /// <summary>Removes everything and zeroes all retained secrets.</summary>
    public void Clear()
    {
        lock (_gate)
        {
            for (var i = 0; i < Capacity; i++)
            {
                _slots[i]?.Secrets?.Zero();
                _slots[i] = null;
            }

            _head = 0;
            _count = 0;
            _retainedBytes = 0;
        }
    }

    private int Physical(int logicalIndex) => (_head + logicalIndex) % Capacity;

    private Slot Logical(int logicalIndex) => _slots[Physical(logicalIndex)]!;

    private int IndexOf(long id)
    {
        int low = 0, high = _count - 1;
        while (low <= high)
        {
            var mid = low + ((high - low) / 2);
            var candidate = Logical(mid).Record.Id;
            if (candidate == id)
            {
                return mid;
            }

            if (candidate < id)
            {
                low = mid + 1;
            }
            else
            {
                high = mid - 1;
            }
        }

        return -1;
    }

    private sealed record Slot(ExchangeRecord Record, RetainedSecrets? Secrets, long Bytes);
}

/// <summary>
/// A cheap estimate of the memory a stored <see cref="ExchangeRecord"/> retains (security review M2): every string it holds at two bytes per character plus a fixed overhead
/// per object group, plus the raw bodies kept for reveal. It follows the strings an unauthenticated peer can make large (target, headers, bodies, certificate names); it does not try to
/// model the CLR object layout exactly, which is why the figure is documented as approximate. Computed once per record, on the consumer thread, never on the request path.
/// </summary>
internal static class ExchangeRecordSize
{
    /// <summary>Object headers, references, numbers and small fixed strings of one record.</summary>
    public const long FixedOverheadBytes = 1024;

    private const long PerHeaderOverheadBytes = 48;
    private const long PerMaskedFieldOverheadBytes = 96;

    public static long Estimate(ExchangeRecord record, RetainedSecrets? secrets = null)
    {
        long total = FixedOverheadBytes;
        total += Chars(record.Identity.ConnectionId) + Chars(record.Identity.RemoteEndPoint);

        if (record.Tls is { } tls)
        {
            total += Chars(tls.Protocol) + Chars(tls.CipherSuite) + Chars(tls.Alpn) + Chars(tls.Sni);
        }

        var cert = record.ClientCertificate;
        total += Chars(cert.Subject) + Chars(cert.Issuer) + Chars(cert.Serial) + Chars(cert.ThumbprintSha256) + Chars(cert.CommonName) + Chars(cert.ChainResult) + Chars(cert.AuthFailure);

        var request = record.Request;
        total += Chars(request.Method) + Chars(request.HttpVersion) + Chars(request.RawTarget) + Chars(request.Prefix) + Chars(request.Namespace)
            + Chars(request.Key) + Chars(request.Operation) + Chars(request.ApiVersion) + Headers(request.Headers) + Body(request.Body);

        var context = record.Context;
        total += Chars(context.RequestId) + Chars(context.CorrelationId) + Chars(context.PoolName) + Chars(context.Algorithm);

        var response = record.Response;
        total += Chars(response.Code) + Headers(response.Headers) + Body(response.Body);

        if (record.Key is { } key)
        {
            total += Chars(key.Type) + Chars(key.State);
        }

        if (record.Faults is { } faults)
        {
            total += Chars(faults.Rule) + Chars(faults.Kind) + Chars(faults.Summary) + Chars(faults.Description);
        }

        return total + (secrets?.ApproximateBytes ?? 0);
    }

    private static long Chars(string? value) => value is null ? 0 : (long)value.Length * sizeof(char);

    private static long Headers(IReadOnlyList<HeaderEntry> headers)
    {
        long total = 0;
        for (var i = 0; i < headers.Count; i++)
        {
            total += PerHeaderOverheadBytes + Chars(headers[i].Name) + Chars(headers[i].Value);
        }

        return total;
    }

    private static long Body(CapturedBody body)
    {
        var total = Chars(body.Text) + Chars(body.Note);
        for (var i = 0; i < body.MaskedFields.Count; i++)
        {
            var field = body.MaskedFields[i];
            total += PerMaskedFieldOverheadBytes + Chars(field.Field) + Chars(field.Display) + Chars(field.Fingerprint);
        }

        return total;
    }
}
