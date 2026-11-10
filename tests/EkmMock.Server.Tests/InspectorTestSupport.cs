using System.Text;
using System.Text.Json;
using EkmMock.Server.Inspector;

namespace EkmMock.Server.Tests;

/// <summary>A reveal gate decided by the test (production reads the environment variable once at start).</summary>
internal sealed class TestRevealGate : IInspectorRevealGate
{
    public TestRevealGate(bool allowed) => IsAllowed = allowed;

    public bool IsAllowed { get; }
}

/// <summary>An audit log in memory, for tests that do not care about the file.</summary>
internal sealed class ListAuditLog : IAuditLog
{
    private readonly List<AuditEntry> _entries = [];

    public bool Fail { get; set; }

    /// <summary>Called with every entry just before it is stored (after the failure check); lets a test observe the world at the moment of the audit write.</summary>
    public Action<AuditEntry>? OnAppend { get; set; }

    public IReadOnlyList<AuditEntry> Entries
    {
        get
        {
            lock (_entries)
            {
                return [.. _entries];
            }
        }
    }

    public void Append(string user, string action, string target, string? detail = null)
    {
        if (Fail)
        {
            throw new IOException("audit unavailable (test)");
        }

        var entry = new AuditEntry(DateTimeOffset.UtcNow, user, action, target, detail);
        OnAppend?.Invoke(entry);
        lock (_entries)
        {
            _entries.Add(entry);
        }
    }

    public IReadOnlyList<AuditEntry> ReadRecent(int count = 200) => Entries;
}

/// <summary>A clock the test moves by hand.</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now;

    public ManualTimeProvider(DateTimeOffset start) => _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;

    public void Set(DateTimeOffset now) => _now = now;
}

/// <summary>A stage that blocks the consumer until the test lets it go (the "deliberately blocked consumer" of spec 14 test 24).</summary>
internal sealed class BlockingStage : IInspectorStage
{
    private readonly ManualResetEventSlim _release = new(false);
    private readonly ManualResetEventSlim _entered = new(false);
    private int _processed;
    private int _armed;
    private int _seen;

    public int Processed => Volatile.Read(ref _processed);

    /// <summary>Exchanges the consumer has been through (this stage is the last one), blocked or not.</summary>
    public int Seen => Volatile.Read(ref _seen);

    /// <summary>From now on the consumer blocks in this stage until <see cref="Release"/>.</summary>
    public void Arm() => Volatile.Write(ref _armed, 1);

    public bool WaitUntilBlocked(TimeSpan timeout) => _entered.Wait(timeout);

    public void Release() => _release.Set();

    public void OnExchange(CapturedExchange exchange)
    {
        if (Volatile.Read(ref _armed) == 0)
        {
            Interlocked.Increment(ref _seen);
            return;
        }

        _entered.Set();
        _release.Wait(TimeSpan.FromSeconds(60));
        Interlocked.Increment(ref _processed);
    }
}

/// <summary>Builds <see cref="ExchangeRecord"/>s for unit tests of the ring buffer, filters, aggregates and writers.</summary>
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
        string? correlationId = null,
        string? poolName = null,
        string? requestId = null,
        DateTimeOffset? at = null,
        string? code = null,
        string bodyText = "{}",
        string responseText = "{}",
        BudgetStatus? budget = null)
        => new()
        {
            Identity = new ExchangeIdentity(id, "conn-1", at ?? Epoch.AddMilliseconds(id), "127.0.0.1:50000"),
            ClientCertificate = new ClientCertFacts { Present = cn is not null, CommonName = cn, AuthEvaluated = true },
            Request = new RequestFacts
            {
                Method = "POST",
                Operation = op,
                Namespace = ns,
                Key = key,
                RawTarget = $"/{key}/{op}?api-version=0.1-preview",
                Body = new CapturedBody { SizeBytes = bodyText.Length, Text = bodyText },
            },
            Context = new EkmContextFacts(requestId, correlationId, poolName, "A256KWP"),
            Response = new ResponseFacts
            {
                Status = status,
                Code = code ?? (status >= 400 ? "Error" : null),
                Body = new CapturedBody { SizeBytes = responseText.Length, Text = responseText },
            },
            Timing = new TimingFacts
            {
                TotalMs = ms,
                Budget = budget ?? LatencyBudget.Classify(ms, 150, 250),
            },
        };
}

internal static class JsonText
{
    public static string Pretty(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
    }

    public static string Serialize(ExchangeRecord record)
        => Encoding.UTF8.GetString(JsonSerializer.SerializeToUtf8Bytes(record, InspectorJsonContext.Default.ExchangeRecord));
}
