using System.Text.Json;
using EkmMock.Server.Hosting;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Inspector;

/// <summary>One audit entry (spec 5.4): who did what, when, to what. <see cref="Detail"/> is a short fixed note, never a secret.</summary>
internal sealed record AuditEntry(DateTimeOffset At, string User, string Action, string Target, string? Detail = null);

/// <summary>
/// The append-only audit log of console actions (spec 5.4). The inspector uses it now (every reveal and replay); M6 wires the Audit log page and the other
/// state-changing console actions to the same abstraction.
/// </summary>
internal interface IAuditLog
{
    /// <summary>Appends one entry. Must be atomic per entry and safe to call from any thread. Throws when the entry cannot be written (callers that guard a secret fail closed).</summary>
    void Append(string user, string action, string target, string? detail = null);

    /// <summary>The newest <paramref name="count"/> entries, oldest first.</summary>
    IReadOnlyList<AuditEntry> ReadRecent(int count = 200);
}

/// <summary>
/// <c>audit.jsonl</c> on the data volume: one JSON object per line, appended under a lock with one write call per line and flushed to disk before
/// <see cref="Append"/> returns (an audit entry that is only in a buffer is not an audit entry). Text fields are JSON-escaped by the serializer and bounded,
/// so a hostile user name cannot forge a second line.
/// </summary>
internal sealed class FileAuditLog : IAuditLog
{
    public const string FileName = "audit.jsonl";
    private const int MaxFieldLength = 256;

    private readonly object _gate = new();
    private readonly string _path;
    private readonly TimeProvider _time;

    public FileAuditLog(IOptions<DataOptions> data, TimeProvider time)
        : this(Path.Combine(Path.GetFullPath(data.Value.Path), FileName), time)
    {
    }

    public FileAuditLog(string path, TimeProvider time)
    {
        _path = path;
        _time = time;
    }

    public string FilePath => _path;

    public void Append(string user, string action, string target, string? detail = null)
    {
        var entry = new AuditEntry(_time.GetUtcNow(), Bound(user), Bound(action), Bound(target), detail is null ? null : Bound(detail));
        var line = JsonSerializer.SerializeToUtf8Bytes(entry, InspectorJsonContext.Default.AuditEntry);
        var buffer = new byte[line.Length + 1];
        line.CopyTo(buffer, 0);
        buffer[^1] = (byte)'\n';

        lock (_gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            using var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read, bufferSize: 1);
            stream.Write(buffer);
            stream.Flush(flushToDisk: true);
        }
    }

    public IReadOnlyList<AuditEntry> ReadRecent(int count = 200)
    {
        lock (_gate)
        {
            if (!File.Exists(_path))
            {
                return [];
            }

            var entries = new List<AuditEntry>();
            using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            while (reader.ReadLine() is { } line)
            {
                if (line.Length > 0 && JsonSerializer.Deserialize(line, InspectorJsonContext.Default.AuditEntry) is { } entry)
                {
                    entries.Add(entry);
                }
            }

            return entries.Count <= count ? entries : entries[^count..];
        }
    }

    private static string Bound(string value)
        => string.IsNullOrEmpty(value) ? "-" : value.Length > MaxFieldLength ? value[..MaxFieldLength] : value;
}
