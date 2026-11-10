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

/// <summary>The <c>Audit</c> configuration section: size-based rotation of <c>audit.jsonl</c> (security review L3).</summary>
internal sealed class AuditOptions
{
    public const string SectionName = "Audit";

    public const long DefaultMaxFileBytes = 50L * 1024 * 1024;

    public const int DefaultMaxFiles = 5;

    /// <summary>The audit file is rolled over (<c>audit.1.jsonl</c>, <c>audit.2.jsonl</c>, ...) before it would grow past this size. Default 50 MiB.</summary>
    public long MaxFileBytes { get; set; } = DefaultMaxFileBytes;

    /// <summary>How many rolled-over files are kept (the oldest is deleted). Default 5, so at most <c>MaxFileBytes * (MaxFiles + 1)</c> of audit history.</summary>
    public int MaxFiles { get; set; } = DefaultMaxFiles;

    public bool IsValid(out string error)
    {
        if (MaxFileBytes < 4096)
        {
            error = "Audit:MaxFileBytes must be at least 4096";
        }
        else if (MaxFiles is < 1 or > 100)
        {
            error = "Audit:MaxFiles must be between 1 and 100";
        }
        else
        {
            error = string.Empty;
            return true;
        }

        return false;
    }
}

internal sealed class AuditOptionsValidator : IValidateOptions<AuditOptions>
{
    public ValidateOptionsResult Validate(string? name, AuditOptions options)
        => options.IsValid(out var error) ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(error);
}

/// <summary>
/// <c>audit.jsonl</c> on the data volume: one JSON object per line, appended under a lock with one write call per line and flushed to disk before
/// <see cref="Append"/> returns (an audit entry that is only in a buffer is not an audit entry). Text fields are JSON-escaped by the serializer and bounded,
/// so a hostile user name cannot forge a second line.
/// <para>
/// Security review L3/L4: the file is created readable and writable by its owner only on Unix; it is rolled over by size (<see cref="AuditOptions"/>, <c>audit.1.jsonl</c> is the
/// newest rolled-over file); and reading is bounded: <see cref="ReadRecent"/> reads backwards from the end of the newest file(s) in blocks and deserialises only the requested
/// number of lines, never the whole history.
/// </para>
/// </summary>
internal sealed class FileAuditLog : IAuditLog
{
    public const string FileName = "audit.jsonl";
    private const int MaxFieldLength = 256;
    private const int BlockBytes = 64 * 1024;

    private readonly object _gate = new();
    private readonly string _path;
    private readonly TimeProvider _time;
    private readonly long _maxFileBytes;
    private readonly int _maxFiles;

    public FileAuditLog(IOptions<DataOptions> data, IOptions<AuditOptions> options, TimeProvider time)
        : this(Path.Combine(Path.GetFullPath(data.Value.Path), FileName), time, options.Value.MaxFileBytes, options.Value.MaxFiles)
    {
    }

    public FileAuditLog(string path, TimeProvider time, long maxFileBytes = AuditOptions.DefaultMaxFileBytes, int maxFiles = AuditOptions.DefaultMaxFiles)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFileBytes, 1L);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFiles, 1);
        _path = path;
        _time = time;
        _maxFileBytes = maxFileBytes;
        _maxFiles = maxFiles;
    }

    public string FilePath => _path;

    /// <summary>The path of the n-th rolled-over file (1 is the newest).</summary>
    public string RolledPath(int n)
    {
        var directory = Path.GetDirectoryName(_path)!;
        return Path.Combine(directory, Path.GetFileNameWithoutExtension(_path) + "." + n.ToString(System.Globalization.CultureInfo.InvariantCulture) + Path.GetExtension(_path));
    }

    /// <summary>Creates the file for appending, with owner-only permissions on Unix (the audit log names users and targets).</summary>
    internal static FileStream OpenForAppend(string path)
        => new(path, OwnerOnlyFile.Options(FileMode.Append, FileAccess.Write, FileShare.Read, bufferSize: 1));

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
            RollOverIfNeeded(buffer.Length);
            using var stream = OpenForAppend(_path);
            stream.Write(buffer);
            stream.Flush(flushToDisk: true);
        }
    }

    // Caller holds the lock. audit.jsonl becomes audit.1.jsonl, audit.1 becomes audit.2, ...; the file that would become audit.{MaxFiles + 1} is deleted.
    private void RollOverIfNeeded(int incomingBytes)
    {
        var info = new FileInfo(_path);
        if (!info.Exists || info.Length == 0 || info.Length + incomingBytes <= _maxFileBytes)
        {
            return;
        }

        File.Delete(RolledPath(_maxFiles));
        for (var n = _maxFiles - 1; n >= 1; n--)
        {
            if (File.Exists(RolledPath(n)))
            {
                File.Move(RolledPath(n), RolledPath(n + 1), overwrite: true);
            }
        }

        File.Move(_path, RolledPath(1), overwrite: true);
    }

    public IReadOnlyList<AuditEntry> ReadRecent(int count = 200)
    {
        if (count < 1)
        {
            return [];
        }

        lock (_gate)
        {
            // Newest file first, then the rolled-over ones, until enough lines were collected; each file is read from its end.
            var groups = new List<List<AuditEntry>>();
            var needed = count;
            for (var n = 0; n <= _maxFiles && needed > 0; n++)
            {
                var path = n == 0 ? _path : RolledPath(n);
                if (!File.Exists(path))
                {
                    continue;
                }

                var entries = ReadTail(path, needed);
                groups.Add(entries);
                needed -= entries.Count;
            }

            var all = new List<AuditEntry>(count);
            for (var g = groups.Count - 1; g >= 0; g--)
            {
                all.AddRange(groups[g]);
            }

            return all.Count <= count ? all : all[^count..];
        }
    }

    /// <summary>The last <paramref name="count"/> entries of one file, oldest first, read from the end in blocks. A line that does not parse (a torn last write) is skipped.</summary>
    private static List<AuditEntry> ReadTail(string path, int count)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var blocks = new List<byte[]>();
        var position = stream.Length;
        var newlines = 0;
        while (position > 0 && newlines <= count)
        {
            var size = (int)Math.Min(BlockBytes, position);
            position -= size;
            var block = new byte[size];
            stream.Seek(position, SeekOrigin.Begin);
            stream.ReadExactly(block);
            newlines += block.AsSpan().Count((byte)'\n');
            blocks.Add(block);
        }

        blocks.Reverse();
        var text = System.Text.Encoding.UTF8.GetString(blocks.SelectMany(static b => b).ToArray());
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var startIndex = position > 0 ? 1 : 0; // the first line of a partial read may be cut in the middle
        var result = new List<AuditEntry>(Math.Min(count, lines.Length));
        for (var i = Math.Max(startIndex, lines.Length - count - 1); i < lines.Length; i++)
        {
            try
            {
                if (JsonSerializer.Deserialize(lines[i], InspectorJsonContext.Default.AuditEntry) is { } entry)
                {
                    result.Add(entry);
                }
            }
            catch (JsonException)
            {
                // A torn or foreign line: not an entry.
            }
        }

        return result.Count <= count ? result : result[^count..];
    }

    private static string Bound(string value)
        => string.IsNullOrEmpty(value) ? "-" : value.Length > MaxFieldLength ? value[..MaxFieldLength] : value;
}

/// <summary>
/// Files that name users, targets and traffic (<c>audit.jsonl</c>, the inspector JSONL files) are created readable and writable by their owner only on Unix, like the key store (security
/// review L4). On Windows the permissions come from the data folder's ACL. The mode applies when the file is <em>created</em>; an existing file keeps its mode.
/// </summary>
internal static class OwnerOnlyFile
{
    /// <summary>The Unix mode of a new file: <c>rw-------</c>.</summary>
    public const UnixFileMode CreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public static FileStreamOptions Options(FileMode mode, FileAccess access, FileShare share, int bufferSize = 4096)
    {
        var options = new FileStreamOptions { Mode = mode, Access = access, Share = share, BufferSize = bufferSize };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = CreateMode;
        }

        return options;
    }
}