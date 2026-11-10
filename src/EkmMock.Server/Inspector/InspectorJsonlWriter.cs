using System.Globalization;
using System.Text.Json;
using EkmMock.Server.Hosting;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Inspector;

/// <summary>
/// The optional persistence of the inspector (spec 8.3, <c>Inspector:Persist=true</c>): one JSON object per line, exchanges and connection events side by side
/// (<c>"type":"exchange"</c> / <c>"type":"connection"</c>). <b>Always masked</b>: it serialises <see cref="ExchangeRecord"/>, which cannot hold a raw secret
/// (the raw bodies live in <see cref="RetainedSecrets"/> in memory only), so there is no code path that writes an unmasked value.
/// <para>
/// Files are named <c>inspector-yyyyMMdd.jsonl</c> (UTC day, <b>daily rotation</b>). A file is rolled over to <c>inspector-yyyyMMdd.1.jsonl</c>, <c>.2</c>, ... before it would
/// exceed <see cref="InspectorOptions.MaxFileBytes"/> (<b>size cap</b>). Files older than <see cref="InspectorOptions.RetainDays"/> days, and the oldest files beyond
/// <see cref="InspectorOptions.MaxTotalBytes"/> in total, are deleted (<b>prune</b>) whenever a new file is opened. Writes are serialised by a lock (the exchange consumer and
/// the connection pump are two threads) and flushed when the queue runs empty. An I/O failure drops that line and is logged (rate limited); it never reaches a request.
/// </para>
/// </summary>
internal sealed class InspectorJsonlWriter : IInspectorStage, IDisposable
{
    private const string FilePrefix = "inspector-";
    private const string FileExtension = ".jsonl";

    private readonly object _gate = new();
    private readonly InspectorOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly string _folder;
    private FileStream? _stream;
    private DateOnly _day;
    private int _index;
    private long _size;
    private long _writeFailures;
    private bool _disposed;

    public InspectorJsonlWriter(IOptions<InspectorOptions> options, IOptions<DataOptions> data, TimeProvider time, ILoggerFactory loggerFactory)
    {
        _options = options.Value;
        _time = time;
        _logger = loggerFactory.CreateLogger("EkmMock.Inspector");
        _folder = string.IsNullOrWhiteSpace(_options.PersistPath)
            ? Path.Combine(Path.GetFullPath(data.Value.Path), "inspector")
            : Path.GetFullPath(_options.PersistPath);
    }

    public bool Enabled => _options.Persist;

    public string Folder => _folder;

    /// <summary>The file currently written to, or null when none is open.</summary>
    public string? CurrentFile
    {
        get
        {
            lock (_gate)
            {
                return _stream?.Name;
            }
        }
    }

    void IInspectorStage.OnExchange(CapturedExchange exchange)
    {
        if (_options.Persist)
        {
            Write(JsonSerializer.SerializeToUtf8Bytes(exchange.Record, InspectorJsonContext.Default.ExchangeRecord));
        }
    }

    void IInspectorStage.OnConnectionEvent(ConnectionEventRecord connectionEvent)
    {
        if (_options.Persist)
        {
            Write(JsonSerializer.SerializeToUtf8Bytes(connectionEvent, InspectorJsonContext.Default.ConnectionEventRecord));
            Flush(); // connection events are rare, and they are the ones one wants to see on disk right away
        }
    }

    void IInspectorStage.OnIdle() => Flush();

    public void Flush()
    {
        lock (_gate)
        {
            try
            {
                _stream?.Flush();
            }
            catch (IOException)
            {
                CloseLocked();
            }
        }
    }

    /// <summary>Appends one JSON document as a line. Public for tests; the stage methods are the production entry points.</summary>
    public void Write(ReadOnlySpan<byte> json)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                var lineBytes = json.Length + 1;
                EnsureFileLocked(lineBytes);
                _stream!.Write(json);
                _stream.WriteByte((byte)'\n');
                _size += lineBytes;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                CloseLocked();
                var failures = ++_writeFailures;
                if (failures is 1 || failures % 1000 == 0)
                {
                    _logger.LogWarning("The inspector could not write to its JSONL file ({ExceptionType}); {Failures} line(s) lost so far.", exception.GetType().Name, failures);
                }
            }
        }
    }

    private void EnsureFileLocked(int lineBytes)
    {
        var today = DateOnly.FromDateTime(_time.GetUtcNow().UtcDateTime);
        if (_stream is not null)
        {
            if (today == _day && _size + lineBytes <= _options.MaxFileBytes)
            {
                return;
            }

            var dayChanged = today != _day;
            CloseLocked();
            _index = dayChanged ? 0 : _index + 1;
        }
        else
        {
            _index = 0;
        }

        _day = today;
        Directory.CreateDirectory(_folder);

        // After a restart continue the last file of the day while it still has room, otherwise take the next index.
        var index = _index;
        if (_stream is null && _index == 0)
        {
            index = HighestExistingIndex(today);
        }

        while (true)
        {
            var path = PathFor(today, index);
            var existing = File.Exists(path) ? new FileInfo(path).Length : 0;
            if (existing == 0 || existing + lineBytes <= _options.MaxFileBytes)
            {
                _stream = new FileStream(path, OwnerOnlyFile.Options(FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete, 64 * 1024));
                _size = existing;
                _index = index;
                break;
            }

            index++;
        }

        Prune(today);
    }

    private int HighestExistingIndex(DateOnly day)
    {
        var highest = 0;
        foreach (var file in Directory.EnumerateFiles(_folder, $"{FilePrefix}{day:yyyyMMdd}*{FileExtension}"))
        {
            if (TryParse(file, out var fileDay, out var index) && fileDay == day)
            {
                highest = Math.Max(highest, index);
            }
        }

        return highest;
    }

    private string PathFor(DateOnly day, int index)
        => Path.Combine(_folder, index == 0 ? $"{FilePrefix}{day:yyyyMMdd}{FileExtension}" : $"{FilePrefix}{day:yyyyMMdd}.{index}{FileExtension}");

    private void Prune(DateOnly today)
    {
        try
        {
            var files = new List<(string Path, DateOnly Day, int Index, long Length)>();
            foreach (var file in Directory.EnumerateFiles(_folder, $"{FilePrefix}*{FileExtension}"))
            {
                if (TryParse(file, out var day, out var index))
                {
                    files.Add((file, day, index, new FileInfo(file).Length));
                }
            }

            var current = _stream?.Name;
            var cutoff = today.AddDays(-(_options.RetainDays - 1));
            var ordered = files.OrderBy(static f => f.Day).ThenBy(static f => f.Index).ToList();
            foreach (var file in ordered.Where(f => f.Day < cutoff && !SamePath(f.Path, current)))
            {
                TryDelete(file.Path);
            }

            var remaining = ordered.Where(f => File.Exists(f.Path)).ToList();
            var total = remaining.Sum(static f => f.Length);
            foreach (var file in remaining)
            {
                if (total <= _options.MaxTotalBytes)
                {
                    break;
                }

                if (SamePath(file.Path, current))
                {
                    continue;
                }

                if (TryDelete(file.Path))
                {
                    total -= file.Length;
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("The inspector could not prune old JSONL files ({ExceptionType}).", exception.GetType().Name);
        }
    }

    private static bool SamePath(string a, string? b) => b is not null && string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);

    private static bool TryDelete(string path)
    {
        try
        {
            File.Delete(path);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool TryParse(string path, out DateOnly day, out int index)
    {
        day = default;
        index = 0;
        var name = Path.GetFileName(path);
        if (!name.StartsWith(FilePrefix, StringComparison.Ordinal) || !name.EndsWith(FileExtension, StringComparison.Ordinal))
        {
            return false;
        }

        var core = name[FilePrefix.Length..^FileExtension.Length];
        var dot = core.IndexOf('.');
        var dayText = dot < 0 ? core : core[..dot];
        if (!DateOnly.TryParseExact(dayText, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out day))
        {
            return false;
        }

        return dot < 0 || int.TryParse(core[(dot + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out index);
    }

    private void CloseLocked()
    {
        try
        {
            _stream?.Dispose();
        }
        catch (IOException)
        {
            // Closing a broken file: nothing left to save.
        }

        _stream = null;
        _size = 0;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            CloseLocked();
        }
    }
}
