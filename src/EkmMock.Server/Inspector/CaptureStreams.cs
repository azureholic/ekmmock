using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;

namespace EkmMock.Server.Inspector;

/// <summary>
/// A pooled buffer that keeps at most <see cref="BodyRedactor.MaxCaptureBytes"/> of what passes through a body stream and counts the rest.
/// It is zeroed before it goes back to the pool, because for a wrap request or an unwrap response it holds a plaintext DEK.
/// </summary>
internal sealed class CaptureBuffer
{
    private byte[]? _buffer;
    private int _length;
    private long _total;

    public long Total => _total;

    public bool Truncated => _total > _length;

    public ReadOnlySpan<byte> Span => _buffer is null ? default : _buffer.AsSpan(0, _length);

    public void Append(ReadOnlySpan<byte> data)
    {
        _total += data.Length;
        var room = BodyRedactor.MaxCaptureBytes - _length;
        if (room <= 0 || data.IsEmpty)
        {
            return;
        }

        _buffer ??= ArrayPool<byte>.Shared.Rent(BodyRedactor.MaxCaptureBytes);
        var take = Math.Min(room, data.Length);
        data[..take].CopyTo(_buffer.AsSpan(_length));
        _length += take;
    }

    /// <summary>Zeroes what was captured and returns the buffer. The counters stay (the size of the body is still needed).</summary>
    public void Release()
    {
        if (_buffer is not null)
        {
            CryptographicOperations.ZeroMemory(_buffer.AsSpan(0, _length));
            ArrayPool<byte>.Shared.Return(_buffer);
            _buffer = null;
            _length = 0;
        }
    }
}

/// <summary>
/// Wraps <c>Request.Body</c>: every read is passed through untouched (including exceptions such as Kestrel's body-size error) and a copy of at most
/// 16 KiB is kept on the side. When the stream reaches its end the session is told, so that a wrap request is masked and its raw copy released at the
/// earliest possible moment instead of at the end of the exchange.
/// </summary>
internal sealed class CapturingRequestStream : Stream
{
    private readonly Stream _inner;
    private readonly ExchangeCaptureSession _session;

    public CapturingRequestStream(Stream inner, ExchangeCaptureSession session)
    {
        _inner = inner;
        _session = session;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var read = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        Observe(buffer.Span[..read]);
        return read;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        var read = _inner.Read(buffer);
        Observe(buffer[..read]);
        return read;
    }

    private void Observe(ReadOnlySpan<byte> data)
    {
        var started = Stopwatch.GetTimestamp();
        if (data.IsEmpty)
        {
            _session.RequestBodyEnded();
        }
        else
        {
            _session.RequestBuffer.Append(data);
        }

        _session.AddOverhead(started);
    }

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// Wraps <c>Response.Body</c>: everything written is passed to the real stream first and a copy of at most 16 KiB is kept on the side. It does not buffer,
/// delay or reorder anything, so the response is exactly as before.
/// </summary>
internal sealed class CapturingResponseStream : Stream
{
    private readonly Stream _inner;
    private readonly ExchangeCaptureSession _session;

    public CapturingResponseStream(Stream inner, ExchangeCaptureSession session)
    {
        _inner = inner;
        _session = session;
    }

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Observe(buffer.Span);
        return _inner.WriteAsync(buffer, cancellationToken);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        Observe(buffer);
        _inner.Write(buffer);
    }

    public override void WriteByte(byte value)
    {
        Span<byte> one = [value];
        Write(one);
    }

    private void Observe(ReadOnlySpan<byte> data)
    {
        var started = Stopwatch.GetTimestamp();
        _session.ResponseBuffer.Append(data);
        _session.AddOverhead(started);
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}
