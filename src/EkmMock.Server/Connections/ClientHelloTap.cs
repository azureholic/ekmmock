using System.Buffers;
using System.IO.Pipelines;

namespace EkmMock.Server.Connections;

/// <summary>
/// A transparent <see cref="IDuplexPipe"/> that watches the first bytes a client sends and reports the ClientHello (or the fact that
/// it was not one). It never changes, delays or consumes data: reads pass straight through, the bytes are only copied for parsing,
/// and tracking stops (and the buffer is returned) as soon as the hello is decided. This is how handshake failures that never
/// reach HTTP can still be explained (spec 7, 8.2).
/// </summary>
internal sealed class ClientHelloTap : IDuplexPipe
{
    public ClientHelloTap(IDuplexPipe inner, Action<ClientHelloParseStatus, ClientHelloInfo?> onResult)
    {
        Output = inner.Output;
        Input = new TapReader(inner.Input, onResult);
    }

    public PipeReader Input { get; }

    public PipeWriter Output { get; }

    private sealed class TapReader : PipeReader
    {
        private readonly PipeReader _inner;
        private readonly Action<ClientHelloParseStatus, ClientHelloInfo?> _onResult;

        private byte[]? _buffer;
        private int _length;
        private long _consumedOffset;
        private long _capturedOffset;
        private ReadOnlySequence<byte> _last;
        private bool _done;

        public TapReader(PipeReader inner, Action<ClientHelloParseStatus, ClientHelloInfo?> onResult)
        {
            _inner = inner;
            _onResult = onResult;
        }

        public override async ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
        {
            var result = await _inner.ReadAsync(cancellationToken).ConfigureAwait(false);
            Observe(result);
            return result;
        }

        public override bool TryRead(out ReadResult result)
        {
            if (_inner.TryRead(out result))
            {
                Observe(result);
                return true;
            }

            return false;
        }

        public override void AdvanceTo(SequencePosition consumed) => AdvanceTo(consumed, consumed);

        public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
        {
            if (!_done)
            {
                _consumedOffset += _last.Slice(_last.Start, consumed).Length;
                _last = default;
            }

            _inner.AdvanceTo(consumed, examined);
        }

        public override void CancelPendingRead() => _inner.CancelPendingRead();

        public override void Complete(Exception? exception = null)
        {
            Finish(ClientHelloParseStatus.NeedMoreData, null);
            _inner.Complete(exception);
        }

        public override ValueTask CompleteAsync(Exception? exception = null)
        {
            Finish(ClientHelloParseStatus.NeedMoreData, null);
            return _inner.CompleteAsync(exception);
        }

        private void Observe(in ReadResult result)
        {
            if (_done)
            {
                return;
            }

            var buffer = result.Buffer;
            _last = buffer;
            _buffer ??= ArrayPool<byte>.Shared.Rent(ClientHelloParser.MaxRecordBytes);

            var skip = _capturedOffset - _consumedOffset;
            if (skip < buffer.Length)
            {
                var fresh = buffer.Slice(skip);
                var count = (int)Math.Min(fresh.Length, ClientHelloParser.MaxRecordBytes - _length);
                fresh.Slice(0, count).CopyTo(_buffer.AsSpan(_length));
                _length += count;
                _capturedOffset += count;

                var status = ClientHelloParser.TryParse(_buffer.AsSpan(0, _length), out var info);
                if (status == ClientHelloParseStatus.NeedMoreData && _length >= ClientHelloParser.MaxRecordBytes)
                {
                    status = ClientHelloParseStatus.Malformed;
                }

                if (status != ClientHelloParseStatus.NeedMoreData)
                {
                    Finish(status, info);
                    return;
                }
            }

            if (result.IsCompleted)
            {
                // The peer closed before a complete hello arrived.
                Finish(ClientHelloParseStatus.NeedMoreData, null);
            }
        }

        private void Finish(ClientHelloParseStatus status, ClientHelloInfo? info)
        {
            if (_done)
            {
                return;
            }

            _done = true;
            _last = default;
            if (_buffer is not null)
            {
                ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
                _buffer = null;
            }

            try
            {
                _onResult(status, info);
            }
            catch (Exception)
            {
                // Observation must never break the connection.
            }
        }
    }
}
