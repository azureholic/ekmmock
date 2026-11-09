using System.Collections.Concurrent;

namespace EkmMock.Crypto.Internal;

/// <summary>
/// Minimal bounded pool of single-owner crypto objects (<c>Aes</c>, <c>RSA</c>). Instances are never shared between
/// threads: a caller rents one exclusively and returns it. Chosen over per-call creation (RSA key import alone costs
/// about one millisecond) and over Microsoft.Extensions.ObjectPool (no extra dependency, and disposal on destroy).
/// </summary>
internal sealed class InstancePool<T> : IDisposable
    where T : class, IDisposable
{
    private readonly ConcurrentQueue<T> _items = new();
    private readonly Func<T> _factory;
    private readonly int _maxRetained;
    private int _count;
    private volatile bool _disposed;

    public InstancePool(Func<T> factory, int maxRetained)
    {
        _factory = factory;
        _maxRetained = maxRetained;
    }

    /// <exception cref="ObjectDisposedException">The pool (that is, the key) has been disposed.</exception>
    public T Rent()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_items.TryDequeue(out var item))
        {
            Interlocked.Decrement(ref _count);
            return item;
        }

        var created = _factory();
        if (_disposed)
        {
            // Raced with Dispose: the key material may already be zeroed, never hand the instance out.
            created.Dispose();
            throw new ObjectDisposedException(nameof(InstancePool<T>));
        }

        return created;
    }

    public void Return(T item)
    {
        if (_disposed || Volatile.Read(ref _count) >= _maxRetained)
        {
            item.Dispose();
            return;
        }

        _items.Enqueue(item);
        Interlocked.Increment(ref _count);
    }

    public void Dispose()
    {
        _disposed = true;
        while (_items.TryDequeue(out var item))
        {
            item.Dispose();
        }
    }
}
