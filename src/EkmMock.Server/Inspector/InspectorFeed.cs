using System.Threading.Channels;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Inspector;

/// <summary>One item of the live feed: either an exchange or a connection event (spec 8.2: connection events also flow inline into the live stream).</summary>
internal abstract record InspectorFeedItem;

internal sealed record ExchangeFeedItem(ExchangeRecord Exchange) : InspectorFeedItem;

internal sealed record ConnectionFeedItem(ConnectionEventRecord Event) : InspectorFeedItem;

internal sealed record InspectorSubscriptionOptions
{
    /// <summary>Capacity of this subscription's queue; null uses <see cref="InspectorOptions.SubscriberCapacity"/>.</summary>
    public int? Capacity { get; init; }

    /// <summary>Only exchanges that match are delivered (applied by the feed, on the consumer thread). Connection events are not filtered.</summary>
    public ExchangeFilter? Filter { get; init; }

    public bool IncludeExchanges { get; init; } = true;

    /// <summary>The "show connection events inline" toggle of the live stream.</summary>
    public bool IncludeConnectionEvents { get; init; } = true;
}

/// <summary>
/// The live-push mechanism for the console (M5's Blazor hub): every subscriber gets its <em>own</em> bounded drop-oldest queue, so a slow or stuck console only loses
/// its own oldest items and can neither block the consumer nor any other subscriber. Items are immutable and shared between subscribers (masked by construction).
/// </summary>
internal interface IInspectorFeed
{
    int SubscriberCount { get; }

    InspectorSubscription Subscribe(InspectorSubscriptionOptions? options = null);
}

/// <summary>One subscriber. Dispose it to unsubscribe: it is removed from the feed and its reader completes. Disposing twice is fine.</summary>
internal sealed class InspectorSubscription : IDisposable, IAsyncDisposable
{
    private readonly InspectorFeed _owner;
    private readonly Channel<InspectorFeedItem> _channel;
    private long _dropped;
    private int _disposed;

    internal InspectorSubscription(InspectorFeed owner, int capacity, InspectorSubscriptionOptions options)
    {
        _owner = owner;
        Options = options;
        _channel = Channel.CreateBounded<InspectorFeedItem>(
            new BoundedChannelOptions(capacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false,
            },
            _ => Interlocked.Increment(ref _dropped));
    }

    internal InspectorSubscriptionOptions Options { get; }

    public ChannelReader<InspectorFeedItem> Reader => _channel.Reader;

    /// <summary>Items this subscriber missed because it did not keep up.</summary>
    public long Dropped => Interlocked.Read(ref _dropped);

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    internal void Offer(InspectorFeedItem item) => _channel.Writer.TryWrite(item);

    internal void CompleteChannel() => _channel.Writer.TryComplete();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _owner.Remove(this);
        _channel.Writer.TryComplete();
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}

internal sealed class InspectorFeed : IInspectorFeed, IInspectorStage
{
    private readonly object _gate = new();
    private readonly int _defaultCapacity;
    private InspectorSubscription[] _subscribers = [];

    public InspectorFeed(IOptions<InspectorOptions> options) => _defaultCapacity = options.Value.SubscriberCapacity;

    public int SubscriberCount => Volatile.Read(ref _subscribers).Length;

    public InspectorSubscription Subscribe(InspectorSubscriptionOptions? options = null)
    {
        options ??= new InspectorSubscriptionOptions();
        var subscription = new InspectorSubscription(this, Math.Max(1, options.Capacity ?? _defaultCapacity), options);
        lock (_gate)
        {
            _subscribers = [.. _subscribers, subscription];
        }

        return subscription;
    }

    internal void Remove(InspectorSubscription subscription)
    {
        lock (_gate)
        {
            _subscribers = [.. _subscribers.Where(s => !ReferenceEquals(s, subscription))];
        }
    }

    void IInspectorStage.OnExchange(CapturedExchange exchange)
    {
        var subscribers = Volatile.Read(ref _subscribers);
        if (subscribers.Length == 0)
        {
            return;
        }

        var item = new ExchangeFeedItem(exchange.Record);
        foreach (var subscriber in subscribers)
        {
            if (subscriber.Options.IncludeExchanges && (subscriber.Options.Filter?.Matches(exchange.Record) ?? true))
            {
                subscriber.Offer(item);
            }
        }
    }

    void IInspectorStage.OnConnectionEvent(ConnectionEventRecord connectionEvent)
    {
        var subscribers = Volatile.Read(ref _subscribers);
        if (subscribers.Length == 0)
        {
            return;
        }

        var item = new ConnectionFeedItem(connectionEvent);
        foreach (var subscriber in subscribers)
        {
            if (subscriber.Options.IncludeConnectionEvents)
            {
                subscriber.Offer(item);
            }
        }
    }

    /// <summary>Completes every subscription (host shutdown), so no reader waits forever.</summary>
    public void CompleteAll()
    {
        InspectorSubscription[] subscribers;
        lock (_gate)
        {
            subscribers = _subscribers;
            _subscribers = [];
        }

        foreach (var subscriber in subscribers)
        {
            subscriber.CompleteChannel();
        }
    }
}
