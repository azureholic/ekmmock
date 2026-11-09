using System.Text;
using System.Text.Json;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.TestSupport;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>The live push mechanism for the console (spec 8.3): independent subscribers, slow ones never block anybody, clean unsubscribe.</summary>
public sealed class InspectorFeedTests
{
    private static InspectorFeed NewFeed(int capacity = 100) => new(Options.Create(new InspectorOptions { SubscriberCapacity = capacity }));

    private static void Publish(InspectorFeed feed, ExchangeRecord record) => ((IInspectorStage)feed).OnExchange(new CapturedExchange(record, null));

    private static void PublishConnection(InspectorFeed feed, string kind = "opened")
        => ((IInspectorStage)feed).OnConnectionEvent(new ConnectionEventRecord { ConnectionId = "c1", Kind = kind, AtUtc = Rec.Epoch });

    private static List<InspectorFeedItem> Drain(InspectorSubscription subscription)
    {
        var items = new List<InspectorFeedItem>();
        while (subscription.Reader.TryRead(out var item))
        {
            items.Add(item);
        }

        return items;
    }

    [Fact]
    public void EverySubscriber_GetsEveryItem_InOrder()
    {
        var feed = NewFeed();
        using var a = feed.Subscribe();
        using var b = feed.Subscribe();

        for (var i = 1; i <= 5; i++)
        {
            Publish(feed, Rec.Make(i));
        }

        feed.SubscriberCount.ShouldBe(2);
        foreach (var subscription in new[] { a, b })
        {
            Drain(subscription).Select(static i => ((ExchangeFeedItem)i).Exchange.Id).ShouldBe([1, 2, 3, 4, 5]);
        }
    }

    [Fact]
    public void ASubscriberThatNeverReads_LosesItsOwnOldestItems_AndNobodyElses()
    {
        var feed = NewFeed(capacity: 3);
        using var slow = feed.Subscribe();
        using var fast = feed.Subscribe(new InspectorSubscriptionOptions { Capacity = 1000 });

        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        for (var i = 1; i <= 500; i++)
        {
            Publish(feed, Rec.Make(i)); // never blocks, even though 'slow' is full since item 4
        }

        System.Diagnostics.Stopwatch.GetElapsedTime(started).ShouldBeLessThan(TimeSpan.FromSeconds(5));
        Drain(slow).Select(static i => ((ExchangeFeedItem)i).Exchange.Id).ShouldBe([498, 499, 500]);
        slow.Dropped.ShouldBe(497);
        Drain(fast).Count.ShouldBe(500);
        fast.Dropped.ShouldBe(0);
    }

    [Fact]
    public void Unsubscribing_RemovesTheSubscriber_CompletesItsReader_AndIsIdempotent()
    {
        var feed = NewFeed();
        var subscription = feed.Subscribe();
        var other = feed.Subscribe();
        Publish(feed, Rec.Make(1));

        subscription.Dispose();
        subscription.Dispose();
        Publish(feed, Rec.Make(2));

        feed.SubscriberCount.ShouldBe(1);
        subscription.IsDisposed.ShouldBeTrue();
        Drain(subscription).Count.ShouldBe(1); // only the item it had before it left
        subscription.Reader.Completion.IsCompleted.ShouldBeTrue();
        Drain(other).Count.ShouldBe(2);
        other.Dispose();
        feed.SubscriberCount.ShouldBe(0);
    }

    [Fact]
    public async Task AReaderWaitingForItems_IsReleased_WhenItsSubscriptionIsDisposed()
    {
        var feed = NewFeed();
        var subscription = feed.Subscribe();
        var waiting = subscription.Reader.WaitToReadAsync(TestContext.Current.CancellationToken).AsTask();

        subscription.Dispose();

        (await waiting.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken)).ShouldBeFalse();
    }

    [Fact]
    public async Task AWaitingReader_IsWokenByANewItem()
    {
        var feed = NewFeed();
        using var subscription = feed.Subscribe();
        var waiting = subscription.Reader.ReadAsync(TestContext.Current.CancellationToken).AsTask();

        Publish(feed, Rec.Make(42));

        ((ExchangeFeedItem)await waiting.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken)).Exchange.Id.ShouldBe(42);
    }

    [Fact]
    public void ConnectionEvents_FlowThroughTheFeed_AndCanBeSwitchedOff()
    {
        var feed = NewFeed();
        using var all = feed.Subscribe();
        using var exchangesOnly = feed.Subscribe(new InspectorSubscriptionOptions { IncludeConnectionEvents = false });
        using var connectionsOnly = feed.Subscribe(new InspectorSubscriptionOptions { IncludeExchanges = false });

        PublishConnection(feed, "handshake_failed");
        Publish(feed, Rec.Make(1));

        Drain(all).Select(static i => i.GetType()).ShouldBe([typeof(ConnectionFeedItem), typeof(ExchangeFeedItem)]);
        Drain(exchangesOnly).ShouldHaveSingleItem().ShouldBeOfType<ExchangeFeedItem>();
        ((ConnectionFeedItem)Drain(connectionsOnly).ShouldHaveSingleItem()).Event.Kind.ShouldBe("handshake_failed");
    }

    [Fact]
    public void AFilter_LimitsWhichExchangesAreDelivered()
    {
        var feed = NewFeed();
        using var errorsOnly = feed.Subscribe(new InspectorSubscriptionOptions { Filter = new ExchangeFilter { OnlyErrors = true, HideInfo = true } });

        Publish(feed, Rec.Make(1, status: 200));
        Publish(feed, Rec.Make(2, status: 401));
        Publish(feed, Rec.Make(3, op: "info", status: 503));
        Publish(feed, Rec.Make(4, status: 404));

        Drain(errorsOnly).Select(static i => ((ExchangeFeedItem)i).Exchange.Id).ShouldBe([2, 4]);
    }

    [Fact]
    public void CompleteAll_ReleasesEverySubscriber_AtShutdown()
    {
        var feed = NewFeed();
        var a = feed.Subscribe();
        var b = feed.Subscribe();

        feed.CompleteAll();

        a.Reader.Completion.IsCompleted.ShouldBeTrue();
        b.Reader.Completion.IsCompleted.ShouldBeTrue();
        feed.SubscriberCount.ShouldBe(0);
    }

    [Fact]
    public async Task ManySubscribersSubscribingAndLeavingWhilePublishing_NeverThrow_AndLeakNothing()
    {
        var feed = NewFeed(10);
        var stop = false;
        var publisher = Task.Run(() =>
        {
            long id = 0;
            while (!Volatile.Read(ref stop))
            {
                Publish(feed, Rec.Make(++id));
            }
        }, TestContext.Current.CancellationToken);

        var churners = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < 500; i++)
            {
                using var subscription = feed.Subscribe();
                subscription.Reader.TryRead(out InspectorFeedItem? _);
            }
        })).ToArray();

        await Task.WhenAll(churners);
        Volatile.Write(ref stop, true);
        await publisher;

        feed.SubscriberCount.ShouldBe(0);
    }
}

/// <summary>The JSONL files (spec 8.3): daily rotation, size cap, pruning, valid lines, masked only.</summary>
public sealed class InspectorJsonlWriterTests : IDisposable
{
    private readonly TempFolder _folder = new("ekmmock-jsonl");

    public void Dispose() => _folder.Dispose();

    private InspectorJsonlWriter Writer(ManualTimeProvider time, Action<InspectorOptions>? configure = null)
    {
        var options = new InspectorOptions { Persist = true, PersistPath = _folder.Path };
        configure?.Invoke(options);
        return new InspectorJsonlWriter(Options.Create(options), Options.Create(new DataOptions { Path = _folder.Path }), time, NullLoggerFactory.Instance);
    }

    private static void Write(InspectorJsonlWriter writer, ExchangeRecord record) => ((IInspectorStage)writer).OnExchange(new CapturedExchange(record, null));

    private string[] Files() => [.. Directory.GetFiles(_folder.Path, "inspector-*.jsonl").Select(Path.GetFileName).Order()!];

    private string[] Lines(string file)
    {
        // The writer still has the file open: read with sharing, like a tail or an export tool would.
        using var stream = new FileStream(Path.Combine(_folder.Path, file), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        var lines = new List<string>();
        while (reader.ReadLine() is { } line)
        {
            lines.Add(line);
        }

        return [.. lines];
    }

    [Fact]
    public void EveryLine_IsOneCompleteJsonObject_WithTheExchangeFields()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 10, 0, 0, TimeSpan.Zero));
        using var writer = Writer(time);

        Write(writer, Rec.Make(1, correlationId: "corr-1", bodyText: """{"value":"32 bytes · fp 3f9a1c07b2e4"}"""));
        Write(writer, Rec.Make(2, status: 401, code: "Unauthenticated"));
        ((IInspectorStage)writer).OnConnectionEvent(new ConnectionEventRecord { ConnectionId = "c1", Kind = "handshake_failed", AtUtc = time.GetUtcNow(), FailureReason = "tls_version_not_supported" });
        writer.Flush();

        var lines = Lines("inspector-20261109.jsonl");
        lines.Length.ShouldBe(3);
        var documents = lines.Select(static l => JsonDocument.Parse(l)).ToList();
        documents.Select(static d => d.RootElement.GetProperty("type").GetString()).ShouldBe(["exchange", "exchange", "connection"]);
        documents[0].RootElement.GetProperty("identity").GetProperty("exchange_id").GetInt64().ShouldBe(1);
        documents[0].RootElement.GetProperty("context").GetProperty("correlation_id").GetString().ShouldBe("corr-1");
        documents[0].RootElement.GetProperty("request").GetProperty("body").GetProperty("text").GetString()!.ShouldContain("32 bytes · fp");
        documents[1].RootElement.GetProperty("response").GetProperty("status").GetInt32().ShouldBe(401);
        documents[2].RootElement.GetProperty("failure_reason").GetString().ShouldBe("tls_version_not_supported");
        documents.ForEach(static d => d.Dispose());
    }

    [Fact]
    public void ANewFileIsStartedEachUtcDay()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 23, 59, 58, TimeSpan.Zero));
        using var writer = Writer(time);

        Write(writer, Rec.Make(1));
        time.Advance(TimeSpan.FromSeconds(1));
        Write(writer, Rec.Make(2));
        time.Advance(TimeSpan.FromSeconds(2)); // 00:00:01 on the 10th
        Write(writer, Rec.Make(3));
        Write(writer, Rec.Make(4));
        time.Advance(TimeSpan.FromDays(1));
        Write(writer, Rec.Make(5));
        writer.Flush();

        Files().ShouldBe(["inspector-20261109.jsonl", "inspector-20261110.jsonl", "inspector-20261111.jsonl"]);
        Lines("inspector-20261109.jsonl").Length.ShouldBe(2);
        Lines("inspector-20261110.jsonl").Length.ShouldBe(2);
        Lines("inspector-20261111.jsonl").Length.ShouldBe(1);
    }

    [Fact]
    public void AFileThatWouldGrowPastTheCap_IsRolledOver_AndNoFileExceedsIt()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 10, 0, 0, TimeSpan.Zero));
        var longestLine = Enumerable.Range(1, 40).Max(static i => Encoding.UTF8.GetByteCount(JsonText.Serialize(Rec.Make(i)))) + 1;
        var cap = longestLine * 3; // room for three lines per file, never for a fourth
        using var writer = Writer(time, o => o.MaxFileBytes = cap);

        for (var i = 1; i <= 40; i++)
        {
            Write(writer, Rec.Make(i));
        }

        writer.Flush();

        var files = Files();
        files.Length.ShouldBeInRange(13, 14, $"cap={cap}; " + string.Join(", ", files.Select(f => $"{f}:{Lines(f).Length} lines:{new FileInfo(Path.Combine(_folder.Path, f)).Length} bytes")));
        files.ShouldContain("inspector-20261109.jsonl");
        files.ShouldContain("inspector-20261109.1.jsonl");
        files.ShouldContain("inspector-20261109.2.jsonl");
        foreach (var file in files)
        {
            new FileInfo(Path.Combine(_folder.Path, file)).Length.ShouldBeLessThanOrEqualTo(cap, file);
        }

        files.Sum(f => Lines(f).Length).ShouldBe(40);
    }

    [Fact]
    public void ALineLargerThanTheCap_IsStillWritten_InAFileOfItsOwn()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 10, 0, 0, TimeSpan.Zero));
        using var writer = Writer(time, o => o.MaxFileBytes = 1024);

        Write(writer, Rec.Make(1, bodyText: new string('x', 3000)));
        Write(writer, Rec.Make(2));
        writer.Flush();

        Files().Sum(f => Lines(f).Length).ShouldBe(2);
        Files().Length.ShouldBe(2);
    }

    [Fact]
    public void AfterARestart_TheSameDaysFileIsContinued_WhileItHasRoom()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 10, 0, 0, TimeSpan.Zero));
        using (var first = Writer(time))
        {
            Write(first, Rec.Make(1));
        }

        using (var second = Writer(time))
        {
            Write(second, Rec.Make(2));
            second.Flush();
        }

        Files().ShouldBe(["inspector-20261109.jsonl"]);
        Lines("inspector-20261109.jsonl").Length.ShouldBe(2);
    }

    [Fact]
    public void OldFiles_AreDeleted_ByAge_AndByTotalSize_OldestFirst()
    {
        // Pre-existing files from earlier days.
        foreach (var day in new[] { "20261020", "20261101", "20261105", "20261108" })
        {
            File.WriteAllText(Path.Combine(_folder.Path, $"inspector-{day}.jsonl"), new string('x', 600));
        }

        File.WriteAllText(Path.Combine(_folder.Path, "unrelated.txt"), "keep me");
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 10, 0, 0, TimeSpan.Zero));

        using (var writer = Writer(time, o => { o.RetainDays = 7; o.MaxTotalBytes = 1000; o.MaxFileBytes = 10_000; }))
        {
            Write(writer, Rec.Make(1));
            writer.Flush();
        }

        // Retain 7 days from the 9th keeps the 3rd onwards: 20261020 and 20261101 go by age. The two remaining old files (1200 bytes) are more than the
        // 1000 byte total, so the oldest of them (20261105) goes too. The current file and files that are not the inspector's are never touched.
        File.Exists(Path.Combine(_folder.Path, "inspector-20261020.jsonl")).ShouldBeFalse();
        File.Exists(Path.Combine(_folder.Path, "inspector-20261101.jsonl")).ShouldBeFalse();
        File.Exists(Path.Combine(_folder.Path, "inspector-20261105.jsonl")).ShouldBeFalse();
        File.Exists(Path.Combine(_folder.Path, "inspector-20261108.jsonl")).ShouldBeTrue();
        File.Exists(Path.Combine(_folder.Path, "inspector-20261109.jsonl")).ShouldBeTrue();
        File.Exists(Path.Combine(_folder.Path, "unrelated.txt")).ShouldBeTrue();
    }

    [Fact]
    public void WhenPersistIsOff_NothingIsWritten_AndNoFolderIsCreated()
    {
        var folder = Path.Combine(_folder.Path, "off");
        using var writer = new InspectorJsonlWriter(
            Options.Create(new InspectorOptions { Persist = false, PersistPath = folder }),
            Options.Create(new DataOptions { Path = _folder.Path }),
            TimeProvider.System,
            NullLoggerFactory.Instance);

        Write(writer, Rec.Make(1));
        writer.Flush();

        Directory.Exists(folder).ShouldBeFalse();
    }

    [Fact]
    public async Task ConcurrentProducers_NeverProduceABrokenLine()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 10, 0, 0, TimeSpan.Zero));
        using var writer = Writer(time, o => o.MaxFileBytes = 64 * 1024);
        var nextId = 0L;

        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < 500; i++)
            {
                var id = Interlocked.Increment(ref nextId);
                Write(writer, Rec.Make(id, bodyText: new string('y', (int)(id % 200))));
                if (i % 50 == 0)
                {
                    ((IInspectorStage)writer).OnConnectionEvent(new ConnectionEventRecord { ConnectionId = "c" + id, Kind = "opened", AtUtc = time.GetUtcNow() });
                }
            }
        })));
        writer.Flush();

        var ids = new HashSet<long>();
        var connectionLines = 0;
        foreach (var file in Files())
        {
            foreach (var line in Lines(file))
            {
                using var document = JsonDocument.Parse(line); // throws on a torn or interleaved line
                if (document.RootElement.GetProperty("type").GetString() == "exchange")
                {
                    ids.Add(document.RootElement.GetProperty("identity").GetProperty("exchange_id").GetInt64());
                }
                else
                {
                    connectionLines++;
                }
            }
        }

        ids.Count.ShouldBe(4000);
        connectionLines.ShouldBe(80);
    }

    [Fact]
    public void TheFileCanBeReadWhileItIsBeingWritten()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 10, 0, 0, TimeSpan.Zero));
        using var writer = Writer(time);

        Write(writer, Rec.Make(1));
        writer.Flush();

        using var reader = new FileStream(writer.CurrentFile!, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        new StreamReader(reader).ReadToEnd().ShouldContain("\"exchange_id\":1");
    }
}

/// <summary>The audit log used by reveal (spec 5.4, 8.4): append-only JSONL, serialised, durable.</summary>
public sealed class FileAuditLogTests : IDisposable
{
    private readonly TempFolder _folder = new("ekmmock-audit");

    public void Dispose() => _folder.Dispose();

    [Fact]
    public void Entries_AreAppended_WithUserTimeActionAndTarget()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero));
        var log = new FileAuditLog(_folder.File("audit.jsonl"), time);

        log.Append("alice", "inspector.reveal", "exchange:7/request.value");
        time.Advance(TimeSpan.FromMinutes(1));
        log.Append("bob", "inspector.replay", "exchange:8", "from the console");

        var entries = log.ReadRecent();
        entries.Count.ShouldBe(2);
        entries[0].ShouldBe(new AuditEntry(new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero), "alice", "inspector.reveal", "exchange:7/request.value"));
        entries[1].User.ShouldBe("bob");
        entries[1].Detail.ShouldBe("from the console");
        File.ReadAllLines(_folder.File("audit.jsonl")).Length.ShouldBe(2);
    }

    [Fact]
    public void AHostileValue_CannotForgeASecondLine()
    {
        var log = new FileAuditLog(_folder.File("audit.jsonl"), TimeProvider.System);

        log.Append("eve\n{\"user\":\"admin\"}", "act\r\nion", "target");

        File.ReadAllLines(_folder.File("audit.jsonl")).Length.ShouldBe(1);
        log.ReadRecent().ShouldHaveSingleItem().User.ShouldContain("admin");
    }

    [Fact]
    public async Task ConcurrentAppends_AreAllWritten_EachAsOneIntactLine()
    {
        var log = new FileAuditLog(_folder.File("audit.jsonl"), TimeProvider.System);

        await Task.WhenAll(Enumerable.Range(0, 8).Select(t => Task.Run(() =>
        {
            for (var i = 0; i < 50; i++)
            {
                log.Append($"user{t}", "inspector.reveal", $"exchange:{(t * 1000) + i}/request.value");
            }
        })));

        var entries = log.ReadRecent(10_000);
        entries.Count.ShouldBe(400);
        entries.Select(static e => e.Target).Distinct().Count().ShouldBe(400);
    }

    [Fact]
    public void ReadRecent_ReturnsTheNewestEntries_OldestFirst_AndNothingForAMissingFile()
    {
        var log = new FileAuditLog(_folder.File("sub/audit.jsonl"), TimeProvider.System);
        log.ReadRecent().ShouldBeEmpty();

        for (var i = 1; i <= 10; i++)
        {
            log.Append("u", "a", $"t{i}");
        }

        log.ReadRecent(3).Select(static e => e.Target).ShouldBe(["t8", "t9", "t10"]);
    }

    [Fact]
    public void LongValues_AreBounded()
    {
        var log = new FileAuditLog(_folder.File("audit.jsonl"), TimeProvider.System);

        log.Append(new string('u', 5000), "a", "t");

        log.ReadRecent().Single().User.Length.ShouldBe(256);
    }
}
