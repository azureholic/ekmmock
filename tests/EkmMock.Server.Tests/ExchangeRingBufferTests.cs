using EkmMock.Server.Inspector;

namespace EkmMock.Server.Tests;

/// <summary>The in-memory ring buffer (spec 8.3): capacity, eviction order, filters, cursor paging, secrets and concurrency.</summary>
public sealed class ExchangeRingBufferTests
{
    private static ExchangeRingBuffer Buffer(int capacity, params ExchangeRecord[] records)
    {
        var ring = new ExchangeRingBuffer(capacity);
        foreach (var record in records)
        {
            ring.Add(record);
        }

        return ring;
    }

    private static long[] Ids(ExchangePage page) => [.. page.Items.Select(static r => r.Id)];

    // ---- capacity and eviction ----

    [Fact]
    public void TheDefaultCapacity_Is10000()
    {
        new InspectorOptions().RingBufferSize.ShouldBe(10_000);
        new ExchangeRingBuffer(Microsoft.Extensions.Options.Options.Create(new InspectorOptions())).Capacity.ShouldBe(10_000);
    }

    [Fact]
    public void OnceFull_TheOldestRecordIsEvictedFirst_AndOrderIsKept()
    {
        var ring = Buffer(3, Rec.Make(1), Rec.Make(2), Rec.Make(3));

        ring.Add(Rec.Make(4));
        ring.Add(Rec.Make(5));

        ring.Count.ShouldBe(3);
        ring.Evicted.ShouldBe(2);
        ring.Get(1).ShouldBeNull();
        ring.Get(2).ShouldBeNull();
        Ids(ring.Query()).ShouldBe([5, 4, 3]);
    }

    [Fact]
    public void GetById_FindsEveryRecord_AndNullForTheUnknown()
    {
        var ring = Buffer(100);
        for (var i = 1; i <= 250; i++)
        {
            ring.Add(Rec.Make(i)); // wraps the circular storage more than twice
        }

        ring.Count.ShouldBe(100);
        for (var i = 151; i <= 250; i++)
        {
            ring.Get(i).ShouldNotBeNull().Id.ShouldBe(i);
        }

        ring.Get(150).ShouldBeNull();
        ring.Get(251).ShouldBeNull();
        ring.Get(-1).ShouldBeNull();
    }

    [Fact]
    public void RecordsThatFinishOutOfOrder_AreKeptSortedById()
    {
        var ring = Buffer(10, Rec.Make(1), Rec.Make(3), Rec.Make(2), Rec.Make(5), Rec.Make(4));

        Ids(ring.Query()).ShouldBe([5, 4, 3, 2, 1]);
        ring.Get(2).ShouldNotBeNull();
        ring.Get(4).ShouldNotBeNull();
    }

    [Fact]
    public void ACapacityOfOne_Works()
    {
        var ring = Buffer(1, Rec.Make(1), Rec.Make(2));

        Ids(ring.Query()).ShouldBe([2]);
        Should.Throw<ArgumentOutOfRangeException>(() => new ExchangeRingBuffer(0));
    }

    // ---- filters ----

    private static ExchangeRingBuffer Mixed() => Buffer(
        100,
        Rec.Make(1, op: "info", status: 200, ms: 1, key: null, cn: "mhsm.a", correlationId: "corr-info"),
        Rec.Make(2, op: "wrapkey", status: 200, ms: 10, key: "aes-1", cn: "mhsm.a", correlationId: "AAA-111", poolName: "pool-one", requestId: "req-1"),
        Rec.Make(3, op: "unwrapkey", status: 400, ms: 12, key: "aes-1", cn: "mhsm.a", correlationId: "BBB-222", code: "InvalidCiphertext"),
        Rec.Make(4, op: "wrapkey", status: 401, ms: 3, key: "rsa-1", cn: null, ns: "contoso", correlationId: "CCC-333", code: "Unauthenticated"),
        Rec.Make(5, op: "unwrapkey", status: 200, ms: 300, key: "rsa-1", cn: "mhsm.b", ns: "contoso", poolName: "Pool-Two"),
        Rec.Make(6, op: "metadata", status: 404, ms: 2, key: "gone", cn: "mhsm.a", code: "KeyNotFound"),
        Rec.Make(7, op: null, status: 404, ms: 1, key: null, ns: null, cn: null, code: "NotFound"),
        Rec.Make(8, op: "wrapkey", status: 503, ms: 260, key: "aes-1", cn: "mhsm.a", code: "HsmUnavailable"),
        Rec.Make(9, op: "wrapkey", status: 429, ms: 2, key: "aes-1", cn: "mhsm.a", code: "TooManyRequests"));

    [Theory]
    [InlineData("info", new long[] { 1 })]
    [InlineData("wrapkey", new long[] { 9, 8, 4, 2 })]
    [InlineData("unwrapkey", new long[] { 5, 3 })]
    [InlineData("metadata", new long[] { 6 })]
    [InlineData("nothing", new long[0])]
    public void Filter_ByOperation(string operation, long[] expected)
        => Ids(Mixed().Query(new ExchangeFilter { Operation = operation })).ShouldBe(expected);

    [Theory]
    [InlineData(2, new long[] { 5, 2, 1 })]
    [InlineData(4, new long[] { 9, 7, 6, 4, 3 })]
    [InlineData(5, new long[] { 8 })]
    public void Filter_ByStatusClass(int statusClass, long[] expected)
        => Ids(Mixed().Query(new ExchangeFilter { StatusClass = (StatusClass)statusClass })).ShouldBe(expected);

    [Fact]
    public void Filter_ByNamespace_Key_AndClientCommonName_AreExactMatches()
    {
        var ring = Mixed();

        Ids(ring.Query(new ExchangeFilter { Namespace = "contoso" })).ShouldBe([5, 4]);
        Ids(ring.Query(new ExchangeFilter { Key = "aes-1" })).ShouldBe([9, 8, 3, 2]);
        Ids(ring.Query(new ExchangeFilter { Key = "aes" })).ShouldBeEmpty();
        Ids(ring.Query(new ExchangeFilter { ClientCommonName = "mhsm.b" })).ShouldBe([5]);
        Ids(ring.Query(new ExchangeFilter { ClientCommonName = "MHSM.B" })).ShouldBeEmpty(); // a CN is case-sensitive
        Ids(ring.Query(new ExchangeFilter { ClientCommonName = "mhsm" })).ShouldBeEmpty();
    }

    [Fact]
    public void Filter_TextSearch_IsACaseInsensitiveSubstringOverCorrelationId_PoolName_AndRequestId()
    {
        var ring = Mixed();

        Ids(ring.Query(new ExchangeFilter { Text = "aaa-1" })).ShouldBe([2]);
        Ids(ring.Query(new ExchangeFilter { Text = "bbb" })).ShouldBe([3]);
        Ids(ring.Query(new ExchangeFilter { Text = "pool" })).ShouldBe([5, 2]);
        Ids(ring.Query(new ExchangeFilter { Text = "REQ-1" })).ShouldBe([2]);
        Ids(ring.Query(new ExchangeFilter { Text = "zzz" })).ShouldBeEmpty();
        Ids(ring.Query(new ExchangeFilter { Text = "" })).Length.ShouldBe(9);
    }

    [Fact]
    public void Filter_OnlyErrors_MeansAStatusOf400OrMore()
        => Ids(Mixed().Query(new ExchangeFilter { OnlyErrors = true })).ShouldBe([9, 8, 7, 6, 4, 3]);

    [Fact]
    public void Filter_OnlyOverBudget_MeansRed()
        => Ids(Mixed().Query(new ExchangeFilter { OnlyOverBudget = true })).ShouldBe([8, 5]);

    [Fact]
    public void Filter_HideInfo_HidesTheHealthProbes()
        => Ids(Mixed().Query(new ExchangeFilter { HideInfo = true })).ShouldBe([9, 8, 7, 6, 5, 4, 3, 2]);

    [Fact]
    public void Filters_AreCombinedWithAnd()
    {
        var ring = Mixed();

        Ids(ring.Query(new ExchangeFilter { Operation = "wrapkey", OnlyErrors = true })).ShouldBe([9, 8, 4]);
        Ids(ring.Query(new ExchangeFilter { Operation = "wrapkey", StatusClass = StatusClass.ServerError, OnlyOverBudget = true })).ShouldBe([8]);
        Ids(ring.Query(new ExchangeFilter { Namespace = "contoso", Operation = "unwrapkey", ClientCommonName = "mhsm.b" })).ShouldBe([5]);
        Ids(ring.Query(new ExchangeFilter { Namespace = "contoso", Operation = "metadata" })).ShouldBeEmpty();
        ring.CountMatching(new ExchangeFilter { HideInfo = true, OnlyErrors = true }).ShouldBe(6);
        ring.CountMatching(null).ShouldBe(9);
    }

    // ---- paging ----

    [Fact]
    public void Paging_IsNewestFirst_WithABeforeIdCursorThatWalksBackwards()
    {
        var ring = Buffer(100);
        for (var i = 1; i <= 25; i++)
        {
            ring.Add(Rec.Make(i));
        }

        var first = ring.Query(paging: new ExchangePaging { Limit = 10 });
        first.HasMore.ShouldBeTrue();
        Ids(first).ShouldBe(Enumerable.Range(16, 10).Reverse().Select(static i => (long)i));
        first.NextBeforeId.ShouldBe(16);

        var second = ring.Query(paging: new ExchangePaging { Limit = 10, BeforeId = first.NextBeforeId });
        Ids(second).ShouldBe(Enumerable.Range(6, 10).Reverse().Select(static i => (long)i));
        second.HasMore.ShouldBeTrue();

        var third = ring.Query(paging: new ExchangePaging { Limit = 10, BeforeId = second.NextBeforeId });
        Ids(third).ShouldBe([5, 4, 3, 2, 1]);
        third.HasMore.ShouldBeFalse();
        third.NextBeforeId.ShouldBeNull();
    }

    [Fact]
    public void Paging_AnAfterIdCursor_ReturnsOnlyWhatIsNewer_ForCatchingUp()
    {
        var ring = Buffer(100);
        for (var i = 1; i <= 20; i++)
        {
            ring.Add(Rec.Make(i));
        }

        Ids(ring.Query(paging: new ExchangePaging { AfterId = 17 })).ShouldBe([20, 19, 18]);
        Ids(ring.Query(paging: new ExchangePaging { AfterId = 20 })).ShouldBeEmpty();
        Ids(ring.Query(paging: new ExchangePaging { AfterId = 0, Limit = 2 })).ShouldBe([20, 19]);
        ring.Query(paging: new ExchangePaging { AfterId = 0, Limit = 2 }).HasMore.ShouldBeTrue();
    }

    [Fact]
    public void Paging_WithAFilter_CountsOnlyMatches_AndCursorsStayStable()
    {
        var ring = Buffer(200);
        for (var i = 1; i <= 100; i++)
        {
            ring.Add(Rec.Make(i, op: i % 2 == 0 ? "wrapkey" : "unwrapkey"));
        }

        var filter = new ExchangeFilter { Operation = "wrapkey" };
        var page = ring.Query(filter, new ExchangePaging { Limit = 20 });

        Ids(page).ShouldBe(Enumerable.Range(0, 20).Select(static i => (long)(100 - (2 * i))));
        page.HasMore.ShouldBeTrue();

        // New traffic arrives between the two page requests: the cursor still continues where the first page ended.
        ring.Add(Rec.Make(101, op: "wrapkey"));
        var next = ring.Query(filter, new ExchangePaging { Limit = 20, BeforeId = page.NextBeforeId });
        Ids(next).ShouldBe(Enumerable.Range(0, 20).Select(static i => (long)(60 - (2 * i))));
    }

    [Fact]
    public void Paging_TheLimitIsClamped()
    {
        var ring = Buffer(5000);
        for (var i = 1; i <= 1500; i++)
        {
            ring.Add(Rec.Make(i));
        }

        ring.Query(paging: new ExchangePaging { Limit = 0 }).Items.Count.ShouldBe(1);
        ring.Query(paging: new ExchangePaging { Limit = 100_000 }).Items.Count.ShouldBe(ExchangePaging.MaxLimit);
    }

    // ---- secrets live and die with the slot ----

    [Fact]
    public void RetainedSecrets_AreZeroedWhenTheirSlotIsEvicted()
    {
        var ring = new ExchangeRingBuffer(2);
        var first = new RetainedSecrets("""{"value":"AAAA"}"""u8.ToArray(), null);
        var second = new RetainedSecrets("""{"value":"BBBB"}"""u8.ToArray(), null);
        ring.Add(Rec.Make(1), first);
        ring.Add(Rec.Make(2), second);
        first.ReadValue(RevealFields.RequestValue).ShouldBe("AAAA");

        ring.Add(Rec.Make(3));

        first.IsEmpty.ShouldBeTrue();
        first.ReadValue(RevealFields.RequestValue).ShouldBeNull();
        second.ReadValue(RevealFields.RequestValue).ShouldBe("BBBB");
        ring.Contains(1, out _).ShouldBeFalse();
        ring.Contains(2, out var hasSecrets).ShouldBeTrue();
        hasSecrets.ShouldBeTrue();
    }

    [Fact]
    public void Clear_ZeroesEverySecret_AndEmptiesTheBuffer()
    {
        var ring = new ExchangeRingBuffer(10);
        var secrets = Enumerable.Range(1, 5).Select(static i => new RetainedSecrets("""{"value":"AAAA"}"""u8.ToArray(), """{"value":"BBBB"}"""u8.ToArray())).ToArray();
        for (var i = 0; i < secrets.Length; i++)
        {
            ring.Add(Rec.Make(i + 1), secrets[i]);
        }

        ring.Clear();

        ring.Count.ShouldBe(0);
        secrets.ShouldAllBe(static s => s.IsEmpty);
        ring.Query().Items.ShouldBeEmpty();
    }

    [Fact]
    public void RetainedSecrets_ExposeOnlyTheTopLevelValue_OfTheRightBody()
    {
        var secrets = new RetainedSecrets(
            """{"request_context":{"value":"nested"},"alg":"A256KW","value":"REQ"}"""u8.ToArray(),
            """{"value":"RESP"}"""u8.ToArray());

        secrets.ReadValue(RevealFields.RequestValue).ShouldBe("REQ");
        secrets.ReadValue(RevealFields.ResponseValue).ShouldBe("RESP");
        secrets.ReadValue("request.other").ShouldBeNull();
        secrets.HasRequestBody.ShouldBeTrue();
        secrets.CopyRequestBody().ShouldNotBeNull().Length.ShouldBeGreaterThan(10);
    }

    // ---- concurrency ----

    [Fact]
    public async Task ParallelWritersAndReaders_NeverThrow_AndEveryReadIsConsistent()
    {
        const int writers = 4;
        const int perWriter = 5000;
        var ring = new ExchangeRingBuffer(1000);
        var nextId = 0L;
        var stop = false;
        var failures = new List<string>();

        var readers = Enumerable.Range(0, 3).Select(r => Task.Run(() =>
        {
            while (!Volatile.Read(ref stop))
            {
                try
                {
                    var page = ring.Query(new ExchangeFilter { OnlyErrors = r % 2 == 0 }, new ExchangePaging { Limit = 50 });
                    var ids = page.Items.Select(static i => i.Id).ToArray();
                    if (!ids.SequenceEqual(ids.OrderByDescending(static i => i)))
                    {
                        lock (failures) { failures.Add("page not newest-first"); }
                    }

                    var snapshot = ring.Snapshot();
                    if (snapshot.Count > 1000 || snapshot.Zip(snapshot.Skip(1)).Any(static p => p.First.Id > p.Second.Id))
                    {
                        lock (failures) { failures.Add("snapshot inconsistent"); }
                    }

                    if (snapshot.Count > 0 && ring.Get(snapshot[^1].Id) is null && ring.Count == 1000)
                    {
                        // A concurrent eviction can legitimately remove it; this only guards against exceptions.
                    }
                }
                catch (Exception exception)
                {
                    lock (failures) { failures.Add(exception.GetType().Name + ": " + exception.Message); }
                }
            }
        })).ToArray();

        var tasks = Enumerable.Range(0, writers).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < perWriter; i++)
            {
                var id = Interlocked.Increment(ref nextId);
                ring.Add(Rec.Make(id, status: id % 7 == 0 ? 500 : 200), id % 50 == 0 ? new RetainedSecrets("""{"value":"AAAA"}"""u8.ToArray(), null) : null);
            }
        })).ToArray();

        await Task.WhenAll(tasks);
        Volatile.Write(ref stop, true);
        await Task.WhenAll(readers);

        failures.ShouldBeEmpty();
        ring.Count.ShouldBe(1000);
        ring.Evicted.ShouldBe((writers * perWriter) - 1000);
        var final = ring.Snapshot();
        final.Zip(final.Skip(1)).ShouldAllBe(static p => p.First.Id < p.Second.Id);
    }
}
