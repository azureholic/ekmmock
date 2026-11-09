using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;

namespace EkmMock.Console.Tests;

/// <summary>The state of the Live traffic page without any UI: bounded list, filter reload, pause with a bounded pending buffer, view-only clear.</summary>
public sealed class LiveTrafficModelTests
{
    private readonly ManualTimeProvider _time = new(Rec.Epoch.AddMinutes(10));
    private readonly FakeInspector _inspector;

    public LiveTrafficModelTests() => _inspector = new FakeInspector(_time);

    private LiveTrafficModel Model(int maxRows = 100, int maxPending = 50, int initial = 100)
        => new(_inspector, new LiveTrafficOptions { MaxRows = maxRows, MaxPending = maxPending, InitialRows = initial }, _time);

    private static ExchangeFeedItem Item(long id, int status = 200, string op = "wrapkey") => new(Rec.Make(id, op, status));

    private static IReadOnlyList<long> Ids(LiveTrafficModel model) => [.. model.Snapshot().Where(static r => r.Kind == LiveRowKind.Exchange).Select(static r => r.Id)];

    [Fact]
    public void Load_TakesTheNewestRowsFromTheInspector_NewestFirst()
    {
        for (var i = 1; i <= 5; i++)
        {
            _inspector.Publish(Rec.Make(i));
        }

        var model = Model(initial: 3);
        model.Load();

        Ids(model).ShouldBe([5, 4, 3]);
    }

    [Fact]
    public void Apply_AddsToTheTop_IgnoresDuplicates_AndRespectsTheFilter()
    {
        var model = Model();
        model.Load();

        model.Apply(Item(1)).ShouldBeTrue();
        model.Apply(Item(2)).ShouldBeTrue();
        model.Apply(Item(2)).ShouldBeFalse("the same exchange arriving through the feed after the initial load is ignored");
        Ids(model).ShouldBe([2, 1]);

        model.SetFilter(new ExchangeFilter { OnlyErrors = true });
        model.Apply(Item(3, 200)).ShouldBeFalse();
        model.Apply(Item(4, 500)).ShouldBeTrue();
        Ids(model).ShouldBe([4]);
    }

    [Fact]
    public void TheVersion_ChangesWithEveryVisibleChange_AndOnlyThen()
    {
        var model = Model();
        model.Load();
        var version = model.Version;

        model.Apply(Item(1));
        model.Version.ShouldBeGreaterThan(version);
        version = model.Version;

        model.Apply(Item(1)); // duplicate
        model.Version.ShouldBe(version);

        model.ShowConnectionEvents = true; // unchanged value
        model.Version.ShouldBe(version);
        model.ShowConnectionEvents = false;
        model.Version.ShouldBeGreaterThan(version);
    }

    [Fact]
    public void TheCap_DropsTheOldestRows_AndCountsThem()
    {
        var model = Model(maxRows: 5);
        model.Load();

        for (var i = 1; i <= 12; i++)
        {
            model.Apply(Item(i));
        }

        Ids(model).ShouldBe([12, 11, 10, 9, 8]);
        model.TrimmedRows.ShouldBe(7);
        model.RowCount.ShouldBe(5);
    }

    [Fact]
    public void Pause_FreezesTheList_CountsPendingItems_AndResumeShowsThemInOrder()
    {
        var model = Model();
        model.Load();
        model.Apply(Item(1));

        model.Pause();
        model.Apply(Item(2)).ShouldBeTrue();
        model.Apply(Item(3)).ShouldBeTrue();

        Ids(model).ShouldBe([1]);
        model.PendingCount.ShouldBe(2);

        model.Resume();

        Ids(model).ShouldBe([3, 2, 1]);
        model.PendingCount.ShouldBe(0);
        model.Paused.ShouldBeFalse();
    }

    [Fact]
    public void PendingItems_ThatDoNotMatchTheFilter_AreNotCounted()
    {
        var model = Model();
        model.SetFilter(new ExchangeFilter { OnlyErrors = true });
        model.Pause();

        model.Apply(Item(1, 200)).ShouldBeFalse();
        model.Apply(Item(2, 500)).ShouldBeTrue();

        model.PendingCount.ShouldBe(1);
    }

    [Fact]
    public void ThePauseBuffer_IsBounded_DropsTheOldestPending_AndCountsTheDrops()
    {
        var model = Model(maxPending: 3);
        model.Load();
        model.Pause();

        for (var i = 1; i <= 8; i++)
        {
            model.Apply(Item(i));
        }

        model.PendingCount.ShouldBe(3);
        model.PendingDropped.ShouldBe(5);
        model.Resume();
        Ids(model).ShouldBe([8, 7, 6]);
    }

    [Fact]
    public void ChangingTheFilterWhilePaused_ReloadsAFrozenView_NotWhatArrivedAfterThePause()
    {
        _inspector.Publish(Rec.Make(1, status: 500));
        _inspector.Publish(Rec.Make(2));
        var model = Model();
        model.Load();
        model.Pause();
        _inspector.Publish(Rec.Make(3, status: 500)); // arrives after the pause
        model.Apply(new ExchangeFeedItem(Rec.Make(3, status: 500)));

        model.SetFilter(new ExchangeFilter { OnlyErrors = true });

        Ids(model).ShouldBe([1], "the frozen view does not show exchange 3");
        model.Resume();
    }

    [Fact]
    public void Clear_EmptiesTheView_ButNotTheInspector_AndASetFilterDoesNotBringTheRowsBack()
    {
        _inspector.Publish(Rec.Make(1));
        _inspector.Publish(Rec.Make(2));
        var model = Model();
        model.Load();

        model.Clear();

        Ids(model).ShouldBeEmpty();
        _inspector.Count().ShouldBe(2);

        _inspector.Publish(Rec.Make(3));
        model.Apply(Item(3));
        model.SetFilter(new ExchangeFilter());
        Ids(model).ShouldBe([3]);
    }

    [Fact]
    public void Clear_WhilePaused_AlsoDiscardsPending()
    {
        var model = Model();
        model.Load();
        model.Pause();
        model.Apply(Item(1));

        model.Clear();

        model.PendingCount.ShouldBe(0);
        model.Resume();
        Ids(model).ShouldBeEmpty();
    }

    [Fact]
    public void ConnectionEvents_AreRowsToo_AndTheToggleHidesThemWithoutLosingThem()
    {
        _inspector.Publish(_inspector.NewConnectionEvent("opened", at: Rec.Epoch.AddSeconds(1)));
        var model = Model();
        model.Load();

        model.Apply(new ConnectionFeedItem(_inspector.NewConnectionEvent("closed", at: Rec.Epoch.AddSeconds(2)))).ShouldBeTrue();

        model.Snapshot().Count(static r => r.Kind == LiveRowKind.Connection).ShouldBe(2);
        model.Snapshot()[0].Connection!.Kind.ShouldBe("closed"); // newest first
        model.ShowConnectionEvents = false;
        model.Snapshot().Count(static r => r.Kind == LiveRowKind.Connection).ShouldBe(0);
        model.ShowConnectionEvents = true;
        model.Snapshot().Count(static r => r.Kind == LiveRowKind.Connection).ShouldBe(2);
    }

    [Fact]
    public void ExchangeAndConnectionKeys_DoNotCollide()
    {
        var model = Model();
        model.Load();

        model.Apply(Item(1)).ShouldBeTrue();
        model.Apply(new ConnectionFeedItem(_inspector.NewConnectionEvent("opened"))).ShouldBeTrue(); // sequence 1 as well

        model.RowCount.ShouldBe(2);
    }

    [Fact]
    public void TheDisplayHelpers_ShortenIds_AndFormatTimes()
    {
        ConsoleDisplay.ShortId("0123456789abcdef").ShouldBe("01234567…");
        ConsoleDisplay.ShortId("short").ShouldBe("short");
        ConsoleDisplay.ShortId("12345678").ShouldBe("12345678");
        ConsoleDisplay.ShortId(null).ShouldBe("-");
        ConsoleDisplay.ShortId(string.Empty).ShouldBe("-");
        ConsoleDisplay.Time(Rec.Epoch.AddMilliseconds(7)).ShouldBe("12:00:00.007");
        ConsoleDisplay.Milliseconds(0.5).ShouldBe("0.50 ms");
        ConsoleDisplay.Milliseconds(12.34).ShouldBe("12.3 ms");
        ConsoleDisplay.Milliseconds(250.4).ShouldBe("250 ms");
        ConsoleDisplay.Bytes(10).ShouldBe("10 B");
        ConsoleDisplay.Bytes(2048).ShouldBe("2.0 KiB");
        ConsoleDisplay.Duration(1500).ShouldBe("1.5 s");
        ConsoleDisplay.Duration(65_000).ShouldBe("1m 5s");
        ConsoleDisplay.StatusWord(200).ShouldBe("OK");
        ConsoleDisplay.StatusWord(404).ShouldBe("Client error");
        ConsoleDisplay.StatusWord(503).ShouldBe("Server error");
    }

    [Fact]
    public void TheValidator_KeepsTheRenderIntervalBelowTheOneSecondGuarantee()
    {
        var options = new ConsoleOptions { LiveTraffic = { RenderIntervalMs = 950 } };

        ConsoleConfigurationValidator.Validate(options, new ConsoleEndpointOptions()).ShouldContain(static p => p.Contains("RenderIntervalMs", StringComparison.Ordinal));
        options.LiveTraffic.RenderIntervalMs = 150;
        ConsoleConfigurationValidator.Validate(options, new ConsoleEndpointOptions()).ShouldBeEmpty();
    }
}
