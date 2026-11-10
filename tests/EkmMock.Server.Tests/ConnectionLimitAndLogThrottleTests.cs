using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using EkmMock.Server.Connections;
using EkmMock.Server.Metrics;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EkmMock.Server.Tests;

/// <summary>Security review L1: the EKM listener's connection limit and the rate limited handshake-failure log line (every failure is still a connection event and a metric).</summary>
public sealed class ConnectionLimitAndLogThrottleTests
{
    // ---- the throttle itself ----

    [Fact]
    public void TheThrottle_AllowsAFewLinesPerSecond_ThenSuppresses_AndStartsAgainInTheNextSecond()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var throttle = new WarningThrottle(clock, maxPerSecond: 3, summaryInterval: TimeSpan.FromSeconds(10));

        Enumerable.Range(0, 10).Count(_ => throttle.TryAcquire()).ShouldBe(3);

        clock.Advance(TimeSpan.FromSeconds(1));
        Enumerable.Range(0, 10).Count(_ => throttle.TryAcquire()).ShouldBe(3);
    }

    [Fact]
    public void TheSummary_CountsExactlyWhatWasSuppressed_AndOnlyAfterTheInterval()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var throttle = new WarningThrottle(clock, maxPerSecond: 2, summaryInterval: TimeSpan.FromSeconds(10));

        for (var i = 0; i < 12; i++)
        {
            throttle.TryAcquire(); // 2 logged, 10 suppressed
        }

        throttle.TakeSummary().ShouldBe(0); // too early
        clock.Advance(TimeSpan.FromSeconds(10));
        throttle.TakeSummary().ShouldBe(10);
        throttle.TakeSummary().ShouldBe(0); // reading resets it
    }

    [Fact]
    public void WithNothingSuppressed_ThereIsNoSummary()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var throttle = new WarningThrottle(clock, maxPerSecond: 5, summaryInterval: TimeSpan.FromSeconds(1));

        throttle.TryAcquire().ShouldBeTrue();
        clock.Advance(TimeSpan.FromMinutes(1));
        throttle.TakeSummary().ShouldBe(0);
    }

    // ---- the capture middleware with hand-made connections ----

    private sealed class Duplex(PipeReader input, PipeWriter output) : IDuplexPipe
    {
        public PipeReader Input { get; } = input;

        public PipeWriter Output { get; } = output;
    }

    private sealed class FakeConnection : DefaultConnectionContext
    {
        public FakeConnection(string id, Pipe toServer, Pipe toClient)
            : base(id, new Duplex(toServer.Reader, toClient.Writer), new Duplex(toClient.Reader, toServer.Writer))
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 40000);
            LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 8443);
        }

        public int Aborts { get; private set; }

        public override void Abort() => Aborts++;

        public override void Abort(ConnectionAbortedException abortReason) => Aborts++;
    }

    private static FakeConnection Connection(string id) => new(id, new Pipe(), new Pipe());

    private sealed record Setup(ConnectionCapture Capture, EkmMetrics Metrics, ConnectionEventSink Sink, CapturingLoggerProvider Logs, ManualTimeProvider Clock);

    private static Setup Create(int maxConnections = ConnectionCapture.DefaultMaxConnections)
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var logs = new CapturingLoggerProvider();
        var factory = LoggerFactory.Create(builder => builder.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var metrics = new EkmMetrics();
        var sink = new ConnectionEventSink();
        var capture = new ConnectionCapture(new ConnectionRegistry(clock), sink, metrics, new EkmListenerPorts(), clock, factory, TimeSpan.FromSeconds(10), maxConnections);
        return new Setup(capture, metrics, sink, logs, clock);
    }

    private static List<ConnectionEvent> Drain(ConnectionEventSink sink)
    {
        var events = new List<ConnectionEvent>();
        while (sink.Reader.TryRead(out var item))
        {
            events.Add(item);
        }

        return events;
    }

    [Fact]
    public async Task AFloodOfFailedHandshakes_LogsAFewLines_ButEveryFailureIsAnEventAndCounted()
    {
        const int failures = 300;
        var setup = Create();
        var outer = setup.Capture.Outer(static _ => Task.CompletedTask); // the TLS layer "fails": the connection ends without a completed handshake

        for (var i = 0; i < failures; i++)
        {
            await outer(Connection("c" + i));
        }

        var warnings = setup.Logs.Entries.Where(static e => e.Level == LogLevel.Warning).ToList();
        warnings.Count(static w => w.Message.StartsWith("TLS handshake failed", StringComparison.Ordinal)).ShouldBe(5); // at most five lines per second
        warnings.Count.ShouldBeLessThan(failures / 10);

        // Nothing is lost: one failed-handshake event per connection, and the metric counter.
        var events = Drain(setup.Sink);
        events.Count(static e => e.Kind == ConnectionEventKind.HandshakeFailed).ShouldBe(failures);
        events.Count(static e => e.Kind == ConnectionEventKind.Closed).ShouldBe(failures);
        setup.Metrics.TotalHandshakeFailures.ShouldBe(failures);

        // After the summary interval the next failure also reports how many lines were left out.
        setup.Clock.Advance(TimeSpan.FromSeconds(11));
        await outer(Connection("last"));
        var summary = setup.Logs.Entries.Single(static e => e.Message.Contains("further TLS handshake failure", StringComparison.Ordinal));
        summary.Message.ShouldContain((failures - 5).ToString());
        setup.Metrics.TotalHandshakeFailures.ShouldBe(failures + 1);
    }

    [Fact]
    public async Task TheConnectionOverTheLimit_IsClosedAtOnce_AndTheLimitFreesUpWhenAConnectionEnds()
    {
        const int limit = 3;
        var setup = Create(limit);
        var release = new TaskCompletionSource();
        var running = 0;
        var outer = setup.Capture.Outer(async _ =>
        {
            Interlocked.Increment(ref running);
            await release.Task;
        });

        var open = Enumerable.Range(0, limit).Select(i => (Connection: Connection("open" + i), Task: (Task?)null)).ToList();
        var tasks = open.Select(static c => c.Connection).Select(c => outer(c)).ToList();
        (await Wait.UntilAsync(() => Volatile.Read(ref running) == limit)).ShouldBeTrue();
        setup.Capture.ActiveConnections.ShouldBe(limit);

        var extra = Connection("extra");
        await outer(extra); // returns without running the rest of the pipeline

        extra.Aborts.ShouldBe(1);
        Volatile.Read(ref running).ShouldBe(limit);
        setup.Capture.RejectedConnections.ShouldBe(1);
        setup.Capture.ActiveConnections.ShouldBe(limit);
        setup.Logs.Entries.ShouldContain(static e => e.Level == LogLevel.Warning && e.Message.Contains("connection limit reached", StringComparison.Ordinal));
        Drain(setup.Sink).ShouldNotContain(static e => e.ConnectionId == "extra"); // not a per-connection event: no state was allocated for it

        release.SetResult();
        await Task.WhenAll(tasks);
        setup.Capture.ActiveConnections.ShouldBe(0);

        var again = Connection("again");
        await outer(again);
        again.Aborts.ShouldBe(0);
    }

    [Fact]
    public async Task AFloodOverTheLimit_LogsAFewLines_AndCountsEveryRefusal()
    {
        var setup = Create(maxConnections: 1);
        var release = new TaskCompletionSource();
        var outer = setup.Capture.Outer(async _ => await release.Task);
        var holder = outer(Connection("holder"));
        (await Wait.UntilAsync(() => setup.Capture.ActiveConnections == 1)).ShouldBeTrue();

        for (var i = 0; i < 200; i++)
        {
            await outer(Connection("flood" + i));
        }

        setup.Capture.RejectedConnections.ShouldBe(200);
        setup.Logs.Entries.Count(static e => e.Message.Contains("connection limit reached", StringComparison.Ordinal)).ShouldBe(5);
        release.SetResult();
        await holder;
    }

    [Fact]
    public void TheLimitIsConfigurable_DefaultsTo1000_AndMustBePositive()
    {
        new EkmMock.Server.Inspector.LimitsOptions().MaxConnections.ShouldBe(1000);
        ConnectionCapture.DefaultMaxConnections.ShouldBe(1000);
        var validator = new EkmMock.Server.Inspector.InspectorOptionsValidator();
        validator.Validate(null, new EkmMock.Server.Inspector.LimitsOptions { MaxConnections = 0 }).Failed.ShouldBeTrue();
        validator.Validate(null, new EkmMock.Server.Inspector.LimitsOptions { MaxConnections = 1 }).Succeeded.ShouldBeTrue();
    }

    // ---- over real Kestrel ----

    [Fact]
    public async Task OnTheRealListener_TheConnectionOverTheLimitIsClosed_WhileTheOnesWithinItStayOpen_AndTheConsoleIsUnaffected()
    {
        const int limit = 3;
        using var pki = new TestPki();
        await using var host = await RealEkmHost.StartAsync(new RealEkmHostOptions
        {
            Pki = pki,
            Namespaces = [TestNamespace.Default(pki.ClientCaA, "limit-client.test")],
            Configuration = new Dictionary<string, string?> { ["Limits:MaxConnections"] = limit.ToString() },
        });

        var held = new List<TcpClient>();
        try
        {
            for (var i = 0; i < limit; i++)
            {
                var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, host.Port, TestContext.Current.CancellationToken);
                held.Add(client); // sends nothing: the server waits for a ClientHello (handshake timeout 10 s)
            }

            var capture = host.App.Services.GetRequiredService<ConnectionRegistry>();
            (await Wait.UntilAsync(() => capture.OpenCount == limit, TimeSpan.FromSeconds(10))).ShouldBeTrue($"{capture.OpenCount} connections registered");

            using var extra = new TcpClient();
            await extra.ConnectAsync(IPAddress.Loopback, host.Port, TestContext.Current.CancellationToken);
            var closed = await ReadsEndOfStreamAsync(extra, TimeSpan.FromSeconds(10));

            closed.ShouldBeTrue("the connection over the limit must be closed by the server");
            foreach (var client in held)
            {
                client.Connected.ShouldBeTrue();
                client.Client.Poll(0, SelectMode.SelectRead).ShouldBeFalse("a connection within the limit stays open"); // readable would mean closed or data
            }

            // The limit is the EKM listener's own: the console on the same process still answers.
            using var console = host.CreateConsoleClient();
            using var health = await console.GetAsync("healthz", TestContext.Current.CancellationToken);
            ((int)health.StatusCode).ShouldBe(200);
        }
        finally
        {
            foreach (var client in held)
            {
                client.Dispose();
            }
        }
    }

    private static async Task<bool> ReadsEndOfStreamAsync(TcpClient client, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        var buffer = new byte[16];
        try
        {
            return await client.GetStream().ReadAsync(buffer, cts.Token) == 0;
        }
        catch (IOException)
        {
            return true; // a reset is a close too
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
