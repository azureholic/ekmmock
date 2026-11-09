#pragma warning disable xUnit1051 // The real-host tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Diagnostics;
using System.Net;
using EkmMock.Crypto;
using EkmMock.Server.Connections;
using EkmMock.Server.Faults;
using EkmMock.Server.Inspector;
using EkmMock.Server.Metrics;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// Spec 10.1, 10.2 and 14 tests 26 and 27 against a real Kestrel listener with mTLS: the faults that depend on a real connection (blackhole, close connection), the internal deadline
/// while the request body is still arriving, queue wait, and the interplay of faults, limits and authentication.
/// </summary>
[Collection(FaultsHostCollection.Name)]
public sealed class FaultInjectionRealHostTests : IAsyncLifetime
{
    private const string Alg = "A256KWP";
    private readonly FaultsHostFixture _fx;

    public FaultInjectionRealHostTests(FaultsHostFixture fixture) => _fx = fixture;

    public ValueTask InitializeAsync() => new(_fx.ResetAsync());

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private static string Path(string key, string op) => EkmClient.Path(null, key, op);

    // ---- blackhole ----

    [Fact]
    public async Task ABlackhole_NeverAnswers_UntilTheClientGivesUp_ThenTheExchangeIsRecordedAsNoResponse()
    {
        var rule = _fx.Faults.Create(new FaultSpec { Kind = FaultKind.Blackhole, Scope = new FaultScope(Key: "aes-key-1") });
        var ekm = _fx.NewClient(TimeSpan.FromSeconds(60));
        var mark = _fx.Mark();
        using var giveUp = new CancellationTokenSource();

        // The client waits; it gives up only once the blackhole has actually engaged (a fixed client timeout would race with a slow handshake on a loaded machine, and a request
        // that is abandoned before the fault acted is correctly not flagged).
        var pending = ekm.Http.PostAsync(Path("aes-key-1", "metadata"), EkmClient.JsonBody(EkmClient.Context), giveUp.Token);
        (await Wait.UntilAsync(() => _fx.Faults.Get(rule.Id)!.Fired == 1 && _fx.Gate.InFlight == 1, TimeSpan.FromSeconds(30))).ShouldBeTrue("the blackhole did not engage");
        await Task.Delay(400);
        pending.IsCompleted.ShouldBeFalse("the server sent nothing while the blackhole was active");
        giveUp.Cancel();
        await Should.ThrowAsync<OperationCanceledException>(() => pending);

        var record = await _fx.WaitForExchangeAsync(mark, static r => r.Faults?.Kind == "blackhole");
        record.Response.Status.ShouldBe(499, "no HTTP response was sent");
        record.Response.ClientAborted.ShouldBeTrue();
        record.Response.ClosedByServer.ShouldBeFalse();
        record.Faults!.Rule.ShouldBe(rule.Id);
        record.Faults.Label.ShouldBe("blackhole");
        record.Timing.TotalMs.ShouldBeGreaterThan(350, "the request was held at least as long as the client waited");
        (await Wait.UntilAsync(() => _fx.Gate.InFlight == 0)).ShouldBeTrue("the slot is released when the client gives up");
        ConsoleDisplayStatus(record).ShouldBe("499 No response");
    }

    [Fact]
    public async Task BlackholedRequests_DoNotBlockThreads_NormalRequestsKeepSucceeding()
    {
        _fx.Faults.Create(new FaultSpec { Kind = FaultKind.Blackhole, Scope = new FaultScope(Key: "pin-key") });
        var pinning = _fx.NewClient(TimeSpan.FromSeconds(30));
        using var release = new CancellationTokenSource();
        var pinned = Enumerable.Range(0, FaultsHostFixture.MaxConcurrency - 2)
            .Select(_ => pinning.Http.PostAsync(Path("pin-key", "metadata"), EkmClient.JsonBody(EkmClient.Context), release.Token))
            .ToList();
        (await Wait.UntilAsync(() => _fx.Gate.InFlight == FaultsHostFixture.MaxConcurrency - 2)).ShouldBeTrue();

        var ekm = _fx.NewClient();
        var stopwatch = Stopwatch.StartNew();
        var dek = Fx.Random(32);
        for (var i = 0; i < 25; i++)
        {
            var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);
            wrapped.StatusCode.ShouldBe(200);
        }

        stopwatch.Stop();
        stopwatch.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(5));
        _fx.Gate.InFlight.ShouldBe(FaultsHostFixture.MaxConcurrency - 2, "only the blackholed requests are still held");

        release.Cancel();
        foreach (var task in pinned)
        {
            await Should.ThrowAsync<OperationCanceledException>(() => task);
        }

        (await Wait.UntilAsync(() => _fx.Gate.InFlight == 0)).ShouldBeTrue();
    }

    [Fact]
    public async Task BlackholedRequests_HoldTheirSlots_SoTheNextRequestIsAnImmediate429_AndAbortedConnectionsGiveThemBack()
    {
        _fx.Faults.Create(new FaultSpec { Kind = FaultKind.Blackhole, Scope = new FaultScope(Key: "pin-key") });
        var ekm = _fx.NewClient();
        var warm = await ekm.MetadataAsync("aes-key-1"); // handshake and JIT are paid for here
        warm.StatusCode.ShouldBe(200);
        var pinning = _fx.NewClient(TimeSpan.FromSeconds(30));
        using var release = new CancellationTokenSource();
        var pinned = Enumerable.Range(0, FaultsHostFixture.MaxConcurrency)
            .Select(_ => pinning.Http.PostAsync(Path("pin-key", "metadata"), EkmClient.JsonBody(EkmClient.Context), release.Token))
            .ToList();
        (await Wait.UntilAsync(() => _fx.Gate.InFlight == FaultsHostFixture.MaxConcurrency)).ShouldBeTrue();

        var stopwatch = Stopwatch.StartNew();
        var rejected = await ekm.MetadataAsync("aes-key-1");
        stopwatch.Stop();

        rejected.ShouldBeProxyError(429, "TooManyRequests");
        stopwatch.Elapsed.ShouldBeLessThan(TimeSpan.FromMilliseconds(250), "refused at once over a real TLS connection");

        release.Cancel(); // the clients abort their connections
        foreach (var task in pinned)
        {
            await Should.ThrowAsync<OperationCanceledException>(() => task);
        }

        (await Wait.UntilAsync(() => _fx.Gate.InFlight == 0)).ShouldBeTrue("every aborted connection released its slot");
        (await ekm.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task ABlackholeThatReachesItsHoldCap_ClosesTheConnection_AndFreesTheSlot()
    {
        _fx.Faults.Create(new FaultSpec { Kind = FaultKind.Blackhole, Scope = new FaultScope(Key: "aes-key-1") });
        var ekm = _fx.NewClient(TimeSpan.FromSeconds(30));
        var mark = _fx.Mark();

        var stopwatch = Stopwatch.StartNew();
        await Should.ThrowAsync<HttpRequestException>(() => ekm.Http.PostAsync(Path("aes-key-1", "metadata"), EkmClient.JsonBody(EkmClient.Context)));
        stopwatch.Stop();

        stopwatch.Elapsed.ShouldBeGreaterThanOrEqualTo(TimeSpan.FromSeconds(FaultsHostFixture.HoldCapSeconds - 0.1));
        stopwatch.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(25));
        var record = await _fx.WaitForExchangeAsync(mark, static r => r.Faults?.Kind == "blackhole" && r.Response.ClosedByServer);
        record.Response.Status.ShouldBe(499);
        record.Response.ClosedByServer.ShouldBeTrue("the server ended it, the client did not give up");
        (await Wait.UntilAsync(() => _fx.Gate.InFlight == 0)).ShouldBeTrue();
    }

    // ---- close connection ----

    [Fact]
    public async Task CloseConnection_ResetsTheConnectionWithoutAResponse_AndTheExchangeIsCapturedAndFlagged()
    {
        var rule = _fx.Faults.Create(new FaultSpec { Kind = FaultKind.CloseConnection, Scope = new FaultScope(Key: "aes-key-1") });
        var ekm = _fx.NewClient(TimeSpan.FromSeconds(10));
        var mark = _fx.Mark();

        await Should.ThrowAsync<HttpRequestException>(() => ekm.MetadataAsync("aes-key-1"));

        var record = await _fx.WaitForExchangeAsync(mark, static r => r.Faults?.Kind == "close");
        record.Response.Status.ShouldBe(499);
        record.Response.ClosedByServer.ShouldBeTrue();
        record.Response.ClientAborted.ShouldBeFalse();
        record.Faults!.Rule.ShouldBe(rule.Id);
        record.Faults.Label.ShouldBe("close connection");
        _fx.Gate.InFlight.ShouldBe(0, "a closed connection never held a slot");
        var other = await _fx.NewClient().MetadataAsync("rsa-key-1");
        other.StatusCode.ShouldBe(200); // not in scope: a new connection works
    }

    // ---- the internal deadline against a real, slow client ----

    [Fact]
    public async Task WhenTheDeadlinePassesWhileTheBodyIsStillArriving_TheServerAnswers429AtTheDeadline_AndNoCryptoRuns()
    {
        var ekm = _fx.NewClient(TimeSpan.FromSeconds(30));
        await ekm.InfoAsync(); // connection and JIT
        var before = _fx.Metrics.BudgetExceededCount(EkmMock.Server.Ekm.EkmOperation.WrapKey);
        var mark = _fx.Mark();
        var dek = Convert.ToBase64String(Fx.Random(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        using var request = new HttpRequestMessage(HttpMethod.Post, Path("aes-key-1", "wrapkey"))
        {
            Content = new SlowBody(EkmClient.WrapBody(Alg, dek), TimeSpan.FromSeconds(3)),
        };

        using var response = await ekm.Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);

        // What the client sees is its own business (HttpClient may finish sending a body before it surfaces an early response); what the server did is on the record:
        // it answered 429 when the deadline passed, not when the slow client had finished sending.
        response.StatusCode.ShouldBe(HttpStatusCode.TooManyRequests);
        var record = await _fx.WaitForExchangeAsync(mark, static r => r.Response.Status == 429);
        record.Timing.TotalMs.ShouldBeGreaterThanOrEqualTo(FaultsHostFixture.DeadlineMs - 50);
        record.Timing.TotalMs.ShouldBeLessThan(1500, "the 429 was decided at the deadline, long before the body of 3 s was complete");
        record.Response.Code.ShouldBe("TooManyRequests");
        record.Timing.CryptoMs.ShouldBe(0);
        record.Key.ShouldBeNull("the engine was never asked");
        _fx.Metrics.BudgetExceededCount(EkmMock.Server.Ekm.EkmOperation.WrapKey).ShouldBe(before + 1);
    }

    [Fact]
    public async Task QueueWait_ShowsTheTimeSpentBeforeTheCryptoStage_ForABodyThatArrivesSlowly()
    {
        var ekm = _fx.NewClient(TimeSpan.FromSeconds(30));
        await ekm.InfoAsync();
        var mark = _fx.Mark();
        var dek = Convert.ToBase64String(Fx.Random(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        using var request = new HttpRequestMessage(HttpMethod.Post, Path("aes-key-1", "wrapkey"))
        {
            Content = new SlowBody(EkmClient.WrapBody(Alg, dek), TimeSpan.FromMilliseconds(150)),
        };

        using var response = await ekm.Http.SendAsync(request);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var record = await _fx.WaitForExchangeAsync(mark, static r => r.Request.Operation == "wrapkey");
        record.Timing.QueueWaitMs.ShouldBeGreaterThan(100);
        record.Timing.QueueWaitMs.ShouldBeLessThan(FaultsHostFixture.DeadlineMs);
        record.Timing.InjectedDelayMs.ShouldBe(0);
        record.Timing.AuthMs.ShouldBeLessThan(record.Timing.QueueWaitMs, "authorization is accounted for separately");
    }

    // ---- fault delay end to end (spec 14 test 26) ----

    [Fact]
    public async Task ADelayPastTheDeadline_OverRealMtls_IsSlowForTheClient_CountedInTheMetrics_AndRedWithTheBadge()
    {
        // The shared host has a 400 ms internal deadline, so 450 ms is the "300 ms with the default 200 ms deadline" of spec 14 test 26: past the 250 ms budget and past the deadline.
        _fx.Faults.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 450 });
        var ekm = _fx.NewClient(TimeSpan.FromSeconds(30));
        await ekm.InfoAsync(); // first, delayed, request pays the handshake; measure the second
        var before = _fx.Metrics.BudgetExceededCount(EkmMock.Server.Ekm.EkmOperation.UnwrapKey);
        var mark = _fx.Mark();
        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, Fx.Random(32));

        var stopwatch = Stopwatch.StartNew();
        var reply = await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value());
        stopwatch.Stop();

        reply.StatusCode.ShouldBe(200);
        stopwatch.Elapsed.TotalMilliseconds.ShouldBeGreaterThan(250);
        _fx.Metrics.BudgetExceededCount(EkmMock.Server.Ekm.EkmOperation.UnwrapKey).ShouldBe(before + 1);
        var record = await _fx.WaitForExchangeAsync(mark, static r => r.Request.Operation == "unwrapkey");
        record.Timing.Budget.ShouldBe(BudgetStatus.Red);
        record.Faults!.Label.ShouldBe("delay 450 ms");
        record.Timing.InjectedDelayMs.ShouldBeGreaterThan(400);
        record.Timing.CryptoMs.ShouldBeLessThan(100);
        record.ClientCertificate.CommonName.ShouldBe(FaultsHostFixture.ClientCn);
    }

    // ---- faults and authentication (spec 7: Route → Faults → Auth → Limits) ----

    [Fact]
    public async Task HsmOffline_AnswersBeforeAuthentication_SoAnAnonymousCallerSees503_NotAn401()
    {
        _fx.Faults.Create(new FaultSpec { Kind = FaultKind.HsmOffline });

        (await _fx.NewAnonymousClient().InfoAsync()).ShouldBeProxyError(503, "HsmUnavailable");
        (await _fx.NewClient().InfoAsync()).ShouldBeProxyError(503, "HsmUnavailable");
    }

    [Fact]
    public async Task TheCallerOfAFaultThatAnswersBeforeAuth_IsStillNamedInTheRecord_ButAuthorizationIsNotClaimed()
    {
        _fx.Faults.Create(new FaultSpec { Kind = FaultKind.HsmOffline });
        var mark = _fx.Mark();

        (await _fx.NewClient().InfoAsync()).ShouldBeProxyError(503, "HsmUnavailable");

        var record = await _fx.WaitForExchangeAsync(mark, static r => r.Faults?.Kind == "offline");
        record.ClientCertificate.Present.ShouldBeTrue();
        record.ClientCertificate.CommonName.ShouldBe(FaultsHostFixture.ClientCn, "the handshake accepted this certificate");
        record.ClientCertificate.AuthEvaluated.ShouldBeFalse("namespace authorization did not run: the fault answered first");
        record.ClientCertificate.NamespaceMatched.ShouldBeNull();
        _fx.Host.Logs.Entries.Last(static e => e.Category == "EkmMock.Exchange" && e.Fields["fault"] is string fault && fault.EndsWith(":offline", StringComparison.Ordinal)).Fields["client_cn"].ShouldBe(FaultsHostFixture.ClientCn);
    }

    [Fact]
    public async Task ABlackholeAndADelay_OnlyApplyToAuthenticatedCallers_AnAnonymousCallerStillGets401()
    {
        // Blackhole and delay need a concurrency slot (a blackhole must count against the limit), and the Limits stage comes after Auth: an unauthenticated caller can
        // neither pin a slot nor be delayed, and learns nothing about the fault. DECISIONS.md "M7: Blackhole, close and the concurrency limit".
        _fx.Faults.Create(new FaultSpec { Kind = FaultKind.Blackhole });
        var mark = _fx.Mark();

        var anonymous = _fx.NewAnonymousClient();
        (await anonymous.InfoAsync()).ShouldBeProxyError(401, "Unauthenticated");
        (await anonymous.MetadataAsync("aes-key-1")).ShouldBeProxyError(401, "Unauthenticated");
        _fx.Gate.InFlight.ShouldBe(0);

        // The rule never acted on these requests, so they are not flagged and the rule's fire count stays at zero.
        var record = await _fx.WaitForExchangeAsync(mark, static r => r.Response.Status == 401 && r.Request.Operation == "metadata");
        record.Faults.ShouldBeNull();
        _fx.Faults.List().Single().Fired.ShouldBe(0);
    }

    [Fact]
    public async Task EveryFaultKind_IsOnlyAppliedToEkmRoutes_TheConsoleAndHealthEndpointsAreNeverAffected()
    {
        foreach (var kind in new[] { FaultKind.HsmOffline, FaultKind.CloseConnection, FaultKind.Blackhole })
        {
            _fx.Faults.Create(new FaultSpec { Kind = kind });
        }

        _fx.Faults.Create(new FaultSpec { Kind = FaultKind.Delay, DelayMs = 5000 });
        _fx.Faults.Create(new FaultSpec { Kind = FaultKind.Error, ErrorPercent = 100, StatusCode = 503 });
        using var console = _fx.Host.CreateConsoleClient();
        console.Timeout = TimeSpan.FromSeconds(3);

        foreach (var path in new[] { "/healthz", "/readyz", "/metrics", "/api/console/status", "/api/console/faults" })
        {
            var stopwatch = Stopwatch.StartNew();
            using var response = await console.GetAsync(path);
            response.StatusCode.ShouldBe(HttpStatusCode.OK, path);
            stopwatch.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(2), path);
        }
    }

    private static string ConsoleDisplayStatus(ExchangeRecord record) => EkmMock.Server.WebConsole.ConsoleDisplay.StatusText(record.Status, record.Response.Code);
}
