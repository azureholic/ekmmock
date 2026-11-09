using System.Buffers.Text;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Text;
using EkmMock.Crypto;
using EkmMock.Server.Connections;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.Server.Metrics;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>Shared helpers for the end-to-end inspector tests on the in-process host.</summary>
internal static class InspectorHarness
{
    public static IInspector InspectorOf(EkmFactory factory) => factory.Services.GetRequiredService<IInspector>();

    /// <summary>Waits until the consumer has stored at least <paramref name="count"/> exchanges, and returns all of them, oldest first.</summary>
    public static async Task<IReadOnlyList<ExchangeRecord>> SettleAsync(IInspector inspector, int count, TimeSpan? timeout = null)
    {
        var reached = await Wait.UntilAsync(() => inspector.Count() >= count, timeout ?? TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(5)); // 30 s: a passing run returns at once; the limit is for a starved CI runner
        reached.ShouldBeTrue($"the inspector stored {inspector.Count()} of {count} exchanges");
        return [.. inspector.Query(paging: new ExchangePaging { Limit = ExchangePaging.MaxLimit }).Items.Reverse()];
    }

    public static EkmFactory CreateFactory(
        bool persist = false,
        bool reveal = false,
        int? ringSize = null,
        int? channelCapacity = null,
        IEngineAvailability? availability = null,
        IAuditLog? audit = null,
        IReplaySender? replaySender = null,
        Action<IServiceCollection>? configure = null,
        bool keys = true,
        bool realRevealGate = false,
        string? secretDisplay = null,
        Dictionary<string, string?>? configuration = null,
        bool faults = false,
        EkmMock.Server.Faults.IFaultRandom? faultRandom = null)
    {
        configuration ??= [];
        if (persist)
        {
            configuration["Inspector:Persist"] = "true";
        }

        if (ringSize is { } ring)
        {
            configuration["Inspector:RingBufferSize"] = ring.ToString();
        }

        if (channelCapacity is { } capacity)
        {
            configuration["Inspector:ChannelCapacity"] = capacity.ToString();
        }

        if (secretDisplay is not null)
        {
            configuration["Inspector:SecretDisplay"] = secretDisplay;
        }

        var factory = new EkmFactory(new EkmFactoryOptions
        {
            Configuration = configuration,
            Availability = availability,
            EnableFaults = faults,
            FaultRandom = faultRandom,
            ConfigureServices = services =>
            {
                if (!realRevealGate)
                {
                    services.AddSingleton<IInspectorRevealGate>(new TestRevealGate(reveal));
                }
                if (audit is not null)
                {
                    services.AddSingleton(audit);
                }

                if (replaySender is not null)
                {
                    services.AddSingleton(replaySender);
                }

                configure?.Invoke(services);
            },
        });
        if (keys)
        {
            factory.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
            factory.Keys.Create("_default", "rsa-key-1", KeyType.Rsa, 2048);
        }

        return factory;
    }

    /// <summary>Everything the inspector shows or writes about the exchanges, as text, for leak scans.</summary>
    public static string AllTextOf(IEnumerable<ExchangeRecord> records)
    {
        var builder = new StringBuilder();
        foreach (var record in records)
        {
            builder.AppendLine(JsonText.Serialize(record));
            builder.AppendLine(record.ToString());
            builder.AppendLine(record.Request.Body.Text);
            builder.AppendLine(record.Request.Body.PrettyJson);
            builder.AppendLine(record.Response.Body.Text);
            builder.AppendLine(record.Response.Body.PrettyJson);
            builder.AppendLine(string.Join("|", record.Request.Body.MaskedFields.Select(static f => f.Display)));
        }

        return builder.ToString();
    }
}

/// <summary>Spec 8.1, 8.3, 14 test 20: every exchange is captured, including the rejected ones, with request and response bodies and timing.</summary>
public sealed class InspectorCaptureTests
{
    private const string Alg = "A256KWP";

    // ---- every kind of request is captured ----

    [Fact]
    public async Task EveryRequest_IncludingTheRejectedOnes_IsCaptured_WithBodiesAndTiming()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);
        var wrapPath = EkmClient.Path(null, "aes-key-1", "wrapkey");
        var wrapBody = EkmClient.WrapBody(Alg, Base64Url.EncodeToString(dek));
        var big = "{\"request_context\":{\"correlation_id\":\"c\"},\"pad\":\"" + new string('x', 20_000) + "\"}";
        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);

        var cases = new List<(string Name, Func<Task<EkmReply>> Send, int Status, string? Op, string? Code)>
        {
            ("info", () => ekm.InfoAsync(), 200, "info", null),
            ("metadata", () => ekm.MetadataAsync("aes-key-1"), 200, "metadata", null),
            ("wrap", () => ekm.WrapAsync("aes-key-1", Alg, dek), 200, "wrapkey", null),
            ("unwrap", () => ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value()), 200, "unwrapkey", null),
            ("missing api-version", () => ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey", query: null), wrapBody), 400, "wrapkey", "UnsupportedApiVersion"),
            ("bad key name", () => ekm.PostAsync(EkmClient.Path(null, "bad_key", "wrapkey"), wrapBody), 400, "wrapkey", "InvalidKeyName"),
            ("wrong content type", () => ekm.PostAsync(wrapPath, wrapBody, "text/plain"), 400, "wrapkey", "InvalidRequest"),
            ("bad json", () => ekm.PostAsync(wrapPath, "{not json " + Base64Url.EncodeToString(dek)), 400, "wrapkey", "InvalidRequest"),
            ("no request_context", () => ekm.PostAsync(wrapPath, "{\"alg\":\"A256KWP\"}"), 400, "wrapkey", "InvalidRequest"),
            ("unknown prefix", () => ekm.PostAsync("/nope/aes-key-1/wrapkey?api-version=0.1-preview", wrapBody), 404, null, "NotFound"),
            ("unknown key", () => ekm.WrapAsync("no-such-key", Alg, dek), 404, "wrapkey", "KeyNotFound"),
            ("method not allowed", () => ekm.SendAsync(HttpMethod.Get, wrapPath, EkmClient.JsonBody(wrapBody)), 405, "wrapkey", "MethodNotAllowed"),
            ("oversize body", () => ekm.PostAsync(EkmClient.Path(null, null, "info"), big), 400, "info", "InvalidRequest"),
            ("invalid base64url", () => ekm.WrapRawAsync("aes-key-1", Alg, "not+base64/here"), 400, "wrapkey", "InvalidRequest"),
            ("unsupported algorithm", () => ekm.WrapRawAsync("aes-key-1", "A128KW", Base64Url.EncodeToString(dek)), 400, "wrapkey", "UnsupportedAlgorithm"),
            ("tampered unwrap", () => ekm.UnwrapAsync("aes-key-1", Alg, Fx.Random(40)), 400, "unwrapkey", "InvalidCiphertext"),
        };
        await InspectorHarness.SettleAsync(inspector, 1);
        var baseline = inspector.Count(); // the setup wrap above

        var replies = new List<EkmReply>();
        foreach (var (_, send, _, _, _) in cases)
        {
            replies.Add(await send());
        }

        var records = (await InspectorHarness.SettleAsync(inspector, (int)baseline + cases.Count)).Skip((int)baseline).ToList();

        records.Count.ShouldBe(cases.Count);
        for (var i = 0; i < cases.Count; i++)
        {
            var (name, _, status, op, code) = cases[i];
            var record = records[i];
            replies[i].StatusCode.ShouldBe(status, name);
            record.Response.Status.ShouldBe(status, name);
            record.Request.Operation.ShouldBe(op, name);
            record.Response.Code.ShouldBe(code, name);
            record.Request.Method.ShouldBe(name == "method not allowed" ? "GET" : "POST", name);
            record.Request.RawTarget.ShouldNotBeNullOrEmpty(name);
            record.Timing.TotalMs.ShouldBeGreaterThan(0, name);
            record.Response.Body.SizeBytes.ShouldBeGreaterThan(0, name);
            record.Response.Body.Captured.ShouldBeTrue(name);
            record.Response.Headers.ShouldContain(static h => h.Name == "Content-Type", name);
            record.Identity.ExchangeId.ShouldBe(records[0].Id + i, name); // sequential
            record.Timing.Budget.ShouldBe(BudgetStatus.Green, name);
            if (code is not null)
            {
                record.Response.Body.Text.ShouldNotBeNull().ShouldContain($"\"code\":\"{code}\"");
            }
        }

        // Request bodies: present for every request that sent one (what is on the wire, size included).
        records[0].Request.Body.Text.ShouldNotBeNull().ShouldContain("request_context");
        records[12].Request.Body.SizeBytes.ShouldBeGreaterThan(20_000);
        records[12].Request.Body.Truncated.ShouldBeTrue();
        records[12].Request.Body.Text.ShouldNotBeNull().Length.ShouldBe(16 * 1024); // an info body is not secret: the first 16 KiB are kept
        records[11].Request.Body.SizeBytes.ShouldBe(Encoding.UTF8.GetByteCount(wrapBody));
        records[9].Request.Namespace.ShouldBeNull(); // an unroutable path has no namespace
        records[9].Request.Body.SizeBytes.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task ATooManyRequestsExchange_IsCaptured_LikeAnyOtherStatus()
    {
        // Spec 10.1 / 14 test 27: over the concurrency limit the answer is an immediate 429, and the inspector captures it with its body. MaxConcurrency 1 and a blackhole
        // rule that pins the one slot make it deterministic: the pinned request holds the slot until its client gives up, so the second request cannot get in.
        using var factory = InspectorHarness.CreateFactory(
            faults: true,
            configuration: new Dictionary<string, string?> { ["Limits:MaxConcurrency"] = "1" });
        var inspector = InspectorHarness.InspectorOf(factory);
        factory.Faults.Create(new EkmMock.Server.Faults.FaultSpec
        {
            Kind = EkmMock.Server.Faults.FaultKind.Blackhole,
            Scope = new EkmMock.Server.Faults.FaultScope(Key: "aes-key-1"),
        });
        var ekm = factory.CreateEkmClient();
        using var pinned = new CancellationTokenSource();
        var pin = ekm.Http.PostAsync(EkmClient.Path(null, "aes-key-1", "metadata"), EkmClient.JsonBody(EkmClient.Context), pinned.Token);
        (await Wait.UntilAsync(() => factory.Gate.InFlight == 1)).ShouldBeTrue();

        var rejected = await ekm.MetadataAsync("rsa-key-1");

        rejected.ShouldBeProxyError(429, "TooManyRequests");
        var record = (await InspectorHarness.SettleAsync(inspector, 1)).Single();
        record.Response.Status.ShouldBe(429);
        record.Response.Code.ShouldBe("TooManyRequests");
        record.Response.Body.Text.ShouldNotBeNull().ShouldContain("\"code\":\"TooManyRequests\"");
        record.Request.Operation.ShouldBe("metadata");
        record.Request.Key.ShouldBe("rsa-key-1");
        record.Faults.ShouldBeNull(); // the concurrency limit is not a fault

        pinned.Cancel();
        await Should.ThrowAsync<OperationCanceledException>(() => pin);
    }

    [Fact]
    public async Task AnUnavailableEngine_Answers503_AndTheExchangeIsCaptured()
    {
        using var factory = InspectorHarness.CreateFactory(availability: new FixedAvailability(false));
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();

        var info = await ekm.InfoAsync();
        var wrap = await ekm.WrapAsync("aes-key-1", Alg, Fx.Random(32));
        var records = await InspectorHarness.SettleAsync(inspector, 2);

        info.StatusCode.ShouldBe(503);
        wrap.StatusCode.ShouldBe(503);
        records.Select(static r => r.Response.Status).ShouldBe([503, 503]);
        records.ShouldAllBe(static r => r.Response.Code == "HsmUnavailable");
        records[0].Response.Body.Text.ShouldNotBeNull().ShouldContain("HsmUnavailable");
        records[1].Request.Body.MaskedFields.ShouldHaveSingleItem().Field.ShouldBe("request.value"); // the DEK was in the request, masked even though the request failed
        records.ShouldAllBe(static r => r.Key == null); // the engine was never asked
    }

    // ---- what a record contains ----

    [Fact]
    public async Task AWrapExchange_HasEveryGroupOfSection81()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();

        await ekm.WrapAsync("aes-key-1", Alg, Fx.Random(32));
        await ekm.UnwrapAsync("aes-key-1", Alg, Fx.Random(40)); // fails: InvalidCiphertext, still touches the key
        var wrap = (await InspectorHarness.SettleAsync(inspector, 2))[0];

        // Identity
        wrap.Identity.ExchangeId.ShouldBe(1);
        (wrap.Identity.ReceivedAtUtc.Ticks % 10).ShouldBe(0); // microsecond precision
        wrap.Identity.ReceivedAtUtc.ShouldBeInRange(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddSeconds(1));
        wrap.Identity.ReceivedAtUtc.Offset.ShouldBe(TimeSpan.Zero);

        // Request
        wrap.Request.Method.ShouldBe("POST");
        wrap.Request.RawTarget.ShouldBe("/aes-key-1/wrapkey?api-version=0.1-preview");
        wrap.Request.Namespace.ShouldBe("_default");
        wrap.Request.Prefix.ShouldBe(string.Empty);
        wrap.Request.Key.ShouldBe("aes-key-1");
        wrap.Request.Operation.ShouldBe("wrapkey");
        wrap.Request.ApiVersion.ShouldBe("0.1-preview");
        wrap.Request.Headers.ShouldContain(static h => h.Name == "Content-Type" && h.Value.StartsWith("application/json", StringComparison.Ordinal));
        wrap.Request.Body.PrettyJson.ShouldNotBeNull().ShouldContain("request_context");

        // EKM context
        wrap.Context.RequestId.ShouldBe("r");
        wrap.Context.CorrelationId.ShouldBe("c");
        wrap.Context.PoolName.ShouldBe("p");
        wrap.Context.Algorithm.ShouldBe(Alg);

        // Response
        wrap.Response.Status.ShouldBe(200);
        wrap.Response.Code.ShouldBeNull();
        wrap.Response.Body.Text.ShouldNotBeNull().ShouldStartWith("{\"value\":\"");
        wrap.Response.Headers.ShouldContain(static h => h.Name == "Content-Type" && h.Value == "application/json");

        // Timing
        wrap.Timing.TotalMs.ShouldBeGreaterThan(0);
        wrap.Timing.CryptoMs.ShouldBeGreaterThan(0);
        wrap.Timing.TotalMs.ShouldBeGreaterThanOrEqualTo(wrap.Timing.CryptoMs);
        wrap.Timing.AuthMs.ShouldBeGreaterThanOrEqualTo(0);
        wrap.Timing.InjectedDelayMs.ShouldBe(0);
        wrap.Timing.QueueWaitMs.ShouldBeInRange(0, 100); // since M7: the time before the crypto stage that is not authorization (a few tenths of a millisecond in process)
        wrap.Timing.Budget.ShouldBe(BudgetStatus.Green);

        // Key and faults
        wrap.Key.ShouldNotBeNull().ShouldBe(new KeyFacts("oct", 256, "Enabled", 1, 0));
        wrap.Faults.ShouldBeNull();

        // No TLS in the in-process host: the group is absent rather than made up.
        wrap.Tls.ShouldBeNull();
        wrap.ClientCertificate.AuthEvaluated.ShouldBeTrue();
        wrap.ClientCertificate.Present.ShouldBeFalse();

        var unwrap = inspector.Get(2).ShouldNotBeNull();
        unwrap.Response.Code.ShouldBe("InvalidCiphertext");
        unwrap.Key.ShouldNotBeNull().WrapCount.ShouldBe(1);
    }

    [Fact]
    public async Task TheUsageCounterOfTheKey_IsTheValueAfterThatCall()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        for (var i = 0; i < 5; i++)
        {
            await ekm.WrapAsync("aes-key-1", Alg, Fx.Random(32));
        }

        var records = await InspectorHarness.SettleAsync(inspector, 5);

        records.Select(static r => r.Key!.WrapCount).ShouldBe([1, 2, 3, 4, 5]);
        records.ShouldAllBe(static r => r.Key!.UnwrapCount == 0);
    }

    [Fact]
    public async Task AnRsaKey_ReportsItsTypeAndSize()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);

        await factory.CreateEkmClient().WrapAsync("rsa-key-1", "RSA-OAEP-256", Fx.Random(32));

        (await InspectorHarness.SettleAsync(inspector, 1))[0].Key.ShouldNotBeNull().ShouldBe(new KeyFacts("RSA", 2048, "Enabled", 1, 0));
    }

    [Fact]
    public async Task ARejectedRequest_WithoutAnUnreadBody_StillCarriesItsRequestContext()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var body = """{"request_context":{"request_id":"rid-7","correlation_id":"corr-401","pool_name":"pool-x"}}""";

        // A 404 is answered before the body is read: the capture reads it itself, so the request can still be found by correlation_id.
        var reply = await factory.CreateEkmClient().PostAsync("/nowhere/info?api-version=0.1-preview", body);
        var record = (await InspectorHarness.SettleAsync(inspector, 1))[0];

        reply.StatusCode.ShouldBe(404);
        record.Context.CorrelationId.ShouldBe("corr-401");
        record.Context.RequestId.ShouldBe("rid-7");
        record.Context.PoolName.ShouldBe("pool-x");
        record.Request.Body.Text.ShouldBe(body);
        inspector.Query(new ExchangeFilter { Text = "corr-401" }).Items.ShouldHaveSingleItem();
    }

    // ---- timing: the producer is not slowed, and the capture is visible quickly ----

    [Fact]
    public async Task ARequest_IsVisibleInTheFeedAndTheQuery_WithinOneSecond()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        using var subscription = inspector.Feed.Subscribe();
        var ekm = factory.CreateEkmClient();
        await ekm.InfoAsync(); // warm up the pipeline so that the measurement is not about JIT
        await subscription.Reader.ReadAsync(TestContext.Current.CancellationToken);

        var started = Stopwatch.GetTimestamp();
        var reply = await ekm.WrapAsync("aes-key-1", Alg, Fx.Random(32));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(1));
        var item = await subscription.Reader.ReadAsync(timeout.Token);

        Stopwatch.GetElapsedTime(started).ShouldBeLessThan(TimeSpan.FromSeconds(1));
        reply.StatusCode.ShouldBe(200);
        var exchange = item.ShouldBeOfType<ExchangeFeedItem>().Exchange;
        exchange.Request.Operation.ShouldBe("wrapkey");
        inspector.Get(exchange.Id).ShouldBeSameAs(exchange); // queryable by the time the console is told
    }

    // ---- capture must not change what the EKM endpoint does ----

    [Fact]
    public async Task TheResponse_IsByteForByteWhatTheClientGets_AndTheDekStillWrapsAndUnwraps()
    {
        using var factory = InspectorHarness.CreateFactory();
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);

        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);
        var unwrapped = await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value());
        var inspector = InspectorHarness.InspectorOf(factory);
        var records = await InspectorHarness.SettleAsync(inspector, 2);

        Fx.Same(unwrapped.Value(), dek).ShouldBeTrue();
        wrapped.Message.Content.Headers.ContentLength.ShouldBe(wrapped.Body.Length);
        records[0].Response.Body.Text.ShouldBe(wrapped.Text); // ciphertext is shown exactly as sent
        records[1].Request.Body.Text.ShouldNotBeNull().ShouldContain(wrapped.ValueText());
    }

    [Fact]
    public void TheCaptureMiddleware_IsTheFirstStageOfTheEkmPipeline()
    {
        var source = File.ReadAllText(Path.Combine(RepoPaths.Src("EkmMock.Server"), "Ekm", "EkmPipeline.cs"));
        var capture = source.IndexOf("UseMiddleware<Inspector.InspectorCaptureMiddleware>", StringComparison.Ordinal);
        var exchange = source.IndexOf("UseMiddleware<EkmExchangeMiddleware>", StringComparison.Ordinal);
        var route = source.IndexOf("UseMiddleware<EkmRouteMiddleware>", StringComparison.Ordinal);
        var auth = source.IndexOf("UseMiddleware<EkmAuthMiddleware>", StringComparison.Ordinal);

        capture.ShouldBeGreaterThan(0);
        capture.ShouldBeLessThan(exchange);
        exchange.ShouldBeLessThan(route);
        route.ShouldBeLessThan(auth);
    }

    // ---- the bounded queue ----

    [Fact]
    public async Task AFullQueue_DropsTheOldest_CountsIt_AndTheRequestsAreNeverSlowed()
    {
        const int capacity = 16;
        const int burst = 100;
        var blocker = new BlockingStage();
        using var factory = InspectorHarness.CreateFactory(channelCapacity: capacity, configure: services => services.AddSingleton<IInspectorStage>(blocker));
        var inspector = InspectorHarness.InspectorOf(factory);
        var metrics = factory.Services.GetRequiredService<EkmMetrics>();
        var ekm = factory.CreateEkmClient();
        var observed = 0L;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Name == "ekmmock_inspector_dropped_total")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, value, _, _) => Interlocked.Add(ref observed, value));
        listener.Start();

        // Baseline: how long a request takes while the consumer keeps up.
        for (var i = 0; i < 10; i++)
        {
            await ekm.InfoAsync();
        }

        var free = new List<double>();
        for (var i = 0; i < 50; i++)
        {
            var sw = Stopwatch.GetTimestamp();
            (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
            free.Add(Stopwatch.GetElapsedTime(sw).TotalMilliseconds);
        }

        // Wait until the consumer has been through every record that was not dropped (a loaded machine may have dropped a few of the 60 with this tiny queue),
        // so that the next record is certain to be the one it blocks on.
        await Wait.UntilAsync(() => blocker.Seen + inspector.Status().DroppedExchanges >= 60).ShouldBeTrueAsync();
        var droppedBefore = inspector.Status().DroppedCaptures;
        var countBefore = inspector.Count();

        blocker.Arm();
        await ekm.InfoAsync(); // the consumer takes this one and blocks inside it
        blocker.WaitUntilBlocked(TimeSpan.FromSeconds(10)).ShouldBeTrue();
        var blockedLatencies = new List<double>();
        for (var i = 0; i < burst; i++)
        {
            var sw = Stopwatch.GetTimestamp();
            var reply = await ekm.InfoAsync();
            blockedLatencies.Add(Stopwatch.GetElapsedTime(sw).TotalMilliseconds);
            reply.StatusCode.ShouldBe(200);
        }

        // Nothing waited for the consumer: every request of the burst completed, none was slower than a generous bound,
        // and the median did not move (a blocked consumer must not show up in request latency at all).
        blockedLatencies.Max().ShouldBeLessThan(1000);
        Median(blockedLatencies).ShouldBeLessThan((Median(free) * 5) + 10);

        // Exactly the overflow was dropped: the consumer holds the blocking record, `capacity` records wait in the queue, the rest of the burst was dropped.
        var dropped = inspector.Status().DroppedCaptures - droppedBefore;
        dropped.ShouldBe(burst - capacity);
        inspector.Status().DroppedExchanges.ShouldBe(inspector.Status().DroppedCaptures);
        metrics.InspectorDroppedTotal.ShouldBe(inspector.Status().DroppedCaptures);
        Interlocked.Read(ref observed).ShouldBeGreaterThanOrEqualTo(dropped); // the instrument ekmmock_inspector_dropped_total counted them (other hosts may add)

        // Releasing the consumer lets it catch up. The OLDEST records were dropped: the buffer ends with what it had, the blocking record and the NEWEST `capacity` of the burst.
        var lastId = 60 + 1 + burst; // exchange ids are sequential: 60 before, the blocking one, the burst
        blocker.Release();
        await Wait.UntilAsync(() => inspector.Get(lastId) is not null).ShouldBeTrueAsync();
        await Wait.UntilAsync(() => inspector.Count() >= countBefore + 1 + capacity).ShouldBeTrueAsync();
        var newest = Enumerable.Range(lastId - capacity + 1, capacity).Select(static i => (long)i).ToList();
        inspector.Query(paging: new ExchangePaging { Limit = capacity }).Items.Select(static r => r.Id).ShouldBe(newest.AsEnumerable().Reverse());
        inspector.Get(60 + 1).ShouldNotBeNull(); // the blocking record
        inspector.Get(lastId - capacity).ShouldBeNull(); // the newest one that was dropped
        inspector.Get(60 + 2).ShouldBeNull(); // the first one of the burst
        inspector.Count().ShouldBe(countBefore + 1 + capacity);
    }

    private static double Median(List<double> values)
    {
        var sorted = values.Order().ToList();
        return sorted[sorted.Count / 2];
    }

    [Fact]
    public async Task WhenTheRingBufferIsFull_TheOldestExchangesAreEvicted()
    {
        using var factory = InspectorHarness.CreateFactory(ringSize: 5);
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();

        for (var i = 0; i < 12; i++)
        {
            await ekm.InfoAsync();
        }

        await Wait.UntilAsync(() => inspector.Status().RingEvicted >= 7).ShouldBeTrueAsync();
        inspector.Status().RingCapacity.ShouldBe(5);
        inspector.Query(paging: new ExchangePaging { Limit = 100 }).Items.Select(static r => r.Id).ShouldBe([12, 11, 10, 9, 8]);
        inspector.Get(7).ShouldBeNull();
    }

    // ---- the queries the console will make ----

    [Fact]
    public async Task TheStatusAndDashboard_ReflectTheTraffic()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        await ekm.InfoAsync();
        await ekm.WrapAsync("aes-key-1", Alg, Fx.Random(32));
        await ekm.WrapAsync("missing", Alg, Fx.Random(32));
        await InspectorHarness.SettleAsync(inspector, 3);

        var dashboard = inspector.Dashboard();
        var status = inspector.Status();

        dashboard.Last15Minutes.Total.ShouldBe(3);
        dashboard.Last15Minutes.Operations.Select(static o => o.Operation).ShouldBe(["info", "wrapkey"]);
        dashboard.Last15Minutes.ErrorsByCode.ShouldBe(new Dictionary<string, long> { ["KeyNotFound"] = 1 });
        dashboard.Heartbeat.EverSeen.ShouldBeTrue();
        dashboard.Heartbeat.IsStale.ShouldBeFalse();
        dashboard.DroppedCaptures.ShouldBe(0);
        status.RingCount.ShouldBe(3);
        status.ExchangesCaptured.ShouldBe(3);
        status.CaptureFailures.ShouldBe(0);
        status.SecretDisplay.ShouldBe(SecretDisplayMode.Masked);
        status.RevealAllowed.ShouldBeFalse();
        inspector.Query(new ExchangeFilter { HideInfo = true, OnlyErrors = true }).Items.ShouldHaveSingleItem().Response.Code.ShouldBe("KeyNotFound");
    }

    [Fact]
    public async Task TheKqlOfAnExchange_UsesItsCorrelationId()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        await factory.CreateEkmClient().UnwrapAsync("aes-key-1", Alg, Fx.Random(40));
        await InspectorHarness.SettleAsync(inspector, 1);

        var snippet = inspector.Kql(1).ShouldNotBeNull();

        snippet.ByCorrelationId.ShouldNotBeNull().ShouldContain("\"c\"");
        snippet.ByCorrelationId.ShouldContain("EkmUnwrapKey");
        inspector.Kql(999).ShouldBeNull();
    }

    [Fact]
    public void TheInspector_IsRegisteredOnceAsASingleton_WithTheSameInstanceBehindEveryInterface()
    {
        using var factory = InspectorHarness.CreateFactory(keys: false);

        factory.Services.GetRequiredService<IInspector>().ShouldBeSameAs(factory.Services.GetRequiredService<IInspectorQuery>());
        factory.Services.GetRequiredService<IInspectorFeed>().ShouldBeSameAs(factory.Services.GetRequiredService<IInspector>().Feed);
        factory.Services.GetRequiredService<IEnumerable<IInspectorStage>>().Select(static s => s.GetType().Name)
            .Take(5).ShouldBe(["ExchangeRingBuffer", "DashboardAggregator", "ConnectionStatsStage", "InspectorFeed", "InspectorJsonlWriter"]);
    }

    [Fact]
    public void TheDefaultCompositionNeverAllowsReveal()
    {
        using var factory = new EkmFactory();

        factory.Services.GetRequiredService<IInspectorRevealGate>().IsAllowed.ShouldBeFalse();
        factory.Services.GetRequiredService<IInspector>().Status().RevealAllowed.ShouldBeFalse();
        factory.Services.GetRequiredService<IInspector>().Status().SecretDisplay.ShouldBe(SecretDisplayMode.Masked);
    }
}

internal static class AsyncAssertions
{
    public static async Task ShouldBeTrueAsync(this Task<bool> task)
        => (await task).ShouldBeTrue();
}
