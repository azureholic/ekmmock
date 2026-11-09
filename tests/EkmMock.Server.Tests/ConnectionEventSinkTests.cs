using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Server.Connections;
using EkmMock.Server.Tls;
using Microsoft.Extensions.Logging.Abstractions;

namespace EkmMock.Server.Tests;

/// <summary>The bounded, non-blocking connection event sink, the in-memory store and the metric (spec 8.2, 8.3, 9).</summary>
public sealed class ConnectionEventSinkTests
{
    private static ConnectionEvent Event(ConnectionEventKind kind = ConnectionEventKind.Opened, string id = "c1")
        => new() { ConnectionId = id, Kind = kind, AtUtc = DateTimeOffset.UtcNow };

    private static List<T> Drain<T>(BoundedDropOldestQueue<T> queue)
    {
        var items = new List<T>();
        while (queue.Reader.TryRead(out var item))
        {
            items.Add(item);
        }

        return items;
    }

    [Fact]
    public void AFullQueue_DropsTheOldest_AndCountsEveryDrop()
    {
        var queue = new BoundedDropOldestQueue<int>(3);

        for (var i = 1; i <= 5; i++)
        {
            queue.TryEnqueue(i).ShouldBeTrue();
        }

        Drain(queue).ShouldBe([3, 4, 5]);
        queue.Dropped.ShouldBe(2);
    }

    [Fact]
    public void AnUnreadQueue_NeverBlocksTheProducer_NoMatterHowManyItemsArrive()
    {
        var queue = new BoundedDropOldestQueue<int>(10);
        var watch = Stopwatch.StartNew();

        for (var i = 0; i < 200_000; i++)
        {
            queue.TryEnqueue(i).ShouldBeTrue();
        }

        watch.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(5));
        queue.Dropped.ShouldBe(199_990);
        Drain(queue).ShouldBe(Enumerable.Range(199_990, 10));
    }

    [Fact]
    public async Task ManyConcurrentProducers_AccountForEveryItem_DroppedPlusDelivered()
    {
        var queue = new BoundedDropOldestQueue<int>(100);
        const int producers = 8;
        const int perProducer = 5000;

        await Task.WhenAll(Enumerable.Range(0, producers).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < perProducer; i++)
            {
                queue.TryEnqueue(i);
            }
        })));

        (Drain(queue).Count + queue.Dropped).ShouldBe(producers * perProducer);
    }

    [Fact]
    public void TheSink_NumbersEventsInOrder_AndSurfacesDropsWhenNobodyReads()
    {
        var sink = new ConnectionEventSink(capacity: 2);

        for (var i = 0; i < 5; i++)
        {
            sink.Publish(Event(id: "c" + i));
        }

        sink.LastSequence.ShouldBe(5);
        sink.Dropped.ShouldBe(3);
        var kept = new List<ConnectionEvent>();
        while (sink.Reader.TryRead(out var item))
        {
            kept.Add(item);
        }

        kept.Select(static e => e.Sequence).ShouldBe([4L, 5L]);
        kept.Select(static e => e.ConnectionId).ShouldBe(["c3", "c4"]);
    }

    [Fact]
    public async Task ThePump_MovesEventsFromTheSinkIntoTheStore_AndTheStoreKeepsOnlyTheLatest()
    {
        var sink = new ConnectionEventSink();
        var store = new ConnectionEventStore(capacity: 3);
        var pump = new ConnectionEventPump(sink, store);
        await pump.StartAsync(TestContext.Current.CancellationToken);

        for (var i = 0; i < 5; i++)
        {
            sink.Publish(Event(id: "c" + i));
        }

        var last = await store.WaitForAsync(static e => e.ConnectionId == "c4", TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        last.ShouldNotBeNull();
        store.Snapshot().Select(static e => e.ConnectionId).ShouldBe(["c2", "c3", "c4"]);
        await pump.StopAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task WaitFor_ReturnsAnEventThatArrivesLater_AndNullOnTimeout()
    {
        var store = new ConnectionEventStore();
        var waiting = store.WaitForAsync(static e => e.Kind == ConnectionEventKind.HandshakeFailed, TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);

        store.Add(Event(ConnectionEventKind.Opened));
        store.Add(Event(ConnectionEventKind.HandshakeFailed, "late"));

        (await waiting).ShouldNotBeNull().ConnectionId.ShouldBe("late");
        (await store.WaitForAsync(static e => e.ConnectionId == "never", TimeSpan.FromMilliseconds(100), TestContext.Current.CancellationToken)).ShouldBeNull();
    }

    [Fact]
    public void TheEventRecord_HasNoPlaceForSecrets()
    {
        // Only names, endpoints, protocol facts and the public summary of a client certificate (no raw certificate, no key, no body).
        var properties = typeof(ConnectionEvent).GetProperties().Select(static p => p.PropertyType).ToList();

        properties.ShouldNotContain(typeof(X509Certificate2));
        properties.ShouldNotContain(typeof(byte[]));
        properties.ShouldNotContain(typeof(Exception));
    }

    [Fact]
    public void TheHandshakeFailureMetric_CountsPerReasonLabel_AndIsAMeterInstrument()
    {
        using var metrics = new EkmMetrics();
        var measured = new List<(long Value, string? Reason)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == EkmMetrics.MeterName && instrument.Name == EkmMetrics.HandshakeFailuresName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Key == "reason")
                {
                    measured.Add((value, tag.Value?.ToString()));
                }
            }
        });
        listener.Start();

        metrics.RecordHandshakeFailure(HandshakeFailureReason.TlsVersionNotSupported);
        metrics.RecordHandshakeFailure(HandshakeFailureReason.TlsVersionNotSupported);
        metrics.RecordHandshakeFailure(HandshakeFailureReason.ClientCertificateNotTrusted);

        metrics.HandshakeFailureCounts["tls_version_not_supported"].ShouldBe(2);
        metrics.HandshakeFailureCounts["client_cert_not_trusted"].ShouldBe(1);
        metrics.TotalHandshakeFailures.ShouldBe(3);
        measured.ShouldBe([(1L, "tls_version_not_supported"), (1L, "tls_version_not_supported"), (1L, "client_cert_not_trusted")]);
        EkmMetrics.HandshakeFailuresName.ShouldBe("ekmmock_tls_handshake_failures_total");
    }

    [Fact]
    public void EveryFailureReason_HasAStableLabelAndASafeDescription()
    {
        var labels = new HashSet<string>();
        foreach (var reason in Enum.GetValues<HandshakeFailureReason>())
        {
            var label = HandshakeFailureReasons.Label(reason);
            label.ShouldMatch("^[a-z_]+$");
            labels.Add(label).ShouldBeTrue($"duplicate label {label}");
            HandshakeFailureReasons.Describe(reason).ShouldNotBeNullOrWhiteSpace();
        }
    }
}

/// <summary>How a connection that did not complete its handshake is explained (spec 8.2): facts first, never the OS error text.</summary>
public sealed class HandshakeFailureClassificationTests
{
    private static readonly TimeSpan Timeout10 = TimeSpan.FromSeconds(10);

    private static ConnectionCapture Capture()
        => new(new ConnectionRegistry(TimeProvider.System), new ConnectionEventSink(), new EkmMetrics(), new EkmListenerPorts(), TimeProvider.System, NullLoggerFactory.Instance, Timeout10);

    private static ConnectionState State(TimeSpan age = default)
        => new("c1", "127.0.0.1:1", 8443, DateTimeOffset.UtcNow, Stopwatch.GetTimestamp() - (long)(age.TotalSeconds * Stopwatch.Frequency));

    private static ClientHelloInfo Hello(ushort[] versions, ushort[] suites)
        => new(0x0303, versions, suites, null, []);

    [Fact]
    public void ARejectedClientCertificate_WinsOverEverythingThatWasOffered()
    {
        var state = State();
        state.SetClientHello(ClientHelloParseStatus.Parsed, Hello([0x0304], [0x1301]));
        state.SetClientCertificateVerdict(new HandshakeVerdict(false, "PartialChain, UntrustedRoot", []));

        var (reason, detail) = Capture().Classify(state);

        reason.ShouldBe(HandshakeFailureReason.ClientCertificateNotTrusted);
        detail.ShouldContain("UntrustedRoot");
    }

    [Fact]
    public void AnAcceptedCertificateThatStillFailedTheHandshake_IsNotBlamedOnTheCertificate()
    {
        var state = State();
        state.SetClientHello(ClientHelloParseStatus.Parsed, Hello([0x0304], [0x1301]));
        state.SetClientCertificateVerdict(new HandshakeVerdict(true, "NoError", []));

        Capture().Classify(state).Reason.ShouldBe(HandshakeFailureReason.Other);
    }

    [Fact]
    public void AClientThatOffersOnlyTls12_IsATlsVersionFailure_NamingWhatItOffered()
    {
        var state = State();
        state.SetClientHello(ClientHelloParseStatus.Parsed, Hello([0x0303], [0xC02F]));

        var (reason, detail) = Capture().Classify(state);

        reason.ShouldBe(HandshakeFailureReason.TlsVersionNotSupported);
        detail.ShouldBe("client offered TLS 1.2");
    }

    [Fact]
    public void ALegacyClientWithoutSupportedVersions_IsATlsVersionFailureToo()
    {
        var state = State();
        state.SetClientHello(ClientHelloParseStatus.Parsed, new ClientHelloInfo(0x0301, [], [0x002F], null, []));

        var (reason, detail) = Capture().Classify(state);

        reason.ShouldBe(HandshakeFailureReason.TlsVersionNotSupported);
        detail.ShouldBe("client offered TLS 1.0");
    }

    [Fact]
    public void ATls13ClientWithoutThePermittedSuites_IsANoCommonCipherFailure()
    {
        var state = State();
        state.SetClientHello(ClientHelloParseStatus.Parsed, Hello([0x0304], [0x1303]));

        var (reason, detail) = Capture().Classify(state);

        reason.ShouldBe(HandshakeFailureReason.NoCommonCipherSuite);
        detail.ShouldContain("TLS_CHACHA20_POLY1305_SHA256");
    }

    [Fact]
    public void ATls13ClientOfferingOneOfThePermittedSuites_IsNotACipherFailure()
    {
        foreach (ushort suite in new ushort[] { 0x1301, 0x1302 })
        {
            var state = State();
            state.SetClientHello(ClientHelloParseStatus.Parsed, Hello([0x0304], [0x1303, suite]));

            Capture().Classify(state).Reason.ShouldBe(HandshakeFailureReason.Other);
        }
    }

    [Fact]
    public void NonTlsBytes_AreNotTls()
    {
        var state = State();
        state.SetClientHello(ClientHelloParseStatus.NotTls, null);

        Capture().Classify(state).Reason.ShouldBe(HandshakeFailureReason.NotTls);
    }

    [Fact]
    public void AMalformedHello_IsOther()
    {
        var state = State();
        state.SetClientHello(ClientHelloParseStatus.Malformed, null);

        Capture().Classify(state).Reason.ShouldBe(HandshakeFailureReason.Other);
    }

    [Fact]
    public void NoCompleteHello_IsClientClosed_UntilTheHandshakeTimeoutHasPassed()
    {
        Capture().Classify(State()).Reason.ShouldBe(HandshakeFailureReason.ClientClosed);

        var early = State();
        early.SetClientHello(ClientHelloParseStatus.NeedMoreData, null);
        Capture().Classify(early).Reason.ShouldBe(HandshakeFailureReason.ClientClosed);

        Capture().Classify(State(TimeSpan.FromSeconds(11))).Reason.ShouldBe(HandshakeFailureReason.HandshakeTimeout);
    }

    [Fact]
    public void APolicyViolation_IsReportedAsSuch()
    {
        var state = State();
        state.RejectByPolicy(HandshakeFailureReason.CipherSuiteNotAllowed, "negotiated TLS 1.3 TLS_CHACHA20_POLY1305_SHA256", "TLS 1.3", "TLS_CHACHA20_POLY1305_SHA256");

        var (reason, detail) = Capture().Classify(state);

        reason.ShouldBe(HandshakeFailureReason.CipherSuiteNotAllowed);
        detail.ShouldContain("CHACHA20");
    }

    // ---- the post-handshake policy (the enforcement where the TLS stack cannot restrict suites, i.e. Windows) -----------------------------

    [Theory]
    [InlineData(SslProtocols.Tls13, System.Net.Security.TlsCipherSuite.TLS_AES_256_GCM_SHA384, null)]
    [InlineData(SslProtocols.Tls13, System.Net.Security.TlsCipherSuite.TLS_AES_128_GCM_SHA256, null)]
    [InlineData(SslProtocols.Tls13, System.Net.Security.TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256, "CipherSuiteNotAllowed")]
    [InlineData(SslProtocols.Tls13, System.Net.Security.TlsCipherSuite.TLS_AES_128_CCM_SHA256, "CipherSuiteNotAllowed")]
    [InlineData(SslProtocols.Tls12, System.Net.Security.TlsCipherSuite.TLS_AES_256_GCM_SHA384, "TlsVersionNotSupported")]
    public void ThePostHandshakePolicy_PermitsOnlyTls13WithThePermittedSuites(SslProtocols protocol, System.Net.Security.TlsCipherSuite suite, string? expected)
        => (ConnectionCapture.EvaluatePolicy(protocol, suite)?.ToString()).ShouldBe(expected);

    [Fact]
    public void AnUnreportedCipherSuite_IsNotAViolation_ButAWrongProtocolStillIs()
    {
        ConnectionCapture.EvaluatePolicy(SslProtocols.Tls13, null).ShouldBeNull();
        ConnectionCapture.EvaluatePolicy(SslProtocols.Tls12, null).ShouldBe(HandshakeFailureReason.TlsVersionNotSupported);
    }
}
