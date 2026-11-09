using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using EkmMock.Crypto;
using EkmMock.Pki;
using EkmMock.Server.Connections;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.TestSupport;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>A real Kestrel mTLS host with the inspector, shared by the mTLS inspector tests.</summary>
public sealed class InspectorMtlsFixture : IAsyncLifetime
{
    public const string CnA = "mhsm-a.managedhsmclient.test";
    public const string CnB = "mhsm-b.managedhsmclient.test";
    public const string Prefix = "contoso/prod";

    internal RealEkmHost Host { get; private set; } = null!;

    internal TestPki Pki { get; private set; } = null!;

    internal FixedAvailability Availability { get; } = new(true);

    internal IInspector Inspector => Host.App.Services.GetRequiredService<IInspector>();

    public async ValueTask InitializeAsync()
    {
        Pki = new TestPki();
        Host = await RealEkmHost.StartAsync(new RealEkmHostOptions
        {
            Pki = Pki,
            Namespaces =
            [
                TestNamespace.Default(Pki.ClientCaA, CnA),
                new TestNamespace("contoso", Prefix, [CnB], [Pki.ClientCaB]),
            ],
            Configuration = new() { ["Tls:HandshakeTimeout"] = "00:00:03", ["Inspector:Persist"] = "true" },
            ConfigureServices = services => services.AddSingleton<IEngineAvailability>(Availability),
        });
        Host.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
        Host.Keys.Create("contoso", "aes-key-1", KeyType.Oct, 256);
    }

    public async ValueTask DisposeAsync()
    {
        await Host.DisposeAsync();
        Pki.Dispose();
    }
}

/// <summary>Spec 14 tests 20 and 21 on the real listener: rejected exchanges (401, 404, 405, 5xx, oversize) and TLS handshake failures show up.</summary>
public sealed class InspectorMtlsTests : IClassFixture<InspectorMtlsFixture>
{
    private const string Alg = "A256KWP";
    private static readonly string[] PermittedSuites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"];

    private readonly InspectorMtlsFixture _fx;

    public InspectorMtlsTests(InspectorMtlsFixture fixture) => _fx = fixture;

    private RealEkmHost Host => _fx.Host;

    private IInspector Inspector => _fx.Inspector;

    /// <summary>Waits for the one exchange that carries <paramref name="marker"/> as its correlation id.</summary>
    private async Task<ExchangeRecord> FindAsync(string marker)
    {
        var filter = new ExchangeFilter { Text = marker };
        (await Wait.UntilAsync(() => Inspector.Count(filter) >= 1, TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(10))).ShouldBeTrue($"exchange {marker} was not captured");
        return Inspector.Query(filter).Items.First();
    }

    private static string Body(string marker, string? extra = null)
        => "{\"request_context\":{\"request_id\":\"rid-" + marker + "\",\"correlation_id\":\"" + marker + "\",\"pool_name\":\"pool-" + marker + "\"}" + extra + "}";

    private static string NewMarker() => "m-" + Guid.NewGuid().ToString("N")[..12];

    // ---- 401: no certificate ----

    [Fact]
    public async Task NoClientCertificate_401_IsCaptured_WithTlsFactsBodiesAndNoCertificate()
    {
        var mark = Host.Mark();
        var marker = NewMarker();
        var ekm = Host.CreateEkmClient();

        var reply = await ekm.PostAsync(EkmClient.Path(null, null, "info"), Body(marker));
        var record = await FindAsync(marker);

        reply.ShouldBeProxyError(401, "Unauthenticated");
        record.Response.Status.ShouldBe(401);
        record.Response.Code.ShouldBe("Unauthenticated");
        record.Request.Operation.ShouldBe("info");
        record.Request.Body.Text.ShouldNotBeNull().ShouldContain("request_context");
        record.Response.Body.Text.ShouldNotBeNull().ShouldContain("Unauthenticated");

        record.ClientCertificate.Present.ShouldBeFalse();
        record.ClientCertificate.AuthEvaluated.ShouldBeTrue();
        record.ClientCertificate.NamespaceMatched.ShouldBe(false);
        record.ClientCertificate.AuthFailure.ShouldBe("NoClientCertificate");
        record.ClientCertificate.Subject.ShouldBeNull();

        // TLS group, from the connection capture of M3.
        var tls = record.Tls.ShouldNotBeNull();
        tls.Protocol.ShouldBe("TLS 1.3");
        tls.CipherSuite.ShouldNotBeNull().ShouldBeOneOf(PermittedSuites);
        (tls.Alpn is null or "http/1.1").ShouldBeTrue($"ALPN was {tls.Alpn}");
        tls.Resumed.ShouldBe(false);
        tls.RequestNumberOnConnection.ShouldBe(1);
        tls.NewConnection.ShouldBeTrue();
        tls.HandshakeMs.ShouldNotBeNull().ShouldBeGreaterThan(0);

        // Identity: the connection id and the remote endpoint are the ones of the connection event.
        var opened = await Host.NextEventAsync(mark, ConnectionEventKind.Opened);
        opened.ShouldNotBeNull();
        record.Identity.ConnectionId.ShouldBe(opened.ConnectionId);
        record.Identity.RemoteEndPoint.ShouldBe(opened.RemoteEndPoint);
        record.Identity.RemoteEndPoint.ShouldNotBeNull().ShouldStartWith("127.0.0.1:");
    }

    [Fact]
    public async Task ACertificateWithTheWrongCommonName_401_RecordsTheCertificateAndWhyItWasRefused()
    {
        var marker = NewMarker();
        using var client = Host.Pki.ClientCaA.IssueClient("some.other.cn");
        var ekm = Host.CreateEkmClient(client.Certificate);

        var reply = await ekm.PostAsync(EkmClient.Path(null, null, "info"), Body(marker));
        var record = await FindAsync(marker);

        reply.ShouldBeProxyError(401, "Unauthenticated");
        var cert = record.ClientCertificate;
        cert.Present.ShouldBeTrue();
        cert.Subject.ShouldNotBeNull().ShouldContain("some.other.cn");
        cert.CommonName.ShouldBe("some.other.cn");
        cert.Issuer.ShouldNotBeNullOrEmpty();
        cert.Serial.ShouldNotBeNullOrEmpty();
        cert.ThumbprintSha256.ShouldBe(client.Thumbprint, StringCompareShould.IgnoreCase);
        cert.NotBeforeUtc.ShouldNotBeNull();
        cert.NotAfterUtc.ShouldNotBeNull().ShouldBeGreaterThan(DateTimeOffset.UtcNow);
        cert.AuthEvaluated.ShouldBeTrue();
        cert.CommonNameAllowed.ShouldBe(false);
        cert.NamespaceMatched.ShouldBe(false);
        cert.ChainResult.ShouldNotBeNull();
        cert.AuthFailure.ShouldBe("CommonNameNotAllowed");
    }

    [Fact]
    public async Task ACertificateOfAnotherNamespace_401_IsCaptured()
    {
        var marker = NewMarker();
        using var client = Host.Pki.ClientCaA.IssueClient(InspectorMtlsFixture.CnA);
        var ekm = Host.CreateEkmClient(client.Certificate);

        var reply = await ekm.PostAsync(EkmClient.Path(InspectorMtlsFixture.Prefix, null, "info"), Body(marker));
        var record = await FindAsync(marker);

        reply.StatusCode.ShouldBe(401);
        record.Request.Namespace.ShouldBe("contoso");
        record.Request.Prefix.ShouldBe(InspectorMtlsFixture.Prefix);
        record.ClientCertificate.CommonName.ShouldBe(InspectorMtlsFixture.CnA);
        record.ClientCertificate.NamespaceMatched.ShouldBe(false);
        record.ClientCertificate.AuthFailure.ShouldNotBeNull();
    }

    // ---- 200 with a valid caller ----

    [Fact]
    public async Task AValidCaller_IsCaptured_WithTheCertificateAuthResultAndPerConnectionTiming()
    {
        var first = NewMarker();
        var second = NewMarker();
        using var client = Host.Pki.ClientCaA.IssueClient(InspectorMtlsFixture.CnA);
        var ekm = Host.CreateEkmClient(client.Certificate, singleConnection: true);
        var dek = Fx.Random(32);

        var wrapped = await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), EkmClient.WrapBody(Alg, System.Buffers.Text.Base64Url.EncodeToString(dek)).Replace("\"c\"", $"\"{first}\""));
        var info = await ekm.PostAsync(EkmClient.Path(null, null, "info"), Body(second));
        var a = await FindAsync(first);
        var b = await FindAsync(second);

        wrapped.StatusCode.ShouldBe(200);
        info.StatusCode.ShouldBe(200);
        a.ClientCertificate.CommonName.ShouldBe(InspectorMtlsFixture.CnA);
        a.ClientCertificate.CommonNameAllowed.ShouldBe(true);
        a.ClientCertificate.NamespaceMatched.ShouldBe(true);
        a.ClientCertificate.ChainResult.ShouldNotBeNull();
        a.ClientCertificate.AuthFailure.ShouldBeNull();
        a.ClientCertificate.ThumbprintSha256.ShouldBe(client.Thumbprint, StringCompareShould.IgnoreCase);
        a.Timing.AuthMs.ShouldBeGreaterThan(0); // the chain build took measurable time

        // The same keep-alive connection: the first exchange carries the handshake time, the second does not.
        a.Identity.ConnectionId.ShouldBe(b.Identity.ConnectionId);
        a.Tls.ShouldNotBeNull().RequestNumberOnConnection.ShouldBe(1);
        a.Tls.HandshakeMs.ShouldNotBeNull().ShouldBeGreaterThan(0);
        b.Tls.ShouldNotBeNull().RequestNumberOnConnection.ShouldBe(2);
        b.Tls.HandshakeMs.ShouldBeNull();
        b.Tls.NewConnection.ShouldBeFalse();
        b.Tls.Protocol.ShouldBe("TLS 1.3");

        // The DEK that went over the wire is masked.
        a.Request.Body.MaskedFields.ShouldHaveSingleItem().Bytes.ShouldBe(32);
        SecretScanner.LeaksInText(InspectorHarness.AllTextOf([a, b]), dek).ShouldBeFalse();
    }

    // ---- 404 / 405 / 400 / 5xx ----

    [Fact]
    public async Task RoutingAndValidationFailures_AreCaptured_WithTheirBodies()
    {
        var unknownPrefix = NewMarker();
        var unknownKey = NewMarker();
        var wrongMethod = NewMarker();
        var badJson = NewMarker();
        using var client = Host.Pki.ClientCaA.IssueClient(InspectorMtlsFixture.CnA);
        var ekm = Host.CreateEkmClient(client.Certificate);
        var dek = Convert.ToHexString(Fx.Random(8));

        var r1 = await ekm.PostAsync("/nowhere/aes-key-1/wrapkey?api-version=0.1-preview", Body(unknownPrefix));
        var r2 = await ekm.WrapAsync("missing-key", Alg, Fx.Random(32));
        var r3 = await ekm.SendAsync(HttpMethod.Get, EkmClient.Path(null, "aes-key-1", "wrapkey"), EkmClient.JsonBody(Body(wrongMethod)));
        var r4 = await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), "{\"request_context\":{\"correlation_id\":\"" + badJson + "\"} oops " + dek);

        r1.StatusCode.ShouldBe(404);
        r2.StatusCode.ShouldBe(404);
        r3.StatusCode.ShouldBe(405);
        r4.StatusCode.ShouldBe(400);

        var a = await FindAsync(unknownPrefix);
        a.Response.Code.ShouldBe("NotFound");
        a.Request.Operation.ShouldBeNull();
        a.ClientCertificate.Present.ShouldBeTrue(); // the certificate is shown even though the path was refused before Auth ran
        a.ClientCertificate.AuthEvaluated.ShouldBeFalse();
        a.Request.Body.Text.ShouldNotBeNull().ShouldContain(unknownPrefix);

        var c = await FindAsync(wrongMethod);
        c.Request.Method.ShouldBe("GET");
        c.Response.Code.ShouldBe("MethodNotAllowed");
        c.Response.Headers.ShouldContain(static h => h.Name == "Allow" && h.Value == "POST");

        var d = await FindAsync(badJson);
        d.Response.Code.ShouldBe("InvalidRequest");
        d.Request.Body.Captured.ShouldBeFalse(); // not valid JSON on a wrap route: size only
        d.Request.Body.SizeBytes.ShouldBeGreaterThan(20);

        Inspector.Query(new ExchangeFilter { Key = "missing-key" }).Items.ShouldHaveSingleItem().Response.Code.ShouldBe("KeyNotFound");
    }

    [Fact]
    public async Task AnUnavailableEngine_5xx_IsCaptured()
    {
        var marker = NewMarker();
        using var client = Host.Pki.ClientCaA.IssueClient(InspectorMtlsFixture.CnA);
        var ekm = Host.CreateEkmClient(client.Certificate);
        _fx.Availability.IsAvailable = false;
        try
        {
            var reply = await ekm.PostAsync(EkmClient.Path(null, null, "info"), Body(marker));
            var record = await FindAsync(marker);

            reply.StatusCode.ShouldBe(503);
            record.Response.Status.ShouldBe(503);
            record.Response.Code.ShouldBe("HsmUnavailable");
            record.ClientCertificate.NamespaceMatched.ShouldBe(true);
        }
        finally
        {
            _fx.Availability.IsAvailable = true;
        }
    }

    [Fact]
    public async Task AnOversizeChunkedBody_IsRefusedByTheEndpoint_AndStillCaptured_WithoutStallingTheConnection()
    {
        var marker = NewMarker();
        using var client = Host.Pki.ClientCaA.IssueClient(InspectorMtlsFixture.CnA);
        using var http = Host.CreateHttpClient(client.Certificate, singleConnection: true);
        var payload = Encoding.UTF8.GetBytes(Body(marker, ",\"pad\":\"" + new string('x', 30_000) + "\""));
        var content = new StreamContent(new NonSeekableStream(payload)); // no Content-Length: Transfer-Encoding chunked
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        using var response = await http.PostAsync(EkmClient.Path(null, null, "info"), content, TestContext.Current.CancellationToken);
        var elapsed = System.Diagnostics.Stopwatch.GetElapsedTime(started);

        ((int)response.StatusCode).ShouldBe(400);
        elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(5));
        var record = await Wait.UntilAsync(() => Inspector.Query(new ExchangeFilter { Operation = "info", StatusClass = StatusClass.ClientError }).Items.Any(r => r.Request.Body.SizeBytes > 8000), TimeSpan.FromSeconds(10))
            ? Inspector.Query(new ExchangeFilter { Operation = "info", StatusClass = StatusClass.ClientError }).Items.First(r => r.Request.Body.SizeBytes > 8000)
            : throw new InvalidOperationException("the oversize exchange was not captured");
        record.Response.Code.ShouldBe("InvalidRequest");
        record.Request.Body.Captured.ShouldBeTrue(); // an info body is not secret: whatever was read is shown
        record.Request.Body.Text.ShouldNotBeNull().Length.ShouldBeLessThanOrEqualTo(16 * 1024);

        // The connection is still usable: the capture did not leave it in a bad state.
        var again = await new EkmClient(http).InfoAsync();
        again.StatusCode.ShouldBeOneOf(200, 400, 401); // 200 for a healthy keep-alive; Kestrel may legitimately have closed it after the body-size error (then a new one is made)
    }

    [Fact]
    public async Task ARejectedRequest_ThatNeverSendsItsBody_IsAnsweredAtOnce_AndCapturedAfterTheBoundedWait()
    {
        var marker = NewMarker();
        var (stream, tcp) = await Host.ConnectTlsAsync(); // no client certificate: 401
        using (stream)
        using (tcp)
        {
            var partial = Body(marker);
            var request = "POST /info?api-version=0.1-preview HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 5000\r\n\r\n" + partial;
            var started = System.Diagnostics.Stopwatch.GetTimestamp();
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request), TestContext.Current.CancellationToken);

            var buffer = new byte[4096];
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            var read = await stream.ReadAsync(buffer, timeout.Token);
            var elapsed = System.Diagnostics.Stopwatch.GetElapsedTime(started);

            Encoding.ASCII.GetString(buffer, 0, read).ShouldStartWith("HTTP/1.1 401");
            elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(1)); // the client got its answer before the capture's bounded wait for the rest of the body

            var record = await FindAsync(marker);
            record.Response.Status.ShouldBe(401);
            record.Request.Body.SizeBytes.ShouldBe(5000); // the declared size
            record.Request.Body.Text.ShouldBe(partial); // what arrived
        }
    }

    // ---- connection events ----

    [Fact]
    public async Task ConnectionEvents_FlowThroughTheInspector_IncludingAHandshakeFailureWithItsReason()
    {
        using var subscription = Inspector.Feed.Subscribe(new InspectorSubscriptionOptions { IncludeExchanges = false });
        var marker = NewMarker();
        using var client = Host.Pki.ClientCaA.IssueClient(InspectorMtlsFixture.CnA);
        var before = Inspector.ConnectionStatistics();

        // A successful connection.
        string connectionId;
        using (var http = Host.CreateHttpClient(client.Certificate, singleConnection: true))
        {
            var ekm = new EkmClient(http);
            (await ekm.PostAsync(EkmClient.Path(null, null, "info"), Body(marker))).StatusCode.ShouldBe(200);
            var record = await FindAsync(marker);
            connectionId = record.Identity.ConnectionId!;

            // While it is open it is listed, with its request count and TLS facts.
            var open = Inspector.OpenConnections().Single(c => c.ConnectionId == connectionId);
            open.RequestCount.ShouldBeGreaterThanOrEqualTo(1);
            open.TlsProtocol.ShouldBe("TLS 1.3");
            open.HandshakeCompleted.ShouldBeTrue();
            open.ClientCertificateSubject.ShouldNotBeNull().ShouldContain(InspectorMtlsFixture.CnA);
        }

        // A TLS 1.2-only client: the handshake fails and never becomes an HTTP request.
        await Should.ThrowAsync<Exception>(async () =>
        {
            var (s, t) = await Host.ConnectTlsAsync(Host.CreateClientSslOptions(protocols: SslProtocols.Tls12));
            s.Dispose();
            t.Dispose();
        });

        (await Wait.UntilAsync(
            () => Inspector.ConnectionEvents(new ConnectionEventFilter { FailuresOnly = true }).Any(e => e.FailureReason == "tls_version_not_supported"),
            TimeSpan.FromSeconds(10))).ShouldBeTrue("the handshake failure did not reach the inspector");
        (await Wait.UntilAsync(() => Inspector.ConnectionEvents(new ConnectionEventFilter { ConnectionId = connectionId, Kind = "closed" }).Count == 1, TimeSpan.FromSeconds(10))).ShouldBeTrue();

        var failure = Inspector.ConnectionEvents(new ConnectionEventFilter { FailuresOnly = true }).First(e => e.FailureReason == "tls_version_not_supported");
        failure.Kind.ShouldBe("handshake_failed");
        failure.FailureDescription.ShouldNotBeNullOrEmpty();
        failure.FailureDetail.ShouldNotBeNull().ShouldContain("TLS 1.2");
        failure.RemoteEndPoint.ShouldNotBeNullOrEmpty();

        var closed = Inspector.ConnectionEvents(new ConnectionEventFilter { ConnectionId = connectionId, Kind = "closed" }).Single();
        closed.RequestCount.ShouldBe(1);
        closed.DurationMs.ShouldNotBeNull().ShouldBeGreaterThan(0);

        var kinds = Inspector.ConnectionEvents(new ConnectionEventFilter { ConnectionId = connectionId }, limit: 10).Select(static e => e.Kind).Reverse().ToList();
        kinds.ShouldBe(["opened", "handshake_succeeded", "closed"]);
        var success = Inspector.ConnectionEvents(new ConnectionEventFilter { ConnectionId = connectionId, Kind = "handshake_succeeded" }).Single();
        success.TlsProtocol.ShouldBe("TLS 1.3");
        success.Resumed.ShouldBe(false);
        success.ClientCertificate.ShouldNotBeNull().Subject.ShouldContain(InspectorMtlsFixture.CnA);

        // The same events came through the live feed.
        var seen = new List<ConnectionEventRecord>();
        while (subscription.Reader.TryRead(out var item))
        {
            seen.Add(item.ShouldBeOfType<ConnectionFeedItem>().Event);
        }

        seen.ShouldContain(e => e.Kind == "handshake_failed" && e.FailureReason == "tls_version_not_supported");
        seen.ShouldContain(e => e.ConnectionId == connectionId && e.Kind == "closed");

        // And the statistics moved.
        var after = Inspector.ConnectionStatistics();
        after.Opened.ShouldBeGreaterThan(before.Opened);
        after.HandshakesSucceeded.ShouldBeGreaterThan(before.HandshakesSucceeded);
        after.HandshakesFailed.ShouldBeGreaterThan(before.HandshakesFailed);
        after.FailuresByReason["tls_version_not_supported"].ShouldBeGreaterThan(before.FailuresByReason.GetValueOrDefault("tls_version_not_supported"));
        after.Closed.ShouldBeGreaterThan(before.Closed);
        after.ResumptionRate.ShouldBe(0); // resumption is disabled on the EKM endpoint
        after.AverageRequestsPerClosedConnection.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task EveryExchange_AlsoReachesTheJsonlFile_Masked()
    {
        var marker = NewMarker();
        using var client = Host.Pki.ClientCaA.IssueClient(InspectorMtlsFixture.CnA);
        var dek = Fx.Random(32);
        var ekm = Host.CreateEkmClient(client.Certificate);

        await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), EkmClient.WrapBody(Alg, System.Buffers.Text.Base64Url.EncodeToString(dek)).Replace("\"c\"", $"\"{marker}\""));
        await FindAsync(marker);

        var folder = Path.Combine(Host.App.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<DataOptions>>().Value.Path, "inspector");
        string[] lines = [];
        await Wait.UntilAsync(() =>
        {
            lines = Directory.Exists(folder) ? [.. Directory.GetFiles(folder).SelectMany(ReadLines).Where(l => l.Contains(marker, StringComparison.Ordinal))] : [];
            return lines.Length > 0;
        }).ShouldBeTrueAsync();

        lines.ShouldHaveSingleItem();
        SecretScanner.LeaksInText(lines[0], dek).ShouldBeFalse();
        lines[0].ShouldContain("\"type\":\"exchange\"");
    }

    private static IEnumerable<string> ReadLines(string file)
    {
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        while (reader.ReadLine() is { } line)
        {
            yield return line;
        }
    }

    /// <summary>A stream that cannot report its length, so HttpClient sends the body with Transfer-Encoding: chunked.</summary>
    private sealed class NonSeekableStream : Stream
    {
        private readonly MemoryStream _inner;

        public NonSeekableStream(byte[] data) => _inner = new MemoryStream(data);

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
