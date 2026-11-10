using System.Buffers.Text;
using System.Text;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using EkmMock.Server.Inspector;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// Security review M2: the inspector's memory is bounded in bytes, not only in record count, and an exchange from an unauthenticated peer can
/// make it retain only a small, fixed amount (headers 4 KiB, bodies 1 KiB). Masking is unchanged.
/// </summary>
public sealed class InspectorMemoryBoundTests
{
    private const string Alg = "A256KWP";

    /// <summary>Test host only: every caller is refused (an unauthenticated peer), exactly as the real authorizer would answer a request without a valid certificate.</summary>
    private sealed class DenyAllAuthorizer : IEkmCallerAuthorizer
    {
        public EkmAuthResult Authorize(HttpContext context, EkmMock.Crypto.NamespaceDefinition ns)
            => new() { Succeeded = false, Failure = AuthFailure.NoClientCertificate };
    }

    private static ExchangeRecord Big(long id, int bodyChars) => Rec.Make(id, bodyText: new string('b', bodyChars), responseText: "{}");

    // ---- the ring buffer evicts by estimated bytes ----

    [Fact]
    public void TheDefaultByteCap_Is128MiB_AndConfigurable()
    {
        new InspectorOptions().MaxBytes.ShouldBe(128L * 1024 * 1024);
        new ExchangeRingBuffer(Microsoft.Extensions.Options.Options.Create(new InspectorOptions())).MaxBytes.ShouldBe(128L * 1024 * 1024);
        new ExchangeRingBuffer(Microsoft.Extensions.Options.Options.Create(new InspectorOptions { MaxBytes = 1_000_000 })).MaxBytes.ShouldBe(1_000_000);
    }

    [Fact]
    public void AByteCapThatIsTooSmall_IsRefusedAtStartup()
    {
        new InspectorOptions { MaxBytes = 1000 }.IsValid(out var error).ShouldBeFalse();
        error.ShouldContain("Inspector:MaxBytes");
        new InspectorOptions { MaxBytes = InspectorOptions.MinMaxBytes }.IsValid(out _).ShouldBeTrue();
    }

    [Fact]
    public void TheRingBuffer_EvictsTheOldestRecords_UntilItIsUnderTheByteCap()
    {
        var one = ExchangeRecordSize.Estimate(Big(1, 10_000));
        var ring = new ExchangeRingBuffer(capacity: 1000, maxBytes: one * 3 + one / 2); // room for three records, not four

        for (var i = 1; i <= 10; i++)
        {
            ring.Add(Big(i, 10_000));
            ring.RetainedBytes.ShouldBeLessThanOrEqualTo(ring.MaxBytes);
        }

        ring.Count.ShouldBe(3);
        ring.Evicted.ShouldBe(7);
        ring.Query().Items.Select(static r => r.Id).ToArray().ShouldBe([10, 9, 8]);
        ring.Get(7).ShouldBeNull();
    }

    [Fact]
    public void AnEvictionByBytes_ZeroesTheRetainedSecretsOfTheEvictedRecord()
    {
        var raw = Fx.Random(64);
        var copy = raw.ToArray();
        var secrets = new RetainedSecrets(raw, null);
        var one = ExchangeRecordSize.Estimate(Big(1, 5_000));
        var ring = new ExchangeRingBuffer(capacity: 1000, maxBytes: one + 100);

        ring.Add(Big(1, 5_000), secrets);
        ring.Add(Big(2, 5_000));

        ring.Get(1).ShouldBeNull();
        secrets.IsEmpty.ShouldBeTrue();
        raw.ShouldAllBe(static b => b == 0); // the array the buffer held was zeroed in place
        copy.ShouldNotBe(raw);
    }

    [Fact]
    public void TheRawSecretsOfARetainedRecord_CountTowardsTheBytes()
    {
        var ring = new ExchangeRingBuffer(capacity: 10);
        ring.Add(Big(1, 100));
        var without = ring.RetainedBytes;

        ring.Add(Big(2, 100), new RetainedSecrets(new byte[4000], null));

        ring.RetainedBytes.ShouldBeGreaterThan(without * 2 + 3500);
    }

    [Fact]
    public void TheNewestRecord_IsKept_EvenWhenItAloneIsLargerThanTheCap()
    {
        var ring = new ExchangeRingBuffer(capacity: 10, maxBytes: 1000);

        ring.Add(Big(1, 5_000));
        ring.Add(Big(2, 5_000));

        ring.Count.ShouldBe(1);
        ring.Get(2).ShouldNotBeNull();
        ring.RetainedBytes.ShouldBe(ExchangeRecordSize.Estimate(Big(2, 5_000)));
    }

    [Fact]
    public void Clear_ResetsTheRetainedBytes()
    {
        var ring = new ExchangeRingBuffer(capacity: 10);
        ring.Add(Big(1, 1000));
        ring.Add(Big(2, 1000));

        ring.Clear();

        ring.RetainedBytes.ShouldBe(0);
        ring.Count.ShouldBe(0);
    }

    [Fact]
    public void ARecordThatFinishesOutOfOrder_StillKeepsTheByteAccountExact()
    {
        var ring = new ExchangeRingBuffer(capacity: 5, maxBytes: long.MaxValue / 2);
        ring.Add(Big(1, 100));
        ring.Add(Big(3, 300));
        ring.Add(Big(2, 200));
        for (var i = 4; i <= 9; i++)
        {
            ring.Add(Big(i, 100 * i)); // count cap evictions too
        }

        var expected = ring.Snapshot().Sum(static r => ExchangeRecordSize.Estimate(r));
        ring.RetainedBytes.ShouldBe(expected);
    }

    [Fact]
    public void UnderAFlood_TheRetainedBytesNeverExceedTheCap_AndTheNewestRecordsSurvive()
    {
        const long cap = 256 * 1024;
        var ring = new ExchangeRingBuffer(capacity: 10_000, maxBytes: cap);
        var random = new Random(20261110);
        long maxSeen = 0;

        for (var id = 1; id <= 5000; id++)
        {
            ring.Add(Big(id, random.Next(10, 12_000)));
            var retained = ring.RetainedBytes;
            maxSeen = Math.Max(maxSeen, retained);
            (retained <= cap || ring.Count == 1).ShouldBeTrue($"{retained} bytes retained after record {id}");
        }

        maxSeen.ShouldBeLessThanOrEqualTo(cap);
        ring.Get(5000).ShouldNotBeNull();
        ring.Count.ShouldBeLessThan(500); // 5000 records of up to 24 KB do not fit into 256 KiB
        ring.Evicted.ShouldBe(5000 - ring.Count);
        ring.RetainedBytes.ShouldBe(ring.Snapshot().Sum(static r => ExchangeRecordSize.Estimate(r)));
    }

    [Fact]
    public void TheEstimate_FollowsTheStringsAnUnauthenticatedPeerControls()
    {
        var small = ExchangeRecordSize.Estimate(Rec.Make(1));
        var bigBody = ExchangeRecordSize.Estimate(Big(1, 10_000));

        small.ShouldBeGreaterThanOrEqualTo(ExchangeRecordSize.FixedOverheadBytes);
        (bigBody - small).ShouldBeGreaterThanOrEqualTo(2L * 9_900); // UTF-16: two bytes per character
    }

    // ---- an unauthenticated peer can make the inspector keep only a little ----

    private static HttpRequestMessage Hostile(string path, string body, int headers, int headerChars)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        for (var i = 0; i < headers; i++)
        {
            request.Headers.TryAddWithoutValidation($"X-Junk-{i}", new string('h', headerChars));
        }

        return request;
    }

    [Fact]
    public async Task AHostileUnauthenticatedRequest_ProducesACappedRecord()
    {
        using var factory = InspectorHarness.CreateFactory(configure: static s => s.AddSingleton<IEkmCallerAuthorizer, DenyAllAuthorizer>());
        var inspector = InspectorHarness.InspectorOf(factory);
        var http = factory.CreateClient();
        var body = "{\"request_context\":{\"correlation_id\":\"" + new string('x', 15_000) + "\"}}";

        using var response = await http.SendAsync(Hostile("/aes-key-1/wrapkey?api-version=0.1-preview&" + new string('q', 5000), body, headers: 50, headerChars: 900), TestContext.Current.CancellationToken);
        var record = (await InspectorHarness.SettleAsync(inspector, 1)).Single();

        ((int)response.StatusCode).ShouldBe(401);
        record.Response.Status.ShouldBe(401);
        record.Request.Body.Truncated.ShouldBeTrue();
        record.Request.Body.Text.ShouldNotBeNull().Length.ShouldBeLessThanOrEqualTo(ExchangeRecordFactory.UnauthenticatedBodyChars);
        record.Request.Body.SizeBytes.ShouldBeGreaterThan(15_000); // the real size is still reported
        record.Request.Body.PrettyJson.ShouldBeNull();
        record.Request.HeadersTruncated.ShouldBeTrue();
        HeaderChars(record.Request.Headers).ShouldBeLessThanOrEqualTo(ExchangeRecordFactory.UnauthenticatedHeaderBudgetChars);
        record.Request.RawTarget.ShouldNotBeNull().Length.ShouldBeLessThanOrEqualTo(2048);
        ExchangeRecordSize.Estimate(record).ShouldBeLessThan(WorstCaseUnauthenticatedRecordBytes);
    }

    // The documented worst case of one unauthenticated record (DECISIONS "Security review follow-up"): 4 KiB of headers, 1 KiB body each way, a 2048 character target,
    // client certificate names, fixed overhead; all at two bytes per character. A record of this test is far below it; the bound is what the channel arithmetic uses.
    private const long WorstCaseUnauthenticatedRecordBytes = 24 * 1024;

    private static int HeaderChars(IReadOnlyList<HeaderEntry> headers) => headers.Sum(static h => h.Name.Length + h.Value.Length);

    [Fact]
    public async Task AnUnroutableRequest_IsCappedToo_BecauseItNeverReachedAuthentication()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var http = factory.CreateClient();
        var body = "{\"request_context\":{\"correlation_id\":\"" + new string('x', 10_000) + "\"}}";

        using var response = await http.SendAsync(Hostile("/no-such-prefix/aes-key-1/wrapkey?api-version=0.1-preview", body, headers: 20, headerChars: 1000), TestContext.Current.CancellationToken);
        var record = (await InspectorHarness.SettleAsync(inspector, 1)).Single();

        ((int)response.StatusCode).ShouldBe(404);
        record.Request.Body.Text.ShouldNotBeNull().Length.ShouldBeLessThanOrEqualTo(ExchangeRecordFactory.UnauthenticatedBodyChars);
        record.Request.Body.Truncated.ShouldBeTrue();
        HeaderChars(record.Request.Headers).ShouldBeLessThanOrEqualTo(ExchangeRecordFactory.UnauthenticatedHeaderBudgetChars);
        record.Request.HeadersTruncated.ShouldBeTrue();
    }

    [Fact]
    public async Task AnAuthenticatedExchange_KeepsItsFullBodyAndHeaders()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var http = factory.CreateClient();
        var body = "{\"request_context\":{\"correlation_id\":\"" + new string('x', 6_000) + "\"}}";

        using var response = await http.SendAsync(Hostile("/info?api-version=0.1-preview", body, headers: 5, headerChars: 900), TestContext.Current.CancellationToken);
        var record = (await InspectorHarness.SettleAsync(inspector, 1)).Single();

        ((int)response.StatusCode).ShouldBe(200);
        record.Request.Body.Truncated.ShouldBeFalse();
        record.Request.Body.Text.ShouldNotBeNull().Length.ShouldBe(body.Length);
        record.Request.HeadersTruncated.ShouldBeFalse();
        record.Request.Headers.Count(static h => h.Name.StartsWith("X-Junk-", StringComparison.Ordinal)).ShouldBe(5);
    }

    [Fact]
    public async Task AnUnauthenticatedWrapRequestThatCarriesADek_IsStillMasked_AndNothingRawIsRetained()
    {
        using var factory = InspectorHarness.CreateFactory(reveal: true, configure: static s => s.AddSingleton<IEkmCallerAuthorizer, DenyAllAuthorizer>());
        var inspector = InspectorHarness.InspectorOf(factory);
        var http = factory.CreateClient();
        var dek = Fx.Random(32);
        var secret = Base64Url.EncodeToString(dek);
        var body = EkmClient.WrapBody(Alg, secret);

        using var response = await http.SendAsync(Hostile("/aes-key-1/wrapkey?api-version=0.1-preview", body, headers: 0, headerChars: 0), TestContext.Current.CancellationToken);
        var record = (await InspectorHarness.SettleAsync(inspector, 1)).Single();

        ((int)response.StatusCode).ShouldBe(401);
        var text = InspectorHarness.AllTextOf([record]);
        text.ShouldNotContain(secret);
        text.ShouldNotContain(Convert.ToBase64String(dek));
        text.ShouldNotContain(Convert.ToHexString(dek), Case.Insensitive);
        record.Request.Body.MaskedFields.ShouldNotBeEmpty();
        factory.Services.GetRequiredService<ExchangeRingBuffer>().Contains(record.Id, out var hasSecrets).ShouldBeTrue();
        hasSecrets.ShouldBeFalse(); // reveal is allowed in this host, but an unauthenticated exchange keeps no raw body
    }

    [Fact]
    public async Task ASecretBeyondTheCap_IsMaskedBeforeTheTextIsCut_AndNeverAppears()
    {
        using var factory = InspectorHarness.CreateFactory(configure: static s => s.AddSingleton<IEkmCallerAuthorizer, DenyAllAuthorizer>());
        var inspector = InspectorHarness.InspectorOf(factory);
        var http = factory.CreateClient();
        var dek = Fx.Random(32);
        var secret = Base64Url.EncodeToString(dek);
        var body = "{\"request_context\":{\"correlation_id\":\"" + new string('x', 3000) + "\"},\"alg\":\"A256KWP\",\"value\":\"" + secret + "\"}";

        using var response = await http.SendAsync(Hostile("/aes-key-1/wrapkey?api-version=0.1-preview", body, headers: 0, headerChars: 0), TestContext.Current.CancellationToken);
        var record = (await InspectorHarness.SettleAsync(inspector, 1)).Single();

        ((int)response.StatusCode).ShouldBe(401);
        record.Request.Body.Truncated.ShouldBeTrue();
        record.Request.Body.Text.ShouldNotBeNull().Length.ShouldBeLessThanOrEqualTo(ExchangeRecordFactory.UnauthenticatedBodyChars);
        InspectorHarness.AllTextOf([record]).ShouldNotContain(secret);
    }

    [Fact]
    public async Task AFloodOfHostileRequests_KeepsTheRingBufferUnderItsByteCap()
    {
        const int cap = 200 * 1024;
        const int requests = 400;
        using var factory = InspectorHarness.CreateFactory(
            configuration: new Dictionary<string, string?> { ["Inspector:MaxBytes"] = cap.ToString() },
            configure: static s => s.AddSingleton<IEkmCallerAuthorizer, DenyAllAuthorizer>());
        var ring = factory.Services.GetRequiredService<ExchangeRingBuffer>();
        var http = factory.CreateClient();
        var body = "{\"request_context\":{\"correlation_id\":\"" + new string('x', 12_000) + "\"}}";

        ring.MaxBytes.ShouldBe(cap);
        for (var i = 0; i < requests; i++)
        {
            using var response = await http.SendAsync(Hostile("/aes-key-1/wrapkey?api-version=0.1-preview", body, headers: 30, headerChars: 700), TestContext.Current.CancellationToken);
            ((int)response.StatusCode).ShouldBe(401);
        }

        (await Wait.UntilAsync(() => ring.Count + ring.Evicted >= requests, TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(10))).ShouldBeTrue($"{ring.Count} stored, {ring.Evicted} evicted of {requests}");
        ring.RetainedBytes.ShouldBeLessThanOrEqualTo(cap);
        ring.Evicted.ShouldBeGreaterThan(0);
        ring.Count.ShouldBeLessThan(requests);
        ring.Get(requests).ShouldNotBeNull(); // the newest is kept
    }

    [Fact]
    public async Task TheRetainedBytesOfAnIdleBuffer_AreAboutWhatTheStoredRecordsAreEstimatedAt()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        var ring = factory.Services.GetRequiredService<ExchangeRingBuffer>();

        for (var i = 0; i < 20; i++)
        {
            (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        }

        var records = await InspectorHarness.SettleAsync(inspector, 20);
        ring.RetainedBytes.ShouldBe(records.Sum(static r => ExchangeRecordSize.Estimate(r)));
    }
}
