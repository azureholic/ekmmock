using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EkmMock.Crypto;
using EkmMock.Server.Inspector;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>Spec 8.4, 14 tests 18 (inspector part) and 22: a DEK never leaves the engine through the inspector in default mode.</summary>
public sealed class InspectorMaskingEndToEndTests
{
    private const string Alg = "A256KWP";

    private static string Fingerprint(byte[] raw) => Convert.ToHexString(SHA256.HashData(raw))[..12].ToLowerInvariant();

    [Fact]
    public async Task WrapInput_AndUnwrapOutput_ShowOnlyLengthAndFingerprint_AndTheFingerprintsMatch()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);

        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);
        var unwrapped = await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value());
        var records = await InspectorHarness.SettleAsync(inspector, 2);
        var wrap = records[0];
        var unwrap = records[1];

        unwrapped.StatusCode.ShouldBe(200); // the DEK itself still comes back to the caller: the API requires it
        Fx.Same(unwrapped.Value(), dek).ShouldBeTrue();

        // Wrap request: the DEK is masked.
        var expected = $"32 bytes · fp {Fingerprint(dek)}";
        wrap.Request.Body.Text.ShouldNotBeNull().ShouldContain($"\"value\":\"{expected}\"");
        wrap.Request.Body.MaskedFields.ShouldHaveSingleItem().ShouldBe(new MaskedField("request.value", expected, 32, Fingerprint(dek), false));

        // Wrap response: ciphertext, shown as sent.
        wrap.Response.Body.Text.ShouldBe(wrapped.Text);

        // Unwrap request: ciphertext, shown as sent.
        unwrap.Request.Body.Text.ShouldNotBeNull().ShouldContain(wrapped.ValueText());
        unwrap.Request.Body.MaskedFields.ShouldBeEmpty();

        // Unwrap response: the DEK is masked, with the same fingerprint as the wrap input.
        unwrap.Response.Body.Text.ShouldBe($$"""{"value":"{{expected}}"}""");
        unwrap.Response.Body.MaskedFields.ShouldHaveSingleItem().Fingerprint.ShouldBe(wrap.Request.Body.MaskedFields.Single().Fingerprint);
        unwrap.Response.Body.PrettyJson.ShouldNotBeNull().ShouldContain(expected);

        // Nothing of the DEK anywhere in the records, in any alphabet.
        SecretScanner.LeaksInText(InspectorHarness.AllTextOf(records), dek).ShouldBeFalse();
    }

    [Fact]
    public async Task EveryAlgorithmAndDekSize_IsMaskedTheSameWay()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        var deks = new List<byte[]>();
        var count = 0;

        foreach (var (key, alg, size) in new[]
        {
            ("aes-key-1", "A256KW", 16), ("aes-key-1", "A256KW", 24), ("aes-key-1", "A256KW", 32), ("aes-key-1", "A256KW", 64),
            ("aes-key-1", "A256KWP", 1), ("aes-key-1", "A256KWP", 20), ("aes-key-1", "A256KWP", 32), ("aes-key-1", "A256KWP", 4096),
            ("rsa-key-1", "RSA-OAEP-256", 32), ("rsa-key-1", "RSA-OAEP", 32), ("rsa-key-1", "RSA-OAEP-256", 190),
        })
        {
            var dek = Fx.Random(size);
            deks.Add(dek);
            var wrapped = await ekm.WrapAsync(key, alg, dek);
            wrapped.StatusCode.ShouldBe(200, $"{alg} {size}");
            (await ekm.UnwrapAsync(key, alg, wrapped.Value())).StatusCode.ShouldBe(200);
            count += 2;
        }

        var records = await InspectorHarness.SettleAsync(inspector, count);

        for (var i = 0; i < deks.Count; i++)
        {
            var wrap = records[2 * i];
            var unwrap = records[(2 * i) + 1];
            var field = wrap.Request.Body.MaskedFields.ShouldHaveSingleItem();
            field.Bytes.ShouldBe(deks[i].Length);
            field.Fingerprint.ShouldBe(Fingerprint(deks[i]));
            unwrap.Response.Body.MaskedFields.ShouldHaveSingleItem().Fingerprint.ShouldBe(field.Fingerprint);
            if (deks[i].Length >= 8)
            {
                SecretScanner.LeaksInText(InspectorHarness.AllTextOf([wrap, unwrap]), deks[i]).ShouldBeFalse($"DEK {i}");
            }
        }
    }

    [Fact]
    public async Task AnInvalidValueInAWrapRequest_IsMaskedByLength_WithoutAFingerprint()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        var standardBase64 = "ab+/" + Convert.ToBase64String(Fx.Random(30)); // "+" and "/" are not base64url (always present, so this never decodes)

        var reply = await ekm.WrapRawAsync("aes-key-1", Alg, standardBase64);
        var record = (await InspectorHarness.SettleAsync(inspector, 1))[0];

        reply.StatusCode.ShouldBe(400);
        record.Request.Body.Text.ShouldNotBeNull().ShouldContain($"\"value\":\"value (invalid, {standardBase64.Length} chars)\"");
        record.Request.Body.Text.ShouldNotContain(standardBase64);
        record.Request.Body.MaskedFields.ShouldHaveSingleItem().Fingerprint.ShouldBeNull();
        record.Response.Body.Text.ShouldNotBeNull().ShouldContain("InvalidRequest");
    }

    [Fact]
    public async Task APaddedValue_IsFingerprintedLikeTheUnpaddedOne()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);
        var unpadded = Base64Url.EncodeToString(dek);

        (await ekm.WrapRawAsync("aes-key-1", Alg, unpadded + "=")).StatusCode.ShouldBe(200);
        (await ekm.WrapRawAsync("aes-key-1", Alg, unpadded)).StatusCode.ShouldBe(200);
        var records = await InspectorHarness.SettleAsync(inspector, 2);

        records[0].Request.Body.MaskedFields.Single().Fingerprint.ShouldBe(records[1].Request.Body.MaskedFields.Single().Fingerprint);
        SecretScanner.LeaksInText(InspectorHarness.AllTextOf(records), dek).ShouldBeFalse();
    }

    [Fact]
    public async Task RejectedRequests_ThatContainADek_NeverLeakIt()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);
        var text = Base64Url.EncodeToString(dek);
        var good = EkmClient.WrapBody(Alg, text);
        var path = EkmClient.Path(null, "aes-key-1", "wrapkey");
        var sent = 0;

        async Task Send(Task<EkmReply> request)
        {
            await request;
            sent++;
        }

        await Send(ekm.PostAsync(path, good, "text/plain")); // wrong content type
        await Send(ekm.PostAsync(path, good + " trailing")); // bad JSON
        await Send(ekm.PostAsync(path, "{\"request_context\":{},\"alg\":\"A256KWP\",\"value\":\"" + text)); // cut off
        await Send(ekm.PostAsync("/unknown-prefix/aes-key-1/wrapkey?api-version=0.1-preview", good)); // unroutable
        await Send(ekm.WrapAsync("no-such-key", Alg, dek)); // unknown key
        await Send(ekm.SendAsync(HttpMethod.Get, path, EkmClient.JsonBody(good))); // wrong method
        await Send(ekm.PostAsync(EkmClient.Path(null, "bad_name", "wrapkey"), good)); // bad key name
        await Send(ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey", query: null), good)); // missing api-version
        await Send(ekm.WrapRawAsync("aes-key-1", text, "AAAA")); // the DEK in the alg field
        await Send(ekm.WrapRawAsync("aes-key-1", "A128KW", text)); // unsupported algorithm
        await Send(ekm.PostAsync(path, "{\"request_context\":{\"correlation_id\":\"c\"},\"alg\":\"A256KWP\",\"dek\":\"" + text + "\"}")); // wrong field name
        await Send(ekm.PostAsync(path, "{\"request_context\":{\"correlation_id\":\"c\"},\"alg\":\"A256KWP\",\"Value\":\"" + text + "\"}")); // wrong case
        await Send(ekm.PostAsync(path, "\"" + text + "\"")); // the DEK as the whole body
        await Send(ekm.PostAsync(path, "{\"request_context\":{\"correlation_id\":\"c\"},\"alg\":\"A256KWP\",\"value\":\"" + text + "\",\"pad\":\"" + new string('p', 20_000) + "\"}")); // oversize
        await Send(ekm.PostAsync(path, "{\"request_context\":{\"correlation_id\":\"c\"},\"alg\":\"A256KWP\",\"value\":{\"x\":\"" + text + "\"}}")); // value of the wrong type
        await Send(ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "metadata"), good)); // a wrap body sent to metadata: no DEK expected there, but a stray value is masked

        var records = await InspectorHarness.SettleAsync(inspector, sent);

        SecretScanner.LeaksInText(InspectorHarness.AllTextOf(records), dek).ShouldBeFalse();
        records.Count.ShouldBe(sent);
        records.Take(sent - 1).ShouldAllBe(static r => r.Response.Status >= 400);
        records[15].Request.Body.Text.ShouldNotBeNull().ShouldContain("32 bytes · fp");

        // Every body that could not be parsed and masked was not stored: only its size is known.
        records[1].Request.Body.Captured.ShouldBeFalse();
        records[2].Request.Body.Captured.ShouldBeFalse();
        records[12].Request.Body.Captured.ShouldBeFalse();
        records[13].Request.Body.Captured.ShouldBeFalse();
        records[13].Request.Body.Truncated.ShouldBeTrue();
        records[13].Request.Body.SizeBytes.ShouldBeGreaterThan(20_000);
        records[1].Request.Body.Note.ShouldNotBeNull().ShouldContain("not captured");

        // Parseable ones are shown with the DEK replaced.
        records[0].Request.Body.Text.ShouldNotBeNull().ShouldContain("32 bytes · fp");
        records[3].Request.Body.Text.ShouldNotBeNull().ShouldContain("32 bytes · fp"); // unroutable: treated like a wrap request
        records[8].Request.Body.Text.ShouldNotBeNull().ShouldContain($"(masked, {text.Length} chars)");
        records[10].Request.Body.Text.ShouldNotBeNull().ShouldContain("(masked, " + text.Length + " chars)");
        records[14].Request.Body.Text.ShouldNotBeNull().ShouldContain("value (invalid, not a string)");
    }

    [Fact]
    public async Task ACorrelationId_StaysSearchable_EvenWhenTheBodyWasNotCaptured()
    {
        using var factory = InspectorHarness.CreateFactory();
        var inspector = InspectorHarness.InspectorOf(factory);
        var dek = Fx.Random(32);

        // The body is rejected as bad JSON (trailing text after the object): the body is not captured, but the request context in front of it is still read, so it is not anonymous.
        var reply = await factory.CreateEkmClient().PostAsync(
            EkmClient.Path(null, "aes-key-1", "wrapkey"),
            "{\"request_context\":{\"correlation_id\":\"corr-search\"},\"alg\":\"A256KWP\",\"value\":\"" + Base64Url.EncodeToString(dek) + "\"} extra");
        await InspectorHarness.SettleAsync(inspector, 1);

        reply.StatusCode.ShouldBe(400);
        inspector.Query(new ExchangeFilter { Text = "corr-search" }).Items.ShouldHaveSingleItem().Id.ShouldBe(1);
        inspector.Get(1).ShouldNotBeNull().Request.Body.Captured.ShouldBeFalse();
    }

    // ---- the leak scan of spec 14 test 18 (inspector part): every sink after a full scenario ----

    [Fact]
    public async Task AfterAFullScenario_NoDek_InAnyAlphabet_IsInTheRingJsonlExportsFeedLogsOrAudit()
    {
        using var factory = InspectorHarness.CreateFactory(persist: true);
        var inspector = InspectorHarness.InspectorOf(factory);
        using var subscription = inspector.Feed.Subscribe(new InspectorSubscriptionOptions { Capacity = 1000 });
        var ekm = factory.CreateEkmClient();
        var deks = new List<byte[]>();
        var sent = 0;

        // Successful traffic for AES and RSA.
        foreach (var (key, alg, size) in new[] { ("aes-key-1", "A256KWP", 32), ("aes-key-1", "A256KW", 24), ("aes-key-1", "A256KWP", 64), ("rsa-key-1", "RSA-OAEP-256", 32), ("rsa-key-1", "RSA-OAEP", 32) })
        {
            var dek = Fx.Random(size);
            deks.Add(dek);
            var wrapped = await ekm.WrapAsync(key, alg, dek);
            await ekm.UnwrapAsync(key, alg, wrapped.Value());
            sent += 2;
        }

        // Rejected traffic that carries DEKs in the places a client could put them.
        var rejected = Fx.Random(32);
        deks.Add(rejected);
        var text = Base64Url.EncodeToString(rejected);
        var path = EkmClient.Path(null, "aes-key-1", "wrapkey");
        foreach (var body in new[]
        {
            EkmClient.WrapBody(Alg, text),
            "{\"request_context\":{},\"alg\":\"" + text + "\",\"value\":\"AAAA\"}",
            "{\"request_context\":{},\"alg\":\"A256KWP\",\"dek\":\"" + text + "\"}",
            "garbage " + text,
        })
        {
            await ekm.PostAsync(path, body, "text/plain");
            await ekm.PostAsync("/nope/aes-key-1/wrapkey?api-version=0.1-preview", body);
            sent += 2;
        }

        await ekm.InfoAsync();
        await ekm.MetadataAsync("aes-key-1");
        await ekm.MetadataAsync("rsa-key-1");
        sent += 3;
        var records = await InspectorHarness.SettleAsync(inspector, sent);

        // ---- gather every sink ----
        var sinks = new Dictionary<string, string>
        {
            ["ring buffer"] = InspectorHarness.AllTextOf(records),
            ["logs"] = factory.Logs.AllText,
        };

        var folder = Path.Combine(factory.DataPath, "inspector");
        await Wait.UntilAsync(() => ReadJsonl(folder).Count(static l => l.Contains("\"type\":\"exchange\"", StringComparison.Ordinal)) >= sent).ShouldBeTrueAsync();
        var jsonl = string.Join('\n', ReadJsonl(folder));
        jsonl.ShouldNotBeNullOrEmpty();
        foreach (var line in jsonl.Split('\n'))
        {
            using var document = JsonDocument.Parse(line); // every line is valid JSON
        }

        sinks["jsonl files"] = jsonl;

        foreach (var format in new[] { ExportFormat.Json, ExportFormat.Jsonl })
        {
            using var stream = new MemoryStream();
            await inspector.ExportAsync(stream, format, cancellationToken: TestContext.Current.CancellationToken);
            sinks[$"export {format}"] = Encoding.UTF8.GetString(stream.ToArray());
        }

        var feedText = new StringBuilder();
        while (subscription.Reader.TryRead(out var item))
        {
            feedText.AppendLine(item is ExchangeFeedItem exchangeItem ? InspectorHarness.AllTextOf([exchangeItem.Exchange]) : item.ToString());
        }

        sinks["live feed"] = feedText.ToString();
        sinks["dashboard and status"] = JsonSerializer.Serialize(inspector.Status().ToString()) + inspector.Dashboard();
        var auditFile = Path.Combine(factory.DataPath, "audit.jsonl");
        sinks["audit log"] = File.Exists(auditFile) ? File.ReadAllText(auditFile) : string.Empty;

        // ---- the scan ----
        foreach (var (name, content) in sinks)
        {
            content.ShouldNotBeNull(name);
            foreach (var (dek, index) in deks.Select(static (d, i) => (d, i)))
            {
                SecretScanner.LeaksInText(content, dek).ShouldBeFalse($"DEK #{index} ({dek.Length} bytes) leaked into: {name}");
            }
        }

        // The scan is meaningful: what is NOT secret is really there, in the same sinks (a scan of empty text would pass too).
        sinks["ring buffer"].ShouldContain("32 bytes · fp");
        sinks["jsonl files"].ShouldContain("32 bytes \\u00B7 fp"); // the JSON serializer escapes the middle dot; the text is the same once parsed
        sinks["export Json"].ShouldContain("32 bytes \\u00B7 fp");
        sinks["live feed"].ShouldContain("32 bytes · fp");
        sinks["export Jsonl"].Split('\n', StringSplitOptions.RemoveEmptyEntries).Length.ShouldBe(sent);
        records.Where(static r => r.Request.Operation == "wrapkey" && r.Response.Status == 200)
            .ShouldAllBe(static r => r.Response.Body.Text!.StartsWith("{\"value\":\"", StringComparison.Ordinal));
        deks.Count.ShouldBe(6);

        // Default mode retains nothing raw: no slot of the ring buffer holds secrets.
        var ring = factory.Services.GetRequiredService<ExchangeRingBuffer>();
        records.All(r => !ring.Contains(r.Id, out var hasSecrets) || !hasSecrets).ShouldBeTrue();
    }

    private static IEnumerable<string> ReadJsonl(string folder)
    {
        if (!Directory.Exists(folder))
        {
            yield break;
        }

        foreach (var file in Directory.GetFiles(folder, "inspector-*.jsonl").Order())
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            while (reader.ReadLine() is { Length: > 0 } line)
            {
                yield return line;
            }
        }
    }

    [Fact]
    public async Task TheExport_IsAlwaysMasked_EvenWhenRevealIsAllowed()
    {
        using var factory = InspectorHarness.CreateFactory(reveal: true);
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);

        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);
        await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value());
        await InspectorHarness.SettleAsync(inspector, 2);
        using var json = new MemoryStream();
        using var jsonl = new MemoryStream();
        await inspector.ExportAsync(json, ExportFormat.Json, cancellationToken: TestContext.Current.CancellationToken);
        await inspector.ExportAsync(jsonl, ExportFormat.Jsonl, new ExchangeFilter { Operation = "unwrapkey" }, TestContext.Current.CancellationToken);

        var jsonText = Encoding.UTF8.GetString(json.ToArray());
        using var document = JsonDocument.Parse(jsonText);
        document.RootElement.GetProperty("masked").GetBoolean().ShouldBeTrue();
        document.RootElement.GetProperty("count").GetInt32().ShouldBe(2);
        document.RootElement.GetProperty("exchanges").GetArrayLength().ShouldBe(2);
        SecretScanner.LeaksInText(jsonText, dek).ShouldBeFalse();
        var lines = Encoding.UTF8.GetString(jsonl.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        lines.ShouldHaveSingleItem();
        SecretScanner.LeaksInText(lines[0], dek).ShouldBeFalse();
        lines[0].ShouldContain("\"operation\":\"unwrapkey\"");
    }
}

/// <summary>Spec 8.4 and 14 test 23: reveal is impossible without the environment flag, and every reveal is audited.</summary>
public sealed class InspectorRevealTests
{
    private const string Alg = "A256KWP";

    private sealed class RecordingReplaySender : IReplaySender
    {
        public ReplayRequest? Seen { get; private set; }

        public byte[]? BodyCopy { get; private set; }

        public Task<ReplayOutcome> SendAsync(ReplayRequest request, CancellationToken cancellationToken)
        {
            Seen = request;
            BodyCopy = request.Body.ToArray();
            return Task.FromResult(new ReplayOutcome(true, 200, null));
        }
    }

    // ---- the gate ----

    [Fact]
    public void TheGate_NeedsBothTheRevealSettingAndTheEnvironmentFlag()
    {
        var previous = Environment.GetEnvironmentVariable(InspectorOptions.AllowRevealVariable);
        try
        {
            foreach (var (display, env, expected) in new (SecretDisplayMode, string?, bool)[]
            {
                (SecretDisplayMode.Masked, null, false),
                (SecretDisplayMode.Masked, "true", false), // the flag alone changes nothing
                (SecretDisplayMode.Reveal, null, false), // the setting alone changes nothing
                (SecretDisplayMode.Reveal, "false", false),
                (SecretDisplayMode.Reveal, "1", false),
                (SecretDisplayMode.Reveal, "yes", false),
                (SecretDisplayMode.Reveal, "true", true),
                (SecretDisplayMode.Reveal, "TRUE", true),
            })
            {
                Environment.SetEnvironmentVariable(InspectorOptions.AllowRevealVariable, env);

                new EnvironmentRevealGate(Microsoft.Extensions.Options.Options.Create(new InspectorOptions { SecretDisplay = display })).IsAllowed
                    .ShouldBe(expected, $"{display} / {env ?? "(unset)"}");
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable(InspectorOptions.AllowRevealVariable, previous);
        }
    }

    [Fact]
    public void TheEnvironmentVariable_IsNeverReadFromConfiguration()
    {
        // A configuration file or --Inspector:AllowReveal=true cannot grant it: the option class has no such member.
        typeof(InspectorOptions).GetProperties().Select(static p => p.Name).ShouldNotContain(static n => n.Contains("AllowReveal", StringComparison.OrdinalIgnoreCase));
        InspectorOptions.AllowRevealVariable.ShouldBe("EKMMOCK_INSPECTOR_ALLOW_REVEAL");
    }

    [Fact]
    public async Task WithTheRealGate_RevealConfiguredButNoEnvironmentFlag_RetainsNothing()
    {
        var previous = Environment.GetEnvironmentVariable(InspectorOptions.AllowRevealVariable);
        Environment.SetEnvironmentVariable(InspectorOptions.AllowRevealVariable, null);
        try
        {
            using var factory = InspectorHarness.CreateFactory(realRevealGate: true, secretDisplay: "Reveal");
            var inspector = InspectorHarness.InspectorOf(factory);
            await factory.CreateEkmClient().WrapAsync("aes-key-1", Alg, Fx.Random(32));
            await InspectorHarness.SettleAsync(inspector, 1);

            inspector.Status().SecretDisplay.ShouldBe(SecretDisplayMode.Reveal);
            inspector.Status().RevealAllowed.ShouldBeFalse();
            factory.Services.GetRequiredService<ExchangeRingBuffer>().Contains(1, out var hasSecrets).ShouldBeTrue();
            hasSecrets.ShouldBeFalse();
            Should.Throw<InspectorRevealException>(() => inspector.Reveal(1, RevealFields.RequestValue, "alice")).Reason.ShouldBe(RevealFailure.Disabled);
        }
        finally
        {
            Environment.SetEnvironmentVariable(InspectorOptions.AllowRevealVariable, previous);
        }
    }

    [Fact]
    public async Task WithTheRealGate_BothSwitches_AllowRevealThroughTheWholeStack()
    {
        var previous = Environment.GetEnvironmentVariable(InspectorOptions.AllowRevealVariable);
        Environment.SetEnvironmentVariable(InspectorOptions.AllowRevealVariable, "true");
        try
        {
            using var factory = InspectorHarness.CreateFactory(realRevealGate: true, secretDisplay: "Reveal");
            var inspector = InspectorHarness.InspectorOf(factory);
            var dek = Fx.Random(32);
            await factory.CreateEkmClient().WrapAsync("aes-key-1", Alg, dek); // the gate is read when the pipeline is first built

            Environment.SetEnvironmentVariable(InspectorOptions.AllowRevealVariable, previous); // read once at start: changing it later changes nothing
            await InspectorHarness.SettleAsync(inspector, 1);

            inspector.Status().RevealAllowed.ShouldBeTrue();
            inspector.Reveal(1, RevealFields.RequestValue, "alice").Value.ShouldBe(Base64Url.EncodeToString(dek));
        }
        finally
        {
            Environment.SetEnvironmentVariable(InspectorOptions.AllowRevealVariable, previous);
        }
    }

    // ---- reveal denied ----

    [Fact]
    public async Task WithoutRevealAllowed_RevealIsDenied_NothingIsRetained_AndTheAttemptIsAudited()
    {
        var audit = new ListAuditLog();
        using var factory = InspectorHarness.CreateFactory(reveal: false, audit: audit);
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);
        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);
        await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value());
        var records = await InspectorHarness.SettleAsync(inspector, 2);
        var ring = factory.Services.GetRequiredService<ExchangeRingBuffer>();

        foreach (var field in new[] { RevealFields.RequestValue, RevealFields.ResponseValue, "bogus" })
        {
            Should.Throw<InspectorRevealException>(() => inspector.Reveal(1, field, "mallory")).Reason.ShouldBe(RevealFailure.Disabled);
        }

        records.All(r => ring.Contains(r.Id, out var hasSecrets) && !hasSecrets).ShouldBeTrue(); // the raw bodies were never kept
        inspector.CanReplay(1).ShouldBe(new ReplayCheck(false, ReplayBlockReason.RevealNotAllowed));
        audit.Entries.Count.ShouldBe(3);
        audit.Entries.ShouldAllBe(static e => e.Action == "inspector.reveal.denied" && e.User == "mallory");
        SecretScanner.LeaksInText(string.Join('\n', audit.Entries.Select(static e => e.ToString())), dek).ShouldBeFalse();
    }

    [Fact]
    public async Task Revealing_NeedsAUser()
    {
        using var factory = InspectorHarness.CreateFactory(reveal: true);

        Should.Throw<ArgumentException>(() => InspectorHarness.InspectorOf(factory).Reveal(1, RevealFields.RequestValue, " "));
        await Task.CompletedTask;
    }

    // ---- reveal allowed ----

    [Fact]
    public async Task WhenAllowed_ARevealReturnsTheRawValue_AndEveryRevealIsAuditedBeforeItIsReturned()
    {
        using var factory = InspectorHarness.CreateFactory(reveal: true, persist: true);
        var inspector = InspectorHarness.InspectorOf(factory);
        var audit = factory.Services.GetRequiredService<IAuditLog>();
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);
        var text = Base64Url.EncodeToString(dek);

        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);
        await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value());
        var records = await InspectorHarness.SettleAsync(inspector, 2);
        records[0].Request.Body.MaskedFields.Single().Revealable.ShouldBeTrue();
        records[1].Response.Body.MaskedFields.Single().Revealable.ShouldBeTrue();
        audit.ReadRecent().ShouldBeEmpty(); // looking at the masked traffic is not a reveal

        var request = inspector.Reveal(1, RevealFields.RequestValue, "alice@example.test");
        var response = inspector.Reveal(2, RevealFields.ResponseValue, "bob@example.test");
        var again = inspector.Reveal(1, RevealFields.RequestValue, "alice@example.test");

        request.Value.ShouldBe(text);
        request.Bytes.ShouldBe(32);
        request.Fingerprint.ShouldBe(records[0].Request.Body.MaskedFields.Single().Fingerprint);
        response.Value.ShouldBe(text);
        again.Value.ShouldBe(text);

        var entries = audit.ReadRecent();
        entries.Select(static e => (e.User, e.Action, e.Target)).ShouldBe(
        [
            ("alice@example.test", "inspector.reveal", "exchange:1/request.value"),
            ("bob@example.test", "inspector.reveal", "exchange:2/response.value"),
            ("alice@example.test", "inspector.reveal", "exchange:1/request.value"),
        ]);
        entries.ShouldAllBe(e => e.At > DateTimeOffset.UtcNow.AddMinutes(-5));
        File.ReadAllText(Path.Combine(factory.DataPath, "audit.jsonl")).Split('\n', StringSplitOptions.RemoveEmptyEntries).Length.ShouldBe(3);
    }

    [Fact]
    public async Task EvenWithRevealAllowed_NothingRawIsPersistedExportedLoggedOrPushed()
    {
        using var factory = InspectorHarness.CreateFactory(reveal: true, persist: true);
        var inspector = InspectorHarness.InspectorOf(factory);
        using var subscription = inspector.Feed.Subscribe();
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);
        var wrapped = await ekm.WrapAsync("aes-key-1", Alg, dek);
        await ekm.UnwrapAsync("aes-key-1", Alg, wrapped.Value());
        var records = await InspectorHarness.SettleAsync(inspector, 2);
        inspector.Reveal(1, RevealFields.RequestValue, "alice");
        inspector.Reveal(2, RevealFields.ResponseValue, "alice");

        using var export = new MemoryStream();
        await inspector.ExportAsync(export, ExportFormat.Json, cancellationToken: TestContext.Current.CancellationToken);
        var folder = Path.Combine(factory.DataPath, "inspector");
        await Wait.UntilAsync(() => Directory.Exists(folder) && Directory.GetFiles(folder).Length > 0 && ReadAll(folder).Split('\n', StringSplitOptions.RemoveEmptyEntries).Length >= 2).ShouldBeTrueAsync();
        var feed = new StringBuilder();
        while (subscription.Reader.TryRead(out var item))
        {
            feed.AppendLine(item is ExchangeFeedItem e ? InspectorHarness.AllTextOf([e.Exchange]) : string.Empty);
        }

        var sinks = new Dictionary<string, string>
        {
            ["records"] = InspectorHarness.AllTextOf(records),
            ["export"] = Encoding.UTF8.GetString(export.ToArray()),
            ["jsonl"] = ReadAll(folder),
            ["feed"] = feed.ToString(),
            ["logs"] = factory.Logs.AllText,
            ["audit"] = File.ReadAllText(Path.Combine(factory.DataPath, "audit.jsonl")),
        };

        foreach (var (name, content) in sinks)
        {
            SecretScanner.LeaksInText(content, dek).ShouldBeFalse($"DEK leaked into {name}");
        }
    }

    private static string ReadAll(string folder)
    {
        var builder = new StringBuilder();
        foreach (var file in Directory.GetFiles(folder))
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            builder.AppendLine(new StreamReader(stream).ReadToEnd());
        }

        return builder.ToString();
    }

    [Fact]
    public async Task RevealFailures_AreExplicit()
    {
        using var factory = InspectorHarness.CreateFactory(reveal: true);
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        await ekm.WrapAsync("aes-key-1", Alg, Fx.Random(32));
        await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), "{\"request_context\":{},\"alg\":\"A256KWP\",\"value\":\"" + new string('A', 20_000) + "\"}");
        await InspectorHarness.SettleAsync(inspector, 2);

        RevealFailure Fail(long id, string field) => Should.Throw<InspectorRevealException>(() => inspector.Reveal(id, field, "alice")).Reason;

        Fail(1, "request.other").ShouldBe(RevealFailure.UnknownField);
        Fail(999, RevealFields.RequestValue).ShouldBe(RevealFailure.ExchangeNotFound);
        Fail(1, RevealFields.ResponseValue).ShouldBe(RevealFailure.NotRetained); // a wrap response is ciphertext: nothing secret to reveal
        Fail(2, RevealFields.RequestValue).ShouldBe(RevealFailure.NotRetained); // an oversize body is never retained
    }

    [Fact]
    public async Task WithoutAnAuditEntry_NothingIsRevealed()
    {
        var audit = new ListAuditLog { Fail = true };
        using var factory = InspectorHarness.CreateFactory(reveal: true, audit: audit);
        var inspector = InspectorHarness.InspectorOf(factory);
        await factory.CreateEkmClient().WrapAsync("aes-key-1", Alg, Fx.Random(32));
        await InspectorHarness.SettleAsync(inspector, 1);

        Should.Throw<InspectorRevealException>(() => inspector.Reveal(1, RevealFields.RequestValue, "alice")).Reason.ShouldBe(RevealFailure.AuditUnavailable);

        audit.Fail = false;
        inspector.Reveal(1, RevealFields.RequestValue, "alice").Value.ShouldNotBeNullOrEmpty();
        audit.Entries.Count.ShouldBe(1);
    }

    [Fact]
    public async Task TheRawValue_IsGoneWhenItsExchangeIsEvicted()
    {
        using var factory = InspectorHarness.CreateFactory(reveal: true, ringSize: 3);
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        await ekm.WrapAsync("aes-key-1", Alg, Fx.Random(32));
        await InspectorHarness.SettleAsync(inspector, 1);
        inspector.Reveal(1, RevealFields.RequestValue, "alice").Value.ShouldNotBeNullOrEmpty();

        for (var i = 0; i < 4; i++)
        {
            await ekm.InfoAsync();
        }

        await Wait.UntilAsync(() => inspector.Get(1) is null).ShouldBeTrueAsync();
        Should.Throw<InspectorRevealException>(() => inspector.Reveal(1, RevealFields.RequestValue, "alice")).Reason.ShouldBe(RevealFailure.ExchangeNotFound);
    }

    // ---- replay seam ----

    [Fact]
    public async Task CanReplay_IsTrueOnlyWhenTheRawRequestBodyIsAvailable()
    {
        using var factory = InspectorHarness.CreateFactory(reveal: true);
        var inspector = InspectorHarness.InspectorOf(factory);
        var ekm = factory.CreateEkmClient();
        await ekm.WrapAsync("aes-key-1", Alg, Fx.Random(32)); // 1: complete body
        await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), "{\"request_context\":{},\"pad\":\"" + new string('x', 20_000) + "\"}"); // 2: oversize
        await ekm.InfoAsync(); // 3
        await InspectorHarness.SettleAsync(inspector, 3);

        inspector.CanReplay(1).ShouldBe(new ReplayCheck(true, ReplayBlockReason.None));
        inspector.CanReplay(2).ShouldBe(new ReplayCheck(false, ReplayBlockReason.BodyNotRetained));
        inspector.CanReplay(3).ShouldBe(new ReplayCheck(true, ReplayBlockReason.None));
        inspector.CanReplay(404).ShouldBe(new ReplayCheck(false, ReplayBlockReason.ExchangeNotFound));
    }

    [Fact]
    public async Task CanReplay_IsFalseWhenRevealIsNotAllowed_BecauseTheRawBodyWasNeverKept()
    {
        using var factory = InspectorHarness.CreateFactory(reveal: false);
        var inspector = InspectorHarness.InspectorOf(factory);
        await factory.CreateEkmClient().InfoAsync();
        await InspectorHarness.SettleAsync(inspector, 1);

        inspector.CanReplay(1).ShouldBe(new ReplayCheck(false, ReplayBlockReason.RevealNotAllowed));
        (await Should.ThrowAsync<InspectorReplayException>(() => inspector.ReplayAsync(1, "alice", TestContext.Current.CancellationToken))).Reason.ShouldBe(ReplayBlockReason.RevealNotAllowed);
    }

    [Fact]
    public async Task Replay_HandsTheRawRequestToTheSender_AndIsAudited()
    {
        var sender = new RecordingReplaySender();
        var audit = new ListAuditLog();
        using var factory = InspectorHarness.CreateFactory(reveal: true, audit: audit, replaySender: sender);
        var inspector = InspectorHarness.InspectorOf(factory);
        var dek = Fx.Random(32);
        await factory.CreateEkmClient().WrapAsync("aes-key-1", Alg, dek);
        await InspectorHarness.SettleAsync(inspector, 1);

        var outcome = await inspector.ReplayAsync(1, "alice", TestContext.Current.CancellationToken);

        outcome.Sent.ShouldBeTrue();
        sender.Seen.ShouldNotBeNull().Method.ShouldBe("POST");
        sender.Seen.PathAndQuery.ShouldBe("/aes-key-1/wrapkey?api-version=0.1-preview");
        sender.Seen.ContentType.ShouldNotBeNull().ShouldStartWith("application/json");
        Encoding.UTF8.GetString(sender.BodyCopy!).ShouldBe(EkmClient.WrapBody(Alg, Base64Url.EncodeToString(dek))); // the exact raw body, DEK included
        sender.Seen.Body.ShouldAllBe(static b => b == 0); // the sender disposed it: zeroed
        audit.Entries.ShouldHaveSingleItem().ShouldSatisfyAllConditions(
            static e => e.Action.ShouldBe("inspector.replay"),
            static e => e.Target.ShouldBe("exchange:1"),
            static e => e.User.ShouldBe("alice"));
    }

    [Fact]
    public async Task Replay_WithoutASender_SaysSo_AndSendsNothing()
    {
        using var factory = InspectorHarness.CreateFactory(reveal: true);
        var inspector = InspectorHarness.InspectorOf(factory);
        await factory.CreateEkmClient().InfoAsync();
        await InspectorHarness.SettleAsync(inspector, 1);

        var outcome = await inspector.ReplayAsync(1, "alice", TestContext.Current.CancellationToken);

        outcome.Sent.ShouldBeFalse();
        outcome.Note.ShouldNotBeNull().ShouldContain("M6");
        inspector.Count().ShouldBe(1);
    }
}
