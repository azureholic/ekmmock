using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using EkmMock.Server.Ekm;
using EkmMock.Server.Inspector;

namespace EkmMock.Server.Tests;

/// <summary>Spec 8.4 and 14 test 22 at unit level: what is masked where, the fingerprint, and what is never captured.</summary>
public sealed class SecretMaskingTests
{
    private static readonly byte[] Dek = Enumerable.Range(1, 32).Select(static i => (byte)(i * 7)).ToArray();

    private static string Fingerprint(byte[] raw) => Convert.ToHexString(SHA256.HashData(raw))[..12].ToLowerInvariant();

    private static string Value(byte[] raw) => Base64Url.EncodeToString(raw);

    private static string WrapBody(string valueJson, string alg = "A256KWP")
        => $$"""{"request_context":{"request_id":"r1","correlation_id":"c1","pool_name":"p1"},"alg":"{{alg}}","value":{{valueJson}}}""";

    private static CapturedBody Redact(string text, BodyPosition position, bool revealable = false)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        return BodyRedactor.Redact(bytes, bytes.Length, truncated: false, position, revealable);
    }

    // ---- the fingerprint ----

    [Fact]
    public void Fingerprint_IsTheFirst12HexCharactersOfTheSha256OfTheRawBytes()
    {
        var expected = Convert.ToHexString(SHA256.HashData(Dek)).ToLowerInvariant()[..12];

        SecretFingerprint.Compute(Dek).ShouldBe(expected);
        SecretFingerprint.Compute(Dek).Length.ShouldBe(12);
        SecretFingerprint.Compute(Dek.AsSpan()).ShouldBe(SecretFingerprint.Compute(Dek.ToArray()));
        SecretFingerprint.Compute(Dek[..31]).ShouldNotBe(SecretFingerprint.Compute(Dek));
        SecretFingerprint.Compute([]).ShouldBe("e3b0c44298fc"); // SHA-256 of nothing: pins the definition
    }

    [Fact]
    public void Display_UsesTheLengthAndFingerprintFormatOfTheSpec()
    {
        SecretFingerprint.Display(32, "3f9a1c07b2e4").ShouldBe("32 bytes · fp 3f9a1c07b2e4");
        SecretFingerprint.DisplayInvalid(7).ShouldBe("value (invalid, 7 chars)");
    }

    // ---- the (operation, direction) rule ----

    [Theory]
    [InlineData("WrapKey", true, "SecretRequest")]
    [InlineData("UnwrapKey", true, "CiphertextRequest")]
    [InlineData("WrapKey", false, "Plain")]
    [InlineData("UnwrapKey", false, "SecretResponse")]
    [InlineData("Info", true, "NoDekRequest")]
    [InlineData("Info", false, "Plain")]
    [InlineData("Metadata", true, "NoDekRequest")]
    [InlineData("Metadata", false, "Plain")]
    public void TheSecrecyRule_PerOperationAndDirection(string operation, bool isRequest, string expected)
        => BodyPositions.For(Enum.Parse<EkmOperation>(operation), isRequest).ToString().ShouldBe(expected);

    [Fact]
    public void AnUnroutedRequest_IsTreatedLikeAWrapRequest_ButItsResponseIsPlain()
    {
        BodyPositions.For(null, isRequest: true).ShouldBe(BodyPosition.SecretRequest);
        BodyPositions.For(null, isRequest: false).ShouldBe(BodyPosition.Plain);
    }

    // ---- masked: wrap request / unwrap response ----

    [Fact]
    public void AWrapRequest_ShowsLengthAndFingerprintInsteadOfTheValue_InTheText()
    {
        var body = Redact(WrapBody($"\"{Value(Dek)}\""), BodyPosition.SecretRequest, revealable: true);

        body.Captured.ShouldBeTrue();
        body.Text.ShouldNotBeNull().ShouldContain($"\"value\":\"32 bytes · fp {Fingerprint(Dek)}\"");
        body.Text!.ShouldNotContain(Value(Dek));
        SecretScanner.LeaksInText(body.Text, Dek).ShouldBeFalse();
        body.PrettyJson.ShouldNotBeNull().ShouldNotContain(Value(Dek));
        body.PrettyJson.ShouldContain("32 bytes · fp");
        body.MaskedFields.ShouldHaveSingleItem().ShouldBe(new MaskedField("request.value", $"32 bytes · fp {Fingerprint(Dek)}", 32, Fingerprint(Dek), true));

        // The rest of the document is untouched, including the request context.
        body.Text.ShouldContain("\"request_context\":{\"request_id\":\"r1\",\"correlation_id\":\"c1\",\"pool_name\":\"p1\"}");
        body.Text.ShouldContain("\"alg\":\"A256KWP\"");
    }

    [Fact]
    public void AnUnwrapResponse_IsMaskedTheSameWay()
    {
        var body = Redact($$"""{"value":"{{Value(Dek)}}"}""", BodyPosition.SecretResponse, revealable: true);

        body.Text.ShouldBe($$"""{"value":"32 bytes · fp {{Fingerprint(Dek)}}"}""");
        body.MaskedFields.Single().Field.ShouldBe("response.value");
        body.MaskedFields.Single().Revealable.ShouldBeTrue();
    }

    [Fact]
    public void WrapInput_AndUnwrapOutput_OfTheSameDek_HaveTheSameFingerprint()
    {
        var request = Redact(WrapBody($"\"{Value(Dek)}\""), BodyPosition.SecretRequest);
        var response = Redact($$"""{"value":"{{Value(Dek)}}"}""", BodyPosition.SecretResponse);

        request.MaskedFields.Single().Fingerprint.ShouldBe(response.MaskedFields.Single().Fingerprint);
        request.MaskedFields.Single().Display.ShouldBe(response.MaskedFields.Single().Display);
    }

    [Fact]
    public void PaddedAndUnpaddedBase64Url_OfTheSameBytes_GiveTheSameFingerprint()
    {
        var unpadded = Redact(WrapBody("\"AQIDBA\""), BodyPosition.SecretRequest);
        var padded = Redact(WrapBody("\"AQIDBA==\""), BodyPosition.SecretRequest);

        unpadded.MaskedFields.Single().Fingerprint.ShouldBe(padded.MaskedFields.Single().Fingerprint);
        unpadded.MaskedFields.Single().Bytes.ShouldBe(4);
    }

    [Fact]
    public void AnEscapedValue_IsDecodedBeforeFingerprinting_AndTheEscapeNeverSurvivesInTheText()
    {
        // \u002D is "-": legal JSON inside a base64url string.
        var raw = new byte[] { 0xFB, 0xEF, 0xBE, 0xFB, 0xEF }; // base64url "--_--_" with '-' at several places
        var plain = Value(raw);
        plain.ShouldContain("-");
        var escaped = plain.Replace("-", "\\u002D", StringComparison.Ordinal);

        var body = Redact(WrapBody($"\"{escaped}\""), BodyPosition.SecretRequest);

        body.MaskedFields.Single().Fingerprint.ShouldBe(Fingerprint(raw));
        body.Text!.ShouldNotContain("002D");
        body.Text!.ShouldNotContain(plain);
    }

    [Theory]
    [InlineData("""{"value":"AAAA"}""")]
    [InlineData("""{ "value" : "AAAA" , "other": 1 }""")]
    public void TheOriginalFormattingAroundAMaskedValueIsKept(string original)
    {
        var body = Redact(original, BodyPosition.SecretResponse);

        body.Text.ShouldNotBeNull();
        body.Text.ShouldNotContain("AAAA\"");
        body.Text.ShouldContain("3 bytes · fp");
        body.Text.StartsWith("{ ", StringComparison.Ordinal).ShouldBe(original.StartsWith("{ ", StringComparison.Ordinal));
    }

    // ---- not secret: shown as they are ----

    [Fact]
    public void AnUnwrapRequest_AndAWrapResponse_CarryCiphertext_AndAreShownAsIs()
    {
        var wrapped = Value(RandomNumberGenerator.GetBytes(40));
        var unwrapRequest = Redact(WrapBody($"\"{wrapped}\""), BodyPosition.CiphertextRequest);
        var wrapResponse = Redact($$"""{"value":"{{wrapped}}"}""", BodyPosition.Plain);

        unwrapRequest.Text.ShouldNotBeNull().ShouldContain(wrapped);
        unwrapRequest.MaskedFields.ShouldBeEmpty();
        wrapResponse.Text.ShouldBe($$"""{"value":"{{wrapped}}"}""");
        wrapResponse.PrettyJson.ShouldNotBeNull().ShouldContain(wrapped);
    }

    [Fact]
    public void ErrorBodies_AreShownAsIs_EvenOnAnUnwrapResponse()
    {
        var error = """{"code":"InvalidCiphertext","message":"The wrapped value could not be unwrapped"}""";

        var body = Redact(error, BodyPosition.SecretResponse);

        body.Text.ShouldBe(error);
        body.MaskedFields.ShouldBeEmpty();
    }

    [Fact]
    public void RsaMetadata_IsNotMasked()
    {
        var metadata = """{"key_type":"RSA","key_size":2048,"key_ops":["wrapKey","unwrapKey"],"n":"AQAB","e":"AQAB"}""";

        Redact(metadata, BodyPosition.Plain).Text.ShouldBe(metadata);
    }

    // ---- invalid / unexpected input on a secret position ----

    [Theory]
    [InlineData("not+base64/here==")] // standard base64 characters
    [InlineData("AAAAA")] // length 1 mod 4
    [InlineData("AA AA")] // whitespace
    [InlineData("AA=A")] // inner padding
    public void AnUndecodableValue_IsMaskedByLengthOnly_WithoutAFingerprint(string value)
    {
        var body = Redact(WrapBody($"\"{value}\""), BodyPosition.SecretRequest);

        body.Captured.ShouldBeTrue();
        body.Text.ShouldNotBeNull().ShouldContain($"\"value\":\"value (invalid, {value.Length} chars)\"");
        body.Text.ShouldNotContain(value);
        body.MaskedFields.Single().Fingerprint.ShouldBeNull();
        body.MaskedFields.Single().Bytes.ShouldBeNull();
        body.MaskedFields.Single().Revealable.ShouldBeFalse();
    }

    [Theory]
    [InlineData("12345", "not a string")]
    [InlineData("true", "not a string")]
    [InlineData("""{"deep":"secret-material"}""", "not a string")]
    [InlineData("""["a","b"]""", "not a string")]
    public void AValueOfTheWrongType_IsReplacedEntirely(string valueJson, string expectedNote)
    {
        var body = Redact(WrapBody(valueJson), BodyPosition.SecretRequest);

        body.Text.ShouldNotBeNull().ShouldContain($"value (invalid, {expectedNote})");
        body.Text.ShouldNotContain("secret-material");
        body.Text.ShouldNotContain("12345");
        body.Text.ShouldNotContain("\"b\"");
        System.Text.Json.JsonDocument.Parse(body.Text).Dispose(); // still valid JSON
    }

    [Fact]
    public void ANullValue_IsLeftAsNull()
    {
        var body = Redact(WrapBody("null"), BodyPosition.SecretRequest);

        body.Text.ShouldNotBeNull().ShouldContain("\"value\":null");
        body.MaskedFields.ShouldBeEmpty();
    }

    [Fact]
    public void ADekSentUnderAWrongFieldName_IsMasked_BecauseOnlyAnAllowListIsShown()
    {
        var dek = Value(Dek);
        foreach (var field in new[] { "Value", "VALUE", "val", "key", "dek", "payload", "data" })
        {
            var body = Redact($$"""{"request_context":{"correlation_id":"c"},"alg":"A256KWP","{{field}}":"{{dek}}"}""", BodyPosition.SecretRequest);

            body.Text.ShouldNotBeNull($"field {field}");
            body.Text.ShouldNotContain(dek);
            SecretScanner.LeaksInText(body.Text, Dek).ShouldBeFalse(field);
        }
    }

    [Fact]
    public void ADekSentInTheAlgField_IsMasked_AndARealAlgorithmNameIsShown()
    {
        var dek = Value(Dek);
        var swapped = Redact($$"""{"request_context":{"correlation_id":"c"},"alg":"{{dek}}","value":"AAAA"}""", BodyPosition.SecretRequest);
        var normal = Redact($$"""{"request_context":{"correlation_id":"c"},"alg":"RSA-OAEP-256","value":"AAAA"}""", BodyPosition.SecretRequest);

        swapped.Text.ShouldNotBeNull().ShouldNotContain(dek);
        swapped.Text.ShouldContain($"(masked, {dek.Length} chars)");
        normal.Text.ShouldNotBeNull().ShouldContain("\"alg\":\"RSA-OAEP-256\"");
    }

    [Fact]
    public void ANestedValue_InsideTheRequestContext_IsMaskedToo()
    {
        var dek = Value(Dek);
        var body = Redact($$"""{"request_context":{"correlation_id":"c","value":"{{dek}}"},"alg":"A256KW","value":"AAAA"}""", BodyPosition.SecretRequest);

        body.Text.ShouldNotBeNull().ShouldNotContain(dek);
        body.Text.ShouldContain("\"correlation_id\":\"c\"");
        body.MaskedFields.Count.ShouldBe(2);
    }

    [Fact]
    public void AnUnknownFieldOnAnUnwrapResponse_IsMasked_ButCodeAndMessageAreShown()
    {
        var body = Redact($$"""{"code":"X","message":"m","value":"{{Value(Dek)}}","extra":"{{Value(Dek)}}"}""", BodyPosition.SecretResponse);

        body.Text.ShouldNotBeNull().ShouldContain("\"code\":\"X\"");
        body.Text.ShouldContain("\"message\":\"m\"");
        SecretScanner.LeaksInText(body.Text, Dek).ShouldBeFalse();
    }

    // ---- unparseable bodies on a secret position: not captured ----

    [Theory]
    [InlineData("{\"alg\":\"A256KWP\",\"value\":\"")] // cut off
    [InlineData("not json at all")]
    [InlineData("\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"")] // a bare string root (could be the DEK itself)
    [InlineData("[\"AAAAAAAAAAAAAAAA\"]")] // array root
    [InlineData("{\"value\":\"AAAA\"} trailing")] // trailing content
    [InlineData("{\"value\":\"AAAA\",}")] // trailing comma
    public void AnUnparseableBody_OnASecretPosition_IsNotCaptured(string text)
    {
        var request = Redact(text, BodyPosition.SecretRequest);
        var response = Redact(text, BodyPosition.SecretResponse);

        foreach (var body in new[] { request, response })
        {
            body.Captured.ShouldBeFalse();
            body.Text.ShouldBeNull();
            body.PrettyJson.ShouldBeNull();
            body.Note.ShouldNotBeNull().ShouldContain("not captured");
            body.SizeBytes.ShouldBe(Encoding.UTF8.GetByteCount(text));
        }
    }

    [Fact]
    public void AnOverlyDeepDocument_OnASecretPosition_IsNotCaptured()
    {
        var text = string.Concat(Enumerable.Repeat("{\"a\":", 40)) + "1" + new string('}', 40);

        Redact(text, BodyPosition.SecretRequest).Captured.ShouldBeFalse();
        Redact(text, BodyPosition.Plain).Captured.ShouldBeTrue(); // plain bodies are not parsed
    }

    [Fact]
    public void InvalidUtf8_OnASecretPosition_IsNotCaptured()
    {
        byte[] bytes = [.. "{\"value\":\"AAAA\",\"x\":\""u8, 0xC3, 0x28, .. "\"}"u8];

        var body = BodyRedactor.Redact(bytes, bytes.Length, false, BodyPosition.SecretRequest, false);

        body.Captured.ShouldBeFalse();
    }

    [Fact]
    public void ATruncatedBody_OnASecretPosition_IsNotCaptured_ButOnAPlainOneItIsKeptAndFlagged()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"value\":\"" + new string('A', 16 * 1024 - 20));

        var secret = BodyRedactor.Redact(bytes, 20_000, truncated: true, BodyPosition.SecretRequest, false);
        var plain = BodyRedactor.Redact(bytes, 20_000, truncated: true, BodyPosition.Plain, false);

        secret.Captured.ShouldBeFalse();
        secret.Truncated.ShouldBeTrue();
        secret.SizeBytes.ShouldBe(20_000);
        plain.Captured.ShouldBeTrue();
        plain.Truncated.ShouldBeTrue();
        plain.Text.ShouldNotBeNull().Length.ShouldBe(bytes.Length);
        plain.PrettyJson.ShouldBeNull(); // incomplete JSON has no pretty form
    }

    [Fact]
    public void AnEmptyBody_IsEmpty_OnEveryPosition()
    {
        foreach (var position in Enum.GetValues<BodyPosition>())
        {
            var body = BodyRedactor.Redact([], 0, false, position, false);

            body.SizeBytes.ShouldBe(0);
            body.Captured.ShouldBeTrue();
            body.Text.ShouldBeNullOrEmpty();
        }
    }

    [Fact]
    public void ABomIsTolerated_AndNeverEndsUpInTheText()
    {
        byte[] bytes = [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes(WrapBody($"\"{Value(Dek)}\""))];

        var body = BodyRedactor.Redact(bytes, bytes.Length, false, BodyPosition.SecretRequest, false);

        body.Captured.ShouldBeTrue();
        body.Text.ShouldNotBeNull().ShouldNotContain(Value(Dek));
        body.Text[0].ShouldBe('{');
    }

    [Fact]
    public void NonAsciiText_RoundTrips_InAPlainBody()
    {
        var body = Redact("""{"request_context":{"pool_name":"pöol-é-日本"}}""", BodyPosition.Plain);

        body.Text.ShouldNotBeNull().ShouldContain("pöol-é-日本");
    }

    // ---- unwrap requests (ciphertext) and info/metadata requests (no DEK expected) ----

    [Fact]
    public void AnUnparseableUnwrapRequest_IsNotCaptured_ButAParseableOneIsShownAsSent()
    {
        var wrapped = Value(RandomNumberGenerator.GetBytes(40));
        var odd = $$"""{"request_context":{"correlation_id":"c"},"alg":"A256KW","value":"{{wrapped}}","extra":"anything"}""";

        var shown = Redact(odd, BodyPosition.CiphertextRequest);

        shown.Text.ShouldBe(odd);
        shown.MaskedFields.ShouldBeEmpty();
        foreach (var broken in new[] { "{\"value\":\"" + Value(Dek), "garbage " + Value(Dek), "\"" + Value(Dek) + "\"" })
        {
            var body = Redact(broken, BodyPosition.CiphertextRequest);

            body.Captured.ShouldBeFalse();
            body.Text.ShouldBeNull();
        }
    }

    [Fact]
    public void AnInfoOrMetadataRequest_IsShownAsIs_ExceptForAStrayValue()
    {
        var ordinary = """{"request_context":{"request_id":"r","correlation_id":"c","pool_name":"p"}}""";
        var misdirected = WrapBody($"\"{Value(Dek)}\"");

        Redact(ordinary, BodyPosition.NoDekRequest).Text.ShouldBe(ordinary);

        var masked = Redact(misdirected, BodyPosition.NoDekRequest);
        masked.Text.ShouldNotBeNull().ShouldNotContain(Value(Dek));
        masked.Text.ShouldContain($"\"value\":\"32 bytes · fp {Fingerprint(Dek)}\"");
        masked.Text.ShouldContain("\"alg\":\"A256KWP\"");
    }

    [Fact]
    public void AnInfoRequestThatIsNotJson_IsShown_BecauseThatIsWhatOneWantsToSeeWhenManagedHsmSendsSomethingUnexpected()
    {
        var body = Redact("this is not json", BodyPosition.NoDekRequest);

        body.Captured.ShouldBeTrue();
        body.Text.ShouldBe("this is not json");
    }

    [Fact]
    public void ARoundTripThroughEveryPosition_NeverShowsTheDekInAnyAlphabet()
    {
        var dek = Value(Dek);
        foreach (var position in new[] { BodyPosition.SecretRequest, BodyPosition.SecretResponse, BodyPosition.NoDekRequest })
        {
            foreach (var text in new[] { WrapBody($"\"{dek}\""), "{\"value\":\"" + dek + "\"}", "{\"a\":{\"b\":{\"value\":\"" + dek + "\"}}}" })
            {
                var body = Redact(text, position);

                if (body.Text is { } shown)
                {
                    SecretScanner.LeaksInText(shown, Dek).ShouldBeFalse($"{position}: {text.Length}");
                }
            }
        }
    }

    // ---- the request context of a body nobody parsed ----

    [Fact]
    public void TheRequestContext_CanBeReadFromARejectedBody()
    {
        var bytes = Encoding.UTF8.GetBytes(WrapBody($"\"{Value(Dek)}\""));

        BodyRedactor.ExtractRequestContext(bytes).ShouldBe(("r1", "c1", "p1"));
        BodyRedactor.ExtractRequestContext("not json"u8).ShouldBe((null, null, null));
        BodyRedactor.ExtractRequestContext("""{"request_context":[1]}"""u8).ShouldBe((null, null, null));
        BodyRedactor.ExtractRequestContext("""{"request_context":{"correlation_id":5}}"""u8).ShouldBe((null, null, null));
    }

    [Fact]
    public void TheRequestContext_IsBoundedTo256Characters()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"request_context\":{\"correlation_id\":\"" + new string('x', 1000) + "\"}}");

        BodyRedactor.ExtractRequestContext(bytes).CorrelationId!.Length.ShouldBe(256);
    }

    // ---- the structural guarantee ----

    [Fact]
    public void NoPublicShapeOfTheRecord_CanHoldRawSecretBytesOrTheRetainedSecrets()
    {
        // ExchangeRecord and everything reachable from it are what gets shown, exported and written to JSONL.
        var visited = new HashSet<Type>();
        var queue = new Queue<Type>([typeof(ExchangeRecord), typeof(ConnectionEventRecord)]);
        while (queue.Count > 0)
        {
            var type = queue.Dequeue();
            if (!visited.Add(type))
            {
                continue;
            }

            foreach (var property in type.GetProperties())
            {
                var propertyType = property.PropertyType;
                propertyType.ShouldNotBe(typeof(byte[]), $"{type.Name}.{property.Name}");
                propertyType.ShouldNotBe(typeof(ReadOnlyMemory<byte>), $"{type.Name}.{property.Name}");
                propertyType.ShouldNotBe(typeof(RetainedSecrets), $"{type.Name}.{property.Name}");
                var inner = Nullable.GetUnderlyingType(propertyType) ?? (propertyType.IsGenericType ? propertyType.GetGenericArguments()[0] : propertyType);
                if (inner.Namespace == typeof(ExchangeRecord).Namespace || inner.Namespace == typeof(EkmMock.Server.Tls.ClientCertificateSummary).Namespace)
                {
                    queue.Enqueue(inner);
                }
            }
        }

        visited.ShouldContain(typeof(CapturedBody));
        visited.ShouldContain(typeof(MaskedField));
    }
}
