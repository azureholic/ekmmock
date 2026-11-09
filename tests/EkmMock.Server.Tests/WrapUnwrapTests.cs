using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using EkmMock.Crypto;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>One server with a few long-lived keys (RSA generation is slow, so it is done once per test class).</summary>
public sealed class KeysFixture : IDisposable
{
    internal const string Aes = "aes-key";
    internal const string Rsa2048 = "rsa-2048";
    internal const string Rsa3072 = "rsa-3072";

    public KeysFixture()
    {
        Factory = new EkmFactory(new EkmFactoryOptions { AllowKeyImport = true });
        Factory.Keys.Create("_default", Aes, KeyType.Oct, 256);
        Factory.Keys.Create("_default", Rsa2048, KeyType.Rsa, 2048);
        Factory.Keys.Create("_default", Rsa3072, KeyType.Rsa, 3072);
        Ekm = Factory.CreateEkmClient();
    }

    internal EkmFactory Factory { get; }

    internal EkmClient Ekm { get; }

    public void Dispose() => Factory.Dispose();
}

/// <summary>Spec 4.8 to 4.10 and acceptance tests 6, 9, 10, 11, 12 over HTTP.</summary>
public sealed class WrapUnwrapTests : IClassFixture<KeysFixture>
{
    private readonly KeysFixture _fx;

    public WrapUnwrapTests(KeysFixture fx) => _fx = fx;

    private EkmClient Ekm => _fx.Ekm;

    private static int Pad8(int n) => (n + 7) / 8 * 8;

    // ---- test 6: round trips ---------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("A256KW", 16)]
    [InlineData("A256KW", 24)]
    [InlineData("A256KW", 32)]
    [InlineData("A256KW", 64)]
    [InlineData("A256KWP", 16)]
    [InlineData("A256KWP", 24)]
    [InlineData("A256KWP", 32)]
    [InlineData("A256KWP", 64)]
    public async Task AesRoundTrip_ForTheStandardDekSizes(string alg, int dekSize)
    {
        var dek = Fx.Random(dekSize);

        var wrapped = await Ekm.WrapAsync(KeysFixture.Aes, alg, dek);
        wrapped.StatusCode.ShouldBe(200, wrapped.Text);
        wrapped.ContentType.ShouldBe("application/json");
        wrapped.ValueText().ShouldNotContain("=");
        wrapped.Value().Length.ShouldBe(alg == "A256KW" ? dekSize + 8 : Pad8(dekSize) + 8);

        var unwrapped = await Ekm.UnwrapAsync(KeysFixture.Aes, alg, wrapped.Value());
        unwrapped.StatusCode.ShouldBe(200);
        Fx.Same(unwrapped.Value(), dek).ShouldBeTrue();
        unwrapped.ValueText().ShouldNotContain("=");
    }

    [Fact]
    public async Task A256KWP_RoundTrips_EverySizeFrom1To64_AndSamplesUpTo4096()
    {
        var sizes = Enumerable.Range(1, 64).Concat([100, 127, 128, 129, 255, 256, 257, 511, 1000, 1023, 1024, 2047, 2048, 3000, 4000, 4095, 4096]);
        foreach (var size in sizes)
        {
            var dek = Fx.Random(size);
            var wrapped = await Ekm.WrapAsync(KeysFixture.Aes, "A256KWP", dek);
            wrapped.StatusCode.ShouldBe(200, $"size {size}");
            wrapped.Value().Length.ShouldBe(Pad8(size) + 8);
            Fx.Same((await Ekm.UnwrapAsync(KeysFixture.Aes, "A256KWP", wrapped.Value())).Value(), dek).ShouldBeTrue($"size {size}");
        }
    }

    [Fact]
    public async Task A256KW_RoundTrips_EveryMultipleOf8_FromMinimumTo1024()
    {
        for (var size = 16; size <= 1024; size += 8)
        {
            var dek = Fx.Random(size);
            var wrapped = await Ekm.WrapAsync(KeysFixture.Aes, "A256KW", dek);
            wrapped.StatusCode.ShouldBe(200, $"size {size}");
            Fx.Same((await Ekm.UnwrapAsync(KeysFixture.Aes, "A256KW", wrapped.Value())).Value(), dek).ShouldBeTrue($"size {size}");
        }
    }

    [Theory]
    [InlineData(KeysFixture.Rsa2048, "RSA-OAEP-256", 256)]
    [InlineData(KeysFixture.Rsa2048, "RSA-OAEP", 256)]
    [InlineData(KeysFixture.Rsa3072, "RSA-OAEP-256", 384)]
    [InlineData(KeysFixture.Rsa3072, "RSA-OAEP", 384)]
    public async Task RsaRoundTrip_ForTheStandardDekSizes_AndTheExactLimit(string key, string alg, int modulusBytes)
    {
        var limit = modulusBytes - (alg == "RSA-OAEP-256" ? 66 : 42);

        foreach (var size in new[] { 16, 24, 32, 64, 1, limit })
        {
            var dek = Fx.Random(size);
            var wrapped = await Ekm.WrapAsync(key, alg, dek);
            wrapped.StatusCode.ShouldBe(200, $"size {size}: {wrapped.Text}");
            wrapped.Value().Length.ShouldBe(modulusBytes);
            Fx.Same((await Ekm.UnwrapAsync(key, alg, wrapped.Value())).Value(), dek).ShouldBeTrue($"size {size}");
        }

        // One byte over the limit: a wrap input error, InvalidRequest (400).
        (await Ekm.WrapAsync(key, alg, Fx.Random(limit + 1))).ShouldBeProxyError(400, "InvalidRequest");
    }

    [Fact]
    public async Task Rsa4096_RoundTrips_AndHasTheDocumentedLimits()
    {
        using var factory = new EkmFactory();
        factory.Keys.Create("_default", "rsa-4096", KeyType.Rsa, 4096);
        var ekm = factory.CreateEkmClient();

        foreach (var (alg, limit) in new[] { ("RSA-OAEP-256", 512 - 66), ("RSA-OAEP", 512 - 42) })
        {
            var dek = Fx.Random(limit);
            var wrapped = await ekm.WrapAsync("rsa-4096", alg, dek);
            wrapped.StatusCode.ShouldBe(200, wrapped.Text);
            wrapped.Value().Length.ShouldBe(512);
            Fx.Same((await ekm.UnwrapAsync("rsa-4096", alg, wrapped.Value())).Value(), dek).ShouldBeTrue();
            (await ekm.WrapAsync("rsa-4096", alg, Fx.Random(limit + 1))).ShouldBeProxyError(400, "InvalidRequest");
        }
    }

    [Fact]
    public async Task ConcurrentRequests_NeverSeeEachOthersPooledBuffers()
    {
        // The request and response buffers come from ArrayPool and are zeroed after use. Hammer them from many tasks
        // with distinct DEKs and sizes: every unwrap must return exactly its own DEK.
        var failures = 0;
        await Parallel.ForAsync(0, 24, new ParallelOptions { MaxDegreeOfParallelism = 24 }, async (worker, _) =>
        {
            for (var i = 0; i < 40; i++)
            {
                var (key, alg, size) = (worker % 3) switch
                {
                    0 => (KeysFixture.Aes, "A256KWP", 1 + ((worker * 37 + i * 11) % 200)),
                    1 => (KeysFixture.Aes, "A256KW", 16 + (8 * ((worker + i) % 20))),
                    _ => (KeysFixture.Rsa2048, "RSA-OAEP-256", 16 + ((worker + i) % 100)),
                };
                var dek = Fx.Random(size);
                var wrapped = await Ekm.WrapAsync(key, alg, dek);
                var unwrapped = await Ekm.UnwrapAsync(key, alg, wrapped.Value());
                if (wrapped.StatusCode != 200 || unwrapped.StatusCode != 200 || !Fx.Same(unwrapped.Value(), dek))
                {
                    Interlocked.Increment(ref failures);
                }
            }
        });

        failures.ShouldBe(0);
    }

    [Fact]
    public async Task WrapIsRandomisedForRsa_AndDeterministicForAes()
    {
        var dek = Fx.Random(32);

        (await Ekm.WrapAsync(KeysFixture.Aes, "A256KWP", dek)).ValueText().ShouldBe((await Ekm.WrapAsync(KeysFixture.Aes, "A256KWP", dek)).ValueText());
        (await Ekm.WrapAsync(KeysFixture.Rsa2048, "RSA-OAEP-256", dek)).ValueText().ShouldNotBe((await Ekm.WrapAsync(KeysFixture.Rsa2048, "RSA-OAEP-256", dek)).ValueText());
    }

    // ---- test 9: algorithm and key type --------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(KeysFixture.Aes, "RSA-OAEP-256")]
    [InlineData(KeysFixture.Aes, "RSA-OAEP")]
    [InlineData(KeysFixture.Rsa2048, "A256KW")]
    [InlineData(KeysFixture.Rsa2048, "A256KWP")]
    [InlineData(KeysFixture.Rsa3072, "A256KWP")]
    public async Task AlgorithmKeyTypeMismatch_Returns400UnsupportedAlgorithm(string key, string alg)
    {
        (await Ekm.WrapAsync(key, alg, Fx.Random(32))).ShouldBeProxyError(400, "UnsupportedAlgorithm");
        (await Ekm.UnwrapAsync(key, alg, Fx.Random(40))).ShouldBeProxyError(400, "UnsupportedAlgorithm");
    }

    [Theory]
    [InlineData("A128KW")]
    [InlineData("A192KW")]
    [InlineData("A256GCM")]
    [InlineData("RSA1_5")]
    [InlineData("RSA-OAEP-384")]
    [InlineData("RSA-OAEP-512")]
    [InlineData("a256kw")]
    [InlineData("a256kwp")]
    [InlineData("rsa-oaep-256")]
    [InlineData("RSA_OAEP")]
    [InlineData("")]
    [InlineData(" A256KW")]
    [InlineData("A256KW ")]
    [InlineData("none")]
    public async Task UnknownAlgorithm_Returns400UnsupportedAlgorithm(string alg)
    {
        foreach (var key in new[] { KeysFixture.Aes, KeysFixture.Rsa2048 })
        {
            (await Ekm.WrapRawAsync(key, alg, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).ShouldBeProxyError(400, "UnsupportedAlgorithm");
            (await Ekm.UnwrapRawAsync(key, alg, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).ShouldBeProxyError(400, "UnsupportedAlgorithm");
        }
    }

    [Theory]
    [InlineData("""{"request_context":{}}""")]
    [InlineData("""{"request_context":{},"value":"AAAA"}""")]
    [InlineData("""{"request_context":{},"alg":null,"value":"AAAA"}""")]
    [InlineData("""{"request_context":{},"alg":7,"value":"AAAA"}""")]
    [InlineData("""{"request_context":{},"alg":["A256KW"],"value":"AAAA"}""")]
    [InlineData("""{"request_context":{},"alg":"A256KWP"}""")]
    [InlineData("""{"request_context":{},"alg":"A256KWP","value":null}""")]
    [InlineData("""{"request_context":{},"alg":"A256KWP","value":12}""")]
    [InlineData("""{"request_context":{},"alg":"A256KWP","value":["AAAA"]}""")]
    [InlineData("""{"request_context":{},"alg":"A256KWP","value":{"a":"b"}}""")]
    [InlineData("""{"request_context":{},"alg":"A256KWP","value":true}""")]
    public async Task MissingOrMistypedAlgOrValue_Returns400InvalidRequest(string body)
    {
        foreach (var op in new[] { "wrapkey", "unwrapkey" })
        {
            (await Ekm.PostAsync(EkmClient.Path(null, KeysFixture.Aes, op), body)).ShouldBeProxyError(400, "InvalidRequest");
        }
    }

    // ---- wrap input rules (4.10) ------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("A256KW", 0)]
    [InlineData("A256KW", 8)]
    [InlineData("A256KW", 15)]
    [InlineData("A256KW", 17)]
    [InlineData("A256KW", 33)]
    [InlineData("A256KWP", 0)]
    [InlineData("A256KWP", 4097)]
    [InlineData("A256KWP", 5000)]
    public async Task WrapInputRules_AreEnforced_AsInvalidRequest(string alg, int size)
    {
        (await Ekm.WrapAsync(KeysFixture.Aes, alg, Fx.Random(size))).ShouldBeProxyError(400, "InvalidRequest");
    }

    [Fact]
    public async Task WrapOfAnEmptyValue_ForRsa_IsInvalidRequest()
    {
        (await Ekm.WrapAsync(KeysFixture.Rsa2048, "RSA-OAEP-256", [])).ShouldBeProxyError(400, "InvalidRequest");
    }

    // ---- unwrap length rules (4.10) ----------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("A256KW", 0)]
    [InlineData("A256KW", 8)]
    [InlineData("A256KW", 16)]
    [InlineData("A256KW", 25)]
    [InlineData("A256KWP", 0)]
    [InlineData("A256KWP", 8)]
    [InlineData("A256KWP", 15)]
    [InlineData("A256KWP", 17)]
    public async Task UnwrapLengthRules_AreInvalidCiphertext_ForAes(string alg, int size)
    {
        (await Ekm.UnwrapAsync(KeysFixture.Aes, alg, Fx.Random(size))).ShouldBeProxyError(400, "InvalidCiphertext");
    }

    [Theory]
    [InlineData(KeysFixture.Rsa2048, "RSA-OAEP-256", 0)]
    [InlineData(KeysFixture.Rsa2048, "RSA-OAEP-256", 255)]
    [InlineData(KeysFixture.Rsa2048, "RSA-OAEP-256", 257)]
    [InlineData(KeysFixture.Rsa2048, "RSA-OAEP", 128)]
    [InlineData(KeysFixture.Rsa3072, "RSA-OAEP-256", 256)]
    [InlineData(KeysFixture.Rsa3072, "RSA-OAEP", 385)]
    public async Task UnwrapLengthRules_AreInvalidCiphertext_ForRsa(string key, string alg, int size)
    {
        (await Ekm.UnwrapAsync(key, alg, Fx.Random(size))).ShouldBeProxyError(400, "InvalidCiphertext");
    }

    // ---- test 10: tampering ---------------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(KeysFixture.Aes, "A256KW", 32)]
    [InlineData(KeysFixture.Aes, "A256KWP", 32)]
    [InlineData(KeysFixture.Aes, "A256KWP", 5)]
    public async Task TamperedAesWrappedValue_Returns400InvalidCiphertext_NeverA500(string key, string alg, int dekSize)
    {
        var wrapped = (await Ekm.WrapAsync(key, alg, Fx.Random(dekSize))).Value();

        for (var index = 0; index < wrapped.Length; index++)
        {
            var tampered = wrapped.ToArray();
            tampered[index] ^= 0x01;
            (await Ekm.UnwrapAsync(key, alg, tampered)).ShouldBeProxyError(400, "InvalidCiphertext");
        }
    }

    [Theory]
    [InlineData(KeysFixture.Rsa2048, "RSA-OAEP-256")]
    [InlineData(KeysFixture.Rsa2048, "RSA-OAEP")]
    public async Task TamperedRsaWrappedValue_Returns400InvalidCiphertext_NeverA500(string key, string alg)
    {
        var wrapped = (await Ekm.WrapAsync(key, alg, Fx.Random(32))).Value();

        foreach (var index in new[] { 0, 1, 100, 200, wrapped.Length - 1 })
        {
            var tampered = wrapped.ToArray();
            tampered[index] ^= 0x80;
            (await Ekm.UnwrapAsync(key, alg, tampered)).ShouldBeProxyError(400, "InvalidCiphertext");
        }

        (await Ekm.UnwrapAsync(key, alg, Fx.Random(wrapped.Length))).ShouldBeProxyError(400, "InvalidCiphertext");
    }

    [Fact]
    public async Task WrongKey_Returns400InvalidCiphertext()
    {
        _fx.Factory.Keys.Create("_default", "other-aes", KeyType.Oct, 256);
        var wrapped = (await Ekm.WrapAsync(KeysFixture.Aes, "A256KWP", Fx.Random(32))).Value();

        (await Ekm.UnwrapAsync("other-aes", "A256KWP", wrapped)).ShouldBeProxyError(400, "InvalidCiphertext");
    }

    [Fact]
    public async Task WrongRsaAlgorithmVariant_Returns400InvalidCiphertext()
    {
        var wrapped = (await Ekm.WrapAsync(KeysFixture.Rsa2048, "RSA-OAEP-256", Fx.Random(32))).Value();

        (await Ekm.UnwrapAsync(KeysFixture.Rsa2048, "RSA-OAEP", wrapped)).ShouldBeProxyError(400, "InvalidCiphertext");
    }

    // ---- test 12: base64url -----------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task PaddedAndUnpaddedInput_AreBothAccepted_AndOutputIsAlwaysUnpadded()
    {
        for (var size = 1; size <= 40; size++)
        {
            var dek = Fx.Random(size);
            var unpadded = Base64Url.EncodeToString(dek);
            var padded = unpadded + new string('=', (4 - (unpadded.Length % 4)) % 4);

            var a = await Ekm.WrapRawAsync(KeysFixture.Aes, "A256KWP", unpadded);
            var b = await Ekm.WrapRawAsync(KeysFixture.Aes, "A256KWP", padded);
            a.StatusCode.ShouldBe(200, $"size {size}");
            b.StatusCode.ShouldBe(200, $"size {size} padded");
            b.ValueText().ShouldBe(a.ValueText());
            a.ValueText().ShouldNotContain("=");

            var wrappedPadded = a.ValueText() + new string('=', (4 - (a.ValueText().Length % 4)) % 4);
            var u = await Ekm.UnwrapRawAsync(KeysFixture.Aes, "A256KWP", wrappedPadded);
            Fx.Same(u.Value(), dek).ShouldBeTrue();
            u.ValueText().ShouldNotContain("=");
            u.ValueText().ShouldBe(unpadded);
        }
    }

    [Theory]
    [InlineData("+/+/AAAA")]
    [InlineData("AAAA+AAA")]
    [InlineData("AAAA/AAA")]
    [InlineData("AA AAAAAA")]
    [InlineData("AAAA\\nAAAA")]
    [InlineData("AAAAAAA=A")]
    [InlineData("AAAAAAAA=")]
    [InlineData("AAAAAAAA===")]
    [InlineData("A")]
    [InlineData("AAAAAAAAA")]
    [InlineData("AAAA*AAA")]
    [InlineData("=AAAAAAA")]
    public async Task InvalidBase64Url_Returns400InvalidRequest(string value)
    {
        foreach (var op in new[] { "wrapkey", "unwrapkey" })
        {
            var reply = await Ekm.PostAsync(EkmClient.Path(null, KeysFixture.Aes, op), EkmClient.WrapBody("A256KWP", value));
            reply.ShouldBeProxyError(400, "InvalidRequest");
            reply.Json().RootElement.GetProperty("message").GetString().ShouldBe("The value field is not valid base64url");
        }
    }

    [Fact]
    public async Task StandardBase64Characters_ArePositivelyRejected_EvenWhenTheBytesWouldDecode()
    {
        // 0xFB 0xFF 0xBF encodes to "+/+/" in standard base64 and "-_-_" in base64url.
        var dek = new byte[] { 0xFB, 0xFF, 0xBF, 0xFB, 0xFF, 0xBF, 0xFB, 0xFF };
        var standard = Convert.ToBase64String(dek);
        standard.ShouldContain("+");
        standard.ShouldContain("/");

        (await Ekm.WrapRawAsync(KeysFixture.Aes, "A256KWP", standard)).ShouldBeProxyError(400, "InvalidRequest");
        (await Ekm.WrapRawAsync(KeysFixture.Aes, "A256KWP", Base64Url.EncodeToString(dek))).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task JsonEscapesInsideTheValue_AreDecodedLikeAnyOtherJsonString()
    {
        // Legal JSON, so it must work: \u002d is '-' and \u005f is '_'.
        var dek = new byte[] { 0xFB, 0xEF, 0xBE, 0xFB, 0xEF, 0xBE, 0xFB, 0xEF }; // base64url "-----------" style characters
        var text = Base64Url.EncodeToString(dek);
        text.ShouldContain("-");
        var escaped = text.Replace("-", "\\u002d").Replace("_", "\\u005f");

        var wrappedPlain = await Ekm.WrapRawAsync(KeysFixture.Aes, "A256KWP", text);
        var wrappedEscaped = await Ekm.WrapRawAsync(KeysFixture.Aes, "A256KWP", escaped);

        wrappedEscaped.StatusCode.ShouldBe(200, wrappedEscaped.Text);
        wrappedEscaped.ValueText().ShouldBe(wrappedPlain.ValueText());
    }

    // ---- 4.5 ---------------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task TheLearnExampleValues_Work_Unpadded()
    {
        // From the Learn EKM Proxy API reference: a 32 byte DEK ("12345678" x4) wraps with A256KWP to 40 bytes.
        var dek = Encoding.ASCII.GetBytes("12345678123456781234567812345678");
        Base64Url.EncodeToString(dek).ShouldBe("MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg");

        var wrapped = await Ekm.WrapRawAsync(KeysFixture.Aes, "A256KWP", "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg");

        wrapped.StatusCode.ShouldBe(200);
        wrapped.Value().Length.ShouldBe(40);
        wrapped.ValueText().Length.ShouldBe(54); // 40 bytes are 54 unpadded base64url characters, like Learn's wrapped example
    }
}

/// <summary>Spec 14 tests 4 and 11 over HTTP: key state and namespace isolation.</summary>
public sealed class KeyStateTests
{
    [Fact]
    public async Task DisabledKey_WrapAndUnwrap403KeyDisabled_MetadataStill200()
    {
        using var factory = new EkmFactory();
        var ekm = factory.CreateEkmClient();
        foreach (var (name, type, size, alg) in new[] { ("aes", KeyType.Oct, 256, "A256KWP"), ("rsa", KeyType.Rsa, 2048, "RSA-OAEP-256") })
        {
            factory.Keys.Create("_default", name, type, size);
            var wrapped = (await ekm.WrapAsync(name, alg, Fx.Random(32))).Value();

            factory.Keys.SetEnabled(new KeyRef("_default", name), enabled: false);

            var wrap = await ekm.WrapAsync(name, alg, Fx.Random(32));
            wrap.ShouldBeProxyError(403, "KeyDisabled");
            wrap.Json().RootElement.GetProperty("message").GetString().ShouldBe("Operation WrapKey is not allowed on a disabled key");
            var unwrap = await ekm.UnwrapAsync(name, alg, wrapped);
            unwrap.ShouldBeProxyError(403, "KeyDisabled");
            unwrap.Json().RootElement.GetProperty("message").GetString().ShouldBe("Operation UnwrapKey is not allowed on a disabled key");
            (await ekm.MetadataAsync(name)).StatusCode.ShouldBe(200);

            factory.Keys.SetEnabled(new KeyRef("_default", name), enabled: true);
            (await ekm.UnwrapAsync(name, alg, wrapped)).StatusCode.ShouldBe(200);
        }
    }

    [Fact]
    public async Task ExpiredKey_WrapAndUnwrap403KeyExpired_MetadataStill200()
    {
        using var factory = new EkmFactory();
        var ekm = factory.CreateEkmClient();
        factory.Keys.Create("_default", "aes", KeyType.Oct, 256);
        var wrapped = (await ekm.WrapAsync("aes", "A256KWP", Fx.Random(32))).Value();

        factory.Keys.SetExpiry(new KeyRef("_default", "aes"), DateTimeOffset.UtcNow.AddMinutes(-1));

        (await ekm.WrapAsync("aes", "A256KWP", Fx.Random(32))).ShouldBeProxyError(403, "KeyExpired");
        var unwrap = await ekm.UnwrapAsync("aes", "A256KWP", wrapped);
        unwrap.ShouldBeProxyError(403, "KeyExpired");
        unwrap.Json().RootElement.GetProperty("message").GetString().ShouldBe("Operation UnwrapKey is not allowed on an expired key");
        (await ekm.MetadataAsync("aes")).StatusCode.ShouldBe(200);

        factory.Keys.SetExpiry(new KeyRef("_default", "aes"), null);
        (await ekm.UnwrapAsync("aes", "A256KWP", wrapped)).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task UnknownDestroyedAndOtherNamespaceKeys_Return404KeyNotFound()
    {
        using var factory = new EkmFactory();
        var ekm = factory.CreateEkmClient();
        factory.Namespaces.Add(new NamespaceDefinition { Name = "contoso", Prefix = "contoso" });
        factory.Keys.Create("_default", "only-default", KeyType.Oct, 256);
        factory.Keys.Create("contoso", "only-contoso", KeyType.Oct, 256);
        factory.Keys.Create("_default", "doomed", KeyType.Oct, 256);
        var wrappedBeforeDestroy = (await ekm.WrapAsync("doomed", "A256KWP", Fx.Random(32))).Value();
        factory.Keys.Destroy(new KeyRef("_default", "doomed"), "test");

        foreach (var (key, prefix) in new (string, string?)[] { ("never-existed", null), ("only-contoso", null), ("only-default", "contoso"), ("doomed", null) })
        {
            (await ekm.MetadataAsync(key, prefix)).ShouldBeProxyError(404, "KeyNotFound");
            (await ekm.WrapAsync(key, "A256KWP", Fx.Random(32), prefix)).ShouldBeProxyError(404, "KeyNotFound");
            (await ekm.UnwrapAsync(key, "A256KWP", wrappedBeforeDestroy, prefix)).ShouldBeProxyError(404, "KeyNotFound");
        }
    }

    [Fact]
    public async Task KeyCreatedAfterStartup_IsServedImmediately()
    {
        using var factory = new EkmFactory();
        var ekm = factory.CreateEkmClient();

        (await ekm.MetadataAsync("late")).ShouldBeProxyError(404, "KeyNotFound");
        factory.Keys.Create("_default", "late", KeyType.Oct, 256);
        (await ekm.MetadataAsync("late")).StatusCode.ShouldBe(200);
    }
}
