using System.Buffers.Text;
using System.Numerics;
using System.Security.Cryptography;
using EkmMock.Crypto;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>Spec 4.7 and acceptance test 5.</summary>
public sealed class MetadataTests
{
    [Fact]
    public async Task AesMetadata_MatchesSection47Exactly()
    {
        using var factory = new EkmFactory();
        factory.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);

        var reply = await factory.CreateEkmClient().MetadataAsync("aes-key-1");

        reply.StatusCode.ShouldBe(200, reply.Text);
        reply.ContentType.ShouldBe("application/json");
        reply.Text.ShouldBe("""{"key_type":"oct","key_size":256,"key_ops":["wrapKey","unwrapKey"]}""");
    }

    [Theory]
    [InlineData(2048, 5)]
    [InlineData(3072, 3)]
    public async Task RsaMetadata_HasTheRightModulus_AQAB_AndNoLeadingZeroByte(int size, int keyCount)
    {
        using var factory = new EkmFactory();
        var ekm = factory.CreateEkmClient();
        var topBytes = new HashSet<byte>();

        for (var i = 0; i < keyCount; i++)
        {
            var name = $"rsa-{i}";
            var info = factory.Keys.Create("_default", name, KeyType.Rsa, size);
            var reply = await ekm.MetadataAsync(name);

            reply.StatusCode.ShouldBe(200, reply.Text);
            using var doc = reply.Json();
            doc.RootElement.EnumerateObject().Select(static p => p.Name).ShouldBe(["key_type", "key_size", "key_ops", "n", "e"]);
            doc.RootElement.GetProperty("key_type").GetString().ShouldBe("RSA");
            doc.RootElement.GetProperty("key_size").GetInt32().ShouldBe(size);
            doc.RootElement.GetProperty("key_ops").EnumerateArray().Select(static e => e.GetString()).ShouldBe(["wrapKey", "unwrapKey"]);
            doc.RootElement.GetProperty("e").GetString().ShouldBe("AQAB");

            var nText = doc.RootElement.GetProperty("n").GetString()!;
            nText.ShouldNotContain("=");
            nText.ShouldNotContain("+");
            nText.ShouldNotContain("/");
            var n = Base64Url.DecodeFromChars(nText);
            n.Length.ShouldBe(size / 8);
            n[0].ShouldNotBe((byte)0, "minimal big-endian: no leading zero byte");
            (n[0] & 0x80).ShouldBe(0x80, "the modulus of a full-size key has its top bit set");
            topBytes.Add(n[0]);

            // The modulus the proxy reports is the one the engine holds.
            Fx.Same(n, info.PublicKey!.Modulus.Span).ShouldBeTrue();

            // Independent proof: a second RSA instance built only from the HTTP answer encrypts, the engine decrypts over HTTP.
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = Base64Url.DecodeFromChars(doc.RootElement.GetProperty("e").GetString()!) });
            var dek = Fx.Random(32);
            var ciphertext = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
            Fx.Same((await ekm.UnwrapAsync(name, "RSA-OAEP-256", ciphertext)).Value(), dek).ShouldBeTrue();
        }

        topBytes.Count.ShouldBeGreaterThan(1, "several different top bytes were exercised");
    }

    [Fact]
    public async Task Rsa4096Metadata_IsCorrect()
    {
        using var factory = new EkmFactory();
        factory.Keys.Create("_default", "rsa-4096", KeyType.Rsa, 4096);

        var reply = await factory.CreateEkmClient().MetadataAsync("rsa-4096");

        using var doc = reply.Json();
        doc.RootElement.GetProperty("key_size").GetInt32().ShouldBe(4096);
        Base64Url.DecodeFromChars(doc.RootElement.GetProperty("n").GetString()!).Length.ShouldBe(512);
        doc.RootElement.GetProperty("e").GetString().ShouldBe("AQAB");
    }

    [Fact]
    public async Task Metadata_NeverContainsAnythingButThePublicNumbers()
    {
        using var factory = new EkmFactory();
        factory.Keys.Create("_default", "rsa", KeyType.Rsa, 2048);
        factory.Keys.Create("_default", "aes", KeyType.Oct, 256);

        foreach (var key in new[] { "rsa", "aes" })
        {
            using var doc = (await factory.CreateEkmClient().MetadataAsync(key)).Json();
            doc.RootElement.EnumerateObject().Select(static p => p.Name)
                .ShouldBeSubsetOf(["key_type", "key_size", "key_ops", "n", "e"]);
            doc.RootElement.TryGetProperty("k", out _).ShouldBeFalse();
            doc.RootElement.TryGetProperty("d", out _).ShouldBeFalse();
        }
    }

    // ---- the encoding of n and e, independent of key generation ---------------------------------------------------------------

    public static TheoryData<string, string, string> EncodingCases => new()
    {
        // modulus bytes (hex), exponent bytes (hex), expected e (base64url)
        { "80" + new string('0', 30), "010001", "AQAB" },
        { "FF" + new string('F', 30), "010001", "AQAB" },
        { "00" + "80" + new string('1', 30), "0000010001", "AQAB" }, // leading zeros are stripped
        { "C0" + new string('A', 30), "03", "Aw" },
        { "9A" + new string('5', 30), "010001", "AQAB" },
        { "0000" + "FF" + new string('7', 30), "0100000001", "AQAAAAE" },
    };

    [Theory]
    [MemberData(nameof(EncodingCases))]
    public async Task NAndE_AreMinimalBigEndianBase64Url_WhateverTheBitPatternOrLeadingZeros(string modulusHex, string exponentHex, string expectedE)
    {
        var modulus = Convert.FromHexString(modulusHex);
        var expectedN = Base64Url.EncodeToString(modulus.SkipWhile(static b => b == 0).ToArray());
        var fake = new FakeMetadataBackend(new RsaPublicKey(modulus, Convert.FromHexString(exponentHex)));
        using var factory = new EkmFactory(new EkmFactoryOptions { ConfigureServices = s => s.AddSingleton<ICryptoBackend>(fake) });

        var reply = await factory.CreateEkmClient().MetadataAsync("any");

        using var doc = reply.Json();
        doc.RootElement.GetProperty("e").GetString().ShouldBe(expectedE);
        var n = doc.RootElement.GetProperty("n").GetString()!;
        n.ShouldBe(expectedN);
        Base64Url.DecodeFromChars(n)[0].ShouldNotBe((byte)0);
        new BigInteger(Base64Url.DecodeFromChars(n), isUnsigned: true, isBigEndian: true)
            .ShouldBe(new BigInteger(modulus, isUnsigned: true, isBigEndian: true));
    }

    private sealed class FakeMetadataBackend : ICryptoBackend
    {
        private readonly RsaPublicKey _key;

        public FakeMetadataBackend(RsaPublicKey key) => _key = key;

        public BackendInfo Info => new("fake", "fake");

        public bool IsAvailable => true;

        public KeyMetadata? GetMetadata(KeyRef key) => new(key, KeyType.Rsa, _key.KeySizeBits, KeyState.Enabled, null, _key);

        public byte[] Wrap(KeyRef key, WrapAlgorithm alg, ReadOnlySpan<byte> dek) => throw new NotSupportedException();

        public byte[] Unwrap(KeyRef key, WrapAlgorithm alg, ReadOnlySpan<byte> wrapped) => throw new NotSupportedException();
    }
}

/// <summary>Acceptance tests 7 and 8 at HTTP level (the engine itself is proven in the M1 tests).</summary>
public sealed class KnownAnswerAndInteropTests
{
    private static readonly byte[] RfcKek = Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

    [Fact]
    public async Task Rfc3394Section4_6_Vector_MatchesOverHttp_WithAnImportedKek()
    {
        using var factory = new EkmFactory(new EkmFactoryOptions { AllowKeyImport = true });
        factory.Keys.Import("_default", "rfc-kek", KeyType.Oct, RfcKek);
        var ekm = factory.CreateEkmClient();
        var data = Convert.FromHexString("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        var expected = Convert.FromHexString("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");

        var wrap = await ekm.WrapAsync("rfc-kek", "A256KW", data);
        var unwrap = await ekm.UnwrapAsync("rfc-kek", "A256KW", expected);

        wrap.StatusCode.ShouldBe(200, wrap.Text);
        Convert.ToHexString(wrap.Value()).ShouldBe(Convert.ToHexString(expected));
        wrap.ValueText().ShouldBe(Base64Url.EncodeToString(expected));
        Fx.Same(unwrap.Value(), data).ShouldBeTrue();
    }

    [Fact]
    public async Task A256KWP_KnownAnswer_MatchesOverHttp_FromAnIndependentImplementation()
    {
        // RFC 5649 section 6 uses a 192-bit KEK; this AES-256-only engine cannot hold it (see DECISIONS.md, M1).
        // Vector from Python 'cryptography' aes_key_wrap_with_padding with the 256-bit KEK 00..1f.
        using var factory = new EkmFactory(new EkmFactoryOptions { AllowKeyImport = true });
        factory.Keys.Import("_default", "kek", KeyType.Oct, RfcKek);
        var ekm = factory.CreateEkmClient();
        var data = Convert.FromHexString("030a11181f262d343b424950575e656c737a8188");

        var wrap = await ekm.WrapAsync("kek", "A256KWP", data);

        Convert.ToHexString(wrap.Value()).ShouldBe("E335AAB1860EEDEDB6C7A1779553A950A2F24E7BBF403666627C932487B2E4CC");
        Fx.Same((await ekm.UnwrapAsync("kek", "A256KWP", wrap.Value())).Value(), data).ShouldBeTrue();
    }

    [Fact]
    public async Task ImportIsRefused_UnlessEnabled_SoTheVectorsCannotBeLoadedInProduction()
    {
        using var factory = new EkmFactory(new EkmFactoryOptions { AllowKeyImport = false });

        var ex = Should.Throw<EkmEngineException>(() => factory.Keys.Import("_default", "kek", KeyType.Oct, RfcKek));
        ex.Kind.ShouldBe(EkmErrorKind.OperationNotAllowed);
        (await factory.CreateEkmClient().MetadataAsync("kek")).ShouldBeProxyError(404, "KeyNotFound");
    }

    [Theory]
    [InlineData("RSA-OAEP-256", 32)]
    [InlineData("RSA-OAEP", 32)]
    [InlineData("RSA-OAEP-256", 190)]
    [InlineData("RSA-OAEP", 214)]
    public async Task Rsa_ProxyWrap_DecryptsWithAnIndependentRsaInstance_AndTheReverse(string alg, int dekSize)
    {
        // The test generates the RSA key itself, imports the PKCS#8 (import is a test-only feature) and keeps its own copy.
        using var rsa = RSA.Create(2048);
        using var factory = new EkmFactory(new EkmFactoryOptions { AllowKeyImport = true });
        factory.Keys.Import("_default", "rsa-imported", KeyType.Rsa, rsa.ExportPkcs8PrivateKey());
        var ekm = factory.CreateEkmClient();
        var padding = alg == "RSA-OAEP-256" ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.OaepSHA1;
        var dek = Fx.Random(dekSize);

        // Proxy wraps, independent instance decrypts.
        var wrapped = await ekm.WrapAsync("rsa-imported", alg, dek);
        wrapped.StatusCode.ShouldBe(200, wrapped.Text);
        Fx.Same(rsa.Decrypt(wrapped.Value(), padding), dek).ShouldBeTrue();

        // Independent instance encrypts, proxy unwraps.
        var ciphertext = rsa.Encrypt(dek, padding);
        Fx.Same((await ekm.UnwrapAsync("rsa-imported", alg, ciphertext)).Value(), dek).ShouldBeTrue();

        // The published n/e are the imported key's.
        using var doc = (await ekm.MetadataAsync("rsa-imported")).Json();
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        Fx.Same(Base64Url.DecodeFromChars(doc.RootElement.GetProperty("n").GetString()!), parameters.Modulus!).ShouldBeTrue();
        Fx.Same(Base64Url.DecodeFromChars(doc.RootElement.GetProperty("e").GetString()!), parameters.Exponent!).ShouldBeTrue();
    }

    [Fact]
    public async Task Rsa_OaepVariants_AreNotInterchangeable()
    {
        using var rsa = RSA.Create(2048);
        using var factory = new EkmFactory(new EkmFactoryOptions { AllowKeyImport = true });
        factory.Keys.Import("_default", "rsa-imported", KeyType.Rsa, rsa.ExportPkcs8PrivateKey());
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);

        var sha1 = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA1);
        var sha256 = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);

        (await ekm.UnwrapAsync("rsa-imported", "RSA-OAEP-256", sha1)).ShouldBeProxyError(400, "InvalidCiphertext");
        (await ekm.UnwrapAsync("rsa-imported", "RSA-OAEP", sha256)).ShouldBeProxyError(400, "InvalidCiphertext");
    }
}

/// <summary>Spec 14 test 13 through the HTTP layer.</summary>
public sealed class PersistenceOverHttpTests
{
    [Fact]
    public async Task KeysNamespacesAndWrappedDeks_SurviveARestart()
    {
        using var data = new TempDir();
        var aesDek = Fx.Random(32);
        var rsaDek = Fx.Random(32);
        var contosoDek = Fx.Random(48);
        byte[] aesWrapped, rsaWrapped, contosoWrapped;
        string rsaMetadataBefore;

        using (var first = new EkmFactory(new EkmFactoryOptions { DataPath = data.Path }))
        {
            first.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
            first.Keys.Create("_default", "rsa-key-1", KeyType.Rsa, 2048);
            first.Namespaces.Add(new NamespaceDefinition { Name = "contoso", Prefix = "contoso/prod", ClientTrust = new ClientTrust { SubjectCommonNames = ["contoso.managedhsmclient.azure.net"] } });
            first.Keys.Create("contoso", "aes-key-1", KeyType.Oct, 256);
            var ekm = first.CreateEkmClient();

            aesWrapped = (await ekm.WrapAsync("aes-key-1", "A256KWP", aesDek)).Value();
            rsaWrapped = (await ekm.WrapAsync("rsa-key-1", "RSA-OAEP-256", rsaDek)).Value();
            contosoWrapped = (await ekm.WrapAsync("aes-key-1", "A256KW", contosoDek, "contoso/prod")).Value();
            rsaMetadataBefore = (await ekm.MetadataAsync("rsa-key-1")).Text;
            first.Keys.SetEnabled(new KeyRef("_default", "rsa-key-1"), enabled: true);
        }

        using var second = new EkmFactory(new EkmFactoryOptions { DataPath = data.Path });
        var after = second.CreateEkmClient();

        Fx.Same((await after.UnwrapAsync("aes-key-1", "A256KWP", aesWrapped)).Value(), aesDek).ShouldBeTrue();
        Fx.Same((await after.UnwrapAsync("rsa-key-1", "RSA-OAEP-256", rsaWrapped)).Value(), rsaDek).ShouldBeTrue();
        Fx.Same((await after.UnwrapAsync("aes-key-1", "A256KW", contosoWrapped, "contoso/prod")).Value(), contosoDek).ShouldBeTrue();
        (await after.MetadataAsync("rsa-key-1")).Text.ShouldBe(rsaMetadataBefore);
        second.Namespaces.Get("contoso")!.ClientTrust.SubjectCommonNames.ShouldBe(["contoso.managedhsmclient.azure.net"]);

        // A wrapped value from namespace contoso still does not unwrap in _default.
        (await after.UnwrapAsync("aes-key-1", "A256KW", contosoWrapped)).ShouldBeProxyError(400, "InvalidCiphertext");
    }

    [Fact]
    public async Task DestroyedKeys_StayDestroyed_AfterARestart()
    {
        using var data = new TempDir();
        using (var first = new EkmFactory(new EkmFactoryOptions { DataPath = data.Path }))
        {
            first.Keys.Create("_default", "doomed", KeyType.Oct, 256);
            first.Keys.Destroy(new KeyRef("_default", "doomed"), "test");
        }

        using var second = new EkmFactory(new EkmFactoryOptions { DataPath = data.Path });

        (await second.CreateEkmClient().MetadataAsync("doomed")).ShouldBeProxyError(404, "KeyNotFound");
    }

    [Fact]
    public async Task WithADifferentMasterKey_EveryKeyIs503_ButTheServerRunsAndInfoWorks()
    {
        using var data = new TempDir();
        byte[] wrapped;
        using (var first = new EkmFactory(new EkmFactoryOptions { DataPath = data.Path, MasterKeyLabel = "a" }))
        {
            first.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
            wrapped = (await first.CreateEkmClient().WrapAsync("aes-key-1", "A256KWP", Fx.Random(32))).Value();
        }

        using var second = new EkmFactory(new EkmFactoryOptions { DataPath = data.Path, MasterKeyLabel = "b" });
        var ekm = second.CreateEkmClient();

        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        (await ekm.UnwrapAsync("aes-key-1", "A256KWP", wrapped)).ShouldBeProxyError(503, "HsmUnavailable");
        (await ekm.MetadataAsync("aes-key-1")).ShouldBeProxyError(503, "HsmUnavailable");
    }
}
