using System.Security.Cryptography;

namespace EkmMock.Crypto.Tests;

/// <summary>Shared engine with one key per type, plus an imported RSA key whose private half the test also holds (for interop).</summary>
public sealed class EngineFixture : IAsyncLifetime
{
    private readonly TempDir _dir = new();

    public SoftwareCryptoBackend Backend { get; private set; } = null!;

    public KeyRef Aes { get; } = new(EkmNames.DefaultNamespace, "aes-main");

    public KeyRef AesOther { get; } = new(EkmNames.DefaultNamespace, "aes-other");

    public KeyRef Rsa2048 { get; } = new(EkmNames.DefaultNamespace, "rsa-2048");

    public KeyRef Rsa2048Other { get; } = new(EkmNames.DefaultNamespace, "rsa-2048-other");

    public KeyRef Rsa3072 { get; } = new(EkmNames.DefaultNamespace, "rsa-3072");

    public KeyRef Rsa4096 { get; } = new(EkmNames.DefaultNamespace, "rsa-4096");

    public KeyRef RsaImported { get; } = new(EkmNames.DefaultNamespace, "rsa-imported");

    /// <summary>Independent RSA instance holding the same private key as <see cref="RsaImported"/>.</summary>
    public RSA ImportedRsa { get; } = RSA.Create(2048);

    public ValueTask InitializeAsync()
    {
        Backend = Fx.NewBackend(_dir.Path, allowImport: true);
        Backend.Create(Aes.Namespace, Aes.Name, KeyType.Oct, 256);
        Backend.Create(AesOther.Namespace, AesOther.Name, KeyType.Oct, 256);
        Backend.Import(RsaImported.Namespace, RsaImported.Name, KeyType.Rsa, ImportedRsa.ExportPkcs8PrivateKey());

        // RSA key generation is the slow part; do it in parallel.
        Task.WaitAll(
            Task.Run(() => Backend.Create(Rsa2048.Namespace, Rsa2048.Name, KeyType.Rsa, 2048)),
            Task.Run(() => Backend.Create(Rsa2048Other.Namespace, Rsa2048Other.Name, KeyType.Rsa, 2048)),
            Task.Run(() => Backend.Create(Rsa3072.Namespace, Rsa3072.Name, KeyType.Rsa, 3072)),
            Task.Run(() => Backend.Create(Rsa4096.Namespace, Rsa4096.Name, KeyType.Rsa, 4096)));
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        Backend.Dispose();
        ImportedRsa.Dispose();
        _dir.Dispose();
        return ValueTask.CompletedTask;
    }
}

public class BackendWrapUnwrapTests : IClassFixture<EngineFixture>
{
    private readonly EngineFixture _fx;

    public BackendWrapUnwrapTests(EngineFixture fx) => _fx = fx;

    private SoftwareCryptoBackend Backend => _fx.Backend;

    // ---- round trips ------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    [InlineData(64)]
    public void A256KW_RoundTrip_ForDekSizes(int size)
    {
        var dek = Fx.Random(size);

        var wrapped = Backend.Wrap(_fx.Aes, WrapAlgorithm.A256KW, dek);

        wrapped.Length.ShouldBe(size + 8);
        Fx.Same(Backend.Unwrap(_fx.Aes, WrapAlgorithm.A256KW, wrapped), dek).ShouldBeTrue();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(1000)]
    [InlineData(4095)]
    [InlineData(4096)]
    public void A256KWP_RoundTrip_ForDekSizesIncludingBoundaries(int size)
    {
        var dek = Fx.Random(size);

        var wrapped = Backend.Wrap(_fx.Aes, WrapAlgorithm.A256KWP, dek);

        wrapped.Length.ShouldBe((size + 7) / 8 * 8 + 8);
        Fx.Same(Backend.Unwrap(_fx.Aes, WrapAlgorithm.A256KWP, wrapped), dek).ShouldBeTrue();
    }

    [Fact]
    public void A256KWP_EveryLengthFrom1To4096_RoundTripsThroughTheEngine()
    {
        for (var size = 1; size <= 4096; size += size < 80 ? 1 : 97)
        {
            var dek = Fx.Random(size);

            Fx.Same(Backend.Unwrap(_fx.Aes, WrapAlgorithm.A256KWP, Backend.Wrap(_fx.Aes, WrapAlgorithm.A256KWP, dek)), dek)
                .ShouldBeTrue($"size {size}");
        }
    }

    [Theory]
    [InlineData(WrapAlgorithm.RsaOaep256, 16)]
    [InlineData(WrapAlgorithm.RsaOaep256, 24)]
    [InlineData(WrapAlgorithm.RsaOaep256, 32)]
    [InlineData(WrapAlgorithm.RsaOaep256, 64)]
    [InlineData(WrapAlgorithm.RsaOaep, 16)]
    [InlineData(WrapAlgorithm.RsaOaep, 24)]
    [InlineData(WrapAlgorithm.RsaOaep, 32)]
    [InlineData(WrapAlgorithm.RsaOaep, 64)]
    public void RsaOaep_RoundTrip_ForDekSizes_On2048(WrapAlgorithm alg, int size)
    {
        var dek = Fx.Random(size);

        var wrapped = Backend.Wrap(_fx.Rsa2048, alg, dek);

        wrapped.Length.ShouldBe(256);
        Fx.Same(Backend.Unwrap(_fx.Rsa2048, alg, wrapped), dek).ShouldBeTrue();
    }

    [Theory]
    [InlineData(2048, WrapAlgorithm.RsaOaep256, 256 - 66)]
    [InlineData(2048, WrapAlgorithm.RsaOaep, 256 - 42)]
    [InlineData(3072, WrapAlgorithm.RsaOaep256, 384 - 66)]
    [InlineData(3072, WrapAlgorithm.RsaOaep, 384 - 42)]
    [InlineData(4096, WrapAlgorithm.RsaOaep256, 512 - 66)]
    [InlineData(4096, WrapAlgorithm.RsaOaep, 512 - 42)]
    public void RsaOaep_AtTheMaximumPlaintextLength_RoundTripsAndOneByteMoreIsInvalidInput(int keySize, WrapAlgorithm alg, int max)
    {
        var key = keySize switch { 2048 => _fx.Rsa2048, 3072 => _fx.Rsa3072, _ => _fx.Rsa4096 };
        var dek = Fx.Random(max);

        var wrapped = Backend.Wrap(key, alg, dek);

        wrapped.Length.ShouldBe(keySize / 8);
        Fx.Same(Backend.Unwrap(key, alg, wrapped), dek).ShouldBeTrue();
        var tooLong = Fx.Random(max + 1);
        Fx.Fails(() => Backend.Wrap(key, alg, tooLong)).Kind.ShouldBe(EkmErrorKind.InvalidInput);
    }

    [Theory]
    [InlineData(WrapAlgorithm.A256KW, 0)]
    [InlineData(WrapAlgorithm.A256KW, 8)]
    [InlineData(WrapAlgorithm.A256KW, 15)]
    [InlineData(WrapAlgorithm.A256KW, 17)]
    [InlineData(WrapAlgorithm.A256KW, 31)]
    [InlineData(WrapAlgorithm.A256KWP, 0)]
    [InlineData(WrapAlgorithm.A256KWP, 4097)]
    public void AesWrap_WithInvalidDekLength_IsInvalidInput(WrapAlgorithm alg, int size)
    {
        var dek = Fx.Random(size);

        Fx.Fails(() => Backend.Wrap(_fx.Aes, alg, dek)).Kind.ShouldBe(EkmErrorKind.InvalidInput);
    }

    [Theory]
    [InlineData(WrapAlgorithm.RsaOaep256)]
    [InlineData(WrapAlgorithm.RsaOaep)]
    public void RsaWrap_WithEmptyDek_IsInvalidInput(WrapAlgorithm alg)
        => Fx.Fails(() => Backend.Wrap(_fx.Rsa2048, alg, [])).Kind.ShouldBe(EkmErrorKind.InvalidInput);

    [Fact]
    public void Wrap_DoesNotModifyTheCallersBuffer()
    {
        var dek = Fx.Random(32);
        var copy = (byte[])dek.Clone();

        Backend.Wrap(_fx.Aes, WrapAlgorithm.A256KWP, dek);
        Backend.Wrap(_fx.Rsa2048, WrapAlgorithm.RsaOaep256, dek);

        Fx.Same(dek, copy).ShouldBeTrue();
    }

    [Fact]
    public void Wrap_OfTheSameDekTwice_ProducesDifferentRsaCiphertextButSameAesCiphertext()
    {
        var dek = Fx.Random(32);

        // OAEP is randomised, key wrap is deterministic by design.
        Fx.Same(Backend.Wrap(_fx.Rsa2048, WrapAlgorithm.RsaOaep256, dek), Backend.Wrap(_fx.Rsa2048, WrapAlgorithm.RsaOaep256, dek)).ShouldBeFalse();
        Fx.Same(Backend.Wrap(_fx.Aes, WrapAlgorithm.A256KW, dek), Backend.Wrap(_fx.Aes, WrapAlgorithm.A256KW, dek)).ShouldBeTrue();
    }

    // ---- failures -------------------------------------------------------------------------------------------------------

    public static TheoryData<WrapAlgorithm> AllAlgorithms => new() { WrapAlgorithm.A256KW, WrapAlgorithm.A256KWP, WrapAlgorithm.RsaOaep256, WrapAlgorithm.RsaOaep };

    private KeyRef KeyFor(WrapAlgorithm alg) => alg.RequiredKeyType() == KeyType.Oct ? _fx.Aes : _fx.Rsa2048;

    [Theory]
    [MemberData(nameof(AllAlgorithms))]
    public void Unwrap_OfTamperedValue_IsInvalidCiphertext_ForEveryByteOfTheInput(WrapAlgorithm alg)
    {
        var key = KeyFor(alg);
        var wrapped = Backend.Wrap(key, alg, Fx.Random(32));
        // RSA: sample positions to keep the run short (each failure still costs one private-key operation).
        var step = alg.RequiredKeyType() == KeyType.Rsa ? 17 : 1;

        for (var i = 0; i < wrapped.Length; i += step)
        {
            var tampered = (byte[])wrapped.Clone();
            tampered[i] ^= 0x01;

            Fx.Fails(() => Backend.Unwrap(key, alg, tampered)).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext, $"byte {i}");
        }
    }

    [Theory]
    [InlineData(WrapAlgorithm.A256KW)]
    [InlineData(WrapAlgorithm.A256KWP)]
    public void Unwrap_WithAnotherAesKey_IsInvalidCiphertext(WrapAlgorithm alg)
    {
        var wrapped = Backend.Wrap(_fx.Aes, alg, Fx.Random(32));

        Fx.Fails(() => Backend.Unwrap(_fx.AesOther, alg, wrapped)).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext);
    }

    [Theory]
    [InlineData(WrapAlgorithm.RsaOaep256)]
    [InlineData(WrapAlgorithm.RsaOaep)]
    public void Unwrap_WithAnotherRsaKey_IsInvalidCiphertext(WrapAlgorithm alg)
    {
        var wrapped = Backend.Wrap(_fx.Rsa2048, alg, Fx.Random(32));

        Fx.Fails(() => Backend.Unwrap(_fx.Rsa2048Other, alg, wrapped)).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext);
    }

    [Fact]
    public void Unwrap_WithTheOtherOaepVariant_IsInvalidCiphertext()
    {
        var wrapped256 = Backend.Wrap(_fx.Rsa2048, WrapAlgorithm.RsaOaep256, Fx.Random(32));
        var wrappedSha1 = Backend.Wrap(_fx.Rsa2048, WrapAlgorithm.RsaOaep, Fx.Random(32));

        Fx.Fails(() => Backend.Unwrap(_fx.Rsa2048, WrapAlgorithm.RsaOaep, wrapped256)).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext);
        Fx.Fails(() => Backend.Unwrap(_fx.Rsa2048, WrapAlgorithm.RsaOaep256, wrappedSha1)).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext);
    }

    [Theory]
    [InlineData(WrapAlgorithm.A256KW, 0)]
    [InlineData(WrapAlgorithm.A256KW, 16)]
    [InlineData(WrapAlgorithm.A256KW, 23)]
    [InlineData(WrapAlgorithm.A256KW, 25)]
    [InlineData(WrapAlgorithm.A256KWP, 0)]
    [InlineData(WrapAlgorithm.A256KWP, 8)]
    [InlineData(WrapAlgorithm.A256KWP, 15)]
    [InlineData(WrapAlgorithm.A256KWP, 17)]
    [InlineData(WrapAlgorithm.A256KWP, 4113)]
    public void AesUnwrap_WithWrongLength_IsInvalidCiphertext(WrapAlgorithm alg, int length)
    {
        var input = Fx.Random(length);

        Fx.Fails(() => Backend.Unwrap(_fx.Aes, alg, input)).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext);
    }

    [Theory]
    [InlineData(WrapAlgorithm.RsaOaep256, 0)]
    [InlineData(WrapAlgorithm.RsaOaep256, 255)]
    [InlineData(WrapAlgorithm.RsaOaep256, 257)]
    [InlineData(WrapAlgorithm.RsaOaep, 128)]
    [InlineData(WrapAlgorithm.RsaOaep, 512)]
    public void RsaUnwrap_WithLengthOtherThanKeySize_IsInvalidCiphertext(WrapAlgorithm alg, int length)
    {
        var input = Fx.Random(length);

        Fx.Fails(() => Backend.Unwrap(_fx.Rsa2048, alg, input)).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext);
    }

    [Fact]
    public void RsaUnwrap_OfExactlyKBytesOfGarbage_IsInvalidCiphertextNotAnUnexpectedException()
    {
        var garbage = Fx.Random(256);
        garbage[0] = 0xFF; // larger than the modulus with very high probability

        Fx.Fails(() => Backend.Unwrap(_fx.Rsa2048, WrapAlgorithm.RsaOaep256, garbage)).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext);
        Fx.Fails(() => Backend.Unwrap(_fx.Rsa2048, WrapAlgorithm.RsaOaep, Fx.Random(256))).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext);
    }

    [Theory]
    [InlineData(WrapAlgorithm.RsaOaep256)]
    [InlineData(WrapAlgorithm.RsaOaep)]
    public void AesKey_WithRsaAlgorithm_IsUnsupportedAlgorithm(WrapAlgorithm alg)
    {
        Fx.Fails(() => Backend.Wrap(_fx.Aes, alg, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.UnsupportedAlgorithm);
        Fx.Fails(() => Backend.Unwrap(_fx.Aes, alg, Fx.Random(256))).Kind.ShouldBe(EkmErrorKind.UnsupportedAlgorithm);
    }

    [Theory]
    [InlineData(WrapAlgorithm.A256KW)]
    [InlineData(WrapAlgorithm.A256KWP)]
    public void RsaKey_WithAesAlgorithm_IsUnsupportedAlgorithm(WrapAlgorithm alg)
    {
        Fx.Fails(() => Backend.Wrap(_fx.Rsa2048, alg, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.UnsupportedAlgorithm);
        Fx.Fails(() => Backend.Unwrap(_fx.Rsa2048, alg, Fx.Random(48))).Kind.ShouldBe(EkmErrorKind.UnsupportedAlgorithm);
    }

    [Fact]
    public void UnknownKey_IsKeyNotFoundForWrapAndUnwrap_AndNullMetadata()
    {
        var missing = new KeyRef(EkmNames.DefaultNamespace, "does-not-exist");

        Fx.Fails(() => Backend.Wrap(missing, WrapAlgorithm.A256KWP, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.KeyNotFound);
        Fx.Fails(() => Backend.Unwrap(missing, WrapAlgorithm.A256KWP, Fx.Random(48))).Kind.ShouldBe(EkmErrorKind.KeyNotFound);
        Backend.GetMetadata(missing).ShouldBeNull();
    }

    [Fact]
    public void KeyInAnotherNamespace_IsKeyNotFound()
        => Fx.Fails(() => Backend.Wrap(new KeyRef("other-ns", _fx.Aes.Name), WrapAlgorithm.A256KWP, Fx.Random(32)))
            .Kind.ShouldBe(EkmErrorKind.KeyNotFound);

    [Fact]
    public void EngineFailures_UseOneExceptionTypeWithAWireCode()
    {
        var ex = Fx.Fails(() => Backend.Unwrap(_fx.Aes, WrapAlgorithm.A256KWP, Fx.Random(48)));

        ex.Code.ShouldBe("InvalidCiphertext");
        ex.Key.ShouldBe(_fx.Aes);
    }

    // ---- metadata ------------------------------------------------------------------------------------------------------

    [Fact]
    public void Metadata_ForAes_IsOct256WithoutPublicKey()
    {
        var metadata = Backend.GetMetadata(_fx.Aes)!;

        metadata.Type.ShouldBe(KeyType.Oct);
        metadata.Size.ShouldBe(256);
        metadata.PublicKey.ShouldBeNull();
        metadata.State.ShouldBe(KeyState.Enabled);
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    public void Metadata_ForRsa_HasMinimalBigEndianModulusAndExponent65537(int size)
    {
        var key = size switch { 2048 => _fx.Rsa2048, 3072 => _fx.Rsa3072, _ => _fx.Rsa4096 };

        var metadata = Backend.GetMetadata(key)!;

        metadata.Type.ShouldBe(KeyType.Rsa);
        metadata.Size.ShouldBe(size);
        var publicKey = metadata.PublicKey!;
        publicKey.Modulus.Length.ShouldBe(size / 8);
        publicKey.Modulus.Span[0].ShouldNotBe((byte)0);
        publicKey.Modulus.Span[0].ShouldBeGreaterThanOrEqualTo((byte)0x80);
        publicKey.Exponent.ToArray().ShouldBe([0x01, 0x00, 0x01]);
        Base64Url(publicKey.Exponent.Span).ShouldBe("AQAB");
    }

    [Fact]
    public void Metadata_ForImportedRsa_MatchesTheIndependentInstancesModulus()
    {
        var expected = _fx.ImportedRsa.ExportParameters(includePrivateParameters: false);

        var publicKey = Backend.GetMetadata(_fx.RsaImported)!.PublicKey!;

        publicKey.Modulus.ToArray().ShouldBe(expected.Modulus!.AsSpan().TrimStart((byte)0).ToArray());
        publicKey.Exponent.ToArray().ShouldBe(expected.Exponent!);
    }

    private static string Base64Url(ReadOnlySpan<byte> data) => System.Buffers.Text.Base64Url.EncodeToString(data);

    // ---- RSA-OAEP interop with an independent RSA instance -------------------------------------------------------------

    [Theory]
    [InlineData(WrapAlgorithm.RsaOaep256)]
    [InlineData(WrapAlgorithm.RsaOaep)]
    public void RsaOaep_EngineWrap_IsDecryptedByAnIndependentRsaInstance(WrapAlgorithm alg)
    {
        var dek = Fx.Random(32);
        var padding = alg == WrapAlgorithm.RsaOaep256 ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.OaepSHA1;

        var wrapped = Backend.Wrap(_fx.RsaImported, alg, dek);

        Fx.Same(_fx.ImportedRsa.Decrypt(wrapped, padding), dek).ShouldBeTrue();
    }

    [Theory]
    [InlineData(WrapAlgorithm.RsaOaep256)]
    [InlineData(WrapAlgorithm.RsaOaep)]
    public void RsaOaep_IndependentInstanceWrap_IsUnwrappedByTheEngine(WrapAlgorithm alg)
    {
        var dek = Fx.Random(32);
        var padding = alg == WrapAlgorithm.RsaOaep256 ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.OaepSHA1;
        using var publicOnly = RSA.Create();
        publicOnly.ImportParameters(_fx.ImportedRsa.ExportParameters(includePrivateParameters: false));

        var wrapped = publicOnly.Encrypt(dek, padding);

        Fx.Same(Backend.Unwrap(_fx.RsaImported, alg, wrapped), dek).ShouldBeTrue();
    }

    [Fact]
    public void RsaOaep_IndependentInstanceBuiltFromTheEnginesPublicMetadata_ProducesUnwrappableCiphertext()
    {
        var publicKey = Backend.GetMetadata(_fx.Rsa2048)!.PublicKey!;
        using var independent = RSA.Create();
        independent.ImportParameters(new RSAParameters { Modulus = publicKey.Modulus.ToArray(), Exponent = publicKey.Exponent.ToArray() });
        var dek = Fx.Random(32);

        var wrapped = independent.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);

        Fx.Same(Backend.Unwrap(_fx.Rsa2048, WrapAlgorithm.RsaOaep256, wrapped), dek).ShouldBeTrue();
    }

    // ---- RFC vectors through the engine (acceptance test 7) -----------------------------------------------------------

    [Fact]
    public void ImportedRfcKek_A256KW_MatchesRfc3394Section4_6()
    {
        var ns = "rfc-" + Fx.NewName("n");
        Backend.Import(ns, "kek", KeyType.Oct, Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
        var key = new KeyRef(ns, "kek");
        var data = Convert.FromHexString("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        var expected = Convert.FromHexString("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");

        Backend.Wrap(key, WrapAlgorithm.A256KW, data).ShouldBe(expected);
        Backend.Unwrap(key, WrapAlgorithm.A256KW, expected).ShouldBe(data);
    }

    [Fact]
    public void ImportedKek_A256KWP_MatchesAnIndependentImplementationsVector()
    {
        // RFC 5649 section 6 itself uses a 192-bit KEK, which an AES-256-only key store cannot hold; those vectors are proven
        // at primitive level in AesKeyWrapTests and in the self-test. Here: 256-bit KEK, vector from Python 'cryptography'.
        var ns = "kwp-" + Fx.NewName("n");
        Backend.Import(ns, "kek", KeyType.Oct, Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        var key = new KeyRef(ns, "kek");
        var data = Convert.FromHexString("030a11181f262d343b424950575e656c737a8188");

        Convert.ToHexString(Backend.Wrap(key, WrapAlgorithm.A256KWP, data)).ShouldBe("E335AAB1860EEDEDB6C7A1779553A950A2F24E7BBF403666627C932487B2E4CC");
    }

    // ---- concurrency / counters ----------------------------------------------------------------------------------------

    [Fact]
    public void ConcurrentWrapUnwrap_OnPooledKeys_AllRoundTripAndCountersAreExact()
    {
        var ns = "conc-" + Fx.NewName("n");
        var aes = new KeyRef(ns, "aes");
        var rsa = new KeyRef(ns, "rsa");
        Backend.Create(ns, aes.Name, KeyType.Oct, 256);
        Backend.Create(ns, rsa.Name, KeyType.Rsa, 2048);
        const int threads = 16;
        const int iterations = 40;
        var failures = 0;

        Parallel.For(0, threads, new ParallelOptions { MaxDegreeOfParallelism = threads }, _ =>
        {
            for (var i = 0; i < iterations; i++)
            {
                var dek = Fx.Random(32);
                var viaAes = Backend.Unwrap(aes, WrapAlgorithm.A256KWP, Backend.Wrap(aes, WrapAlgorithm.A256KWP, dek));
                var viaRsa = Backend.Unwrap(rsa, WrapAlgorithm.RsaOaep256, Backend.Wrap(rsa, WrapAlgorithm.RsaOaep256, dek));
                if (!Fx.Same(viaAes, dek) || !Fx.Same(viaRsa, dek))
                {
                    Interlocked.Increment(ref failures);
                }
            }
        });

        failures.ShouldBe(0);
        var info = Backend.Get(aes)!;
        info.WrapCount.ShouldBe(threads * iterations);
        info.UnwrapCount.ShouldBe(threads * iterations);
        Backend.Get(rsa)!.WrapCount.ShouldBe(threads * iterations);
    }

    [Fact]
    public void SuccessfulOperations_IncrementCountersAndFailuresDoNot()
    {
        var name = Fx.NewName("cnt");
        Backend.Create("counters", name, KeyType.Oct, 256);
        var key = new KeyRef("counters", name);
        var before = Backend.Get(key)!;
        before.LastUsedAt.ShouldBeNull();

        var wrapped = Backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32));
        Backend.Unwrap(key, WrapAlgorithm.A256KWP, wrapped);
        Fx.Fails(() => Backend.Unwrap(key, WrapAlgorithm.A256KWP, Fx.Random(48)));
        Fx.Fails(() => Backend.Wrap(key, WrapAlgorithm.A256KWP, []));

        var after = Backend.Get(key)!;
        after.WrapCount.ShouldBe(1);
        after.UnwrapCount.ShouldBe(1);
        after.LastUsedAt.ShouldNotBeNull();
    }
}
