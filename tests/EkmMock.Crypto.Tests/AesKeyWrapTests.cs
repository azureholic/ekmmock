using System.Security.Cryptography;
using EkmMock.Crypto.Internal;

namespace EkmMock.Crypto.Tests;

/// <summary>RFC 3394 / RFC 5649 known answers plus cross-checks of the runtime KWP API against the own reference implementation.</summary>
public class AesKeyWrapTests
{
    private static Aes AesWith(string kekHex)
    {
        var aes = Aes.Create();
        aes.Key = Convert.FromHexString(kekHex);
        return aes;
    }

    // RFC 3394 section 4: every published example.
    public static TheoryData<string, string, string, string> Rfc3394Vectors => new()
    {
        { "4.1 128-bit KEK, 128-bit data", "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5" },
        { "4.2 192-bit KEK, 128-bit data", "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D" },
        { "4.3 256-bit KEK, 128-bit data", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7" },
        { "4.4 192-bit KEK, 192-bit data", "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607", "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2" },
        { "4.5 256-bit KEK, 192-bit data", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607", "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1" },
        { "4.6 256-bit KEK, 256-bit data", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21" },
    };

    [Theory]
    [MemberData(nameof(Rfc3394Vectors))]
    public void Rfc3394_Wrap_MatchesPublishedVector(string name, string kek, string data, string expected)
    {
        using var aes = AesWith(kek);

        Convert.ToHexString(AesKeyWrap.Wrap(aes, Convert.FromHexString(data))).ShouldBe(expected, name);
    }

    [Theory]
    [MemberData(nameof(Rfc3394Vectors))]
    public void Rfc3394_Unwrap_MatchesPublishedVector(string name, string kek, string data, string expected)
    {
        using var aes = AesWith(kek);

        var result = AesKeyWrap.Unwrap(aes, Convert.FromHexString(expected));

        result.ShouldNotBeNull(name);
        Convert.ToHexString(result).ShouldBe(data, name);
    }

    private const string Rfc5649Kek = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";

    public static TheoryData<string, string, string> Rfc5649Vectors => new()
    {
        { "6 example 1: 20 octets, 192-bit KEK", "c37b7e6492584340bed12207808941155068f738", "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a" },
        { "6 example 2: 7 octets, 192-bit KEK", "466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f" },
    };

    [Theory]
    [MemberData(nameof(Rfc5649Vectors))]
    public void Rfc5649_RuntimeApi_WrapAndUnwrap_MatchPublishedVector(string name, string key, string expected)
    {
        using var aes = AesWith(Rfc5649Kek);

        Convert.ToHexString(AesKeyWrap.WrapPadded(aes, Convert.FromHexString(key))).ShouldBe(expected.ToUpperInvariant(), name);
        Convert.ToHexString(AesKeyWrap.UnwrapPadded(aes, Convert.FromHexString(expected))!).ShouldBe(key.ToUpperInvariant(), name);
    }

    [Theory]
    [MemberData(nameof(Rfc5649Vectors))]
    public void Rfc5649_OwnReferenceImplementation_WrapAndUnwrap_MatchPublishedVector(string name, string key, string expected)
    {
        using var aes = AesWith(Rfc5649Kek);

        Convert.ToHexString(AesKeyWrap.WrapPaddedReference(aes, Convert.FromHexString(key))).ShouldBe(expected.ToUpperInvariant(), name);
        Convert.ToHexString(AesKeyWrap.UnwrapPaddedReference(aes, Convert.FromHexString(expected))!).ShouldBe(key.ToUpperInvariant(), name);
    }

    // Independent third implementation (Python 'cryptography' aes_key_wrap_with_padding), 256-bit KEK 00..1f, key bytes (i*7+3)&0xFF.
    public static TheoryData<int, string> Kwp256Vectors => new()
    {
        { 1, "bfae7145269d379207e60adeb7a09662" },
        { 7, "a7d96382b36a1207f9f1ab88e4a59456" },
        { 8, "76be56734ca64548fcd657169c37227c" },
        { 9, "0d7bf73b302d16799ad7ed349e076a0bb08e879654003490" },
        { 16, "e5d927322e546a242d20df0d2f14ddd7f2bf1cb6345d9e13" },
        { 20, "e335aab1860eededb6c7a1779553a950a2f24e7bbf403666627c932487b2e4cc" },
        { 32, "978db231bbcd8a4e569ea466f592bffa93588a75f63b4bdf83dd73ccee1647a0f057d455b01a5956" },
        { 33, "795c15f07c0fb69766bc9ef5d6d75c226475162c684b57113324fe46a5cfe269d55b59142c6f9c3d1dc2b9fc4a9c546e" },
    };

    [Theory]
    [MemberData(nameof(Kwp256Vectors))]
    public void Kwp_With256BitKek_MatchesIndependentImplementation(int length, string expectedHex)
    {
        using var aes = AesWith("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var key = Enumerable.Range(0, length).Select(i => (byte)((i * 7 + 3) & 0xFF)).ToArray();
        var expected = Convert.FromHexString(expectedHex);

        AesKeyWrap.WrapPadded(aes, key).ShouldBe(expected);
        AesKeyWrap.WrapPaddedReference(aes, key).ShouldBe(expected);
        AesKeyWrap.UnwrapPadded(aes, expected).ShouldBe(key);
        AesKeyWrap.UnwrapPaddedReference(aes, expected).ShouldBe(key);
    }

    [Fact]
    public void Kwp_RuntimeApiAndReference_AgreeForEveryLengthFrom1To4096()
    {
        using var aes = Aes.Create();
        aes.Key = Fx.Random(32);

        for (var length = 1; length <= AesKeyWrap.MaxKwpKeyBytes; length++)
        {
            var key = Fx.Random(length);
            var viaRuntime = AesKeyWrap.WrapPadded(aes, key);
            var viaReference = AesKeyWrap.WrapPaddedReference(aes, key);

            Fx.Same(viaRuntime, viaReference).ShouldBeTrue($"wrap differs at length {length}");
            Fx.Same(AesKeyWrap.UnwrapPaddedReference(aes, viaRuntime)!, key).ShouldBeTrue($"reference unwrap differs at length {length}");
            Fx.Same(AesKeyWrap.UnwrapPadded(aes, viaReference)!, key).ShouldBeTrue($"runtime unwrap differs at length {length}");
        }
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(4096)]
    public void Kw_RoundTrip_ReturnsOriginalAndAddsEightBytes(int length)
    {
        using var aes = Aes.Create();
        aes.Key = Fx.Random(32);
        var key = Fx.Random(length);

        var wrapped = AesKeyWrap.Wrap(aes, key);

        wrapped.Length.ShouldBe(length + 8);
        Fx.Same(AesKeyWrap.Unwrap(aes, wrapped)!, key).ShouldBeTrue();
    }

    [Fact]
    public void Kw_Unwrap_EverySingleBitFlipIsRejected()
    {
        using var aes = Aes.Create();
        aes.Key = Fx.Random(32);
        var wrapped = AesKeyWrap.Wrap(aes, Fx.Random(32));

        for (var bit = 0; bit < wrapped.Length * 8; bit++)
        {
            var tampered = (byte[])wrapped.Clone();
            tampered[bit / 8] ^= (byte)(1 << (bit % 8));

            AesKeyWrap.Unwrap(aes, tampered).ShouldBeNull($"bit {bit} flip was accepted");
        }
    }

    [Fact]
    public void Kwp_Unwrap_EverySingleBitFlipIsRejectedByBothImplementations()
    {
        using var aes = Aes.Create();
        aes.Key = Fx.Random(32);
        foreach (var length in new[] { 1, 7, 20, 33 })
        {
            var wrapped = AesKeyWrap.WrapPadded(aes, Fx.Random(length));
            for (var bit = 0; bit < wrapped.Length * 8; bit++)
            {
                var tampered = (byte[])wrapped.Clone();
                tampered[bit / 8] ^= (byte)(1 << (bit % 8));

                AesKeyWrap.UnwrapPadded(aes, tampered).ShouldBeNull($"runtime: len {length} bit {bit}");
                AesKeyWrap.UnwrapPaddedReference(aes, tampered).ShouldBeNull($"reference: len {length} bit {bit}");
            }
        }
    }

    [Fact]
    public void Unwrap_RandomGarbageOfEveryValidLength_NeverThrowsAndNeverSucceeds()
    {
        using var aes = Aes.Create();
        aes.Key = Fx.Random(32);

        for (var length = 16; length <= AesKeyWrap.MaxKwpKeyBytes + 8; length += 8)
        {
            var garbage = Fx.Random(length);

            AesKeyWrap.UnwrapPadded(aes, garbage).ShouldBeNull($"len {length}");
            AesKeyWrap.UnwrapPaddedReference(aes, garbage).ShouldBeNull($"len {length}");
            if (length >= 24)
            {
                AesKeyWrap.Unwrap(aes, garbage).ShouldBeNull($"len {length}");
            }
        }
    }

    [Fact]
    public void Unwrap_WithWrongKey_IsRejected()
    {
        using var right = Aes.Create();
        using var wrong = Aes.Create();
        right.Key = Fx.Random(32);
        wrong.Key = Fx.Random(32);
        var key = Fx.Random(32);

        AesKeyWrap.Unwrap(wrong, AesKeyWrap.Wrap(right, key)).ShouldBeNull();
        AesKeyWrap.UnwrapPadded(wrong, AesKeyWrap.WrapPadded(right, key)).ShouldBeNull();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(23)]
    public void Kw_Wrap_RejectsKeyDataThatIsTooShortOrNotAMultipleOfEight(int length)
    {
        using var aes = Aes.Create();
        aes.Key = Fx.Random(32);
        var key = Fx.Random(length);

        Should.Throw<ArgumentException>(() => AesKeyWrap.Wrap(aes, key));
    }

    [Fact]
    public void Runtime_ShipsOnlyTheRfc5649PaddedKeyWrapApi_SoRfc3394HasToBeImplementedHere()
    {
        // Evidence for docs/OPEN-QUESTIONS.md #8. If a future .NET adds a public RFC 3394 API this fails and the decision
        // in docs/DECISIONS.md must be revisited (spec 6.4: prefer the built-in API).
        var keyWrapMethods = typeof(Aes)
            .GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Static)
            .Select(m => m.Name)
            .Where(n => n.Contains("KeyWrap", StringComparison.Ordinal))
            .Distinct()
            .ToList();

        keyWrapMethods.ShouldNotBeEmpty();
        keyWrapMethods.ShouldAllBe(n => n.Contains("Padded", StringComparison.Ordinal));
        keyWrapMethods.ShouldContain("EncryptKeyWrapPadded");
        keyWrapMethods.ShouldContain("DecryptKeyWrapPadded");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(23)]
    [InlineData(4105)]
    [InlineData(4112)]
    public void Kwp_Unwrap_RejectsWrappedLengthsOutsideTheValidSet(int length)
    {
        using var aes = Aes.Create();
        aes.Key = Fx.Random(32);

        AesKeyWrap.UnwrapPadded(aes, Fx.Random(length)).ShouldBeNull();
        AesKeyWrap.IsValidPaddedWrappedLength(length).ShouldBeFalse();
    }
}
