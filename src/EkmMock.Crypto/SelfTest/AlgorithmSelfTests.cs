using System.Diagnostics;
using System.Security.Cryptography;
using EkmMock.Crypto.Internal;

namespace EkmMock.Crypto.SelfTest;

/// <summary>
/// Algorithm known-answer and round-trip tests (spec 6.5). Case names carry a prefix that maps a failure to
/// the algorithm that must be switched off: <c>aes-kw/</c>, <c>aes-kwp/</c>, <c>rsa-oaep-256/</c>, <c>rsa-oaep/</c>.
/// </summary>
internal static class AlgorithmSelfTests
{
    // RFC 3394 section 4.6: 256-bit KEK wrapping 256 bits of key data.
    private const string Rfc3394Kek = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    private const string Rfc3394Data = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    private const string Rfc3394Wrapped = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";

    // RFC 5649 section 6 (both examples use a 192-bit KEK).
    private const string Rfc5649Kek = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";
    private const string Rfc5649Key20 = "c37b7e6492584340bed1220780894115" + "5068f738";
    private const string Rfc5649Wrapped20 = "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a";
    private const string Rfc5649Key7 = "466f7250617369";
    private const string Rfc5649Wrapped7 = "afbeb0f07dfbf5419200f2ccb50bb24f";

    public static string? WrapAlgorithmPrefixFor(WrapAlgorithm alg) => alg switch
    {
        WrapAlgorithm.A256KW => "aes-kw/",
        WrapAlgorithm.A256KWP => "aes-kwp/",
        WrapAlgorithm.RsaOaep256 => "rsa-oaep-256/",
        WrapAlgorithm.RsaOaep => "rsa-oaep/",
        _ => null,
    };

    public static List<SelfTestCaseResult> Run(Func<string, bool>? forceFailure)
    {
        var results = new List<SelfTestCaseResult>
        {
            RunCase("aes-kw/rfc3394-4.6-256bit-kek-256bit-data", forceFailure, AesKwKnownAnswer),
            RunCase("aes-kwp/rfc5649-6-20-byte-key", forceFailure, () => AesKwpKnownAnswer(Rfc5649Key20, Rfc5649Wrapped20)),
            RunCase("aes-kwp/rfc5649-6-7-byte-key", forceFailure, () => AesKwpKnownAnswer(Rfc5649Key7, Rfc5649Wrapped7)),
        };

        // One ephemeral 2048-bit key for both OAEP variants. If generation itself fails, both fail.
        RSA? ephemeral = null;
        Exception? generationFailure = null;
        try
        {
            ephemeral = RSA.Create(2048);
        }
        catch (Exception ex)
        {
            generationFailure = ex;
        }

        using (ephemeral)
        {
            results.Add(RunCase("rsa-oaep-256/roundtrip-and-independent-crosscheck", forceFailure, () => RsaRoundTrip(ephemeral, generationFailure, WrapAlgorithm.RsaOaep256)));
            results.Add(RunCase("rsa-oaep/roundtrip-and-independent-crosscheck", forceFailure, () => RsaRoundTrip(ephemeral, generationFailure, WrapAlgorithm.RsaOaep)));
        }

        return results;
    }

    internal static SelfTestCaseResult RunCase(string name, Func<string, bool>? forceFailure, Action body)
    {
        var started = Stopwatch.GetTimestamp();
        try
        {
            if (forceFailure?.Invoke(name) == true)
            {
                throw new InvalidOperationException("Forced failure");
            }

            body();
            return new SelfTestCaseResult(name, SelfTestOutcome.Passed, Stopwatch.GetElapsedTime(started), null);
        }
        catch (Exception ex)
        {
            // Only the exception type: messages from crypto primitives are not guaranteed to be free of detail.
            return new SelfTestCaseResult(name, SelfTestOutcome.Failed, Stopwatch.GetElapsedTime(started), ex.GetType().Name);
        }
    }

    private static void AesKwKnownAnswer()
    {
        using var aes = Aes.Create();
        aes.Key = Convert.FromHexString(Rfc3394Kek);
        var data = Convert.FromHexString(Rfc3394Data);
        var expected = Convert.FromHexString(Rfc3394Wrapped);

        Require(AesKeyWrap.Wrap(aes, data).AsSpan().SequenceEqual(expected));
        var unwrapped = AesKeyWrap.Unwrap(aes, expected);
        Require(unwrapped is not null && unwrapped.AsSpan().SequenceEqual(data));
    }

    private static void AesKwpKnownAnswer(string keyHex, string wrappedHex)
    {
        using var aes = Aes.Create();
        aes.Key = Convert.FromHexString(Rfc5649Kek);
        var key = Convert.FromHexString(keyHex);
        var expected = Convert.FromHexString(wrappedHex);

        // Production path (runtime API) and the independent own implementation must both match the RFC.
        Require(AesKeyWrap.WrapPadded(aes, key).AsSpan().SequenceEqual(expected));
        Require(AesKeyWrap.WrapPaddedReference(aes, key).AsSpan().SequenceEqual(expected));
        var unwrapped = AesKeyWrap.UnwrapPadded(aes, expected);
        Require(unwrapped is not null && unwrapped.AsSpan().SequenceEqual(key));
        var unwrappedReference = AesKeyWrap.UnwrapPaddedReference(aes, expected);
        Require(unwrappedReference is not null && unwrappedReference.AsSpan().SequenceEqual(key));
    }

    private static void RsaRoundTrip(RSA? first, Exception? generationFailure, WrapAlgorithm alg)
    {
        if (first is null)
        {
            throw generationFailure ?? new InvalidOperationException("No RSA key");
        }

        // Independent second instance, built from exported parameters.
        var parameters = first.ExportParameters(includePrivateParameters: true);
        try
        {
            using var second = RSA.Create();
            second.ImportParameters(parameters);

            var dek = RandomNumberGenerator.GetBytes(32);
            try
            {
                Require(RoundTrips(first, first, alg, dek));
                Require(RoundTrips(first, second, alg, dek));
                Require(RoundTrips(second, first, alg, dek));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dek);
            }
        }
        finally
        {
            ZeroParameters(parameters);
        }
    }

    private static bool RoundTrips(RSA encryptor, RSA decryptor, WrapAlgorithm alg, byte[] dek)
    {
        var wrapped = RsaOaep.Wrap(encryptor, alg, dek);
        var unwrapped = RsaOaep.Unwrap(decryptor, alg, wrapped);
        try
        {
            return unwrapped is not null && CryptographicOperations.FixedTimeEquals(unwrapped, dek);
        }
        finally
        {
            if (unwrapped is not null)
            {
                CryptographicOperations.ZeroMemory(unwrapped);
            }
        }
    }

    private static void ZeroParameters(RSAParameters p)
    {
        foreach (var part in new[] { p.D, p.P, p.Q, p.DP, p.DQ, p.InverseQ })
        {
            if (part is not null)
            {
                CryptographicOperations.ZeroMemory(part);
            }
        }
    }

    private static void Require(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Self-test verification failed");
        }
    }
}
