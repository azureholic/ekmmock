using System.Security.Cryptography;

namespace EkmMock.Crypto.Internal;

/// <summary>RSA-OAEP wrap (public key) and unwrap (private key) with SHA-256 or SHA-1, empty label.</summary>
internal static class RsaOaep
{
    public static RSAEncryptionPadding Padding(WrapAlgorithm alg) => alg switch
    {
        WrapAlgorithm.RsaOaep256 => RSAEncryptionPadding.OaepSHA256,
        WrapAlgorithm.RsaOaep => RSAEncryptionPadding.OaepSHA1,
        _ => throw new ArgumentOutOfRangeException(nameof(alg)),
    };

    /// <summary>Largest plaintext for modulus length <paramref name="keyBytes"/>: k - 2*hLen - 2 (k-66 / k-42).</summary>
    public static int MaxPlaintextBytes(int keyBytes, WrapAlgorithm alg) => alg switch
    {
        WrapAlgorithm.RsaOaep256 => keyBytes - 66,
        WrapAlgorithm.RsaOaep => keyBytes - 42,
        _ => throw new ArgumentOutOfRangeException(nameof(alg)),
    };

    public static byte[] Wrap(RSA rsa, WrapAlgorithm alg, ReadOnlySpan<byte> dek)
        => rsa.Encrypt(dek, Padding(alg));

    /// <summary>Returns null for any decryption failure (wrong key, bad padding, tampering).</summary>
    public static byte[]? Unwrap(RSA rsa, WrapAlgorithm alg, ReadOnlySpan<byte> wrapped)
    {
        try
        {
            return rsa.Decrypt(wrapped, Padding(alg));
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
