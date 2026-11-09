using System.Buffers.Binary;
using System.Security.Cryptography;

namespace EkmMock.Crypto.Internal;

/// <summary>
/// AES Key Wrap primitives.
/// <list type="bullet">
/// <item>RFC 3394 (A256KW): .NET 10 has only a non-public helper, so it is implemented here on top of single-block
/// <c>Aes.EncryptEcb/DecryptEcb</c>.</item>
/// <item>RFC 5649 (A256KWP): .NET 10 ships <c>Aes.EncryptKeyWrapPadded/DecryptKeyWrapPadded</c>, which production uses.
/// An own implementation (<c>*Reference</c>) is kept as an independent cross-check for tests and the self-test.</item>
/// </list>
/// Callers pass an exclusively-owned <see cref="Aes"/> (not thread-safe). Base64url is not this layer's concern.
/// </summary>
internal static class AesKeyWrap
{
    public const int SemiBlockSize = 8;
    public const int MinKwKeyBytes = 16;
    public const int MaxKwpKeyBytes = 4096;

    // RFC 3394 section 2.2.3.1 default initial value.
    private static ReadOnlySpan<byte> DefaultIv => [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

    // RFC 5649 section 3: constant part of the alternative initial value.
    private static ReadOnlySpan<byte> AivPrefix => [0xA6, 0x59, 0x59, 0xA6];

    // ---- RFC 3394 -------------------------------------------------------------------------------------------------

    /// <summary>Wraps key data (at least 16 bytes, a multiple of 8). Output is 8 bytes longer.</summary>
    public static byte[] Wrap(Aes aes, ReadOnlySpan<byte> keyData)
    {
        if (keyData.Length < MinKwKeyBytes || keyData.Length % SemiBlockSize != 0)
        {
            throw new ArgumentException("Key data must be at least 16 bytes and a multiple of 8.", nameof(keyData));
        }

        var output = new byte[keyData.Length + SemiBlockSize];
        WrapCore(aes, DefaultIv, keyData, output);
        return output;
    }

    /// <summary>Unwraps; returns null when the integrity check fails. Length must be a multiple of 8 and at least 24.</summary>
    public static byte[]? Unwrap(Aes aes, ReadOnlySpan<byte> wrapped)
    {
        if (wrapped.Length < MinKwKeyBytes + SemiBlockSize || wrapped.Length % SemiBlockSize != 0)
        {
            return null;
        }

        var registers = new byte[wrapped.Length];
        var a = registers.AsSpan(0, SemiBlockSize);
        var r = registers.AsSpan(SemiBlockSize);
        UnwrapCore(aes, wrapped, a, r);

        var ok = CryptographicOperations.FixedTimeEquals(a, DefaultIv);
        if (!ok)
        {
            CryptographicOperations.ZeroMemory(registers);
            return null;
        }

        var keyData = r.ToArray();
        CryptographicOperations.ZeroMemory(registers);
        return keyData;
    }

    // ---- RFC 5649: production path uses the runtime API ------------------------------------------------------------

    public static byte[] WrapPadded(Aes aes, ReadOnlySpan<byte> keyData)
    {
        if (keyData.Length is < 1 or > MaxKwpKeyBytes)
        {
            throw new ArgumentException("Key data must be 1 to 4096 bytes.", nameof(keyData));
        }

        return aes.EncryptKeyWrapPadded(keyData);
    }

    /// <summary>Returns null for any malformed or tampered input.</summary>
    public static byte[]? UnwrapPadded(Aes aes, ReadOnlySpan<byte> wrapped)
    {
        if (!IsValidPaddedWrappedLength(wrapped.Length))
        {
            return null;
        }

        try
        {
            return aes.DecryptKeyWrapPadded(wrapped);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    // Wrapped length for 1..4096 byte keys: 16 .. 4104, always a multiple of 8.
    public static bool IsValidPaddedWrappedLength(int length)
        => length >= 2 * SemiBlockSize && length <= MaxKwpKeyBytes + SemiBlockSize && length % SemiBlockSize == 0;

    // ---- RFC 5649: own implementation, independent cross-check ------------------------------------------------------

    public static byte[] WrapPaddedReference(Aes aes, ReadOnlySpan<byte> keyData)
    {
        if (keyData.Length is < 1 or > MaxKwpKeyBytes)
        {
            throw new ArgumentException("Key data must be 1 to 4096 bytes.", nameof(keyData));
        }

        var m = keyData.Length;
        var n = (m + SemiBlockSize - 1) / SemiBlockSize;
        var padded = new byte[n * SemiBlockSize];
        keyData.CopyTo(padded);

        Span<byte> aiv = stackalloc byte[SemiBlockSize];
        AivPrefix.CopyTo(aiv);
        BinaryPrimitives.WriteUInt32BigEndian(aiv[4..], (uint)m);

        var output = new byte[(n + 1) * SemiBlockSize];
        if (n == 1)
        {
            Span<byte> block = stackalloc byte[2 * SemiBlockSize];
            aiv.CopyTo(block);
            padded.CopyTo(block[SemiBlockSize..]);
            aes.EncryptEcb(block, output, PaddingMode.None);
            CryptographicOperations.ZeroMemory(block);
        }
        else
        {
            WrapCore(aes, aiv, padded, output);
        }

        CryptographicOperations.ZeroMemory(padded);
        return output;
    }

    public static byte[]? UnwrapPaddedReference(Aes aes, ReadOnlySpan<byte> wrapped)
    {
        if (!IsValidPaddedWrappedLength(wrapped.Length))
        {
            return null;
        }

        var n = wrapped.Length / SemiBlockSize - 1;
        var registers = new byte[wrapped.Length];
        var a = registers.AsSpan(0, SemiBlockSize);
        var padded = registers.AsSpan(SemiBlockSize);

        if (n == 1)
        {
            aes.DecryptEcb(wrapped, registers, PaddingMode.None);
        }
        else
        {
            UnwrapCore(aes, wrapped, a, padded);
        }

        // RFC 5649 section 3 checks, evaluated without short-circuiting.
        var prefixOk = CryptographicOperations.FixedTimeEquals(a[..4], AivPrefix);
        var mli = BinaryPrimitives.ReadUInt32BigEndian(a[4..]);
        var lengthOk = mli > (uint)(SemiBlockSize * (n - 1)) && mli <= (uint)(SemiBlockSize * n);

        var paddingOk = true;
        if (lengthOk)
        {
            for (var i = (int)mli; i < padded.Length; i++)
            {
                paddingOk &= padded[i] == 0;
            }
        }

        byte[]? result = null;
        if (prefixOk & lengthOk & paddingOk)
        {
            result = padded[..(int)mli].ToArray();
        }

        CryptographicOperations.ZeroMemory(registers);
        return result;
    }

    // ---- RFC 3394 core (shared by KW and the reference KWP) ----------------------------------------------------------

    // output = A | R[1..n]; input = P[1..n]. Section 2.2.1, index based variant.
    private static void WrapCore(Aes aes, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output)
    {
        var n = input.Length / SemiBlockSize;
        var a = output[..SemiBlockSize];
        var r = output[SemiBlockSize..];
        iv.CopyTo(a);
        input.CopyTo(r);

        Span<byte> block = stackalloc byte[2 * SemiBlockSize];
        Span<byte> encrypted = stackalloc byte[2 * SemiBlockSize];
        try
        {
            for (var j = 0; j <= 5; j++)
            {
                for (var i = 1; i <= n; i++)
                {
                    var ri = r.Slice((i - 1) * SemiBlockSize, SemiBlockSize);
                    a.CopyTo(block);
                    ri.CopyTo(block[SemiBlockSize..]);
                    aes.EncryptEcb(block, encrypted, PaddingMode.None);

                    encrypted[..SemiBlockSize].CopyTo(a);
                    XorCounter(a, (ulong)n * (ulong)j + (ulong)i);
                    encrypted[SemiBlockSize..].CopyTo(ri);
                }
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(output);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
            CryptographicOperations.ZeroMemory(encrypted);
        }
    }

    // input = C[0..n] (n + 1 semi-blocks); outputs the recovered A and R[1..n]. Section 2.2.2.
    private static void UnwrapCore(Aes aes, ReadOnlySpan<byte> input, Span<byte> a, Span<byte> r)
    {
        var n = input.Length / SemiBlockSize - 1;
        input[..SemiBlockSize].CopyTo(a);
        input[SemiBlockSize..].CopyTo(r);

        Span<byte> block = stackalloc byte[2 * SemiBlockSize];
        Span<byte> decrypted = stackalloc byte[2 * SemiBlockSize];
        try
        {
            for (var j = 5; j >= 0; j--)
            {
                for (var i = n; i >= 1; i--)
                {
                    var ri = r.Slice((i - 1) * SemiBlockSize, SemiBlockSize);
                    a.CopyTo(block);
                    XorCounter(block[..SemiBlockSize], (ulong)n * (ulong)j + (ulong)i);
                    ri.CopyTo(block[SemiBlockSize..]);
                    aes.DecryptEcb(block, decrypted, PaddingMode.None);

                    decrypted[..SemiBlockSize].CopyTo(a);
                    decrypted[SemiBlockSize..].CopyTo(ri);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
            CryptographicOperations.ZeroMemory(decrypted);
        }
    }

    // A = A xor t, t as a 64-bit big-endian value.
    private static void XorCounter(Span<byte> a, ulong t)
    {
        var current = BinaryPrimitives.ReadUInt64BigEndian(a);
        BinaryPrimitives.WriteUInt64BigEndian(a, current ^ t);
    }
}
