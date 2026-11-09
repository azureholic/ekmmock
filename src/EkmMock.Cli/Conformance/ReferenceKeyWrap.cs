using System.Buffers.Binary;
using System.Security.Cryptography;

namespace EkmMock.Cli.Conformance;

/// <summary>
/// An <b>independent</b> implementation of AES Key Wrap (RFC 3394) and AES Key Wrap with Padding (RFC 5649), written only for the conformance suite as a test oracle: it shares no code with the server's
/// engine, so "EkmMock's A256KW/A256KWP output equals the reference output for a KEK the client knows" is a real cross-check. It is proven against the RFC test vectors every time the suite uses it
/// (<see cref="SelfCheck"/>), including the 192-bit-KEK examples of RFC 5649 section 6, which the server cannot be given as a key (EkmMock keys are AES-256).
/// </summary>
internal static class ReferenceKeyWrap
{
    private static readonly byte[] DefaultIv = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

    /// <summary>RFC 3394 wrap. <paramref name="plaintext"/> must be a multiple of 8 bytes and at least 16.</summary>
    public static byte[] Wrap(byte[] kek, byte[] plaintext)
    {
        if (plaintext.Length < 16 || plaintext.Length % 8 != 0)
        {
            throw new ArgumentException("RFC 3394 needs at least two 64-bit blocks.", nameof(plaintext));
        }

        return WrapCore(kek, plaintext, DefaultIv);
    }

    /// <summary>RFC 3394 unwrap; returns null when the integrity check fails.</summary>
    public static byte[]? Unwrap(byte[] kek, byte[] ciphertext)
    {
        if (ciphertext.Length < 24 || ciphertext.Length % 8 != 0)
        {
            return null;
        }

        var (a, r) = UnwrapCore(kek, ciphertext);
        return CryptographicOperations.FixedTimeEquals(a, DefaultIv) ? r : null;
    }

    /// <summary>RFC 5649 wrap with padding: any length from 1 byte.</summary>
    public static byte[] WrapWithPadding(byte[] kek, byte[] plaintext)
    {
        if (plaintext.Length == 0)
        {
            throw new ArgumentException("RFC 5649 needs at least one byte.", nameof(plaintext));
        }

        var iv = new byte[8];
        iv[0] = 0xA6;
        iv[1] = 0x59;
        iv[2] = 0x59;
        iv[3] = 0xA6;
        BinaryPrimitives.WriteUInt32BigEndian(iv.AsSpan(4), (uint)plaintext.Length);
        var padded = new byte[(plaintext.Length + 7) / 8 * 8];
        plaintext.CopyTo(padded, 0);

        if (padded.Length == 8)
        {
            using var aes = Aes.Create();
            aes.Key = kek;
            var block = new byte[16];
            iv.CopyTo(block, 0);
            padded.CopyTo(block, 8);
            return aes.EncryptEcb(block, PaddingMode.None);
        }

        return WrapCore(kek, padded, iv);
    }

    /// <summary>RFC 5649 unwrap; returns null when the integrity or padding check fails.</summary>
    public static byte[]? UnwrapWithPadding(byte[] kek, byte[] ciphertext)
    {
        if (ciphertext.Length < 16 || ciphertext.Length % 8 != 0)
        {
            return null;
        }

        byte[] a;
        byte[] padded;
        if (ciphertext.Length == 16)
        {
            using var aes = Aes.Create();
            aes.Key = kek;
            var block = aes.DecryptEcb(ciphertext, PaddingMode.None);
            a = block[..8];
            padded = block[8..];
        }
        else
        {
            (a, padded) = UnwrapCore(kek, ciphertext);
        }

        if (a[0] != 0xA6 || a[1] != 0x59 || a[2] != 0x59 || a[3] != 0xA6)
        {
            return null;
        }

        var length = (int)BinaryPrimitives.ReadUInt32BigEndian(a.AsSpan(4));
        if (length <= 8 * (padded.Length / 8 - 1) || length > padded.Length)
        {
            return null;
        }

        for (var i = length; i < padded.Length; i++)
        {
            if (padded[i] != 0)
            {
                return null;
            }
        }

        return padded[..length];
    }

    private static byte[] WrapCore(byte[] kek, byte[] plaintext, byte[] iv)
    {
        var n = plaintext.Length / 8;
        var a = (byte[])iv.Clone();
        var r = new byte[n][];
        for (var i = 0; i < n; i++)
        {
            r[i] = plaintext[(i * 8)..((i + 1) * 8)];
        }

        using var aes = Aes.Create();
        aes.Key = kek;
        var block = new byte[16];
        for (var j = 0; j < 6; j++)
        {
            for (var i = 0; i < n; i++)
            {
                a.CopyTo(block, 0);
                r[i].CopyTo(block, 8);
                var b = aes.EncryptEcb(block, PaddingMode.None);
                var t = (ulong)(n * j + i + 1);
                for (var k = 0; k < 8; k++)
                {
                    a[k] = (byte)(b[k] ^ (byte)(t >> (8 * (7 - k))));
                }

                r[i] = b[8..];
            }
        }

        var output = new byte[8 * (n + 1)];
        a.CopyTo(output, 0);
        for (var i = 0; i < n; i++)
        {
            r[i].CopyTo(output, 8 * (i + 1));
        }

        return output;
    }

    private static (byte[] A, byte[] Plaintext) UnwrapCore(byte[] kek, byte[] ciphertext)
    {
        var n = ciphertext.Length / 8 - 1;
        var a = ciphertext[..8];
        var r = new byte[n][];
        for (var i = 0; i < n; i++)
        {
            r[i] = ciphertext[(8 * (i + 1))..(8 * (i + 2))];
        }

        using var aes = Aes.Create();
        aes.Key = kek;
        var block = new byte[16];
        for (var j = 5; j >= 0; j--)
        {
            for (var i = n - 1; i >= 0; i--)
            {
                var t = (ulong)(n * j + i + 1);
                for (var k = 0; k < 8; k++)
                {
                    block[k] = (byte)(a[k] ^ (byte)(t >> (8 * (7 - k))));
                }

                r[i].CopyTo(block, 8);
                var b = aes.DecryptEcb(block, PaddingMode.None);
                a = b[..8];
                r[i] = b[8..];
            }
        }

        var plaintext = new byte[8 * n];
        for (var i = 0; i < n; i++)
        {
            r[i].CopyTo(plaintext, 8 * i);
        }

        return (a, plaintext);
    }

    /// <summary>Checks this implementation against the RFC vectors (3394 section 4.1 and 4.6, 5649 section 6). Returns null when all match, otherwise what differs.</summary>
    public static string? SelfCheck()
    {
        static byte[] H(string hex) => Convert.FromHexString(hex);

        // RFC 3394 4.1 (128-bit KEK) and 4.6 (256-bit KEK).
        var kw1 = Wrap(H("000102030405060708090A0B0C0D0E0F"), H("00112233445566778899AABBCCDDEEFF"));
        if (!kw1.AsSpan().SequenceEqual(H("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")))
        {
            return "RFC 3394 section 4.1 does not match";
        }

        var kek256 = H("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        var data256 = H("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        var kw6 = Wrap(kek256, data256);
        if (!kw6.AsSpan().SequenceEqual(H("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")) || Unwrap(kek256, kw6) is not { } back || !back.AsSpan().SequenceEqual(data256))
        {
            return "RFC 3394 section 4.6 does not match";
        }

        // RFC 5649 section 6 (192-bit KEK).
        var kek192 = H("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        var twenty = H("c37b7e6492584340bed12207808941155068f738");
        var seven = H("466f7250617369");
        var kwp20 = WrapWithPadding(kek192, twenty);
        var kwp7 = WrapWithPadding(kek192, seven);
        if (!kwp20.AsSpan().SequenceEqual(H("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a")) || UnwrapWithPadding(kek192, kwp20) is not { } back20 || !back20.AsSpan().SequenceEqual(twenty))
        {
            return "RFC 5649 section 6 (20 octets) does not match";
        }

        if (!kwp7.AsSpan().SequenceEqual(H("afbeb0f07dfbf5419200f2ccb50bb24f")) || UnwrapWithPadding(kek192, kwp7) is not { } back7 || !back7.AsSpan().SequenceEqual(seven))
        {
            return "RFC 5649 section 6 (7 octets) does not match";
        }

        return null;
    }
}
