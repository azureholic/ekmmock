using System.Buffers;
using System.Buffers.Text;

namespace EkmMock.Server.Ekm;

/// <summary>
/// Strict base64url (RFC 7515 section 2, spec 4.5) over UTF-8 bytes.
/// <para>
/// <c>System.Buffers.Text.Base64Url</c> (.NET 10, measured in the M2 tests) accepts padded and unpadded input, rejects
/// <c>+</c> and <c>/</c> and non-canonical trailing bits, but it silently <em>skips whitespace</em>. The spec asks for strict
/// handling, so this codec pre-scans the input: only <c>A-Z a-z 0-9 - _</c>, optionally followed by 1 or 2 <c>=</c> that make
/// the length a multiple of four. Everything else is rejected before the runtime decoder sees it.
/// </para>
/// </summary>
internal static class Base64UrlCodec
{
    public static int MaxDecodedLength(int encodedLength) => Base64Url.GetMaxDecodedLength(encodedLength);

    public static int EncodedLength(int rawLength) => Base64Url.GetEncodedLength(rawLength);

    /// <summary>Decodes into <paramref name="destination"/> (at least <see cref="MaxDecodedLength"/> bytes). False on any invalid input.</summary>
    public static bool TryDecode(ReadOnlySpan<byte> utf8, Span<byte> destination, out int written)
    {
        written = 0;
        var core = utf8;
        var padding = 0;
        while (padding < 3 && padding < core.Length && core[^(padding + 1)] == (byte)'=')
        {
            padding++;
        }

        if (padding > 0)
        {
            if (padding > 2 || utf8.Length % 4 != 0)
            {
                return false;
            }

            core = utf8[..^padding];
        }

        foreach (var b in core)
        {
            if (!IsAlphabet(b))
            {
                return false;
            }
        }

        if (core.Length % 4 == 1)
        {
            return false;
        }

        if (destination.Length < Base64Url.GetMaxDecodedLength(core.Length))
        {
            throw new ArgumentException("Destination is too small", nameof(destination));
        }

        return Base64Url.DecodeFromUtf8(core, destination, out _, out written, isFinalBlock: true) == OperationStatus.Done;
    }

    /// <summary>Encodes without padding into <paramref name="destination"/> (at least <see cref="EncodedLength"/> bytes).</summary>
    public static int Encode(ReadOnlySpan<byte> raw, Span<byte> destination)
    {
        var status = Base64Url.EncodeToUtf8(raw, destination, out _, out var written);
        if (status != OperationStatus.Done)
        {
            throw new InvalidOperationException("Base64url encoding failed");
        }

        return written;
    }

    private static bool IsAlphabet(byte b)
        => (b >= (byte)'A' && b <= (byte)'Z')
        || (b >= (byte)'a' && b <= (byte)'z')
        || (b >= (byte)'0' && b <= (byte)'9')
        || b == (byte)'-'
        || b == (byte)'_';
}
