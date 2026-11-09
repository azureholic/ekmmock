using System.Security.Cryptography;

namespace EkmMock.Console.Tests;

/// <summary>Looks for secret bytes in text as hex and base64/base64url at every alignment (the same idea as the M1 and M4 scanners). Test diagnostics never print the bytes.</summary>
internal static class SecretScanner
{
    public static bool LeaksInText(string text, byte[] secret)
    {
        const int probeLength = 24;
        var probes = secret.Length <= probeLength ? [secret] : new[] { secret[..probeLength], secret[^probeLength..] };
        foreach (var probe in probes)
        {
            if (text.Contains(Convert.ToHexString(probe), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            for (var alignment = 0; alignment < 3; alignment++)
            {
                if (probe.Length - alignment < 6)
                {
                    continue;
                }

                var b64 = Convert.ToBase64String(probe[alignment..]);
                b64 = b64[..^4];
                if (b64.Length < 8)
                {
                    continue;
                }

                if (text.Contains(b64, StringComparison.Ordinal) || text.Contains(b64.Replace('+', '-').Replace('/', '_'), StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }

    public static byte[] RandomDek(int length = 32) => RandomNumberGenerator.GetBytes(length);

    /// <summary>The unpadded base64url text of a DEK, as it appears in a wrap request.</summary>
    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
