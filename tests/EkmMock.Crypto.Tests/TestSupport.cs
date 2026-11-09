using System.Security.Cryptography;
using System.Text;

namespace EkmMock.Crypto.Tests;

internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ekmmock-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup of a temp folder.
        }
    }
}

/// <summary>Deterministic clock so expiry tests never sleep.</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now;

    public ManualTimeProvider(DateTimeOffset start) => _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

internal static class Fx
{
    /// <summary>Synthetic master key for tests only.</summary>
    public static byte[] MasterKeyBytes(string label = "default") => SHA256.HashData(Encoding.UTF8.GetBytes("ekmmock-test-master:" + label));

    public static SoftwareCryptoBackend NewBackend(
        string dataPath,
        string masterLabel = "default",
        bool allowImport = false,
        TimeProvider? time = null)
        => new(new SoftwareCryptoBackendOptions
        {
            DataPath = dataPath,
            MasterKeyProvider = new ExplicitMasterKeyProvider(MasterKeyBytes(masterLabel)),
            AllowKeyImport = allowImport,
            TimeProvider = time ?? TimeProvider.System,
            CounterFlushInterval = TimeSpan.Zero,
        });

    public static string NewName(string prefix = "k") => $"{prefix}-{Guid.NewGuid():N}"[..Math.Min(30, prefix.Length + 13)];

    public static byte[] Random(int length) => RandomNumberGenerator.GetBytes(length);

    /// <summary>Secret-safe equality: no byte values end up in assertion output.</summary>
    public static bool Same(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => CryptographicOperations.FixedTimeEquals(a, b) && a.Length == b.Length;

    public static EkmEngineException Fails(Action action) => Should.Throw<EkmEngineException>(action);
}

/// <summary>Looks for key bytes in text (hex, base64, base64url, at all three base64 alignments) and in raw bytes.</summary>
internal static class SecretScanner
{
    private static IEnumerable<byte[]> Probes(byte[] secret)
    {
        const int probeLength = 24;
        if (secret.Length <= probeLength)
        {
            yield return secret;
            yield break;
        }

        yield return secret[..probeLength];
        yield return secret[^probeLength..];
        if (secret.Length >= 3 * probeLength)
        {
            var middle = (secret.Length - probeLength) / 2;
            yield return secret[middle..(middle + probeLength)];
        }
    }

    private static IEnumerable<string> TextVariants(byte[] probe)
    {
        yield return Convert.ToHexString(probe);
        yield return Convert.ToHexStringLower(probe);

        for (var alignment = 0; alignment < 3; alignment++)
        {
            var b64 = Convert.ToBase64String(probe[alignment..]);
            b64 = b64[..^4]; // drop the final (possibly padded / partial) quartet
            if (b64.Length < 8)
            {
                continue;
            }

            yield return b64;
            yield return b64.Replace('+', '-').Replace('/', '_');
        }
    }

    public static bool LeaksInText(string text, byte[] secret)
        => Probes(secret).Any(probe => TextVariants(probe).Any(variant => text.Contains(variant, StringComparison.Ordinal)));

    public static bool LeaksInBytes(ReadOnlySpan<byte> haystack, byte[] secret)
    {
        foreach (var probe in Probes(secret))
        {
            if (haystack.IndexOf(probe) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Text plus every base64 string value inside a JSON document, decoded and searched as raw bytes.</summary>
    public static bool LeaksInJsonFile(string json, byte[] secret)
    {
        if (LeaksInText(json, secret))
        {
            return true;
        }

        using var doc = System.Text.Json.JsonDocument.Parse(json);
        return Walk(doc.RootElement, secret);
    }

    private static bool Walk(System.Text.Json.JsonElement element, byte[] secret)
    {
        switch (element.ValueKind)
        {
            case System.Text.Json.JsonValueKind.String:
                var text = element.GetString()!;
                var buffer = new byte[text.Length];
                return Convert.TryFromBase64String(text, buffer, out var written) && LeaksInBytes(buffer.AsSpan(0, written), secret);
            case System.Text.Json.JsonValueKind.Object:
                return element.EnumerateObject().Any(p => Walk(p.Value, secret));
            case System.Text.Json.JsonValueKind.Array:
                return element.EnumerateArray().Any(e => Walk(e, secret));
            default:
                return false;
        }
    }
}
