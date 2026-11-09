using System.Security.Cryptography;

namespace EkmMock.Crypto.Internal;

/// <summary>Crash-safe file replacement: write a temp file in the same directory, flush it to disk, then rename over the target.</summary>
internal static class AtomicFile
{
    public static void Write(string path, ReadOnlySpan<byte> content)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);

        var temp = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
            };
            if (!OperatingSystem.IsWindows())
            {
                // Key store and namespaces are owner-only on Unix.
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using (var stream = new FileStream(temp, options))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }

    /// <summary>Removes temp files left behind by a crash between write and rename.</summary>
    public static void DeleteStaleTempFiles(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        if (!Directory.Exists(directory))
        {
            return;
        }

        foreach (var stale in Directory.EnumerateFiles(directory, Path.GetFileName(path) + ".*.tmp"))
        {
            try
            {
                File.Delete(stale);
            }
            catch (IOException)
            {
                // Best effort only.
            }
        }
    }
}

/// <summary>AES-256-GCM protection of key material under the master key (spec 6.2).</summary>
internal static class KeyBlobCipher
{
    public const int NonceSize = 12;
    public const int TagSize = 16;

    public static string TypeName(KeyType type) => type switch
    {
        KeyType.Oct => "oct",
        KeyType.Rsa => "rsa",
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    public static bool TryParseType(string? text, out KeyType type)
    {
        switch (text)
        {
            case "oct":
                type = KeyType.Oct;
                return true;
            case "rsa":
                type = KeyType.Rsa;
                return true;
            default:
                type = default;
                return false;
        }
    }

    /// <summary>AAD = "ekmmock:v1:" + namespace + ":" + name + ":" + type + ":" + size. Binds a blob to its identity.</summary>
    public static byte[] BuildAad(string ns, string name, KeyType type, int size)
        => System.Text.Encoding.UTF8.GetBytes($"ekmmock:v1:{ns}:{name}:{TypeName(type)}:{size}");

    public static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) Encrypt(
        ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> secret, byte[] aad)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[secret.Length];
        var tag = new byte[TagSize];
        using var gcm = new AesGcm(masterKey, TagSize);
        gcm.Encrypt(nonce, secret, ciphertext, tag, aad);
        return (nonce, ciphertext, tag);
    }

    /// <summary>Returns null when authentication fails (wrong master key, tampered blob or metadata) or the blob is malformed.</summary>
    public static byte[]? TryDecrypt(
        ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, byte[] aad)
    {
        if (nonce.Length != NonceSize || tag.Length != TagSize || ciphertext.Length == 0)
        {
            return null;
        }

        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var gcm = new AesGcm(masterKey, TagSize);
            gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            return plaintext;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            return null;
        }
    }
}
