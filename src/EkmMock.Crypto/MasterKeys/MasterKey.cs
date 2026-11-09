using System.Security.Cryptography;

namespace EkmMock.Crypto;

/// <summary>
/// Key Store Master Key (KSMK): 32 bytes protecting key blobs at rest. The bytes are only reachable inside the
/// assembly; the public surface shows where the key came from and whether it is a throw-away dev key.
/// </summary>
public sealed class MasterKey : IDisposable
{
    public const int SizeBytes = 32;

    private readonly byte[] _bytes;

    private MasterKey(byte[] bytes, string source, bool isThrowAway)
    {
        _bytes = bytes;
        Source = source;
        IsThrowAway = isThrowAway;
    }

    /// <summary>Human readable origin, for example <c>environment:EKMMOCK_MASTER_KEY</c>. Never contains key bytes.</summary>
    public string Source { get; }

    /// <summary>True for the explicit dev-mode key that is lost at exit (the console shows a red banner).</summary>
    public bool IsThrowAway { get; }

    internal ReadOnlySpan<byte> Bytes => _bytes;

    /// <summary>Creates a master key from exactly 32 bytes (the input is copied).</summary>
    public static MasterKey FromBytes(ReadOnlySpan<byte> bytes, string source)
    {
        if (bytes.Length != SizeBytes)
        {
            throw new MasterKeyUnavailableException($"Master key must be exactly {SizeBytes} bytes.");
        }

        return new MasterKey(bytes.ToArray(), source, isThrowAway: false);
    }

    /// <summary>Creates a fresh random key that only lives in this process.</summary>
    public static MasterKey CreateThrowAway()
        => new(RandomNumberGenerator.GetBytes(SizeBytes), "dev-throwaway", isThrowAway: true);

    /// <summary>Parses a standard base64 master key; error messages never echo the input.</summary>
    public static MasterKey FromBase64(string? base64, string source)
    {
        Span<byte> buffer = stackalloc byte[SizeBytes + 4];
        try
        {
            if (string.IsNullOrWhiteSpace(base64)
                || !Convert.TryFromBase64String(base64.Trim(), buffer, out var written)
                || written != SizeBytes)
            {
                throw new MasterKeyUnavailableException($"Master key from {source} is not valid base64 of exactly {SizeBytes} bytes.");
            }

            return new MasterKey(buffer[..written].ToArray(), source, isThrowAway: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>Generates a new random master key as base64 (what <c>ekmmock init</c> prints once).</summary>
    public static string GenerateBase64() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(SizeBytes));

    public void Dispose() => CryptographicOperations.ZeroMemory(_bytes);

    public override string ToString() => $"MasterKey(source={Source}, throwAway={IsThrowAway})";
}

/// <summary>The master key is missing, ambiguous or malformed. The engine must refuse to start.</summary>
public sealed class MasterKeyUnavailableException : Exception
{
    public MasterKeyUnavailableException(string message)
        : base(message)
    {
    }
}
