namespace EkmMock.Crypto;

public sealed class SoftwareCryptoBackendOptions
{
    public const string AllowKeyImportVariable = "EKMMOCK_ALLOW_KEY_IMPORT";

    /// <summary>Data folder holding <c>keystore.json</c> (created if missing).</summary>
    public required string DataPath { get; init; }

    /// <summary>Where the Key Store Master Key comes from. A missing key makes construction throw.</summary>
    public required IMasterKeyProvider MasterKeyProvider { get; init; }

    /// <summary>Key import is for RFC test vectors only and is off unless explicitly enabled.</summary>
    public bool AllowKeyImport { get; init; }

    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>
    /// How often dirty usage counters are flushed to disk. Counters are never written on the hot path.
    /// <see cref="TimeSpan.Zero"/> disables the timer (flush on <c>Flush()</c> and <c>Dispose()</c> only).
    /// </summary>
    public TimeSpan CounterFlushInterval { get; init; } = TimeSpan.FromSeconds(30);

    public BackendInfo Info { get; init; } = new("EkmMock", "EkmMock Software HSM");

    public string KeyStoreFileName { get; init; } = "keystore.json";

    /// <summary>True when <c>EKMMOCK_ALLOW_KEY_IMPORT=true</c> (the reader is injectable so tests avoid real environment variables).</summary>
    public static bool IsKeyImportEnabledInEnvironment(Func<string, string?>? getEnvironmentVariable = null)
        => string.Equals((getEnvironmentVariable ?? Environment.GetEnvironmentVariable)(AllowKeyImportVariable), "true", StringComparison.OrdinalIgnoreCase);
}

/// <summary>What the key store loader found. Corrupt keys are kept (and shown in red); unreadable entries cannot be addressed.</summary>
public sealed record KeyStoreLoadReport(int Keys, int CorruptKeys, int UnreadableEntries, int Tombstones);
