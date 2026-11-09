using System.Text.Json.Serialization;

namespace EkmMock.Crypto.KeyStore;

// Persisted shape of keystore.json. snake_case, strings for enums, base64 (standard) for binary.
// Only the blob (nonce/ciphertext/tag) is secret-derived, and it is AES-256-GCM encrypted under the master key.

internal sealed class KeyStoreFile
{
    public int Version { get; set; } = 1;

    public List<StoredKey> Keys { get; set; } = [];

    public List<StoredTombstone> Tombstones { get; set; } = [];
}

internal sealed class StoredKey
{
    public string Namespace { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    /// <summary>"oct" or "rsa"; also part of the GCM AAD.</summary>
    public string Type { get; set; } = string.Empty;

    public int Size { get; set; }

    /// <summary>"generated" or "imported".</summary>
    public string Origin { get; set; } = "generated";

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? NotAfter { get; set; }

    public bool Enabled { get; set; } = true;

    public long WrapCount { get; set; }

    public long UnwrapCount { get; set; }

    public DateTimeOffset? LastUsedAt { get; set; }

    public string Nonce { get; set; } = string.Empty;

    public string Ciphertext { get; set; } = string.Empty;

    public string Tag { get; set; } = string.Empty;
}

internal sealed class StoredTombstone
{
    public string Namespace { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public int Size { get; set; }

    public string Origin { get; set; } = "generated";

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset DestroyedAt { get; set; }

    public string DestroyedBy { get; set; } = "unknown";
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(KeyStoreFile))]
internal sealed partial class KeyStoreJsonContext : JsonSerializerContext
{
}
