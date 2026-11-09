namespace EkmMock.Crypto;

/// <summary>
/// The wrap/unwrap surface the EKM endpoint calls. Synchronous by design: crypto is CPU bound,
/// is never cancelled once started, and must not be wrapped in Tasks.
/// All failures are <see cref="EkmEngineException"/>.
/// </summary>
public interface ICryptoBackend
{
    BackendInfo Info { get; }

    bool IsAvailable { get; }

    /// <summary>Returns null when the key does not exist (or was destroyed).</summary>
    /// <exception cref="EkmEngineException">HsmUnavailable when the engine or this key is unavailable.</exception>
    KeyMetadata? GetMetadata(KeyRef key);

    /// <summary>Wraps a DEK. The caller owns and should zero <paramref name="dek"/> afterwards.</summary>
    byte[] Wrap(KeyRef key, WrapAlgorithm alg, ReadOnlySpan<byte> dek);

    /// <summary>Unwraps a DEK. The returned plaintext DEK is owned by the caller, who should zero it after use.</summary>
    byte[] Unwrap(KeyRef key, WrapAlgorithm alg, ReadOnlySpan<byte> wrapped);
}

/// <summary>Key lifecycle management. No member ever returns secret or private key material.</summary>
public interface IKeyManager
{
    /// <summary>Generates a new key. Oct requires <paramref name="size"/> 256; RSA 2048, 3072 or 4096.</summary>
    /// <param name="allowReuseOfDestroyedName">Explicit override to reuse a name that has a tombstone.</param>
    KeyInfo Create(string ns, string name, KeyType type, int size, bool allowReuseOfDestroyedName = false);

    /// <summary>
    /// Imports key material (test vectors only). Oct: 32 raw bytes. RSA: PKCS#8 private key.
    /// Throws OperationNotAllowed unless import was enabled (<c>EKMMOCK_ALLOW_KEY_IMPORT=true</c>).
    /// </summary>
    KeyInfo Import(string ns, string name, KeyType type, ReadOnlySpan<byte> material, bool allowReuseOfDestroyedName = false);

    KeyInfo? Get(KeyRef key);

    void SetEnabled(KeyRef key, bool enabled);

    void SetExpiry(KeyRef key, DateTimeOffset? notAfter);

    /// <summary>Irreversible crypto-shred: removes the blob and records a tombstone.</summary>
    void Destroy(KeyRef key, string? destroyedBy = null);

    /// <summary>Lists keys (including destroyed tombstones) for one namespace or all of them.</summary>
    IReadOnlyList<KeyInfo> List(string? ns = null);
}
