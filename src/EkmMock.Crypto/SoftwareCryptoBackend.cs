using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using EkmMock.Crypto.Internal;
using EkmMock.Crypto.KeyStore;

namespace EkmMock.Crypto;

/// <summary>
/// The software HSM: real AES-256 / RSA keys, encrypted at rest under the Key Store Master Key, kept in memory after
/// load, with real wrap/unwrap. Implements <see cref="ICryptoBackend"/> and <see cref="IKeyManager"/> synchronously.
/// Thread safe: the key map is lock-free on the hot path, crypto objects are pooled per key and never shared between
/// threads, mutations are serialised by one lock.
/// </summary>
public sealed partial class SoftwareCryptoBackend : ICryptoBackend, IKeyManager, IDisposable
{
    private readonly SoftwareCryptoBackendOptions _options;
    private readonly TimeProvider _time;
    private readonly MasterKey _masterKey;
    private readonly string _keyStorePath;
    private readonly ConcurrentDictionary<KeyRef, KeyEntry> _keys = new();
    private readonly Dictionary<KeyRef, StoredTombstone> _tombstones = [];
    private readonly List<StoredKey> _unreadable = [];
    private readonly object _gate = new();
    private readonly Timer? _flushTimer;
    private volatile bool _countersDirty;
    private volatile bool _disposed;

    public SoftwareCryptoBackend(SoftwareCryptoBackendOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DataPath);

        _options = options;
        _time = options.TimeProvider;
        _keyStorePath = Path.Combine(options.DataPath, options.KeyStoreFileName);

        // Refuses to start (throws) when no master key is available.
        _masterKey = options.MasterKeyProvider.GetMasterKey();
        try
        {
            Directory.CreateDirectory(options.DataPath);
            AtomicFile.DeleteStaleTempFiles(_keyStorePath);
            LoadReport = Load();
        }
        catch
        {
            foreach (var entry in _keys.Values)
            {
                entry.Dispose();
            }

            _masterKey.Dispose();
            throw;
        }

        if (options.CounterFlushInterval > TimeSpan.Zero)
        {
            _flushTimer = new Timer(_ => FlushQuietly(), null, options.CounterFlushInterval, options.CounterFlushInterval);
        }
    }

    public BackendInfo Info => _options.Info;

    public bool IsAvailable => !_disposed;

    public KeyStoreLoadReport LoadReport { get; }

    /// <summary>Where the master key came from (never the key itself).</summary>
    public string MasterKeySource => _masterKey.Source;

    /// <summary>True when dev mode created a throw-away master key: the console must show a red banner.</summary>
    public bool IsMasterKeyThrowAway => _masterKey.IsThrowAway;

    public string KeyStorePath => _keyStorePath;

    // ---- ICryptoBackend ----------------------------------------------------------------------------------------------

    public KeyMetadata? GetMetadata(KeyRef key)
    {
        ThrowIfUnavailable();
        if (!_keys.TryGetValue(key, out var entry))
        {
            return null;
        }

        if (entry.Health != KeyHealth.Ok)
        {
            throw EkmEngineException.HsmUnavailable("Key is unavailable", key);
        }

        return new KeyMetadata(key, entry.Type, entry.Size, ComputeState(entry), entry.Flags.NotAfter, entry.PublicKey);
    }

    public byte[] Wrap(KeyRef key, WrapAlgorithm alg, ReadOnlySpan<byte> dek)
    {
        var entry = RequireUsable(key, alg, "WrapKey");
        var wrapped = WrapCore(entry, alg, dek);
        entry.RecordWrap(_time.GetUtcNow());
        _countersDirty = true;
        return wrapped;
    }

    public byte[] Unwrap(KeyRef key, WrapAlgorithm alg, ReadOnlySpan<byte> wrapped)
    {
        var entry = RequireUsable(key, alg, "UnwrapKey");
        var dek = UnwrapCore(entry, alg, wrapped);
        entry.RecordUnwrap(_time.GetUtcNow());
        _countersDirty = true;
        return dek;
    }

    // Shared by the public operations and the self-test (which must not touch counters or key state checks).
    private static byte[] WrapCore(KeyEntry entry, WrapAlgorithm alg, ReadOnlySpan<byte> dek)
    {
        switch (alg)
        {
            case WrapAlgorithm.A256KW:
                if (dek.Length < AesKeyWrap.MinKwKeyBytes || dek.Length % AesKeyWrap.SemiBlockSize != 0)
                {
                    throw EkmEngineException.InvalidInput("DEK must be at least 16 bytes and a multiple of 8 for A256KW", entry.Key);
                }

                return WrapWithAes(entry, padded: false, dek);

            case WrapAlgorithm.A256KWP:
                if (dek.Length is < 1 or > AesKeyWrap.MaxKwpKeyBytes)
                {
                    throw EkmEngineException.InvalidInput("DEK must be 1 to 4096 bytes for A256KWP", entry.Key);
                }

                return WrapWithAes(entry, padded: true, dek);

            case WrapAlgorithm.RsaOaep256:
            case WrapAlgorithm.RsaOaep:
                var max = RsaOaep.MaxPlaintextBytes(entry.RsaKeyBytes, alg);
                if (dek.Length < 1 || dek.Length > max)
                {
                    throw EkmEngineException.InvalidInput($"DEK must be 1 to {max} bytes for {alg.ToWireName()} with this key", entry.Key);
                }

                return WrapWithRsa(entry, alg, dek);

            default:
                throw EkmEngineException.UnsupportedAlgorithm(entry.Key);
        }
    }

    private static byte[] UnwrapCore(KeyEntry entry, WrapAlgorithm alg, ReadOnlySpan<byte> wrapped)
    {
        byte[]? dek;
        switch (alg)
        {
            case WrapAlgorithm.A256KW:
                if (wrapped.Length < AesKeyWrap.MinKwKeyBytes + AesKeyWrap.SemiBlockSize || wrapped.Length % AesKeyWrap.SemiBlockSize != 0)
                {
                    throw EkmEngineException.InvalidCiphertext(entry.Key);
                }

                dek = UnwrapWithAes(entry, padded: false, wrapped);
                break;

            case WrapAlgorithm.A256KWP:
                if (!AesKeyWrap.IsValidPaddedWrappedLength(wrapped.Length))
                {
                    throw EkmEngineException.InvalidCiphertext(entry.Key);
                }

                dek = UnwrapWithAes(entry, padded: true, wrapped);
                break;

            case WrapAlgorithm.RsaOaep256:
            case WrapAlgorithm.RsaOaep:
                if (wrapped.Length != entry.RsaKeyBytes)
                {
                    throw EkmEngineException.InvalidCiphertext(entry.Key);
                }

                dek = UnwrapWithRsa(entry, alg, wrapped);
                break;

            default:
                throw EkmEngineException.UnsupportedAlgorithm(entry.Key);
        }

        return dek ?? throw EkmEngineException.InvalidCiphertext(entry.Key);
    }

    // The four helpers below rent a pooled, exclusively-owned instance. Spans cannot be captured by lambdas, hence no delegates.

    private static byte[] WrapWithAes(KeyEntry entry, bool padded, ReadOnlySpan<byte> dek)
    {
        var pool = entry.AesPool ?? throw EkmEngineException.HsmUnavailable("Key is unavailable", entry.Key);
        var aes = RentOrKeyGone(pool, entry.Key);
        try
        {
            return padded ? AesKeyWrap.WrapPadded(aes, dek) : AesKeyWrap.Wrap(aes, dek);
        }
        catch (CryptographicException)
        {
            throw OperationFailed(entry.Key);
        }
        finally
        {
            pool.Return(aes);
        }
    }

    private static byte[]? UnwrapWithAes(KeyEntry entry, bool padded, ReadOnlySpan<byte> wrapped)
    {
        var pool = entry.AesPool ?? throw EkmEngineException.HsmUnavailable("Key is unavailable", entry.Key);
        var aes = RentOrKeyGone(pool, entry.Key);
        try
        {
            return padded ? AesKeyWrap.UnwrapPadded(aes, wrapped) : AesKeyWrap.Unwrap(aes, wrapped);
        }
        catch (CryptographicException)
        {
            throw OperationFailed(entry.Key);
        }
        finally
        {
            pool.Return(aes);
        }
    }

    private static byte[] WrapWithRsa(KeyEntry entry, WrapAlgorithm alg, ReadOnlySpan<byte> dek)
    {
        var pool = entry.RsaPool ?? throw EkmEngineException.HsmUnavailable("Key is unavailable", entry.Key);
        var rsa = RentOrKeyGone(pool, entry.Key);
        try
        {
            return RsaOaep.Wrap(rsa, alg, dek);
        }
        catch (CryptographicException)
        {
            throw OperationFailed(entry.Key);
        }
        finally
        {
            pool.Return(rsa);
        }
    }

    private static byte[]? UnwrapWithRsa(KeyEntry entry, WrapAlgorithm alg, ReadOnlySpan<byte> wrapped)
    {
        var pool = entry.RsaPool ?? throw EkmEngineException.HsmUnavailable("Key is unavailable", entry.Key);
        var rsa = RentOrKeyGone(pool, entry.Key);
        try
        {
            // RsaOaep.Unwrap already maps decryption failures to null (-> InvalidCiphertext).
            return RsaOaep.Unwrap(rsa, alg, wrapped);
        }
        finally
        {
            pool.Return(rsa);
        }
    }

    private static T RentOrKeyGone<T>(InstancePool<T> pool, KeyRef key)
        where T : class, IDisposable
    {
        try
        {
            return pool.Rent();
        }
        catch (ObjectDisposedException)
        {
            // The key was destroyed while this request was in flight.
            throw EkmEngineException.KeyNotFound(key);
        }
    }

    private static EkmEngineException OperationFailed(KeyRef key)
        => new(EkmErrorKind.InternalError, "The cryptographic operation failed", key);

    private KeyEntry RequireUsable(KeyRef key, WrapAlgorithm alg, string operation)
    {
        ThrowIfUnavailable();

        if (!_keys.TryGetValue(key, out var entry))
        {
            throw EkmEngineException.KeyNotFound(key);
        }

        if (entry.Health != KeyHealth.Ok)
        {
            throw EkmEngineException.HsmUnavailable("Key is unavailable", key);
        }

        if (alg.RequiredKeyType() != entry.Type || IsAlgorithmUnavailable(alg))
        {
            throw EkmEngineException.UnsupportedAlgorithm(key);
        }

        var flags = entry.Flags;
        if (!flags.Enabled)
        {
            throw EkmEngineException.KeyDisabled(key, operation);
        }

        if (flags.NotAfter is { } notAfter && notAfter <= _time.GetUtcNow())
        {
            throw EkmEngineException.KeyExpired(key, operation);
        }

        return entry;
    }

    private void ThrowIfUnavailable()
    {
        if (_disposed)
        {
            throw EkmEngineException.HsmUnavailable("The crypto engine is not available");
        }
    }

    private KeyState ComputeState(KeyEntry entry)
    {
        if (entry.Health == KeyHealth.Corrupt)
        {
            return KeyState.Corrupt;
        }

        if (entry.Health == KeyHealth.Unavailable)
        {
            return KeyState.Unavailable;
        }

        var flags = entry.Flags;
        if (!flags.Enabled)
        {
            return KeyState.Disabled;
        }

        return flags.NotAfter is { } notAfter && notAfter <= _time.GetUtcNow() ? KeyState.Expired : KeyState.Enabled;
    }

    // ---- IKeyManager -------------------------------------------------------------------------------------------------

    public KeyInfo Create(string ns, string name, KeyType type, int size, bool allowReuseOfDestroyedName = false)
    {
        ThrowIfUnavailable();
        var key = ValidateIdentity(ns, name);
        ValidateTypeAndSize(type, size);
        lock (_gate)
        {
            EnsureNameFree(key, allowReuseOfDestroyedName);
        }

        // Generation (RSA-4096 can take seconds) happens outside the lock.
        byte[] secret;
        if (type == KeyType.Oct)
        {
            secret = RandomNumberGenerator.GetBytes(32);
        }
        else
        {
            using var rsa = RSA.Create(size);
            secret = rsa.ExportPkcs8PrivateKey();
        }

        try
        {
            return AddKey(key, type, size, KeyOrigin.Generated, secret, allowReuseOfDestroyedName);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public KeyInfo Import(string ns, string name, KeyType type, ReadOnlySpan<byte> material, bool allowReuseOfDestroyedName = false)
    {
        ThrowIfUnavailable();
        if (!_options.AllowKeyImport)
        {
            throw new EkmEngineException(
                EkmErrorKind.OperationNotAllowed,
                $"Key import is disabled; set {SoftwareCryptoBackendOptions.AllowKeyImportVariable}=true to enable it (test vectors only)");
        }

        var key = ValidateIdentity(ns, name);
        byte[] secret;
        int size;
        switch (type)
        {
            case KeyType.Oct:
                if (material.Length != 32)
                {
                    throw EkmEngineException.InvalidInput("An imported oct key must be exactly 32 bytes (AES-256)");
                }

                secret = material.ToArray();
                size = 256;
                break;

            case KeyType.Rsa:
                try
                {
                    using var rsa = RSA.Create();
                    rsa.ImportPkcs8PrivateKey(material, out _);
                    size = rsa.KeySize;
                    ValidateTypeAndSize(KeyType.Rsa, size);
                    secret = rsa.ExportPkcs8PrivateKey();
                }
                catch (CryptographicException)
                {
                    throw EkmEngineException.InvalidInput("An imported RSA key must be a valid PKCS#8 private key");
                }

                break;

            default:
                throw EkmEngineException.InvalidInput("Unknown key type");
        }

        try
        {
            return AddKey(key, type, size, KeyOrigin.Imported, secret, allowReuseOfDestroyedName);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public KeyInfo? Get(KeyRef key)
    {
        ThrowIfUnavailable();
        if (_keys.TryGetValue(key, out var entry))
        {
            return ToInfo(entry);
        }

        lock (_gate)
        {
            return _tombstones.TryGetValue(key, out var tombstone) ? ToInfo(tombstone) : null;
        }
    }

    public void SetEnabled(KeyRef key, bool enabled)
        => MutateFlags(key, flags => flags with { Enabled = enabled });

    public void SetExpiry(KeyRef key, DateTimeOffset? notAfter)
        => MutateFlags(key, flags => flags with { NotAfter = notAfter?.ToUniversalTime() });

    public void Destroy(KeyRef key, string? destroyedBy = null)
    {
        ThrowIfUnavailable();
        KeyEntry entry;
        lock (_gate)
        {
            if (!_keys.TryRemove(key, out entry!))
            {
                throw EkmEngineException.KeyNotFound(key);
            }

            var tombstone = new StoredTombstone
            {
                Namespace = key.Namespace,
                Name = key.Name,
                Type = KeyBlobCipher.TypeName(entry.Type),
                Size = entry.Size,
                Origin = OriginName(entry.Origin),
                CreatedAt = entry.CreatedAt,
                DestroyedAt = _time.GetUtcNow(),
                DestroyedBy = string.IsNullOrWhiteSpace(destroyedBy) ? "unknown" : destroyedBy,
            };
            _tombstones[key] = tombstone;

            try
            {
                PersistLocked();
            }
            catch
            {
                _tombstones.Remove(key);
                _keys[key] = entry;
                throw;
            }
        }

        // Only after the blob is gone from disk: drop the in-memory material (crypto-shred).
        entry.Dispose();
    }

    public IReadOnlyList<KeyInfo> List(string? ns = null)
    {
        ThrowIfUnavailable();
        var result = new List<KeyInfo>();
        foreach (var entry in _keys.Values)
        {
            if (ns is null || entry.Key.Namespace == ns)
            {
                result.Add(ToInfo(entry));
            }
        }

        lock (_gate)
        {
            foreach (var tombstone in _tombstones.Values)
            {
                if (ns is null || tombstone.Namespace == ns)
                {
                    result.Add(ToInfo(tombstone));
                }
            }
        }

        result.Sort(static (a, b) =>
        {
            var byNamespace = string.CompareOrdinal(a.Namespace, b.Namespace);
            return byNamespace != 0 ? byNamespace : string.CompareOrdinal(a.Name, b.Name);
        });
        return result;
    }

    private static KeyRef ValidateIdentity(string ns, string name)
    {
        if (!EkmNames.IsValidNamespaceName(ns))
        {
            throw EkmEngineException.InvalidInput("Invalid namespace name");
        }

        if (!EkmNames.IsValidKeyName(name))
        {
            throw new EkmEngineException(EkmErrorKind.InvalidKeyName, "Key name must match ^[A-Za-z0-9-]{1,64}$");
        }

        return new KeyRef(ns, name);
    }

    private static void ValidateTypeAndSize(KeyType type, int size)
    {
        var valid = type switch
        {
            KeyType.Oct => size == 256,
            KeyType.Rsa => size is 2048 or 3072 or 4096,
            _ => false,
        };

        if (!valid)
        {
            throw EkmEngineException.InvalidInput("Unsupported key type or size (oct 256; RSA 2048, 3072, 4096)");
        }
    }

    // Caller holds _gate.
    private void EnsureNameFree(KeyRef key, bool allowReuseOfDestroyedName)
    {
        // If every stored key is Corrupt the configured master key is almost certainly wrong. Adding a key now would mix
        // two master keys in one file and make the new key unreadable once the right master key is restored.
        if (!_keys.IsEmpty && _keys.Values.All(static e => e.Health == KeyHealth.Corrupt))
        {
            throw EkmEngineException.HsmUnavailable("The key store cannot be decrypted with the configured master key; refusing to add keys");
        }

        if (_keys.ContainsKey(key))
        {
            throw new EkmEngineException(EkmErrorKind.KeyAlreadyExists, "A key with this name already exists", key);
        }

        if (!allowReuseOfDestroyedName && _tombstones.ContainsKey(key))
        {
            throw new EkmEngineException(
                EkmErrorKind.KeyNameReserved, "This name belongs to a destroyed key and cannot be reused without an explicit override", key);
        }
    }

    private KeyInfo AddKey(KeyRef key, KeyType type, int size, KeyOrigin origin, byte[] secret, bool allowReuseOfDestroyedName)
    {
        var aad = KeyBlobCipher.BuildAad(key.Namespace, key.Name, type, size);
        var (nonce, ciphertext, tag) = KeyBlobCipher.Encrypt(_masterKey.Bytes, secret, aad);

        var entry = new KeyEntry(
            key, type, size, origin, _time.GetUtcNow(), new KeyFlags(true, null), 0, 0, null,
            Convert.ToBase64String(nonce), Convert.ToBase64String(ciphertext), Convert.ToBase64String(tag));

        if (!entry.TryAttachMaterial(secret))
        {
            entry.Dispose();
            throw new EkmEngineException(EkmErrorKind.InternalError, "The key material is not valid for the requested key type", key);
        }

        lock (_gate)
        {
            try
            {
                EnsureNameFree(key, allowReuseOfDestroyedName);
            }
            catch
            {
                entry.Dispose();
                throw;
            }

            _tombstones.Remove(key, out var removedTombstone);
            _keys[key] = entry;
            try
            {
                PersistLocked();
            }
            catch
            {
                _keys.TryRemove(key, out _);
                if (removedTombstone is not null)
                {
                    _tombstones[key] = removedTombstone;
                }

                entry.Dispose();
                throw;
            }
        }

        return ToInfo(entry);
    }

    private void MutateFlags(KeyRef key, Func<KeyFlags, KeyFlags> change)
    {
        ThrowIfUnavailable();
        lock (_gate)
        {
            if (!_keys.TryGetValue(key, out var entry))
            {
                throw EkmEngineException.KeyNotFound(key);
            }

            var previous = entry.Flags;
            entry.Flags = change(previous);
            try
            {
                PersistLocked();
            }
            catch
            {
                entry.Flags = previous;
                throw;
            }
        }
    }

    private KeyInfo ToInfo(KeyEntry entry) => new(
        entry.Key.Name,
        entry.Key.Namespace,
        entry.Type,
        entry.Size,
        ComputeState(entry),
        entry.CreatedAt,
        entry.Flags.NotAfter,
        entry.Origin,
        entry.WrapCount,
        entry.UnwrapCount,
        entry.LastUsedAt,
        entry.PublicKey);

    private static KeyInfo ToInfo(StoredTombstone tombstone)
    {
        _ = KeyBlobCipher.TryParseType(tombstone.Type, out var type);
        return new KeyInfo(
            tombstone.Name,
            tombstone.Namespace,
            type,
            tombstone.Size,
            KeyState.Destroyed,
            tombstone.CreatedAt,
            null,
            ParseOrigin(tombstone.Origin),
            0,
            0,
            null,
            null,
            tombstone.DestroyedAt,
            tombstone.DestroyedBy);
    }

    private static string OriginName(KeyOrigin origin) => origin == KeyOrigin.Imported ? "imported" : "generated";

    private static KeyOrigin ParseOrigin(string? text) => text == "imported" ? KeyOrigin.Imported : KeyOrigin.Generated;

    // ---- Persistence ------------------------------------------------------------------------------------------------

    private KeyStoreLoadReport Load()
    {
        if (!File.Exists(_keyStorePath))
        {
            return new KeyStoreLoadReport(0, 0, 0, 0);
        }

        KeyStoreFile? file;
        try
        {
            file = JsonSerializer.Deserialize(File.ReadAllBytes(_keyStorePath), KeyStoreJsonContext.Default.KeyStoreFile);
        }
        catch (JsonException)
        {
            throw new InvalidDataException("keystore.json is not valid JSON; refusing to start so it is not overwritten.");
        }

        if (file is null || file.Version != 1)
        {
            throw new InvalidDataException("keystore.json has an unsupported format version; refusing to start.");
        }

        foreach (var stored in file.Keys)
        {
            LoadKey(stored);
        }

        var tombstones = 0;
        foreach (var tombstone in file.Tombstones)
        {
            var tombstoneKey = new KeyRef(tombstone.Namespace, tombstone.Name);
            if (EkmNames.IsValidNamespaceName(tombstone.Namespace) && EkmNames.IsValidKeyName(tombstone.Name) && !_keys.ContainsKey(tombstoneKey))
            {
                _tombstones[tombstoneKey] = tombstone;
                tombstones++;
            }
        }

        var corrupt = _keys.Values.Count(static e => e.Health == KeyHealth.Corrupt);
        return new KeyStoreLoadReport(_keys.Count, corrupt, _unreadable.Count, tombstones);
    }

    private void LoadKey(StoredKey stored)
    {
        var addressable = EkmNames.IsValidNamespaceName(stored.Namespace)
            && EkmNames.IsValidKeyName(stored.Name)
            && KeyBlobCipher.TryParseType(stored.Type, out _);
        if (!addressable
            || _keys.ContainsKey(new KeyRef(stored.Namespace, stored.Name)))
        {
            _unreadable.Add(stored);
            return;
        }

        KeyBlobCipher.TryParseType(stored.Type, out var type);
        var key = new KeyRef(stored.Namespace, stored.Name);
        var entry = new KeyEntry(
            key,
            type,
            stored.Size,
            ParseOrigin(stored.Origin),
            stored.CreatedAt,
            new KeyFlags(stored.Enabled, stored.NotAfter),
            stored.WrapCount,
            stored.UnwrapCount,
            stored.LastUsedAt,
            stored.Nonce,
            stored.Ciphertext,
            stored.Tag);

        byte[]? secret = null;
        try
        {
            if (TryDecode(stored.Nonce, out var nonce) && TryDecode(stored.Ciphertext, out var ciphertext) && TryDecode(stored.Tag, out var tag))
            {
                var aad = KeyBlobCipher.BuildAad(stored.Namespace, stored.Name, type, stored.Size);
                secret = KeyBlobCipher.TryDecrypt(_masterKey.Bytes, nonce, ciphertext, tag, aad);
            }

            if (secret is null || !entry.TryAttachMaterial(secret))
            {
                // Tampered file or wrong master key: keep the key (blob untouched), mark it, carry on loading the rest.
                entry.Health = KeyHealth.Corrupt;
            }
        }
        finally
        {
            if (secret is not null)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }

        _keys[key] = entry;
    }

    private static bool TryDecode(string text, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(text);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }

    // Caller holds _gate. Clears the dirty flag first so a concurrent counter increment is never lost.
    private void PersistLocked()
    {
        _countersDirty = false;
        var file = new KeyStoreFile();
        foreach (var entry in _keys.Values.OrderBy(static e => e.Key.Namespace, StringComparer.Ordinal).ThenBy(static e => e.Key.Name, StringComparer.Ordinal))
        {
            var flags = entry.Flags;
            file.Keys.Add(new StoredKey
            {
                Namespace = entry.Key.Namespace,
                Name = entry.Key.Name,
                Type = KeyBlobCipher.TypeName(entry.Type),
                Size = entry.Size,
                Origin = OriginName(entry.Origin),
                CreatedAt = entry.CreatedAt,
                NotAfter = flags.NotAfter,
                Enabled = flags.Enabled,
                WrapCount = entry.WrapCount,
                UnwrapCount = entry.UnwrapCount,
                LastUsedAt = entry.LastUsedAt,
                Nonce = entry.Nonce,
                Ciphertext = entry.Ciphertext,
                Tag = entry.Tag,
            });
        }

        file.Keys.AddRange(_unreadable);
        file.Tombstones.AddRange(
            _tombstones.Values.OrderBy(static t => t.Namespace, StringComparer.Ordinal).ThenBy(static t => t.Name, StringComparer.Ordinal));

        try
        {
            AtomicFile.Write(_keyStorePath, JsonSerializer.SerializeToUtf8Bytes(file, KeyStoreJsonContext.Default.KeyStoreFile));
        }
        catch
        {
            _countersDirty = true;
            throw;
        }
    }

    /// <summary>Writes pending usage counters to disk. Called by the lazy timer and on <see cref="Dispose"/>; never on the hot path.</summary>
    public void Flush()
    {
        if (!_countersDirty)
        {
            return;
        }

        lock (_gate)
        {
            if (_countersDirty)
            {
                PersistLocked();
            }
        }
    }

    private void FlushQuietly()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            Flush();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Stays dirty and is retried at the next tick; counters are advisory.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _flushTimer?.Dispose();
        try
        {
            Flush();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort at shutdown.
        }

        _disposed = true;
        foreach (var entry in _keys.Values)
        {
            entry.Dispose();
        }

        _masterKey.Dispose();
    }

    /// <summary>Test-only (InternalsVisibleTo): the plaintext secret of a key, to prove it never reaches disk, logs or serialisation.</summary>
    internal byte[]? CopySecretForTests(KeyRef key) => _keys.TryGetValue(key, out var entry) ? entry.CopySecretForTests() : null;
}
