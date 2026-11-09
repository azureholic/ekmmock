using System.Security.Cryptography;
using EkmMock.Crypto.Internal;

namespace EkmMock.Crypto.KeyStore;

internal enum KeyHealth
{
    Ok = 0,
    Corrupt = 1,
    Unavailable = 2,
}

/// <summary>Mutable operational flags, replaced atomically as one immutable object.</summary>
internal sealed record KeyFlags(bool Enabled, DateTimeOffset? NotAfter);

/// <summary>
/// In-memory state of one key: identity, the encrypted blob exactly as persisted (so the file can be rewritten without the
/// master key, and corrupt blobs survive a rewrite untouched), counters, and the decrypted material with its object pools.
/// </summary>
internal sealed class KeyEntry : IDisposable
{
    private static readonly byte[] Exponent65537 = [0x01, 0x00, 0x01];
    private static readonly int PoolSize = Math.Max(4, Environment.ProcessorCount);

    private volatile KeyFlags _flags;
    private long _wrapCount;
    private long _unwrapCount;
    private long _lastUsedTicks;
    private int _health;
    private byte[]? _aesKey;
    private byte[]? _pkcs8;

    public KeyEntry(
        KeyRef key,
        KeyType type,
        int size,
        KeyOrigin origin,
        DateTimeOffset createdAt,
        KeyFlags flags,
        long wrapCount,
        long unwrapCount,
        DateTimeOffset? lastUsedAt,
        string nonce,
        string ciphertext,
        string tag)
    {
        Key = key;
        Type = type;
        Size = size;
        Origin = origin;
        CreatedAt = createdAt;
        _flags = flags;
        _wrapCount = wrapCount;
        _unwrapCount = unwrapCount;
        _lastUsedTicks = lastUsedAt?.UtcTicks ?? 0;
        Nonce = nonce;
        Ciphertext = ciphertext;
        Tag = tag;
    }

    public KeyRef Key { get; }

    public KeyType Type { get; }

    public int Size { get; }

    public KeyOrigin Origin { get; }

    public DateTimeOffset CreatedAt { get; }

    public string Nonce { get; }

    public string Ciphertext { get; }

    public string Tag { get; }

    public KeyFlags Flags
    {
        get => _flags;
        set => _flags = value;
    }

    public KeyHealth Health
    {
        get => (KeyHealth)Volatile.Read(ref _health);
        set => Volatile.Write(ref _health, (int)value);
    }

    public long WrapCount => Interlocked.Read(ref _wrapCount);

    public long UnwrapCount => Interlocked.Read(ref _unwrapCount);

    public DateTimeOffset? LastUsedAt
    {
        get
        {
            var ticks = Interlocked.Read(ref _lastUsedTicks);
            return ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
        }
    }

    public RsaPublicKey? PublicKey { get; private set; }

    public InstancePool<Aes>? AesPool { get; private set; }

    public InstancePool<RSA>? RsaPool { get; private set; }

    public int RsaKeyBytes => Size / 8;

    public void RecordWrap(DateTimeOffset now)
    {
        Interlocked.Increment(ref _wrapCount);
        Interlocked.Exchange(ref _lastUsedTicks, now.UtcTicks);
    }

    public void RecordUnwrap(DateTimeOffset now)
    {
        Interlocked.Increment(ref _unwrapCount);
        Interlocked.Exchange(ref _lastUsedTicks, now.UtcTicks);
    }

    /// <summary>Attaches decrypted material. Returns false (and attaches nothing) if it does not match the declared type/size.</summary>
    public bool TryAttachMaterial(ReadOnlySpan<byte> secret)
    {
        switch (Type)
        {
            case KeyType.Oct:
                if (secret.Length != 32 || Size != 256)
                {
                    return false;
                }

                _aesKey = secret.ToArray();
                var aesKey = _aesKey;
                AesPool = new InstancePool<Aes>(
                    () =>
                    {
                        var aes = Aes.Create();
                        aes.Key = aesKey;
                        return aes;
                    },
                    PoolSize);
                return true;

            case KeyType.Rsa:
                return TryAttachRsa(secret);

            default:
                return false;
        }
    }

    private bool TryAttachRsa(ReadOnlySpan<byte> pkcs8)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(pkcs8, out _);
            if (rsa.KeySize != Size)
            {
                return false;
            }

            var parameters = rsa.ExportParameters(includePrivateParameters: false);
            var publicKey = new RsaPublicKey(parameters.Modulus!, parameters.Exponent!);
            if (!publicKey.Exponent.Span.SequenceEqual(Exponent65537) || publicKey.KeySizeBits != Size)
            {
                return false;
            }

            var pkcs8Copy = pkcs8.ToArray();
            _pkcs8 = pkcs8Copy;
            PublicKey = publicKey;
            RsaPool = new InstancePool<RSA>(
                () =>
                {
                    var instance = RSA.Create();
                    instance.ImportPkcs8PrivateKey(pkcs8Copy, out _);
                    return instance;
                },
                PoolSize);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Test-only access (via InternalsVisibleTo) to the plaintext secret, to prove it never reaches disk or logs.</summary>
    internal byte[]? CopySecretForTests() => (_aesKey ?? _pkcs8)?.ToArray();

    public void Dispose()
    {
        AesPool?.Dispose();
        RsaPool?.Dispose();
        if (_aesKey is not null)
        {
            CryptographicOperations.ZeroMemory(_aesKey);
        }

        if (_pkcs8 is not null)
        {
            CryptographicOperations.ZeroMemory(_pkcs8);
        }
    }
}
