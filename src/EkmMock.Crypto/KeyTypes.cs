namespace EkmMock.Crypto;

/// <summary>Address of a key: the namespace it lives in plus its external key identifier.</summary>
public readonly record struct KeyRef(string Namespace, string Name)
{
    public override string ToString() => $"{Namespace}/{Name}";
}

public enum KeyType
{
    /// <summary>Symmetric AES key (JWK <c>oct</c>), 256 bit only.</summary>
    Oct,

    /// <summary>RSA key pair, 2048/3072/4096 bit, public exponent 65537.</summary>
    Rsa,
}

public enum WrapAlgorithm
{
    A256KW,
    A256KWP,
    RsaOaep256,
    RsaOaep,
}

public enum KeyState
{
    Enabled,
    Disabled,

    /// <summary>The key is enabled but its <c>NotAfter</c> instant has passed.</summary>
    Expired,

    /// <summary>Only visible through <see cref="IKeyManager.List"/> as a tombstone; never usable.</summary>
    Destroyed,

    /// <summary>The stored blob failed authentication at load (tampered file or wrong master key).</summary>
    Corrupt,

    /// <summary>The per-key startup self-test failed; the key is not used until restart.</summary>
    Unavailable,
}

public enum KeyOrigin
{
    Generated,
    Imported,
}

/// <summary>Wire names and key-type rules for <see cref="WrapAlgorithm"/> (spec section 4.10).</summary>
public static class WrapAlgorithms
{
    public static bool TryParse(string? wireName, out WrapAlgorithm algorithm)
    {
        // Case-sensitive on purpose: the EKM contract uses exact algorithm names.
        switch (wireName)
        {
            case "A256KW":
                algorithm = WrapAlgorithm.A256KW;
                return true;
            case "A256KWP":
                algorithm = WrapAlgorithm.A256KWP;
                return true;
            case "RSA-OAEP-256":
                algorithm = WrapAlgorithm.RsaOaep256;
                return true;
            case "RSA-OAEP":
                algorithm = WrapAlgorithm.RsaOaep;
                return true;
            default:
                algorithm = default;
                return false;
        }
    }

    public static string ToWireName(this WrapAlgorithm algorithm) => algorithm switch
    {
        WrapAlgorithm.A256KW => "A256KW",
        WrapAlgorithm.A256KWP => "A256KWP",
        WrapAlgorithm.RsaOaep256 => "RSA-OAEP-256",
        WrapAlgorithm.RsaOaep => "RSA-OAEP",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    public static KeyType RequiredKeyType(this WrapAlgorithm algorithm) => algorithm switch
    {
        WrapAlgorithm.A256KW or WrapAlgorithm.A256KWP => KeyType.Oct,
        WrapAlgorithm.RsaOaep256 or WrapAlgorithm.RsaOaep => KeyType.Rsa,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };
}
