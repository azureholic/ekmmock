namespace EkmMock.Crypto;

/// <summary>
/// Makes <see cref="RsaPublicKey"/> serialise as <c>{"n":"…","e":"AQAB"}</c> (base64url, unpadded, JWK style), so a
/// <see cref="KeyInfo"/> can be written to JSON directly without ever touching anything but the public numbers.
/// </summary>
public sealed class RsaPublicKeyJsonConverter : System.Text.Json.Serialization.JsonConverter<RsaPublicKey>
{
    public override RsaPublicKey? Read(ref System.Text.Json.Utf8JsonReader reader, Type typeToConvert, System.Text.Json.JsonSerializerOptions options)
    {
        string? n = null;
        string? e = null;
        if (reader.TokenType != System.Text.Json.JsonTokenType.StartObject)
        {
            throw new System.Text.Json.JsonException("Expected an object with 'n' and 'e'.");
        }

        while (reader.Read() && reader.TokenType != System.Text.Json.JsonTokenType.EndObject)
        {
            var name = reader.GetString();
            reader.Read();
            switch (name)
            {
                case "n":
                    n = reader.GetString();
                    break;
                case "e":
                    e = reader.GetString();
                    break;
                default:
                    reader.Skip();
                    break;
            }
        }

        if (n is null || e is null)
        {
            throw new System.Text.Json.JsonException("Both 'n' and 'e' are required.");
        }

        return new RsaPublicKey(System.Buffers.Text.Base64Url.DecodeFromChars(n), System.Buffers.Text.Base64Url.DecodeFromChars(e));
    }

    public override void Write(System.Text.Json.Utf8JsonWriter writer, RsaPublicKey value, System.Text.Json.JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString("n", System.Buffers.Text.Base64Url.EncodeToString(value.Modulus.Span));
        writer.WriteString("e", System.Buffers.Text.Base64Url.EncodeToString(value.Exponent.Span));
        writer.WriteEndObject();
    }
}

/// <summary>Public half of an RSA key as minimal big-endian unsigned bytes (no leading 0x00).</summary>
[System.Text.Json.Serialization.JsonConverter(typeof(RsaPublicKeyJsonConverter))]
public sealed class RsaPublicKey
{
    private readonly byte[] _modulus;
    private readonly byte[] _exponent;

    public RsaPublicKey(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent)
    {
        _modulus = Minimal(modulus);
        _exponent = Minimal(exponent);
    }

    /// <summary>RSA modulus <c>n</c>.</summary>
    public ReadOnlyMemory<byte> Modulus => _modulus;

    /// <summary>RSA public exponent <c>e</c> (65537 is <c>01 00 01</c>).</summary>
    public ReadOnlyMemory<byte> Exponent => _exponent;

    public int KeySizeBits => _modulus.Length * 8;

    public override string ToString() => $"RsaPublicKey({KeySizeBits})";

    private static byte[] Minimal(ReadOnlySpan<byte> value)
    {
        var trimmed = value.TrimStart((byte)0);
        return trimmed.ToArray();
    }
}

/// <summary>Everything the console may show about a key. Never contains secret or private material.</summary>
public sealed record KeyInfo(
    string Name,
    string Namespace,
    KeyType Type,
    int Size,
    KeyState State,
    DateTimeOffset CreatedAt,
    DateTimeOffset? NotAfter,
    KeyOrigin Origin,
    long WrapCount,
    long UnwrapCount,
    DateTimeOffset? LastUsedAt,
    RsaPublicKey? PublicKey,
    DateTimeOffset? DestroyedAt = null,
    string? DestroyedBy = null)
{
    public KeyRef Ref => new(Namespace, Name);
}

/// <summary>What the EKM <c>metadata</c> operation needs (spec section 4.7).</summary>
public sealed record KeyMetadata(
    KeyRef Key,
    KeyType Type,
    int Size,
    KeyState State,
    DateTimeOffset? NotAfter,
    RsaPublicKey? PublicKey);

/// <summary>Vendor/product strings reported by the <c>info</c> operation.</summary>
public sealed record BackendInfo(string Vendor, string Product);
