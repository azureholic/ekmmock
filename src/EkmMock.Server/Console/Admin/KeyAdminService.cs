using System.Security.Cryptography;
using System.Text;
using EkmMock.Crypto;

namespace EkmMock.Server.WebConsole;

/// <summary>A key as the console and the REST API show it. Contains no secret and no private material (it is built from <see cref="KeyInfo"/>, which has none).</summary>
internal sealed record KeyView(
    string Namespace,
    string Name,
    string Type,
    int Size,
    string State,
    string Origin,
    DateTimeOffset CreatedAt,
    DateTimeOffset? NotAfter,
    DateTimeOffset? LastUsedAt,
    long WrapCount,
    long UnwrapCount,
    DateTimeOffset? DestroyedAt,
    string? DestroyedBy,
    string? StateNote)
{
    /// <summary>Corrupt and unavailable keys are shown red (spec 6.2); also a destroyed key is shown as such, but not as an error.</summary>
    public bool IsProblem => State is nameof(KeyState.Corrupt) or nameof(KeyState.Unavailable);

    public bool IsDestroyed => State == nameof(KeyState.Destroyed);

    public bool IsImported => Origin == nameof(KeyOrigin.Imported);

    public bool IsRsa => Type == "RSA";

    public string Display => Type == "oct" ? "AES-" + Size : "RSA-" + Size;

    public static KeyView From(KeyInfo key) => new(
        key.Namespace,
        key.Name,
        key.Type == KeyType.Oct ? "oct" : "RSA",
        key.Size,
        key.State.ToString(),
        key.Origin.ToString(),
        key.CreatedAt,
        key.NotAfter,
        key.LastUsedAt,
        key.WrapCount,
        key.UnwrapCount,
        key.DestroyedAt,
        key.DestroyedBy,
        NoteFor(key.State, key.NotAfter));

    private static string? NoteFor(KeyState state, DateTimeOffset? notAfter) => state switch
    {
        KeyState.Corrupt => "The stored key blob failed authentication when the key store was loaded: the keystore.json file was changed, or this process runs with a different master key. " +
            "Wrap and unwrap answer 503 HsmUnavailable for this key. The key cannot be repaired from the console: restore the original master key or keystore.json, or destroy the key.",
        KeyState.Unavailable => "The startup self-test of this key failed, so it is not used until the process restarts. Wrap and unwrap answer 503 HsmUnavailable. See the self-test on the About page.",
        KeyState.Expired => $"The expiry ({notAfter:yyyy-MM-dd HH:mm 'UTC'}) has passed: wrap and unwrap answer 403 KeyExpired, metadata still works. Clear or move the expiry to use the key again.",
        KeyState.Disabled => "Disabled: wrap and unwrap answer 403 KeyDisabled, metadata still works.",
        KeyState.Destroyed => "Destroyed (crypto-shred): the key material is gone, requests answer 404 KeyNotFound, and the name is reserved so that it cannot be reused by accident.",
        _ => null,
    };
}

/// <summary>The public half of an RSA key in the two forms the user needs, and the command that registers the key with Managed HSM. Never private parameters.</summary>
internal sealed record PublicKeyView(string Pem, string JwkN, string JwkE, string Jwk);

internal sealed record KeyDetail(KeyView Key, PublicKeyView? PublicKey, string AzCommand, string RoutingNote);

/// <summary>A key type the Keys page offers (spec 6.1): AES-256 or RSA 2048/3072/4096.</summary>
internal sealed record KeyTypeOption(string Label, string Type, int Size)
{
    public static readonly IReadOnlyList<KeyTypeOption> All =
    [
        new("AES-256", "oct", 256),
        new("RSA-2048", "RSA", 2048),
        new("RSA-3072", "RSA", 3072),
        new("RSA-4096", "RSA", 4096),
    ];
}

internal sealed record CreateKeyRequest(string Namespace, string Name, string Type, int Size, bool AllowReuseOfDestroyedName = false);

/// <summary>
/// The key management actions of the console (spec 8.5.5), shared by the Keys page and <c>/api/console/keys</c>. Every state change is audited with the acting user;
/// the typed-name confirmation of a destroy is checked here, so the REST API cannot skip it. No method returns secret or private material.
/// </summary>
internal sealed class KeyAdminService
{
    public const string AzCommandTemplate = "az keyvault key create --hsm-name <hsm> --name <ref-name> --external-key-id {0}";

    private readonly IKeyManager _keys;
    private readonly NamespaceStore _namespaces;
    private readonly AuditRecorder _audit;
    private readonly SoftwareCryptoBackendOptions _engineOptions;

    public KeyAdminService(IKeyManager keys, NamespaceStore namespaces, AuditRecorder audit, SoftwareCryptoBackendOptions engineOptions)
    {
        _keys = keys;
        _namespaces = namespaces;
        _audit = audit;
        _engineOptions = engineOptions;
    }

    /// <summary>Key import (RFC test vectors) exists only when the process started with <c>EKMMOCK_ALLOW_KEY_IMPORT=true</c> (spec 6.2). The page hides the dialog otherwise.</summary>
    public bool ImportEnabled => _engineOptions.AllowKeyImport;

    /// <summary>All keys (destroyed tombstones included), grouped by nothing: the caller groups by namespace. Sorted by namespace, then name.</summary>
    public IReadOnlyList<KeyView> List(string? ns = null)
    {
        try
        {
            return [.. _keys.List(ns).Select(KeyView.From).OrderBy(static k => k.Namespace, StringComparer.Ordinal).ThenBy(static k => k.Name, StringComparer.Ordinal)];
        }
        catch (EkmEngineException exception)
        {
            throw ConsoleActionException.From(exception);
        }
    }

    public KeyDetail Get(string ns, string name)
    {
        var info = Find(ns, name);
        var view = KeyView.From(info);
        return new KeyDetail(view, info.PublicKey is { } rsa ? BuildPublicKey(rsa) : null, AzCommand(name), RoutingNote(ns));
    }

    public KeyView Create(string actor, CreateKeyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var ns = RequireNamespace(request.Namespace);
        if (!EkmNames.IsValidKeyName(request.Name))
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The key name must be 1 to 64 characters of letters, digits and '-' (spec 4.2).");
        }

        var type = ParseType(request.Type);
        KeyInfo created;
        try
        {
            created = _keys.Create(ns.Name, request.Name, type, request.Size, request.AllowReuseOfDestroyedName);
        }
        catch (EkmEngineException exception)
        {
            throw ConsoleActionException.From(exception);
        }

        _audit.Record(actor, AuditActions.KeyCreate, Target(ns.Name, request.Name), $"type={KeyView.From(created).Display}{(request.AllowReuseOfDestroyedName ? " reuse_destroyed_name=true" : string.Empty)}");
        return KeyView.From(created);
    }

    /// <summary>
    /// Imports key material for test vectors. <paramref name="material"/> is the raw AES key (32 bytes) or an RSA PKCS#8 private key; it is passed to the engine and
    /// <b>never</b> stored, echoed, logged or written to the audit log (the entry says only type and size). The caller owns the buffer and should zero it; this method
    /// does not keep a reference.
    /// </summary>
    public KeyView Import(string actor, string ns, string name, KeyType type, ReadOnlySpan<byte> material, bool allowReuseOfDestroyedName = false)
    {
        if (!ImportEnabled)
        {
            throw new ConsoleActionException(ConsoleErrorCode.Forbidden, "Key import is switched off. Start the process with EKMMOCK_ALLOW_KEY_IMPORT=true to import test vectors.");
        }

        var target = RequireNamespace(ns);
        if (!EkmNames.IsValidKeyName(name))
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The key name must be 1 to 64 characters of letters, digits and '-' (spec 4.2).");
        }

        KeyInfo imported;
        try
        {
            imported = _keys.Import(target.Name, name, type, material, allowReuseOfDestroyedName);
        }
        catch (EkmEngineException exception)
        {
            throw ConsoleActionException.From(exception);
        }
        catch (CryptographicException)
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The key material is not valid for this key type.");
        }

        var view = KeyView.From(imported);
        _audit.Record(actor, AuditActions.KeyImport, Target(target.Name, name), $"type={view.Display} origin=Imported");
        return view;
    }

    public KeyView SetEnabled(string actor, string ns, string name, bool enabled)
    {
        var key = new KeyRef(ns, name);
        try
        {
            _keys.SetEnabled(key, enabled);
        }
        catch (EkmEngineException exception)
        {
            throw ConsoleActionException.From(exception);
        }

        _audit.Record(actor, enabled ? AuditActions.KeyEnable : AuditActions.KeyDisable, Target(ns, name));
        return KeyView.From(Find(ns, name));
    }

    /// <summary>Sets (or clears, with null) the expiry. A date in the past is allowed on purpose: it is the way to test the <c>403 KeyExpired</c> path.</summary>
    public KeyView SetExpiry(string actor, string ns, string name, DateTimeOffset? notAfter)
    {
        var key = new KeyRef(ns, name);
        try
        {
            _keys.SetExpiry(key, notAfter);
        }
        catch (EkmEngineException exception)
        {
            throw ConsoleActionException.From(exception);
        }

        _audit.Record(
            actor,
            notAfter is null ? AuditActions.KeyExpiryClear : AuditActions.KeyExpirySet,
            Target(ns, name),
            notAfter is null ? null : "not_after=" + notAfter.Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
        return KeyView.From(Find(ns, name));
    }

    /// <summary>Irreversible crypto-shred. <paramref name="confirmName"/> must equal the key name exactly (case-sensitive); that is enforced here and not only in the dialog.</summary>
    public KeyView Destroy(string actor, string ns, string name, string? confirmName)
    {
        var info = Find(ns, name);
        if (info.State == KeyState.Destroyed)
        {
            throw new ConsoleActionException(ConsoleErrorCode.Conflict, "This key is already destroyed.");
        }

        if (!string.Equals(confirmName, name, StringComparison.Ordinal))
        {
            throw new ConsoleActionException(ConsoleErrorCode.ConfirmationMismatch, "Type the exact key name to confirm that it is destroyed. Nothing was changed.");
        }

        try
        {
            _keys.Destroy(new KeyRef(ns, name), actor);
        }
        catch (EkmEngineException exception)
        {
            throw ConsoleActionException.From(exception);
        }

        _audit.Record(actor, AuditActions.KeyDestroy, Target(ns, name), "irreversible crypto-shred");
        return KeyView.From(Find(ns, name));
    }

    /// <summary>The exact command that registers the key (spec 8.5.5). <c>&lt;hsm&gt;</c> and <c>&lt;ref-name&gt;</c> are placeholders the user fills in.</summary>
    public static string AzCommand(string keyName, string hsm = "<hsm>", string refName = "<ref-name>")
        => string.Format(System.Globalization.CultureInfo.InvariantCulture, AzCommandTemplate, keyName).Replace("<hsm>", hsm, StringComparison.Ordinal).Replace("<ref-name>", refName, StringComparison.Ordinal);

    /// <summary>The RSA public key as SubjectPublicKeyInfo PEM and as JWK <c>n</c>/<c>e</c>. Built from the public numbers only.</summary>
    public static PublicKeyView BuildPublicKey(RsaPublicKey key)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = key.Modulus.ToArray(), Exponent = key.Exponent.ToArray() });
        var n = System.Buffers.Text.Base64Url.EncodeToString(key.Modulus.Span);
        var e = System.Buffers.Text.Base64Url.EncodeToString(key.Exponent.Span);
        var jwk = $$"""{"kty":"RSA","n":"{{n}}","e":"{{e}}"}""";
        return new PublicKeyView(rsa.ExportSubjectPublicKeyInfoPem(), n, e, jwk);
    }

    private string RoutingNote(string ns)
    {
        var definition = _namespaces.Get(ns);
        return definition is null
            ? $"Namespace '{ns}' is not defined, so no EKM request can reach this key."
            : definition.Prefix.Length == 0
                ? "Reached on the connection without --path-prefix (namespace _default)."
                : $"Reached on the connection created with --path-prefix /{definition.Prefix}.";
    }

    private KeyInfo Find(string ns, string name)
    {
        try
        {
            return _keys.Get(new KeyRef(ns, name)) ?? throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Key not found.");
        }
        catch (EkmEngineException exception)
        {
            throw ConsoleActionException.From(exception);
        }
    }

    private NamespaceDefinition RequireNamespace(string? ns)
        => !string.IsNullOrEmpty(ns) && _namespaces.Get(ns) is { } definition
            ? definition
            : throw new ConsoleActionException(ConsoleErrorCode.NotFound, "Namespace not found. Create the namespace first.");

    private static KeyType ParseType(string? type) => type?.ToLowerInvariant() switch
    {
        "oct" or "aes" => KeyType.Oct,
        "rsa" => KeyType.Rsa,
        _ => throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The key type must be 'oct' (AES-256) or 'RSA' (2048, 3072 or 4096 bits)."),
    };

    private static string Target(string ns, string name) => $"key:{ns}/{name}";
}

/// <summary>Parses the key material of the gated import dialog (hex or base64url for AES, PEM or base64 PKCS#8 for RSA) into a buffer the caller must zero.</summary>
internal static class KeyMaterialInput
{
    /// <summary>Returns the decoded bytes or null when the text is not valid for the type. The text is never echoed in an error.</summary>
    public static byte[]? TryDecode(KeyType type, string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var trimmed = text.Trim();
        try
        {
            if (type == KeyType.Oct)
            {
                if (trimmed.Length == 64 && trimmed.All(Uri.IsHexDigit))
                {
                    return Convert.FromHexString(trimmed);
                }

                var buffer = new byte[Base64UrlLength(trimmed.Length)];
                var utf8 = Encoding.ASCII.GetBytes(trimmed);
                try
                {
                    return Ekm.Base64UrlCodec.TryDecode(utf8, buffer, out var written) ? buffer[..written] : null;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(utf8);
                    CryptographicOperations.ZeroMemory(buffer);
                }
            }

            var pem = trimmed.Contains("-----BEGIN", StringComparison.Ordinal);
            if (pem)
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem(trimmed);
                return rsa.ExportPkcs8PrivateKey();
            }

            return Convert.FromBase64String(trimmed);
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException or ArgumentException)
        {
            return null;
        }
    }

    private static int Base64UrlLength(int chars) => Ekm.Base64UrlCodec.MaxDecodedLength(Math.Max(chars, 4)) + 4;
}
