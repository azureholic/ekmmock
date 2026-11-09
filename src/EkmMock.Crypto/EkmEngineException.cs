namespace EkmMock.Crypto;

/// <summary>
/// Failure categories of the crypto engine. The names equal the EKM <c>ProxyError.code</c> values
/// where one exists, so the server maps kind to HTTP status in exactly one place.
/// </summary>
public enum EkmErrorKind
{
    KeyNotFound,
    KeyDisabled,
    KeyExpired,
    UnsupportedAlgorithm,

    /// <summary>The plaintext/DEK handed to wrap (or a management argument) is not acceptable.</summary>
    InvalidInput,

    /// <summary>Unwrap failed: wrong key, tampered or malformed wrapped value.</summary>
    InvalidCiphertext,

    /// <summary>Engine or this key is unavailable (store not loaded, corrupt key, self-test failure).</summary>
    HsmUnavailable,

    InvalidKeyName,
    KeyAlreadyExists,

    /// <summary>The name belongs to a destroyed key and may not be reused without an explicit override.</summary>
    KeyNameReserved,

    /// <summary>An operation that is switched off, for example key import.</summary>
    OperationNotAllowed,

    InternalError,
}

/// <summary>
/// Typed engine failure. Messages are fixed strings and never contain key material,
/// plaintext, wrapped values or inner exception details.
/// </summary>
public sealed class EkmEngineException : Exception
{
    public EkmEngineException(EkmErrorKind kind, string message, KeyRef? key = null)
        : base(message)
    {
        Kind = kind;
        Key = key;
    }

    public EkmErrorKind Kind { get; }

    public KeyRef? Key { get; }

    /// <summary>The wire <c>code</c> string for this failure.</summary>
    public string Code => Kind.ToString();

    internal static EkmEngineException KeyNotFound(KeyRef key) => new(EkmErrorKind.KeyNotFound, "Key not found", key);

    internal static EkmEngineException KeyDisabled(KeyRef key, string operation)
        => new(EkmErrorKind.KeyDisabled, $"Operation {operation} is not allowed on a disabled key", key);

    internal static EkmEngineException KeyExpired(KeyRef key, string operation)
        => new(EkmErrorKind.KeyExpired, $"Operation {operation} is not allowed on an expired key", key);

    internal static EkmEngineException UnsupportedAlgorithm(KeyRef? key = null)
        => new(EkmErrorKind.UnsupportedAlgorithm, "Algorithm is not supported for this key", key);

    internal static EkmEngineException InvalidInput(string message, KeyRef? key = null)
        => new(EkmErrorKind.InvalidInput, message, key);

    internal static EkmEngineException InvalidCiphertext(KeyRef? key = null)
        => new(EkmErrorKind.InvalidCiphertext, "The wrapped value could not be unwrapped", key);

    internal static EkmEngineException HsmUnavailable(string message, KeyRef? key = null)
        => new(EkmErrorKind.HsmUnavailable, message, key);
}
