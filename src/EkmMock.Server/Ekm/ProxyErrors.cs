using EkmMock.Crypto;

namespace EkmMock.Server.Ekm;

/// <summary>
/// Every <c>code</c> the EKM endpoint can put in a ProxyError body (spec 4.4). The status per code and the mapping
/// from engine failures live in <see cref="ProxyErrors"/> and nowhere else.
/// </summary>
internal enum ProxyErrorCode
{
    InvalidRequest,
    InvalidKeyName,
    UnsupportedApiVersion,
    UnsupportedAlgorithm,
    InvalidCiphertext,
    Unauthenticated,
    KeyDisabled,
    KeyExpired,
    OperationNotAllowed,
    KeyNotFound,

    /// <summary>Unknown prefix, unknown operation or extra path segments (spec 4.2).</summary>
    NotFound,

    /// <summary>Anything but POST (spec 4.1). The spec gives the status but no code; this name is a decision (DECISIONS.md).</summary>
    MethodNotAllowed,

    TooManyRequests,
    HsmUnavailable,
    InternalError,
}

/// <summary>A request that cannot be served. Messages are string literals chosen at the throw site: never input, never key material.</summary>
internal sealed class EkmProtocolException : Exception
{
    public EkmProtocolException(ProxyErrorCode code, string? message = null)
        : base(message ?? ProxyErrors.DefaultMessage(code, null))
    {
        Code = code;
    }

    public ProxyErrorCode Code { get; }
}

/// <summary>The wire body of every error (spec 4.4). Serialised snake_case by <see cref="EkmJsonContext"/>.</summary>
internal sealed record ProxyError(string Code, string Message);

/// <summary>The outcome of mapping an exception: what goes on the wire, plus the exception type name if it was unexpected.</summary>
internal readonly record struct MappedError(int StatusCode, ProxyErrorCode Code, string Message, string? UnexpectedExceptionType);

/// <summary>
/// The single place that turns failures into HTTP. <see cref="StatusOf"/> is the status table of spec 4.4,
/// <see cref="FromEngine"/> the only engine-kind to wire-code mapping, and <see cref="Map"/> the safety net that
/// guarantees that whatever is thrown, the client sees a ProxyError and never an exception message.
/// </summary>
internal static class ProxyErrors
{
    public static int StatusOf(ProxyErrorCode code) => code switch
    {
        ProxyErrorCode.InvalidRequest => StatusCodes.Status400BadRequest,
        ProxyErrorCode.InvalidKeyName => StatusCodes.Status400BadRequest,
        ProxyErrorCode.UnsupportedApiVersion => StatusCodes.Status400BadRequest,
        ProxyErrorCode.UnsupportedAlgorithm => StatusCodes.Status400BadRequest,
        ProxyErrorCode.InvalidCiphertext => StatusCodes.Status400BadRequest,
        ProxyErrorCode.Unauthenticated => StatusCodes.Status401Unauthorized,
        ProxyErrorCode.KeyDisabled => StatusCodes.Status403Forbidden,
        ProxyErrorCode.KeyExpired => StatusCodes.Status403Forbidden,
        ProxyErrorCode.OperationNotAllowed => StatusCodes.Status403Forbidden,
        ProxyErrorCode.KeyNotFound => StatusCodes.Status404NotFound,
        ProxyErrorCode.NotFound => StatusCodes.Status404NotFound,
        ProxyErrorCode.MethodNotAllowed => StatusCodes.Status405MethodNotAllowed,
        ProxyErrorCode.TooManyRequests => StatusCodes.Status429TooManyRequests,
        ProxyErrorCode.HsmUnavailable => StatusCodes.Status503ServiceUnavailable,
        ProxyErrorCode.InternalError => StatusCodes.Status500InternalServerError,
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, null),
    };

    /// <summary>Engine failure kind to wire code. Kinds that cannot arise from a wrap/unwrap/metadata request become InternalError.</summary>
    public static ProxyErrorCode FromEngine(EkmErrorKind kind) => kind switch
    {
        EkmErrorKind.KeyNotFound => ProxyErrorCode.KeyNotFound,
        EkmErrorKind.KeyDisabled => ProxyErrorCode.KeyDisabled,
        EkmErrorKind.KeyExpired => ProxyErrorCode.KeyExpired,
        EkmErrorKind.UnsupportedAlgorithm => ProxyErrorCode.UnsupportedAlgorithm,
        EkmErrorKind.InvalidInput => ProxyErrorCode.InvalidRequest,
        EkmErrorKind.InvalidCiphertext => ProxyErrorCode.InvalidCiphertext,
        EkmErrorKind.HsmUnavailable => ProxyErrorCode.HsmUnavailable,
        EkmErrorKind.InvalidKeyName => ProxyErrorCode.InvalidKeyName,
        EkmErrorKind.OperationNotAllowed => ProxyErrorCode.OperationNotAllowed,
        EkmErrorKind.KeyAlreadyExists => ProxyErrorCode.InternalError,
        EkmErrorKind.KeyNameReserved => ProxyErrorCode.InternalError,
        EkmErrorKind.InternalError => ProxyErrorCode.InternalError,
        _ => ProxyErrorCode.InternalError,
    };

    /// <summary>Fixed, input-free message for a code. <paramref name="operation"/> only personalises KeyDisabled/KeyExpired (Learn's example wording).</summary>
    public static string DefaultMessage(ProxyErrorCode code, EkmOperation? operation) => code switch
    {
        ProxyErrorCode.InvalidRequest => "The request is not valid",
        ProxyErrorCode.InvalidKeyName => "The key name is not valid",
        ProxyErrorCode.UnsupportedApiVersion => "The api-version query parameter is missing or not supported",
        ProxyErrorCode.UnsupportedAlgorithm => "The algorithm is not supported for this key",
        ProxyErrorCode.InvalidCiphertext => "The wrapped value could not be unwrapped",
        ProxyErrorCode.Unauthenticated => "Authentication failed",
        ProxyErrorCode.KeyDisabled => $"Operation {operation.DisplayName()} is not allowed on a disabled key",
        ProxyErrorCode.KeyExpired => $"Operation {operation.DisplayName()} is not allowed on an expired key",
        ProxyErrorCode.OperationNotAllowed => "The operation is not allowed",
        ProxyErrorCode.KeyNotFound => "The key was not found",
        ProxyErrorCode.NotFound => "The requested resource was not found",
        ProxyErrorCode.MethodNotAllowed => "Only POST is supported",
        ProxyErrorCode.TooManyRequests => "Too many requests",
        ProxyErrorCode.HsmUnavailable => "The HSM is unavailable",
        ProxyErrorCode.InternalError => "An internal error occurred",
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, null),
    };

    /// <summary>
    /// Maps anything thrown while serving an EKM request. Engine and protocol exceptions are expected; the
    /// exception <em>message</em> is never copied to the client. Anything else is an unexpected failure: a generic
    /// 500 and only the exception type name is reported (for the log).
    /// </summary>
    public static MappedError Map(Exception exception, EkmOperation? operation)
    {
        switch (exception)
        {
            case EkmProtocolException protocol:
                return new MappedError(StatusOf(protocol.Code), protocol.Code, protocol.Message, null);

            case EkmEngineException engine:
                var code = FromEngine(engine.Kind);
                return new MappedError(
                    StatusOf(code),
                    code,
                    DefaultMessage(code, operation),
                    code == ProxyErrorCode.InternalError ? engine.GetType().Name : null);

            case BadHttpRequestException:
                // Transport level rejections (malformed chunking, a host-enforced body limit, header timeouts).
                return new MappedError(StatusCodes.Status400BadRequest, ProxyErrorCode.InvalidRequest, DefaultMessage(ProxyErrorCode.InvalidRequest, operation), null);

            default:
                return new MappedError(
                    StatusCodes.Status500InternalServerError,
                    ProxyErrorCode.InternalError,
                    DefaultMessage(ProxyErrorCode.InternalError, operation),
                    exception.GetType().Name);
        }
    }
}
