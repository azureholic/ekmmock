using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Ekm;

/// <summary>
/// The four EKM operations (spec 4.6 to 4.10) over <see cref="ICryptoBackend"/>. Crypto is called synchronously and is
/// never wrapped in a Task; only the HTTP I/O around it is async. Handlers throw <see cref="EkmProtocolException"/> or let
/// <see cref="EkmEngineException"/> propagate: the exchange middleware maps both in one place (<see cref="ProxyErrors"/>).
/// </summary>
internal sealed class EkmHandlers
{
    private static readonly string[] KeyOps = ["wrapKey", "unwrapKey"];

    private readonly IOptions<ProxyInfoOptions> _proxyInfo;
    private readonly ICryptoBackend _backend;

    public EkmHandlers(IOptions<ProxyInfoOptions> proxyInfo, ICryptoBackend backend)
    {
        _proxyInfo = proxyInfo;
        _backend = backend;
    }

    public Task InfoAsync(HttpContext context)
    {
        var info = _proxyInfo.Value;
        return EkmResponse.WriteJsonAsync(
            context,
            StatusCodes.Status200OK,
            new ProxyInfoResponse(info.ApiVersion, info.ProxyVendor, info.ProxyName, info.EkmVendor, info.EkmProduct),
            EkmJsonContext.Default.ProxyInfoResponse,
            context.RequestAborted);
    }

    public Task MetadataAsync(HttpContext context, KeyRef key, EkmRequestContext exchange)
    {
        var started = Stopwatch.GetTimestamp();
        KeyMetadata metadata;
        try
        {
            // Unknown or destroyed keys are null (404). Disabled and expired keys still answer 200 (open question 3).
            // A corrupt key throws HsmUnavailable (503).
            metadata = _backend.GetMetadata(key) ?? throw new EkmProtocolException(ProxyErrorCode.KeyNotFound);
        }
        finally
        {
            exchange.CryptoElapsed = Stopwatch.GetElapsedTime(started);
        }

        var response = metadata.Type == KeyType.Rsa && metadata.PublicKey is { } publicKey
            ? new KeyMetadataResponse(
                "RSA",
                metadata.Size,
                KeyOps,
                Base64UrlEncode(publicKey.Modulus.Span),
                Base64UrlEncode(publicKey.Exponent.Span))
            : new KeyMetadataResponse("oct", metadata.Size, KeyOps, null, null);

        return EkmResponse.WriteJsonAsync(context, StatusCodes.Status200OK, response, EkmJsonContext.Default.KeyMetadataResponse, context.RequestAborted);
    }

    public Task WrapAsync(HttpContext context, KeyRef key, EkmRequestContext exchange, EkmRequestBody body)
        => WrapOrUnwrapAsync(context, key, exchange, body, wrap: true);

    public Task UnwrapAsync(HttpContext context, KeyRef key, EkmRequestContext exchange, EkmRequestBody body)
        => WrapOrUnwrapAsync(context, key, exchange, body, wrap: false);

    private async Task WrapOrUnwrapAsync(HttpContext context, KeyRef key, EkmRequestContext exchange, EkmRequestBody body, bool wrap)
    {
        // The synchronous part holds the DEK in spans and rented buffers; nothing secret lives across an await except
        // the finished response buffer, which is zeroed in the finally block below.
        var (response, length) = Execute(key, exchange, body, wrap);
        try
        {
            await EkmResponse.WriteBytesAsync(context, StatusCodes.Status200OK, response.AsMemory(0, length), context.RequestAborted).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(response.AsSpan(0, length));
            ArrayPool<byte>.Shared.Return(response);
        }
    }

    private (byte[] Response, int Length) Execute(KeyRef key, EkmRequestContext exchange, EkmRequestBody body, bool wrap)
    {
        // Syntax first (spec 4.4 "400 InvalidRequest"), then the engine decides about key existence, state and algorithm fit.
        if (body.HasInvalidAlgorithm)
        {
            throw new EkmProtocolException(ProxyErrorCode.InvalidRequest, "The alg field must be a string");
        }

        if (body.Algorithm is null)
        {
            throw new EkmProtocolException(ProxyErrorCode.InvalidRequest, "The alg field is required");
        }

        if (!WrapAlgorithms.TryParse(body.Algorithm, out var algorithm))
        {
            throw new EkmProtocolException(ProxyErrorCode.UnsupportedAlgorithm);
        }

        if (body.HasInvalidValue)
        {
            throw new EkmProtocolException(ProxyErrorCode.InvalidRequest, "The value field must be a string");
        }

        if (!body.HasValue)
        {
            throw new EkmProtocolException(ProxyErrorCode.InvalidRequest, "The value field is required");
        }

        var encoded = body.ValueUtf8;
        var input = ArrayPool<byte>.Shared.Rent(Math.Max(1, Base64UrlCodec.MaxDecodedLength(encoded.Length)));
        var inputLength = 0;
        byte[]? output = null;
        try
        {
            if (!Base64UrlCodec.TryDecode(encoded, input, out inputLength))
            {
                throw new EkmProtocolException(ProxyErrorCode.InvalidRequest, "The value field is not valid base64url");
            }

            var started = Stopwatch.GetTimestamp();
            try
            {
                output = wrap
                    ? _backend.Wrap(key, algorithm, input.AsSpan(0, inputLength))
                    : _backend.Unwrap(key, algorithm, input.AsSpan(0, inputLength));
            }
            finally
            {
                exchange.CryptoElapsed = Stopwatch.GetElapsedTime(started);
            }

            var response = ArrayPool<byte>.Shared.Rent(EkmResponse.ValueBodyLength(output.Length));
            var length = EkmResponse.BuildValueBody(output, response);
            return (response, length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input); // the whole rented array: a failed decode may have left partial bytes
            ArrayPool<byte>.Shared.Return(input);
            if (output is not null)
            {
                // After unwrap this is the plaintext DEK.
                CryptographicOperations.ZeroMemory(output);
            }
        }
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes) => System.Buffers.Text.Base64Url.EncodeToString(bytes);
}
