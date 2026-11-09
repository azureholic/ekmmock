using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using Microsoft.Net.Http.Headers;

namespace EkmMock.Server.Ekm;

/// <summary>
/// The last stage of the EKM pipeline: the request checks in their documented order (DECISIONS.md "EKM validation order")
/// and then the operation handler. Everything that can go wrong is thrown and mapped by <see cref="EkmExchangeMiddleware"/>.
/// <para>
/// Pipeline (spec 7): <c>Exchange (capture, safety net, log) → Route → [Faults M7] → [Auth M3] → [Limits M7] → Dispatcher → ICryptoBackend</c>.
/// Auth, Faults and Limits slot in between <c>Route</c> and the dispatcher; see <see cref="EkmPipeline"/>.
/// </para>
/// </summary>
internal sealed class EkmDispatcher
{
    private readonly EkmHandlers _handlers;
    private readonly IEngineAvailability _availability;

    public EkmDispatcher(EkmHandlers handlers, IEngineAvailability availability)
    {
        _handlers = handlers;
        _availability = availability;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var exchange = context.GetEkmContext();
        var route = exchange.Route ?? throw new EkmProtocolException(ProxyErrorCode.NotFound);
        var request = context.Request;

        // 2. Method (404 for an unroutable path already happened in the routing middleware).
        if (!string.Equals(request.Method, HttpMethods.Post, StringComparison.Ordinal))
        {
            throw new EkmProtocolException(ProxyErrorCode.MethodNotAllowed);
        }

        // 3. api-version.
        RequireSupportedApiVersion(request);
        exchange.ApiVersion = EkmApi.SupportedApiVersion;

        // 4. Key name (key operations only), before anything is read from the body.
        if (route.Operation != EkmOperation.Info && !EkmNames.IsValidKeyName(route.KeyName))
        {
            throw new EkmProtocolException(ProxyErrorCode.InvalidKeyName);
        }

        // 5. Content-Type.
        RequireJsonContentType(request);

        // 6. Body: size, JSON, request_context.
        using var body = await EkmRequestBody.ReadAsync(request, EkmRequestBody.MaxBodyBytes, context.RequestAborted).ConfigureAwait(false);
        exchange.RequestBodyBytes = body.Length;
        exchange.RequestId = body.RequestId;
        exchange.CorrelationId = body.CorrelationId;
        exchange.PoolName = body.PoolName;
        exchange.Algorithm = body.Algorithm is null ? null : WrapAlgorithms.TryParse(body.Algorithm, out _) ? body.Algorithm : "unsupported";
        if (!body.HasRequestContext)
        {
            throw new EkmProtocolException(ProxyErrorCode.InvalidRequest, "The request_context field is required");
        }

        // 7. Engine availability (info and all key operations).
        if (!_availability.IsAvailable)
        {
            throw new EkmProtocolException(ProxyErrorCode.HsmUnavailable);
        }

        // 8. The operation itself (alg, value, engine checks).
        var key = new KeyRef(route.Namespace.Name, route.KeyName ?? string.Empty);
        switch (route.Operation)
        {
            case EkmOperation.Info:
                await _handlers.InfoAsync(context).ConfigureAwait(false);
                break;
            case EkmOperation.Metadata:
                await _handlers.MetadataAsync(context, key, exchange).ConfigureAwait(false);
                break;
            case EkmOperation.WrapKey:
                await _handlers.WrapAsync(context, key, exchange, body).ConfigureAwait(false);
                break;
            case EkmOperation.UnwrapKey:
                await _handlers.UnwrapAsync(context, key, exchange, body).ConfigureAwait(false);
                break;
            default:
                throw new EkmProtocolException(ProxyErrorCode.NotFound);
        }
    }

    private static void RequireSupportedApiVersion(HttpRequest request)
    {
        if (!request.Query.TryGetValue(EkmApi.ApiVersionQueryParameter, out var values)
            || values.Count != 1
            || !string.Equals(values[0], EkmApi.SupportedApiVersion, StringComparison.Ordinal))
        {
            throw new EkmProtocolException(ProxyErrorCode.UnsupportedApiVersion);
        }
    }

    private static void RequireJsonContentType(HttpRequest request)
    {
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType)
            || !contentType.MediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase)
            || (contentType.Charset.HasValue && !contentType.Charset.Equals("utf-8", StringComparison.OrdinalIgnoreCase)))
        {
            throw new EkmProtocolException(ProxyErrorCode.InvalidRequest, "The Content-Type must be application/json");
        }
    }
}
