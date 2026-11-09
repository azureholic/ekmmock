using System.Diagnostics;
using System.Net;
using EkmMock.Crypto;
using EkmMock.Server.Connections;
using EkmMock.Server.Ekm;
using EkmMock.Server.Hosting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Inspector;

/// <summary>What the request path hands to the consumer: the masked record and, only when reveal is allowed, the raw bodies that belong to it.</summary>
internal sealed record CapturedExchange(ExchangeRecord Record, RetainedSecrets? Secrets);

/// <summary>Counters and an optional observer of the capture middleware itself (the benchmark uses the observer; production leaves it null).</summary>
internal sealed class CaptureDiagnostics
{
    private long _captured;
    private long _failures;

    /// <summary>Told, for every exchange, how many <see cref="Stopwatch"/> ticks the capture itself used (excluding the time the pipeline took).</summary>
    public ICaptureOverheadObserver? Observer { get; set; }

    public long Captured => Interlocked.Read(ref _captured);

    /// <summary>Exchanges that could not be captured because capturing itself failed (never because of the request).</summary>
    public long Failures => Interlocked.Read(ref _failures);

    public void RecordCaptured() => Interlocked.Increment(ref _captured);

    public long RecordFailure() => Interlocked.Increment(ref _failures);
}

internal interface ICaptureOverheadObserver
{
    void Observe(long overheadTicks);
}

/// <summary>
/// The per-exchange state of the capture: the two side buffers, the sealed (masked) request body and the optional raw copies. Created by
/// <see cref="InspectorCaptureMiddleware"/>, owned by one request, never shared.
/// </summary>
internal sealed class ExchangeCaptureSession
{
    /// <summary>How long the capture waits for the rest of a request body that the pipeline never read (a rejected request). It only bounds the extra time the connection is held.</summary>
    public static readonly TimeSpan DrainTimeout = TimeSpan.FromMilliseconds(100);

    private const int DrainScratchBytes = 4096;

    private readonly HttpContext _context;
    private readonly bool _revealAllowed;
    private long _overheadTicks;
    private bool _requestSealed;

    public ExchangeCaptureSession(HttpContext context, bool revealAllowed)
    {
        _context = context;
        _revealAllowed = revealAllowed;
    }

    public CaptureBuffer RequestBuffer { get; } = new();

    public CaptureBuffer ResponseBuffer { get; } = new();

    public bool RequestEnded { get; private set; }

    /// <summary>Set once the request body has been judged and its raw copy released.</summary>
    public CapturedBody? RequestBody { get; private set; }

    /// <summary>The raw request body, kept only when reveal is allowed and the body is complete.</summary>
    public byte[]? RetainedRequestBody { get; private set; }

    public (string? RequestId, string? CorrelationId, string? PoolName) BodyContext { get; private set; }

    public long OverheadTicks => _overheadTicks;

    public void AddOverhead(long startedTimestamp) => _overheadTicks += Stopwatch.GetTimestamp() - startedTimestamp;

    /// <summary>Called by the request stream when it reaches the end of the body: the request is masked now and the raw copy released. It runs on the request path (inside a read of the pipeline), so it must never throw.</summary>
    public void RequestBodyEnded()
    {
        RequestEnded = true;
        try
        {
            SealRequest();
        }
        catch (Exception)
        {
            // The capture failed, the request must not: record that the body is not available and carry on.
            RequestBody ??= new CapturedBody { SizeBytes = RequestBuffer.Total, Captured = false, Note = "The inspector could not process this body." };
            RetainedRequestBody = null;
        }
    }

    public void SealRequest()
    {
        if (_requestSealed)
        {
            return;
        }

        _requestSealed = true;
        try
        {
            var exchange = _context.TryGetEkmContext();
            var position = BodyPositions.For(exchange?.Operation, isRequest: true);
            var buffer = RequestBuffer;
            var size = Math.Max(buffer.Total, _context.Request.ContentLength ?? 0);
            RequestBody = BodyRedactor.Redact(buffer.Span, size, buffer.Truncated, position, _revealAllowed);
            if (!buffer.Truncated && buffer.Total > 0)
            {
                BodyContext = BodyRedactor.ExtractRequestContext(buffer.Span);
            }

            if (_revealAllowed && !buffer.Truncated)
            {
                RetainedRequestBody = buffer.Span.ToArray();
            }
        }
        finally
        {
            RequestBuffer.Release();
        }
    }

    /// <summary>
    /// Reads what is left of a request body that the pipeline did not read (a request rejected before its body was needed: 401, 404, 405), bounded by
    /// 16 KiB and <see cref="DrainTimeout"/>, so that rejected requests are captured with their body. It reads through the capturing stream; any failure
    /// (a client that is too slow, Kestrel's own size error) simply ends the capture of the body, never the request.
    /// </summary>
    public async Task DrainRequestAsync(Stream capturingRequestBody, CancellationToken requestAborted)
    {
        if (_requestSealed)
        {
            return;
        }

        if (_context.Request.ContentLength == 0 || requestAborted.IsCancellationRequested)
        {
            SealRequest();
            return;
        }

        var scratch = System.Buffers.ArrayPool<byte>.Shared.Rent(DrainScratchBytes);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(requestAborted);
            timeout.CancelAfter(DrainTimeout);
            while (!_requestSealed && RequestBuffer.Total <= BodyRedactor.MaxCaptureBytes)
            {
                if (await capturingRequestBody.ReadAsync(scratch.AsMemory(), timeout.Token).ConfigureAwait(false) == 0)
                {
                    break;
                }
            }
        }
        catch (Exception)
        {
            // Timeout, client gone, body too large: the body is whatever was captured until now.
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(scratch);
            System.Buffers.ArrayPool<byte>.Shared.Return(scratch);
            SealRequest();
        }
    }

    /// <summary>Zeroes the retained raw request body of an exchange that will not be handed to the consumer.</summary>
    public void DiscardRetained()
    {
        if (RetainedRequestBody is { } raw)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(raw);
            RetainedRequestBody = null;
        }
    }

    public void ReleaseBuffers()
    {
        RequestBuffer.Release();
        ResponseBuffer.Release();
    }
}

/// <summary>Builds the <see cref="ExchangeRecord"/> of a finished exchange from what the pipeline reported and what the session captured.</summary>
internal sealed class ExchangeRecordFactory
{
    private const int MaxHeaders = 64;
    private const int MaxHeaderValueLength = 1024;
    private const int MaxTargetLength = 2048;

    private static readonly HashSet<string> SensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "Api-Key", "X-Auth-Token",
    };

    private readonly LimitsOptions _limits;
    private readonly IKeyManager _keys;
    private readonly bool _revealAllowed;

    public ExchangeRecordFactory(IOptions<LimitsOptions> limits, IKeyManager keys, IInspectorRevealGate revealGate)
    {
        _limits = limits.Value;
        _keys = keys;
        _revealAllowed = revealGate.IsAllowed;
    }

    public CapturedExchange Create(HttpContext context, EkmRequestContext exchange, ExchangeCaptureSession session)
    {
        var request = context.Request;
        var response = context.Response;

        // The response body: masked on an unwrap response (the plaintext DEK), shown as it is otherwise.
        var responsePosition = BodyPositions.For(exchange.Operation, isRequest: false);
        var responseBuffer = session.ResponseBuffer;
        var responseBody = BodyRedactor.Redact(responseBuffer.Span, responseBuffer.Total, responseBuffer.Truncated, responsePosition, _revealAllowed);
        byte[]? retainedResponse = _revealAllowed && responsePosition == BodyPosition.SecretResponse && !responseBuffer.Truncated && responseBuffer.Total > 0
            ? responseBuffer.Span.ToArray()
            : null;

        var requestBody = session.RequestBody ?? CapturedBody.Empty;
        var (bodyRequestId, bodyCorrelationId, bodyPoolName) = session.BodyContext;
        var status = exchange.StatusCode;

        var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(rawTarget))
        {
            // The in-process test host does not set it; the path as the pipeline sees it is the best available.
            rawTarget = request.Path.Value + request.QueryString.Value;
        }

        var record = new ExchangeRecord
        {
            Identity = new ExchangeIdentity(exchange.ExchangeId, exchange.ConnectionId, TruncateToMicroseconds(exchange.ReceivedAtUtc), RemoteEndPoint(context, exchange)),
            Tls = TlsOf(exchange),
            ClientCertificate = ClientCertificateOf(context, exchange),
            Request = new RequestFacts
            {
                Method = request.Method,
                HttpVersion = request.Protocol,
                RawTarget = Bound(rawTarget, MaxTargetLength),
                Prefix = exchange.Route?.Namespace.Prefix,
                Namespace = exchange.NamespaceName,
                Key = Bound(exchange.KeyName, EkmNames.MaxKeyNameLength + 16),
                Operation = exchange.Operation?.WireName(),
                ApiVersion = Bound(request.Query.TryGetValue(EkmApi.ApiVersionQueryParameter, out var versions) ? versions.ToString() : null, 64),
                Headers = HeadersOf(request.Headers),
                Body = requestBody,
            },
            Context = new EkmContextFacts(
                exchange.RequestId ?? bodyRequestId,
                exchange.CorrelationId ?? bodyCorrelationId,
                exchange.PoolName ?? bodyPoolName,
                exchange.Algorithm),
            Response = new ResponseFacts
            {
                Status = status,
                Code = exchange.ErrorCode,
                Headers = HeadersOf(response.Headers),
                Body = responseBody,
                ClientAborted = exchange.ClientAborted,
            },
            Timing = new TimingFacts
            {
                TotalMs = Ms(exchange.Duration),
                AuthMs = Ms(exchange.AuthElapsed),
                CryptoMs = Ms(exchange.CryptoElapsed),
                InjectedDelayMs = Ms(exchange.InjectedDelay),
                QueueWaitMs = Ms(exchange.QueueWait),
                Budget = LatencyBudget.Classify(exchange.Duration, _limits),
            },
            Key = KeyOf(exchange, status),
            Faults = exchange.FaultRule is null ? null : new FaultFacts(exchange.FaultRule),
        };

        var secrets = session.RetainedRequestBody is not null || retainedResponse is not null
            ? new RetainedSecrets(session.RetainedRequestBody, retainedResponse)
            : null;
        return new CapturedExchange(record, secrets);
    }

    private KeyFacts? KeyOf(EkmRequestContext exchange, int status)
    {
        // Only when the engine was actually asked about the key, and not for "not found" (which would look up the tombstones under the store lock).
        if (!exchange.EngineCalled || status == StatusCodes.Status404NotFound || exchange.Route is not { KeyName: { } name } route)
        {
            return null;
        }

        try
        {
            return _keys.Get(new KeyRef(route.Namespace.Name, name)) is { } info
                ? new KeyFacts(info.Type == KeyType.Rsa ? "RSA" : "oct", info.Size, info.State.ToString(), info.WrapCount, info.UnwrapCount)
                : null;
        }
        catch (EkmEngineException)
        {
            return null;
        }
    }

    private static ClientCertFacts ClientCertificateOf(HttpContext context, EkmRequestContext exchange)
    {
        var auth = exchange.Authentication;
        var summary = auth?.Certificate ?? exchange.Connection?.ClientCertificate;
        var present = summary is not null || context.Connection.ClientCertificate is not null;
        return new ClientCertFacts
        {
            Present = present,
            Subject = summary?.Subject,
            Issuer = summary?.Issuer,
            Serial = summary?.SerialNumber,
            ThumbprintSha256 = summary?.ThumbprintSha256,
            NotBeforeUtc = summary?.NotBeforeUtc,
            NotAfterUtc = summary?.NotAfterUtc,
            CommonName = auth?.CommonName,
            AuthEvaluated = auth is not null,
            ChainResult = auth?.ChainResult,
            CommonNameAllowed = auth?.CommonNameAllowed,
            NamespaceMatched = auth?.NamespaceMatched,
            AuthFailure = auth is { Succeeded: false } ? auth.Failure.ToString() : null,
        };
    }

    private static TlsFacts? TlsOf(EkmRequestContext exchange)
    {
        if (exchange.Connection is not { } connection)
        {
            return null;
        }

        var ordinal = exchange.RequestNumberOnConnection;

        // EkmMock disables TLS session resumption (DECISIONS "M3: TLS stack"), so a completed handshake is never a resumed one.
        bool? resumed = connection.HandshakeCompleted ? false : null;

        // Only the first exchange of a connection carries the handshake time (spec 8.1: "handshake time for new connections").
        double? handshakeMs = null;
        if (ordinal == 1 && connection.HandshakeTime is { } handshake)
        {
            handshakeMs = Math.Round(handshake.TotalMilliseconds, 3);
        }

        return new TlsFacts(connection.TlsProtocol, connection.CipherSuite, connection.Alpn, connection.Sni, resumed, handshakeMs, ordinal);
    }

    private static string? RemoteEndPoint(HttpContext context, EkmRequestContext exchange)
    {
        if (exchange.Connection?.RemoteEndPoint is { } known)
        {
            return known;
        }

        return context.Connection.RemoteIpAddress is { } address ? new IPEndPoint(address, context.Connection.RemotePort).ToString() : null;
    }

    private static IReadOnlyList<HeaderEntry> HeadersOf(IHeaderDictionary headers)
    {
        if (headers.Count == 0)
        {
            return [];
        }

        var list = new List<HeaderEntry>(Math.Min(headers.Count, MaxHeaders));
        foreach (var header in headers)
        {
            if (list.Count >= MaxHeaders)
            {
                break;
            }

            var value = SensitiveHeaders.Contains(header.Key) ? "[redacted]" : Bound(header.Value.ToString(), MaxHeaderValueLength) ?? string.Empty;
            list.Add(new HeaderEntry(header.Key, value));
        }

        return list;
    }

    private static string? Bound(string? value, int max) => value is not null && value.Length > max ? value[..max] : value;

    private static double Ms(TimeSpan span) => Math.Round(span.TotalMilliseconds, 3);

    private static DateTimeOffset TruncateToMicroseconds(DateTimeOffset value) => new(value.Ticks - (value.Ticks % 10), value.Offset);
}

/// <summary>
/// The first stage of the EKM pipeline (spec 7, 8.3): it sees every exchange, including those that Route, Auth or the dispatcher reject. It wraps the request
/// and response body streams (a copy of at most 16 KiB of each, nothing buffered or delayed), and when the exchange is over it builds the masked
/// <see cref="ExchangeRecord"/> and hands it to the bounded queue with a non-blocking write. It never awaits the consumer and never fails a request:
/// whatever goes wrong while capturing is counted and logged, not thrown.
/// </summary>
internal sealed class InspectorCaptureMiddleware
{
    private readonly RequestDelegate _next;
    private readonly InspectorPipeline _pipeline;
    private readonly ExchangeRecordFactory _factory;
    private readonly CaptureDiagnostics _diagnostics;
    private readonly bool _revealAllowed;
    private readonly ILogger _logger;

    public InspectorCaptureMiddleware(
        RequestDelegate next,
        InspectorPipeline pipeline,
        ExchangeRecordFactory factory,
        CaptureDiagnostics diagnostics,
        IInspectorRevealGate revealGate,
        ILoggerFactory loggerFactory)
    {
        _next = next;
        _pipeline = pipeline;
        _factory = factory;
        _diagnostics = diagnostics;
        _revealAllowed = revealGate.IsAllowed;
        _logger = loggerFactory.CreateLogger("EkmMock.Inspector");
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var started = Stopwatch.GetTimestamp();
        var request = context.Request;
        var response = context.Response;
        var originalRequestBody = request.Body;
        var originalResponseBody = response.Body;
        var session = new ExchangeCaptureSession(context, _revealAllowed);
        var capturingRequestBody = new CapturingRequestStream(originalRequestBody, session);
        request.Body = capturingRequestBody;
        response.Body = new CapturingResponseStream(originalResponseBody, session);
        session.AddOverhead(started);

        try
        {
            await _next(context).ConfigureAwait(false);
        }
        finally
        {
            await CompleteAsync(context, session, capturingRequestBody).ConfigureAwait(false);
            request.Body = originalRequestBody;
            response.Body = originalResponseBody;
        }
    }

    private async Task CompleteAsync(HttpContext context, ExchangeCaptureSession session, Stream capturingRequestBody)
    {
        var handedOver = false;
        try
        {
            // Waiting for a rejected request's body is I/O, not capture work: it is outside the overhead measurement on purpose.
            await session.DrainRequestAsync(capturingRequestBody, context.RequestAborted).ConfigureAwait(false);

            var started = Stopwatch.GetTimestamp();
            if (context.TryGetEkmContext() is { } exchange)
            {
                var captured = _factory.Create(context, exchange, session);
                handedOver = true;
                if (!_pipeline.Enqueue(captured))
                {
                    captured.Secrets?.Zero();
                }

                _diagnostics.RecordCaptured();
            }

            session.AddOverhead(started);
        }
        catch (Exception exception)
        {
            if (!handedOver)
            {
                session.DiscardRetained();
            }

            var failures = _diagnostics.RecordFailure();
            if (failures is 1 || failures % 1000 == 0)
            {
                // The type only: the message of a parser exception can quote the request.
                _logger.LogWarning("The inspector could not capture an exchange ({ExceptionType}); {Failures} capture failure(s) so far. The request itself was not affected.", exception.GetType().Name, failures);
            }
        }
        finally
        {
            var released = Stopwatch.GetTimestamp();
            session.ReleaseBuffers();
            session.AddOverhead(released);
            _diagnostics.Observer?.Observe(session.OverheadTicks);
        }
    }
}
