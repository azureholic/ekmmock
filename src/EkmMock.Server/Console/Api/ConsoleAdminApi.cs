using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using EkmMock.Server.Inspector;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;

namespace EkmMock.Server.WebConsole;

// ---- request bodies (snake_case on the wire) ----
internal sealed record CreateKeyBody(string? Namespace, string? Name, string? Type, int Size, bool AllowReuseOfDestroyedName);

internal sealed record ExpiryBody(DateTimeOffset? NotAfter);

internal sealed record DestroyKeyBody(string? ConfirmName);

internal sealed record NamespaceBody(string? Name, string? Prefix, List<string>? SubjectCommonNames, List<string>? CaCertificatesDerBase64);

internal sealed record DeleteNamespaceBody(string? ConfirmName, bool DestroyKeys);

internal sealed record TrustImportBody(string? Format, string? Content, List<string>? SubjectCommonNames, string? Mode, bool DryRun);

internal sealed record UploadCertificateBody(string? CertificatePem, string? PrivateKeyPem);

internal sealed record GenerateCertificateBody(string? Fqdn, List<string>? HostNames);

/// <summary>The body of a fault rule create or update (snake_case on the wire: <c>delay_ms</c>, <c>error_percent</c>, <c>expires_after_seconds</c>, ...).</summary>
internal sealed record FaultRuleBody(
    string? Kind,
    string? Namespace,
    string? Key,
    string? Op,
    int? DelayMs,
    int? MinMs,
    int? MaxMs,
    double? ErrorPercent,
    int? StatusCode,
    string? Description,
    int? ExpiresAfterSeconds,
    bool? Enabled)
{
    public FaultRuleRequest ToRequest() => new(Kind, Namespace, Key, Op, DelayMs, MinMs, MaxMs, ErrorPercent, StatusCode, Description, ExpiresAfterSeconds, Enabled);
}

// ---- responses ----
internal sealed record KeyList(IReadOnlyList<KeyView> Keys);

internal sealed record NamespaceList(IReadOnlyList<NamespaceView> Namespaces);

internal sealed record NamespaceDeleted(bool Deleted, int DestroyedKeys);

/// <summary>The REST API of the console actions (spec 12). Same JSON conventions as the rest of <c>/api/console</c>: snake_case, enums as strings, nulls omitted, source generated.</summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    WriteIndented = false)]
[JsonSerializable(typeof(CreateKeyBody))]
[JsonSerializable(typeof(ExpiryBody))]
[JsonSerializable(typeof(DestroyKeyBody))]
[JsonSerializable(typeof(NamespaceBody))]
[JsonSerializable(typeof(DeleteNamespaceBody))]
[JsonSerializable(typeof(TrustImportBody))]
[JsonSerializable(typeof(UploadCertificateBody))]
[JsonSerializable(typeof(GenerateCertificateBody))]
[JsonSerializable(typeof(FaultRuleBody))]
[JsonSerializable(typeof(FaultList))]
[JsonSerializable(typeof(FaultRuleView))]
[JsonSerializable(typeof(FaultCleared))]
[JsonSerializable(typeof(KeyList))]
[JsonSerializable(typeof(KeyView))]
[JsonSerializable(typeof(KeyDetail))]
[JsonSerializable(typeof(NamespaceList))]
[JsonSerializable(typeof(NamespaceView))]
[JsonSerializable(typeof(NamespaceDeleted))]
[JsonSerializable(typeof(TrustPreview))]
[JsonSerializable(typeof(CertificatePageModel))]
[JsonSerializable(typeof(ServerCertificateView))]
[JsonSerializable(typeof(GeneratedPki))]
[JsonSerializable(typeof(AuditPage))]
[JsonSerializable(typeof(AboutInfo))]
[JsonSerializable(typeof(SelfTestView))]
[JsonSerializable(typeof(ApiError))]
internal sealed partial class ConsoleAdminJsonContext : JsonSerializerContext
{
}

/// <summary>
/// CSRF protection of the state-changing endpoints of <c>/api/console</c>. Two accepted proofs:
/// <list type="number">
/// <item>The browser way: the antiforgery cookie plus the matching <c>X-CSRF-TOKEN</c> header (token from <c>GET /api/console/antiforgery</c>).</item>
/// <item>The CLI way (no cookie jar needed): the custom header <c>X-EkmMock-Client</c> with any non-empty value, sent <b>without an <c>Origin</c> header</b> and not as a cross-site
/// fetch. A web page cannot send a custom header cross-origin without a CORS preflight, which this server never grants (no CORS), and a browser always adds <c>Origin</c> to
/// a cross-origin POST; so this proof cannot be produced by a hostile page. It is the standard "custom request header" CSRF defence and does not weaken the browser path:
/// a request that carries an <c>Origin</c> header must use the antiforgery token. In <c>EntraId</c> mode the call must still carry the sign-in (cookie today; the CLI's device-code token in M8).</item>
/// </list>
/// </summary>
internal sealed class ConsoleMutationFilter : IEndpointFilter
{
    public const string ClientHeader = "X-EkmMock-Client";

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        if (!IsScriptedClient(http.Request))
        {
            var antiforgery = http.RequestServices.GetRequiredService<IAntiforgery>();
            try
            {
                await antiforgery.ValidateRequestAsync(http).ConfigureAwait(false);
            }
            catch (AntiforgeryValidationException)
            {
                return ConsoleAdminApi.Error(StatusCodes.Status400BadRequest, "AntiforgeryTokenInvalid", $"A valid antiforgery token is required, or send the {ClientHeader} header from a non-browser client.");
            }
        }

        return await next(context).ConfigureAwait(false);
    }

    internal static bool IsScriptedClient(HttpRequest request)
        => !string.IsNullOrWhiteSpace(request.Headers[ClientHeader].ToString())
            && !request.Headers.ContainsKey("Origin")
            && !string.Equals(request.Headers["Sec-Fetch-Site"].ToString(), "cross-site", StringComparison.OrdinalIgnoreCase);
}

/// <summary>The REST API of keys, namespaces and trust, certificates, audit and About (spec 12), a thin layer over the same services the Blazor pages use.</summary>
internal static class ConsoleAdminApi
{
    private const int MaxBodyBytes = 512 * 1024;

    public static IResult Error(int status, string code, string message)
        => Results.Json(new ApiError(code, message), ConsoleAdminJsonContext.Default.ApiError, statusCode: status);

    public static RouteGroupBuilder MapConsoleAdminApi(this RouteGroupBuilder api)
    {
        // ---- keys ----
        api.MapGet("/keys", (HttpContext http, KeyAdminService keys) => Run(() => Json(new KeyList(keys.List(Normalize(http.Request.Query["namespace"]))), ConsoleAdminJsonContext.Default.KeyList)));
        api.MapGet("/keys/{ns}/{name}", (string ns, string name, KeyAdminService keys) => Run(() => Json(keys.Get(ns, name), ConsoleAdminJsonContext.Default.KeyDetail)));

        api.MapPost("/keys", (HttpContext http, KeyAdminService keys, IConsoleUser user) => RunBody(http, ConsoleAdminJsonContext.Default.CreateKeyBody, async body =>
        {
            var created = keys.Create(await Actor(user), new CreateKeyRequest(body.Namespace ?? string.Empty, body.Name ?? string.Empty, body.Type ?? string.Empty, body.Size, body.AllowReuseOfDestroyedName));
            return Results.Json(created, ConsoleAdminJsonContext.Default.KeyView, statusCode: StatusCodes.Status201Created);
        })).AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/keys/{ns}/{name}/enable", (string ns, string name, KeyAdminService keys, IConsoleUser user)
            => Run(async () => Json(keys.SetEnabled(await Actor(user), ns, name, enabled: true), ConsoleAdminJsonContext.Default.KeyView))).AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/keys/{ns}/{name}/disable", (string ns, string name, KeyAdminService keys, IConsoleUser user)
            => Run(async () => Json(keys.SetEnabled(await Actor(user), ns, name, enabled: false), ConsoleAdminJsonContext.Default.KeyView))).AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/keys/{ns}/{name}/expiry", (string ns, string name, HttpContext http, KeyAdminService keys, IConsoleUser user)
            => RunBody(http, ConsoleAdminJsonContext.Default.ExpiryBody, async body => Json(keys.SetExpiry(await Actor(user), ns, name, body.NotAfter), ConsoleAdminJsonContext.Default.KeyView)))
            .AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/keys/{ns}/{name}/destroy", (string ns, string name, HttpContext http, KeyAdminService keys, IConsoleUser user)
            => RunBody(http, ConsoleAdminJsonContext.Default.DestroyKeyBody, async body => Json(keys.Destroy(await Actor(user), ns, name, body.ConfirmName), ConsoleAdminJsonContext.Default.KeyView)))
            .AddEndpointFilter<ConsoleMutationFilter>();

        // ---- namespaces and trust ----
        api.MapGet("/namespaces", (NamespaceAdminService namespaces) => Run(() => Json(new NamespaceList(namespaces.List()), ConsoleAdminJsonContext.Default.NamespaceList)));
        api.MapGet("/namespaces/{name}", (string name, NamespaceAdminService namespaces) => Run(() => Json(namespaces.Get(name), ConsoleAdminJsonContext.Default.NamespaceView)));

        api.MapPost("/namespaces", (HttpContext http, NamespaceAdminService namespaces, IConsoleUser user) => RunBody(http, ConsoleAdminJsonContext.Default.NamespaceBody, async body =>
        {
            var created = namespaces.Create(await Actor(user), new NamespaceChange(body.Name ?? string.Empty, body.Prefix ?? string.Empty, body.SubjectCommonNames, body.CaCertificatesDerBase64));
            return Results.Json(created, ConsoleAdminJsonContext.Default.NamespaceView, statusCode: StatusCodes.Status201Created);
        })).AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPut("/namespaces/{name}", (string name, HttpContext http, NamespaceAdminService namespaces, IConsoleUser user)
            => RunBody(http, ConsoleAdminJsonContext.Default.NamespaceBody, async body
                => Json(namespaces.Update(await Actor(user), new NamespaceChange(name, body.Prefix ?? string.Empty, body.SubjectCommonNames, body.CaCertificatesDerBase64)), ConsoleAdminJsonContext.Default.NamespaceView)))
            .AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/namespaces/{name}/delete", (string name, HttpContext http, NamespaceAdminService namespaces, IConsoleUser user)
            => RunBody(http, ConsoleAdminJsonContext.Default.DeleteNamespaceBody, async body
                => Json(new NamespaceDeleted(true, namespaces.Delete(await Actor(user), name, body.ConfirmName, body.DestroyKeys)), ConsoleAdminJsonContext.Default.NamespaceDeleted)))
            .AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/namespaces/{name}/trust/import", (string name, HttpContext http, NamespaceAdminService namespaces, IConsoleUser user)
            => RunBody(http, ConsoleAdminJsonContext.Default.TrustImportBody, async body
                => Json(
                    namespaces.Import(await Actor(user), name, body.Content ?? string.Empty, body.Format, body.SubjectCommonNames, body.Mode ?? TrustImportModes.Merge, body.DryRun),
                    ConsoleAdminJsonContext.Default.TrustPreview)))
            .AddEndpointFilter<ConsoleMutationFilter>();

        // ---- certificates ----
        api.MapGet("/certificates", (CertificateAdminService certificates) => Run(() => Json(certificates.GetPage(), ConsoleAdminJsonContext.Default.CertificatePageModel)));

        api.MapPost("/certificates/upload", (HttpContext http, CertificateAdminService certificates, IConsoleUser user)
            => RunBody(http, ConsoleAdminJsonContext.Default.UploadCertificateBody, async body
                => Json(await certificates.UploadAsync(await Actor(user), body.CertificatePem, body.PrivateKeyPem, http.RequestAborted), ConsoleAdminJsonContext.Default.ServerCertificateView)))
            .AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/certificates/generate", (HttpContext http, CertificateAdminService certificates, IConsoleUser user)
            => RunBody(http, ConsoleAdminJsonContext.Default.GenerateCertificateBody, async body =>
            {
                var names = new List<string>();
                if (!string.IsNullOrWhiteSpace(body.Fqdn))
                {
                    names.Add(body.Fqdn);
                }

                names.AddRange(body.HostNames ?? []);
                return Json(await certificates.GenerateTestPkiAsync(await Actor(user), names, http.RequestAborted), ConsoleAdminJsonContext.Default.GeneratedPki);
            }))
            .AddEndpointFilter<ConsoleMutationFilter>();

        api.MapGet("/certificates/root-ca.pem", (HttpContext http, CertificateAdminService certificates) =>
        {
            if (certificates.GetRootCaPem() is not { } pem)
            {
                return Error(StatusCodes.Status404NotFound, "NotFound", "No root CA certificate is available: generate test PKI first. An uploaded chain is signed by your own CA.");
            }

            http.Response.Headers.ContentDisposition = $"attachment; filename=\"{CertificateAdminService.RootCaFileName}\"";
            return Results.Text(pem, "application/x-pem-file");
        });

        // ---- fault injection (spec 10.2) ----
        api.MapGet("/faults", (FaultAdminService faults) => Run(() => Json(faults.List(), ConsoleAdminJsonContext.Default.FaultList)));
        api.MapGet("/faults/{id}", (string id, FaultAdminService faults) => Run(() => Json(faults.Get(id), ConsoleAdminJsonContext.Default.FaultRuleView)));

        api.MapPost("/faults", (HttpContext http, FaultAdminService faults, IConsoleUser user) => RunBody(http, ConsoleAdminJsonContext.Default.FaultRuleBody, async body
            => Results.Json(faults.Create(await Actor(user), body.ToRequest()), ConsoleAdminJsonContext.Default.FaultRuleView, statusCode: StatusCodes.Status201Created)))
            .AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPut("/faults/{id}", (string id, HttpContext http, FaultAdminService faults, IConsoleUser user) => RunBody(http, ConsoleAdminJsonContext.Default.FaultRuleBody, async body
            => Json(faults.Update(await Actor(user), id, body.ToRequest()), ConsoleAdminJsonContext.Default.FaultRuleView)))
            .AddEndpointFilter<ConsoleMutationFilter>();

        api.MapDelete("/faults/{id}", (string id, FaultAdminService faults, IConsoleUser user) => Run(async () =>
        {
            faults.Delete(await Actor(user), id);
            return Results.NoContent();
        })).AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/faults/{id}/enable", (string id, FaultAdminService faults, IConsoleUser user)
            => Run(async () => Json(faults.SetEnabled(await Actor(user), id, enabled: true), ConsoleAdminJsonContext.Default.FaultRuleView))).AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/faults/{id}/disable", (string id, FaultAdminService faults, IConsoleUser user)
            => Run(async () => Json(faults.SetEnabled(await Actor(user), id, enabled: false), ConsoleAdminJsonContext.Default.FaultRuleView))).AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/faults/clear", (FaultAdminService faults, IConsoleUser user)
            => Run(async () => Json(new FaultCleared(faults.Clear(await Actor(user))), ConsoleAdminJsonContext.Default.FaultCleared))).AddEndpointFilter<ConsoleMutationFilter>();

        api.MapPost("/faults/presets/{presetId}", (string presetId, FaultAdminService faults, IConsoleUser user)
            => Run(async () => Results.Json(faults.ApplyPreset(await Actor(user), presetId), ConsoleAdminJsonContext.Default.FaultRuleView, statusCode: StatusCodes.Status201Created)))
            .AddEndpointFilter<ConsoleMutationFilter>();

        // ---- audit and about ----
        api.MapGet("/audit", (HttpContext http, IAuditLog audit) => Run(() =>
        {
            var query = http.Request.Query;
            if (!TryDate(query["from"], out var from) || !TryDate(query["to"], out var to))
            {
                return Error(StatusCodes.Status400BadRequest, "InvalidQuery", "from and to must be ISO 8601 date-times.");
            }

            var filter = new AuditFilter { User = Normalize(query["user"]), Action = Normalize(query["action"]), Text = Normalize(query["text"]), From = from, To = to };
            var skip = int.TryParse(query["skip"], out var s) ? s : 0;
            var take = int.TryParse(query["take"], out var t) ? t : 50;
            return Json(audit.Query(filter, skip, take), ConsoleAdminJsonContext.Default.AuditPage);
        }));

        api.MapGet("/about", (AboutService about) => Run(() => Json(about.Get(), ConsoleAdminJsonContext.Default.AboutInfo)));
        api.MapGet("/self-test", (AboutService about) => Run(() => Json(about.SelfTest(), ConsoleAdminJsonContext.Default.SelfTestView)));
        return api;
    }

    // ---- helpers ----

    private static IResult Json<T>(T value, JsonTypeInfo<T> typeInfo) => Results.Json(value, typeInfo);

    private static async ValueTask<string> Actor(IConsoleUser user) => (await user.GetAsync().ConfigureAwait(false)).AuditName;

    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static bool TryDate(string? text, out DateTimeOffset? value)
    {
        value = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return true;
        }

        if (DateTimeOffset.TryParse(text, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed))
        {
            value = parsed;
            return true;
        }

        return false;
    }

    private static Task<IResult> Run(Func<IResult> action) => Run(() => Task.FromResult(action()));

    private static async Task<IResult> Run(Func<Task<IResult>> action)
    {
        try
        {
            return await action().ConfigureAwait(false);
        }
        catch (ConsoleActionException exception)
        {
            return Error(exception.HttpStatus, exception.Code.ToString(), exception.Message);
        }
    }

    private static async Task<IResult> RunBody<T>(HttpContext http, JsonTypeInfo<T> typeInfo, Func<T, Task<IResult>> action)
        where T : class
    {
        T? body;
        try
        {
            body = await ReadBodyAsync(http, typeInfo).ConfigureAwait(false);
        }
        catch (ConsoleActionException exception)
        {
            return Error(exception.HttpStatus, exception.Code.ToString(), exception.Message);
        }

        return await Run(() => action(body)).ConfigureAwait(false);
    }

    // Reads a bounded JSON body; the message of a parse failure is fixed text (a parser message can quote the input, which may be a key or certificate).
    private static async Task<T> ReadBodyAsync<T>(HttpContext http, JsonTypeInfo<T> typeInfo)
        where T : class
    {
        if (http.Request.ContentLength > MaxBodyBytes)
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The request body is too large.");
        }

        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await http.Request.Body.ReadAsync(chunk, http.RequestAborted).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxBodyBytes)
            {
                throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The request body is too large.");
            }

            buffer.Write(chunk, 0, read);
        }

        try
        {
            return JsonSerializer.Deserialize(buffer.GetBuffer().AsSpan(0, (int)buffer.Length), typeInfo)
                ?? throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "A JSON object body is required.");
        }
        catch (JsonException)
        {
            throw new ConsoleActionException(ConsoleErrorCode.InvalidRequest, "The request body is not valid JSON for this endpoint.");
        }
        finally
        {
            // The body of an upload holds a private key: do not leave our copy lying around (best effort; the deserialized strings cannot be zeroed).
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer.GetBuffer());
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(chunk);
        }
    }
}
