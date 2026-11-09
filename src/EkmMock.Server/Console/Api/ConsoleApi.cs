using System.Text.Json.Serialization;
using EkmMock.Server.Inspector;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;

namespace EkmMock.Server.WebConsole;

internal sealed record HealthBody(string Status);

internal sealed record ReadyBody(string Status, IReadOnlyList<string>? NotReady);

internal sealed record ApiError(string Code, string Message);

internal sealed record RevealRequest(string? Field);

internal sealed record AntiforgeryTokenBody(string HeaderName, string Token);

internal sealed record ConnectionList(IReadOnlyList<ConnectionEventRecord> Events);

internal sealed record OpenConnectionList(IReadOnlyList<OpenConnectionInfo> Connections);

/// <summary>
/// JSON of <c>/api/console/*</c> (decision: <c>snake_case</c>, like the EKM wire format and the inspector export; enums as strings; nulls omitted). Source-generated,
/// so nothing here uses reflection. Every type reachable from here is already masked by construction, except <see cref="RevealedField"/>, which is the audited,
/// <c>no-store</c> answer of the reveal endpoint.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    WriteIndented = false)]
[JsonSerializable(typeof(HealthBody))]
[JsonSerializable(typeof(ReadyBody))]
[JsonSerializable(typeof(ApiError))]
[JsonSerializable(typeof(RevealRequest))]
[JsonSerializable(typeof(RevealedField))]
[JsonSerializable(typeof(AntiforgeryTokenBody))]
[JsonSerializable(typeof(ConsoleStatus))]
[JsonSerializable(typeof(ExchangePage))]
[JsonSerializable(typeof(ExchangeRecord))]
[JsonSerializable(typeof(KqlSnippet))]
[JsonSerializable(typeof(ConnectionList))]
[JsonSerializable(typeof(OpenConnectionList))]
[JsonSerializable(typeof(ConnectionStatistics))]
[JsonSerializable(typeof(DashboardSnapshot))]
[JsonSerializable(typeof(InspectorStatus))]
internal sealed partial class ConsoleApiJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Requires a valid antiforgery token on a state-changing console API call (spec 5.4). A browser gets its token from the antiforgery cookie plus the
/// <c>X-CSRF-TOKEN</c> header; the CLI (M8) asks <c>GET /api/console/antiforgery</c> first. A Bearer/Entra token policy for the CLI is an M8 decision.
/// </summary>
internal sealed class AntiforgeryEndpointFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var antiforgery = context.HttpContext.RequestServices.GetRequiredService<IAntiforgery>();
        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext).ConfigureAwait(false);
        }
        catch (AntiforgeryValidationException)
        {
            return ConsoleApi.Error(StatusCodes.Status400BadRequest, "AntiforgeryTokenInvalid", "A valid antiforgery token is required for this action.");
        }

        return await next(context).ConfigureAwait(false);
    }
}

/// <summary>The thin read-only inspector API (spec 7) over the M4 services, plus status and the audited reveal action. Everything sits behind the console policy.</summary>
internal static class ConsoleApi
{
    public const string BasePath = "/api/console";
    public const string AntiforgeryHeader = "X-CSRF-TOKEN";

    public static IResult Error(int status, string code, string message)
        => Results.Json(new ApiError(code, message), ConsoleApiJsonContext.Default.ApiError, statusCode: status);

    public static IEndpointRouteBuilder MapConsoleApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/healthz", () => Results.Json(new HealthBody("alive"), ConsoleApiJsonContext.Default.HealthBody))
            .AllowAnonymous();

        endpoints.MapGet("/readyz", (IConsoleStatusProvider status) =>
        {
            var readiness = status.CheckReadiness();
            return readiness.Ready
                ? Results.Json(new ReadyBody("ready", null), ConsoleApiJsonContext.Default.ReadyBody)
                : Results.Json(new ReadyBody("not_ready", readiness.NotReady), ConsoleApiJsonContext.Default.ReadyBody, statusCode: StatusCodes.Status503ServiceUnavailable);
        }).AllowAnonymous();

        var api = endpoints.MapGroup(BasePath).RequireAuthorization(ConsoleAuth.PolicyName);

        api.MapGet("/status", (IConsoleStatusProvider status) => Results.Json(status.Get(), ConsoleApiJsonContext.Default.ConsoleStatus));

        api.MapGet("/inspector/status", (IInspectorQuery inspector) => Results.Json(inspector.Status(), ConsoleApiJsonContext.Default.InspectorStatus));

        api.MapGet("/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);
            return Results.Json(new AntiforgeryTokenBody(AntiforgeryHeader, tokens.RequestToken ?? string.Empty), ConsoleApiJsonContext.Default.AntiforgeryTokenBody);
        });

        api.MapGet("/exchanges", (HttpContext context, IInspectorQuery inspector) =>
        {
            var query = context.Request.Query;
            if (!ExchangeQuery.TryParse(query, out var filter, out var paging, out var problem))
            {
                return Error(StatusCodes.Status400BadRequest, "InvalidQuery", problem);
            }

            return Results.Json(inspector.Query(filter, paging), ConsoleApiJsonContext.Default.ExchangePage);
        });

        api.MapGet("/exchanges/{id:long}", (long id, IInspectorQuery inspector)
            => inspector.Get(id) is { } record
                ? Results.Json(record, ConsoleApiJsonContext.Default.ExchangeRecord)
                : Error(StatusCodes.Status404NotFound, "ExchangeNotFound", "The exchange is no longer in the inspector."));

        api.MapGet("/exchanges/{id:long}/kql", (long id, IInspectorQuery inspector)
            => inspector.Kql(id) is { } kql
                ? Results.Json(kql, ConsoleApiJsonContext.Default.KqlSnippet)
                : Error(StatusCodes.Status404NotFound, "ExchangeNotFound", "The exchange is no longer in the inspector."));

        // The one state-changing action of M5: reveal is audited (as the current user, before the value is returned) and needs an antiforgery token.
        api.MapPost("/exchanges/{id:long}/reveal", async (long id, RevealRequest? body, IInspector inspector, IConsoleUser user) =>
        {
            if (string.IsNullOrWhiteSpace(body?.Field))
            {
                return Error(StatusCodes.Status400BadRequest, "InvalidRequest", "The field to reveal is required (request.value or response.value).");
            }

            var current = await user.GetAsync().ConfigureAwait(false);
            try
            {
                return Results.Json(inspector.Reveal(id, body.Field, current.AuditName), ConsoleApiJsonContext.Default.RevealedField);
            }
            catch (InspectorRevealException exception)
            {
                return exception.Reason switch
                {
                    RevealFailure.Disabled => Error(StatusCodes.Status403Forbidden, "RevealDisabled", exception.Message),
                    RevealFailure.UnknownField => Error(StatusCodes.Status400BadRequest, "UnknownField", exception.Message),
                    RevealFailure.ExchangeNotFound => Error(StatusCodes.Status404NotFound, "ExchangeNotFound", exception.Message),
                    RevealFailure.NotRetained => Error(StatusCodes.Status409Conflict, "NotRetained", exception.Message),
                    _ => Error(StatusCodes.Status503ServiceUnavailable, "AuditUnavailable", exception.Message),
                };
            }
        }).AddEndpointFilter<AntiforgeryEndpointFilter>();

        api.MapConsoleAdminApi();

        api.MapGet("/connections", (HttpContext context, IInspectorQuery inspector) =>
        {
            var query = context.Request.Query;
            var filter = new ConnectionEventFilter
            {
                Kind = Normalize(query["kind"]),
                ConnectionId = Normalize(query["connection_id"]),
                FailuresOnly = ExchangeQuery.Flag(query["failures_only"]),
            };
            var limit = int.TryParse(query["limit"], out var l) ? Math.Clamp(l, 1, 1000) : 200;
            return Results.Json(new ConnectionList(inspector.ConnectionEvents(filter, limit)), ConsoleApiJsonContext.Default.ConnectionList);
        });

        api.MapGet("/connections/open", (IInspectorQuery inspector)
            => Results.Json(new OpenConnectionList(inspector.OpenConnections()), ConsoleApiJsonContext.Default.OpenConnectionList));

        api.MapGet("/connections/statistics", (IInspectorQuery inspector)
            => Results.Json(inspector.ConnectionStatistics(), ConsoleApiJsonContext.Default.ConnectionStatistics));

        api.MapGet("/dashboard", (IInspectorQuery inspector) => Results.Json(inspector.Dashboard(), ConsoleApiJsonContext.Default.DashboardSnapshot));

        api.MapGet("/export", async (HttpContext context, IInspector inspector) =>
        {
            var query = context.Request.Query;
            if (!ExchangeQuery.TryParse(query, out var filter, out _, out var problem))
            {
                await Error(StatusCodes.Status400BadRequest, "InvalidQuery", problem).ExecuteAsync(context).ConfigureAwait(false);
                return;
            }

            var jsonl = string.Equals(query["format"], "jsonl", StringComparison.OrdinalIgnoreCase);
            var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", System.Globalization.CultureInfo.InvariantCulture);
            context.Response.ContentType = jsonl ? "application/x-ndjson" : "application/json";
            context.Response.Headers.ContentDisposition = $"attachment; filename=\"ekmmock-exchanges-{stamp}.{(jsonl ? "jsonl" : "json")}\"";
            await inspector.ExportAsync(context.Response.Body, jsonl ? ExportFormat.Jsonl : ExportFormat.Json, filter, context.RequestAborted).ConfigureAwait(false);
        });

        return endpoints;
    }

    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}

/// <summary>Parses the filter and paging query string of the exchange list and the export.</summary>
internal static class ExchangeQuery
{
    public static bool TryParse(IQueryCollection query, out ExchangeFilter filter, out ExchangePaging paging, out string problem)
    {
        problem = string.Empty;
        filter = new ExchangeFilter();
        paging = new ExchangePaging();

        StatusClass? statusClass = null;
        if (query.TryGetValue("status_class", out var sc) && !string.IsNullOrEmpty(sc.ToString()))
        {
            statusClass = sc.ToString() switch
            {
                "2" or "2xx" => StatusClass.Success,
                "4" or "4xx" => StatusClass.ClientError,
                "5" or "5xx" => StatusClass.ServerError,
                _ => null,
            };
            if (statusClass is null)
            {
                problem = "status_class must be 2, 4 or 5.";
                return false;
            }
        }

        if (!TryLong(query["before_id"], out var before) || !TryLong(query["after_id"], out var after))
        {
            problem = "before_id and after_id must be exchange ids.";
            return false;
        }

        var limit = 100;
        if (query.TryGetValue("limit", out var limitText) && !string.IsNullOrEmpty(limitText.ToString()))
        {
            if (!int.TryParse(limitText, out limit) || limit < 1)
            {
                problem = "limit must be a positive number.";
                return false;
            }

            limit = Math.Min(limit, ExchangePaging.MaxLimit);
        }

        filter = new ExchangeFilter
        {
            Operation = Text(query["op"]),
            StatusClass = statusClass,
            Namespace = Text(query["namespace"]),
            Key = Text(query["key"]),
            ClientCommonName = Text(query["client_cn"]),
            Text = Text(query["text"]),
            OnlyErrors = Flag(query["only_errors"]),
            OnlyOverBudget = Flag(query["only_over_budget"]),
            HideInfo = Flag(query["hide_info"]),
        };
        paging = new ExchangePaging { Limit = limit, BeforeId = before, AfterId = after };
        return true;
    }

    public static bool Flag(string? value) => value is not null && (value.Equals("true", StringComparison.OrdinalIgnoreCase) || value == "1");

    private static string? Text(string? value) => string.IsNullOrEmpty(value) ? null : value;

    private static bool TryLong(string? value, out long? parsed)
    {
        parsed = null;
        if (string.IsNullOrEmpty(value))
        {
            return true;
        }

        if (long.TryParse(value, out var number) && number >= 0)
        {
            parsed = number;
            return true;
        }

        return false;
    }
}
