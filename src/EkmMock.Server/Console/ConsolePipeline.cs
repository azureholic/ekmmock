using System.Net;
using EkmMock.Server.Connections;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Endpoints;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.WebConsole;

/// <summary>
/// Security headers of every console response (spec 5.4): a CSP without any external host (everything is served by this process: the Blazor script, the Fluent UI
/// assets, the console CSS and script), <c>frame-ancestors 'none'</c>, <c>nosniff</c>, no referrer, <c>no-store</c> for everything that is not a static asset, and
/// HSTS for non-loopback host names. See DECISIONS.md "M5: CSP and headers".
/// </summary>
internal sealed class ConsoleSecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public ConsoleSecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    public Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(static state =>
        {
            var http = (HttpContext)state;
            Apply(http);
            return Task.CompletedTask;
        }, context);
        return _next(context);
    }

    public static string ContentSecurityPolicy(HostString host)
    {
        // 'self' covers the WebSocket of the Blazor circuit in current browsers; the explicit wss:// origin covers the older ones that do not apply 'self' to ws(s).
        var socket = host.HasValue ? $" wss://{host.Value}" : string.Empty;
        return "default-src 'self'; " +
               "script-src 'self'; " +
               "style-src 'self' 'unsafe-inline'; " +
               "img-src 'self' data:; " +
               "font-src 'self' data:; " +
               $"connect-src 'self'{socket}; " +
               "object-src 'none'; " +
               "base-uri 'self'; " +
               "form-action 'self'; " +
               "frame-ancestors 'none'";
    }

    private static void Apply(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers.ContentSecurityPolicy = ContentSecurityPolicy(context.Request.Host);
        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        headers["Cross-Origin-Resource-Policy"] = "same-origin";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";

        // Dynamic pages, the API and the detail views can contain exchange data: never cache them. Static assets keep the caching headers their own endpoints set.
        if (!headers.ContainsKey("Cache-Control"))
        {
            headers.CacheControl = "no-store";
            headers.Pragma = "no-cache";
        }

        // HSTS is host-wide, not port-wide: sending it for localhost would make browsers refuse every other plain-HTTP dev server on that name, so it is only
        // sent for a real host name (the EntraId deployment). max-age one year, no includeSubDomains, no preload.
        if (context.Request.IsHttps && !IsLoopbackHost(context.Request.Host))
        {
            headers.StrictTransportSecurity = "max-age=31536000";
        }
    }

    internal static bool IsLoopbackHost(HostString host)
        => host.Host is "localhost" or "127.0.0.1" or "[::1]" or "::1"
            || host.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
            || (IPAddress.TryParse(host.Host.Trim('[', ']'), out var ip) && ConsoleEndpointAddress.IsLoopback(ip));
}

/// <summary>
/// The request guard in front of everything on the console (spec 5.4, defence in depth):
/// <list type="bullet">
/// <item>LoopbackOnly: the connection's remote address must be loopback (<see cref="ConsoleOptions.EnforceLoopbackClient"/>, default on) and the <c>Host</c> header must be a
/// loopback name or one of <see cref="ConsoleOptions.AllowedHosts"/> (DNS rebinding: a hostile page that points its own name at 127.0.0.1 sends its own Host).</item>
/// <item>Always: a cross-origin <c>Origin</c> is refused for the SignalR hub and for state-changing requests (cross-site WebSocket hijacking, CSRF), because LoopbackOnly has no
/// credentials a browser would need to present.</item>
/// </list>
/// </summary>
internal sealed class ConsoleRequestGuardMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ConsoleOptions _options;
    private readonly ConsoleExposure _exposure;

    public ConsoleRequestGuardMiddleware(RequestDelegate next, IOptions<ConsoleOptions> options, ConsoleExposure? exposure = null)
    {
        _next = next;
        _options = options.Value;
        _exposure = exposure ?? ConsoleExposure.None;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var refusal = Check(context);
        if (refusal is not null)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync(refusal).ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
    }

    internal string? Check(HttpContext context)
    {
        if (_options.Auth == ConsoleAuthMode.LoopbackOnly)
        {
            // A null address is the in-process test host, which has no socket.
            if (_exposure.ContainerPublishActive)
            {
                // The container-publish opt-in (open question 33): the listener is not loopback-only, so the source address is the only runtime check. It always applies (EnforceLoopbackClient does not
                // turn it off): only loopback and private/link-local sources (the container bridge) are served. With a loopback-restricted host publish Docker presents the bridge gateway here, so
                // this is defence in depth against a mistaken 0.0.0.0 publish reached from outside the private ranges; the primary control is the host-side 127.0.0.1 publish.
                if (context.Connection.RemoteIpAddress is { } source && !ConsoleContainerPublish.IsContainerNetworkSource(source))
                {
                    return "The console accepts connections from the local container network only.";
                }
            }
            else if (_options.EnforceLoopbackClient && context.Connection.RemoteIpAddress is { } remote && !ConsoleEndpointAddress.IsLoopback(remote))
            {
                return "The console accepts local connections only.";
            }

            if (!IsAllowedHost(context.Request.Host))
            {
                return "Unexpected Host header.";
            }
        }

        if (context.Request.Headers.Origin.Count > 0 && RequiresSameOrigin(context.Request) && !IsSameOrigin(context.Request))
        {
            return "Cross-origin request refused.";
        }

        return null;
    }

    private bool IsAllowedHost(HostString host)
        => ConsoleSecurityHeadersMiddleware.IsLoopbackHost(host)
            || _options.AllowedHosts.Any(allowed => string.Equals(allowed, host.Host, StringComparison.OrdinalIgnoreCase));

    private static bool RequiresSameOrigin(HttpRequest request)
        => !HttpMethods.IsGet(request.Method) && !HttpMethods.IsHead(request.Method) && !HttpMethods.IsOptions(request.Method)
            || request.Path.StartsWithSegments("/_blazor", StringComparison.OrdinalIgnoreCase);

    private static bool IsSameOrigin(HttpRequest request)
    {
        var origin = request.Headers.Origin.ToString();
        return Uri.TryCreate(origin, UriKind.Absolute, out var uri)
            && string.Equals(uri.Scheme, request.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(uri.Authority, request.Host.Value, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Kestrel's <c>MaxRequestBodySize</c> is server wide and set to 16 KiB for the EKM endpoint (spec 4.1). The console takes bigger uploads (a certificate chain with its key, a trust JSON: up to
/// <see cref="ConsoleAdminApi.MaxBodyBytes"/>), so its branch raises the limit <em>for its own requests</em> through <c>IHttpMaxRequestBodySizeFeature</c>. The EKM branch never does (security review L10).
/// A host without Kestrel (the in-process test server) has no such feature and is left alone.
/// </summary>
internal sealed class ConsoleBodyLimitMiddleware
{
    private readonly RequestDelegate _next;

    public ConsoleBodyLimitMiddleware(RequestDelegate next) => _next = next;

    public Task InvokeAsync(HttpContext context)
    {
        if (context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } feature)
        {
            feature.MaxRequestBodySize = ConsoleAdminApi.MaxBodyBytes;
        }

        return _next(context);
    }
}

/// <summary>
/// The console branch of the pipeline (spec 5.4, 7): runs only for connections on a console port (<see cref="IConsolePortPolicy"/>, by <c>HttpContext.Connection.LocalPort</c>,
/// never by Host header), with its own routing, authentication, authorization, antiforgery and endpoints. Everything else on other ports is not served by it.
/// </summary>
internal static class ConsolePipeline
{
    public static IApplicationBuilder UseConsolePipeline(this IApplicationBuilder app)
    {
        var ports = app.ApplicationServices.GetRequiredService<IConsolePortPolicy>();
        var auth = app.ApplicationServices.GetRequiredService<IOptions<ConsoleOptions>>().Value.Auth;

        // Resolved now so that the container-publish warning (if the opt-in is active) is logged at start-up, before the first request.
        app.ApplicationServices.GetRequiredService<ConsoleExposure>();
        // WebApplication adds UseAuthentication/UseAuthorization to the TOP of the pipeline by itself when the authentication services are registered and the top-level builder has not
        // called them (calls inside a UseWhen branch do not count). That would run the console's fallback policy for EKM requests too: an EntraId console would answer the EKM endpoint
        // with 401 and a LoopbackOnly one would run the loopback handler on every wrap/unwrap. The console branch below has its own UseAuthentication/UseAuthorization, so declare both
        // as handled. (The two keys are the framework's own "middleware already set" markers; an integration test pins the behaviour: EKM requests never see the console policy.)
        app.Properties["__AuthenticationMiddlewareSet"] = true;
        app.Properties["__AuthorizationMiddlewareSet"] = true;

        app.UseWhen(context => ports.IsConsolePort(context.Connection.LocalPort), branch =>
        {
            branch.UseMiddleware<ConsoleBodyLimitMiddleware>();
            branch.UseMiddleware<ConsoleSecurityHeadersMiddleware>();
            branch.UseMiddleware<ConsoleRequestGuardMiddleware>();
            branch.UseExceptionHandler(handler => handler.Run(WriteGenericError));
            branch.UseRouting();
            branch.UseAuthentication();
            branch.UseAuthorization();
            branch.UseAntiforgery();
            branch.UseEndpoints(endpoints =>
            {
                MapStaticAssets(endpoints);
                endpoints.MapConsoleApi();
                if (auth == ConsoleAuthMode.EntraId)
                {
                    endpoints.MapSignOut();
                }

                endpoints.MapRazorComponents<ConsoleApp>().AddInteractiveServerRenderMode();

                // Anything the console does not serve is a plain 404 for every method (without this, a POST to an unknown path would be answered 405 by the GET-only
                // catch-all of the static assets). EKM routes in particular must be 404 on the console port, not "method not allowed".
                endpoints.Map("/{**unmatched}", static () => Results.NotFound()).WithOrder(int.MaxValue).AllowAnonymous().WithDisplayName("console-not-found");
            });
        });

        return app;
    }

    // The static assets (Blazor script, Fluent UI, console.css/js) are served from this assembly's own manifest. The manifest is looked up by the server assembly's name, not the entry
    // assembly's: when the host runs inside a test process the entry assembly is the test project. A host without the manifest (nothing published or built for it) serves no assets.
    private static void MapStaticAssets(IEndpointRouteBuilder endpoints)
    {
        var manifest = Path.Combine(AppContext.BaseDirectory, typeof(ConsoleApp).Assembly.GetName().Name + ".staticwebassets.endpoints.json");
        if (File.Exists(manifest))
        {
            endpoints.MapStaticAssets(manifest);
        }
    }

    // Never a stack trace, never the exception message: the details are in the (secret-free) logs.
    private static async Task WriteGenericError(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        if (ConsoleAuth.IsApiOrHub(context.Request.Path))
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("""{"code":"InternalError","message":"The console could not complete the request."}""").ConfigureAwait(false);
            return;
        }

        context.Response.ContentType = "text/plain; charset=utf-8";
        await context.Response.WriteAsync("The console could not complete the request.").ConfigureAwait(false);
    }

    /// <summary>EntraId only: a GET page with a POST form (antiforgery-protected), so a third-party page cannot sign the user out.</summary>
    private static IEndpointRouteBuilder MapSignOut(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/signout", (HttpContext context, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);
            var html = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Sign out - EkmMock console</title></head><body>" +
                       "<main><h1>Sign out</h1><form method=\"post\" action=\"/signout\">" +
                       $"<input type=\"hidden\" name=\"{System.Net.WebUtility.HtmlEncode(tokens.FormFieldName)}\" value=\"{System.Net.WebUtility.HtmlEncode(tokens.RequestToken)}\">" +
                       "<button type=\"submit\">Sign out of the EkmMock console</button></form></main></body></html>";
            return Results.Content(html, "text/html; charset=utf-8");
        });

        endpoints.MapPost("/signout", async Task<IResult> (HttpContext context) =>
        {
            await context.SignOutAsync("Cookies").ConfigureAwait(false);
            await context.SignOutAsync("OpenIdConnect", new AuthenticationProperties { RedirectUri = "/" }).ConfigureAwait(false);
            return Results.Empty;
        }).AddEndpointFilter<AntiforgeryEndpointFilter>();
        return endpoints;
    }
}
