using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;

namespace EkmMock.Server.WebConsole;

/// <summary>Claim types the console looks at (Entra emits both the short and the long object id claim depending on the claim mapping).</summary>
internal static class ConsoleClaims
{
    public const string ObjectId = "oid";
    public const string ObjectIdLong = "http://schemas.microsoft.com/identity/claims/objectidentifier";
    public const string TenantId = "tid";
    public const string TenantIdLong = "http://schemas.microsoft.com/identity/claims/tenantid";
    public const string Groups = "groups";
    public const string PreferredUsername = "preferred_username";
    public const string Name = "name";

    /// <summary>The auth mode of the principal, set by the loopback handler so that the audit name does not depend on claims a browser could influence.</summary>
    public const string AuthMode = "ekmmock:auth_mode";
}

/// <summary>Who is using the console, as the audit log and the pages need it.</summary>
internal sealed record ConsoleUserInfo(string Id, string DisplayName, ConsoleAuthMode Mode)
{
    public const string LoopbackName = "loopback";

    /// <summary>The user text written to audit entries: <c>loopback</c>, or <c>Display Name (object-id)</c>.</summary>
    public string AuditName => Mode == ConsoleAuthMode.LoopbackOnly ? LoopbackName : $"{DisplayName} ({Id})";

    public static ConsoleUserInfo From(ClaimsPrincipal? principal, ConsoleAuthMode mode)
    {
        if (mode == ConsoleAuthMode.LoopbackOnly)
        {
            return new ConsoleUserInfo(LoopbackName, LoopbackName, mode);
        }

        if (principal?.Identity?.IsAuthenticated != true)
        {
            return new ConsoleUserInfo("anonymous", "anonymous", mode);
        }

        var id = ConsoleAccessPolicy.ObjectIdOf(principal) ?? "unknown";
        var name = principal.FindFirstValue(ConsoleClaims.Name)
            ?? principal.FindFirstValue(ConsoleClaims.PreferredUsername)
            ?? principal.Identity?.Name
            ?? id;
        return new ConsoleUserInfo(id, name, mode);
    }
}

/// <summary>
/// The one abstraction for "the current console user" (spec 5.4: every state-changing action is audited with the user). Blazor circuits read the identity the
/// circuit was started with; request-scoped code (<c>/api/console/*</c>) reads the request's principal.
/// </summary>
internal interface IConsoleUser
{
    ValueTask<ConsoleUserInfo> GetAsync();
}

internal sealed class ConsoleUser : IConsoleUser
{
    private readonly IOptions<ConsoleOptions> _options;
    private readonly IHttpContextAccessor _http;
    private readonly AuthenticationStateProvider? _state;

    public ConsoleUser(IOptions<ConsoleOptions> options, IHttpContextAccessor http, IServiceProvider services)
    {
        _options = options;
        _http = http;
        _state = services.GetService<AuthenticationStateProvider>();
    }

    public async ValueTask<ConsoleUserInfo> GetAsync()
    {
        var mode = _options.Value.Auth;
        if (mode == ConsoleAuthMode.LoopbackOnly)
        {
            return ConsoleUserInfo.From(null, mode);
        }

        if (_state is not null)
        {
            try
            {
                var state = await _state.GetAuthenticationStateAsync().ConfigureAwait(false);
                if (state.User.Identity?.IsAuthenticated == true)
                {
                    return ConsoleUserInfo.From(state.User, mode);
                }
            }
            catch (InvalidOperationException)
            {
                // Not inside a circuit: fall back to the request principal.
            }
        }

        return ConsoleUserInfo.From(_http.HttpContext?.User, mode);
    }
}

/// <summary>The authorization rule of <see cref="ConsoleAuth.PolicyName"/> for <see cref="ConsoleAuthMode.EntraId"/>: allowed object ids or group membership (and the configured tenant).</summary>
internal static class ConsoleAccessPolicy
{
    public static string? ObjectIdOf(ClaimsPrincipal principal)
        => principal.FindFirstValue(ConsoleClaims.ObjectId) ?? principal.FindFirstValue(ConsoleClaims.ObjectIdLong);

    public static bool IsAllowed(ClaimsPrincipal principal, EntraIdOptions options)
    {
        if (principal.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        // The tenant claim is ALWAYS enforced (security review L2): a multi-tenant misconfiguration must not let another tenant's user in, and a token without a tenant claim is not ours either.
        // The configured tenant has to be a GUID (refused at startup otherwise); if it somehow is not, nobody is allowed (fail closed) instead of everybody.
        if (!ConsoleConfigurationValidator.TryParseTenantId(options.TenantId, out var configuredTenant))
        {
            return false;
        }

        var tenant = principal.FindFirstValue(ConsoleClaims.TenantId) ?? principal.FindFirstValue(ConsoleClaims.TenantIdLong);
        if (!ConsoleConfigurationValidator.TryParseTenantId(tenant, out var actual) || actual != configuredTenant)
        {
            return false;
        }

        if (ObjectIdOf(principal) is { } oid && options.AllowedObjectIds.Any(allowed => string.Equals(allowed?.Trim(), oid, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(options.AllowedGroupId)
            && principal.FindAll(ConsoleClaims.Groups).Any(group => string.Equals(group.Value, options.AllowedGroupId.Trim(), StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>The loopback "authentication": every request on the (loopback-bound) console is the local user. There is no sign-in and no cookie.</summary>
internal sealed class LoopbackAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public LoopbackAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.Name, ConsoleUserInfo.LoopbackName),
                new Claim(ConsoleClaims.ObjectId, ConsoleUserInfo.LoopbackName),
                new Claim(ConsoleClaims.AuthMode, nameof(ConsoleAuthMode.LoopbackOnly)),
            ],
            authenticationType: Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
    }
}

/// <summary>
/// Bearer-token access to <c>/api/console/*</c> for the CLI in <see cref="ConsoleAuthMode.EntraId"/> (spec 12, open question 38). The token is the user's Entra access token
/// for the console's app registration, validated by Microsoft.Identity.Web (signature, issuer, audience, lifetime) and then judged by the same
/// <see cref="ConsoleAccessPolicy"/> (allowed object ids or group, tenant) as the browser sign-in. Accepted on <c>/api/console/*</c> <b>only</b>: never for Blazor pages,
/// <c>/_blazor</c>, <c>/metrics</c> or the EKM endpoint (the EKM port does not run the console pipeline at all).
/// </summary>
internal static class ConsoleBearer
{
    public const string Scheme = "EkmMock.Bearer";

    public const string SelectorScheme = "EkmMock.ConsoleAuth";

    /// <summary>Set in <c>HttpContext.Items</c> by the bearer handler once it validated the token of this request.</summary>
    public const string AuthenticatedItem = "ekmmock:bearer-authenticated";

    public static bool IsBearerApiRequest(HttpRequest request)
        => request.Path.StartsWithSegments(ConsoleApi.BasePath, StringComparison.OrdinalIgnoreCase)
            && request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when this request was authenticated by a validated bearer token. Such a request carries no ambient credential (no cookie), so it cannot be forged cross-site.</summary>
    public static bool IsBearerAuthenticated(HttpContext context)
        => context.Items.TryGetValue(AuthenticatedItem, out var marker) && marker is true && context.User.Identity?.IsAuthenticated == true;
}

/// <summary>Authentication and authorization of the console (spec 5.4), chosen by <see cref="ConsoleOptions.Auth"/>.</summary>
internal static class ConsoleAuth
{
    /// <summary>The policy every console endpoint requires (as the fallback policy); only <c>/healthz</c> and <c>/readyz</c> opt out.</summary>
    public const string PolicyName = "EkmMock.Console";

    public const string LoopbackScheme = "EkmMock.Loopback";

    public static IServiceCollection AddConsoleAuthentication(this IServiceCollection services, ConsoleOptions options)
    {
        if (options.Auth == ConsoleAuthMode.EntraId)
        {
            AddEntra(services, options.EntraId);
        }
        else
        {
            services.AddAuthentication(LoopbackScheme).AddScheme<AuthenticationSchemeOptions, LoopbackAuthenticationHandler>(LoopbackScheme, null);
        }

        // Reads the configured options at the time of use, so a test that supplies a different allow-list through DI sees it.
        services.AddAuthorizationBuilder()
            .AddPolicy(PolicyName, policy =>
            {
                policy.RequireAuthenticatedUser();
                if (options.Auth == ConsoleAuthMode.EntraId)
                {
                    policy.RequireAssertion(context => ConsoleAccessPolicy.IsAllowed(context.User, options.EntraId));
                }
            });
        services.Configure<AuthorizationOptions>(static authorization =>
            authorization.FallbackPolicy = authorization.GetPolicy(PolicyName));

        services.AddCascadingAuthenticationState();
        services.AddHttpContextAccessor();
        services.AddScoped<IConsoleUser, ConsoleUser>();
        return services;
    }

    private static void AddEntra(IServiceCollection services, EntraIdOptions entra)
    {
        // The secret is read once from the environment (never from configuration) and only ever handed to the OIDC client.
        var secret = ConsoleSecrets.ReadClientSecret();

        // The default scheme is a policy scheme that sends a bearer-carrying request for /api/console/* to the JWT bearer scheme (the CLI, spec 12) and everything else to the
        // OpenID Connect + cookie sign-in (the browser). The selector looks at the path, so a bearer token is never looked at for pages, the SignalR hub or anything else.
        var builder = services.AddAuthentication(ConsoleBearer.SelectorScheme);
        builder.AddPolicyScheme(ConsoleBearer.SelectorScheme, "EkmMock console", scheme =>
        {
            scheme.ForwardDefault = OpenIdConnectDefaults.AuthenticationScheme;
            scheme.ForwardDefaultSelector = static context => ConsoleBearer.IsBearerApiRequest(context.Request) ? ConsoleBearer.Scheme : null;
        });
        builder.AddMicrosoftIdentityWebApi(
            jwt =>
            {
                // Short claim names (oid, tid, name, groups): ConsoleAccessPolicy and the audit name read the same claims for both sign-in paths.
                jwt.MapInboundClaims = false;
                jwt.TokenValidationParameters.NameClaimType = ConsoleClaims.Name;
            },
            identity =>
            {
                identity.Instance = entra.Instance ?? "https://login.microsoftonline.com/";
                identity.TenantId = entra.TenantId;
                identity.ClientId = entra.ClientId;
            },
            ConsoleBearer.Scheme,
            subscribeToJwtBearerMiddlewareDiagnosticsEvents: false);
        services.PostConfigure<JwtBearerOptions>(ConsoleBearer.Scheme, static jwt =>
        {
            // Remember that this request was authenticated by a bearer token: that is what makes it a non-browser call for the CSRF rule of ConsoleMutationFilter.
            var previous = jwt.Events.OnTokenValidated;
            jwt.Events.OnTokenValidated = async context =>
            {
                context.HttpContext.Items[ConsoleBearer.AuthenticatedItem] = true;
                await previous(context).ConfigureAwait(false);
            };
        });

        builder
            .AddMicrosoftIdentityWebApp(
                identity =>
                {
                    identity.Instance = entra.Instance ?? "https://login.microsoftonline.com/";
                    identity.TenantId = entra.TenantId;
                    identity.ClientId = entra.ClientId;
                    identity.CallbackPath = entra.CallbackPath;
                    identity.SignedOutCallbackPath = entra.SignedOutCallbackPath;
                    identity.ClientCredentials =
                    [
                        new CredentialDescription { SourceType = CredentialSource.ClientSecret, ClientSecret = secret },
                    ];
                },
                cookie =>
                {
                    cookie.Cookie.Name = "__Host-ekmmock-console";
                    cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                    cookie.Cookie.SameSite = SameSiteMode.Lax;
                    cookie.Cookie.HttpOnly = true;
                    cookie.SlidingExpiration = true;
                    cookie.ExpireTimeSpan = TimeSpan.FromHours(8);
                    cookie.Events.OnRedirectToAccessDenied = static context =>
                    {
                        // Spec 5.4: a signed-in user who is not on the allow-list gets 403, not a redirect to a page that does not exist.
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        return Task.CompletedTask;
                    };
                    cookie.Events.OnRedirectToLogin = static context => ChallengeForApi(context.HttpContext, context.RedirectUri, context.Response);
                });

        services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, static oidc =>
        {
            var previous = oidc.Events.OnRedirectToIdentityProvider;
            oidc.Events.OnRedirectToIdentityProvider = async context =>
            {
                // The JSON API and the SignalR hub get a plain 401 instead of a redirect a script cannot follow.
                if (IsApiOrHub(context.HttpContext.Request.Path))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.HandleResponse();
                    return;
                }

                await previous(context).ConfigureAwait(false);
            };
        });
    }

    private static Task ChallengeForApi(HttpContext context, string redirectUri, HttpResponse response)
    {
        if (IsApiOrHub(context.Request.Path))
        {
            response.StatusCode = StatusCodes.Status401Unauthorized;
        }
        else
        {
            response.Redirect(redirectUri);
        }

        return Task.CompletedTask;
    }

    internal static bool IsApiOrHub(PathString path)
        => path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase) || path.StartsWithSegments("/_blazor", StringComparison.OrdinalIgnoreCase);
}
