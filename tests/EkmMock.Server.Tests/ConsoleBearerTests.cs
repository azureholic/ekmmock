#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using EkmMock.Server.WebConsole;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace EkmMock.Server.Tests;

/// <summary>
/// M8, spec 12 and open question 38: the CLI signs in with an Entra device-code token and presents it as a bearer token on <c>/api/console/*</c>. There is no tenant offline, so the
/// production JWT bearer scheme (Microsoft.Identity.Web) runs for real and only its <em>key source</em> is replaced: tokens are signed with a local symmetric key and the metadata fetch is
/// replaced by a static configuration. Signature, issuer, audience and lifetime validation, the claim mapping, the allow-list policy and the CSRF rule are the production code.
/// Not verified here: a token from a real tenant (see OPEN-QUESTIONS 38).
/// </summary>
public sealed class ConsoleBearerTests : IAsyncLifetime
{
    internal const string Issuer = "https://login.microsoftonline.com/44444444-4444-4444-4444-444444444444/v2.0";
    internal const string ClientId = "55555555-5555-5555-5555-555555555555";

    private static readonly SymmetricSecurityKey SigningKey = new(Encoding.UTF8.GetBytes("test-signing-key-for-the-fake-tenant-0123456789"));

    private ConsoleTestHost _host = null!;
    private ConsoleTestHost _groupHost = null!;
    private ConsoleTestHost _loopback = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync(entra: true, testAuthScheme: false, configureServices: UseLocalSigningKey);
        _groupHost = await ConsoleTestHost.StartAsync(entra: true, testAuthScheme: false, groupId: ConsoleTestHost.GroupId, configureServices: UseLocalSigningKey);
        _loopback = await ConsoleTestHost.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        await _groupHost.DisposeAsync();
        await _loopback.DisposeAsync();
    }

    internal static void UseLocalSigningKey(IServiceCollection services)
    {
        // The browser sign-in cannot reach a tenant either: a static configuration makes its challenge (a redirect to the sign-in page) answerable offline.
        services.PostConfigure<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>(
            Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectDefaults.AuthenticationScheme,
            options =>
            {
                options.Configuration = new OpenIdConnectConfiguration { Issuer = Issuer, AuthorizationEndpoint = "https://login.invalid/authorize" };
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
            });
        services.PostConfigure<JwtBearerOptions>(ConsoleBearer.Scheme, options =>
        {
            options.Configuration = new OpenIdConnectConfiguration { Issuer = Issuer };
            options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.Configuration);
            options.TokenValidationParameters.ValidateIssuer = true;
            options.TokenValidationParameters.IssuerValidator = null;
            options.TokenValidationParameters.ValidIssuer = Issuer;
            options.TokenValidationParameters.ValidateIssuerSigningKey = true;
            options.TokenValidationParameters.IssuerSigningKey = SigningKey;
            options.TokenValidationParameters.ValidateAudience = true;
            options.TokenValidationParameters.ValidAudiences = [ClientId, $"api://{ClientId}"];
            options.TokenValidationParameters.ValidateLifetime = true;
            options.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(5);
        });
    }

    internal static string Token(
        string? oid = ConsoleTestHost.AllowedOid,
        string tid = ConsoleTestHost.TenantId,
        string audience = $"api://{ClientId}",
        string name = "Alice Admin",
        string? group = null,
        TimeSpan? lifetime = null,
        SecurityKey? key = null,
        string issuer = Issuer)
    {
        var claims = new Dictionary<string, object> { ["tid"] = tid, ["name"] = name, ["ver"] = "2.0", ["scp"] = "access_as_user" };
        if (oid is not null)
        {
            claims["oid"] = oid;
        }

        if (group is not null)
        {
            claims["groups"] = new[] { group };
        }

        var now = DateTime.UtcNow;
        var lifetimeValue = lifetime ?? TimeSpan.FromMinutes(30);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = claims,
            NotBefore = lifetimeValue < TimeSpan.Zero ? now.AddHours(-2) : now.AddMinutes(-1),
            Expires = lifetimeValue < TimeSpan.Zero ? now.AddHours(-1) : now.Add(lifetimeValue),
            SigningCredentials = new SigningCredentials(key ?? SigningKey, SecurityAlgorithms.HmacSha256),
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static Action<HttpRequestMessage> Bearer(string token) => request => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

    private AdminApi Api(ConsoleTestHost host) => new(host.Host.CreateConsoleClient());

    // ---- accepted ----

    [Fact]
    public async Task AValidToken_OfAnAllowedUser_CanCallTheApi()
    {
        var reply = await Api(_host).GetAsync("/api/console/keys", Bearer(Token()));

        reply.StatusCode.ShouldBe(200, reply.Text);
        reply.Root.GetProperty("keys").GetArrayLength().ShouldBe(2);
    }

    [Theory]
    [InlineData($"api://{ClientId}")]
    [InlineData(ClientId)]
    public async Task BothAudienceForms_OfTheAppRegistration_AreAccepted(string audience)
    {
        var reply = await Api(_host).GetAsync("/api/console/status", Bearer(Token(audience: audience)));

        reply.StatusCode.ShouldBe(200, reply.Text);
    }

    [Fact]
    public async Task AUserInTheAllowedGroup_IsAccepted_WithoutBeingOnTheObjectIdList()
    {
        var reply = await Api(_groupHost).GetAsync("/api/console/keys", Bearer(Token(oid: ConsoleTestHost.OtherOid, group: ConsoleTestHost.GroupId)));

        reply.StatusCode.ShouldBe(200, reply.Text);
    }

    // ---- refused ----

    [Fact]
    public async Task NoToken_IsRefusedWith401()
    {
        (await Api(_host).GetAsync("/api/console/keys")).StatusCode.ShouldBe(401);
    }

    [Fact]
    public async Task ACliHeaderAlone_IsNotASignIn()
    {
        var reply = await Api(_host).PostAsync("/api/console/keys", new { @namespace = "_default", name = "no-token", type = "oct", size = 256 });

        reply.StatusCode.ShouldBe(401);
    }

    [Fact]
    public async Task AValidToken_OfAUserWhoIsNotOnTheAllowList_Gets403()
    {
        var reply = await Api(_host).GetAsync("/api/console/keys", Bearer(Token(oid: ConsoleTestHost.OtherOid)));

        reply.StatusCode.ShouldBe(403);
    }

    [Fact]
    public async Task AValidToken_FromAnotherTenant_Gets403_EvenForAnAllowedObjectId()
    {
        var reply = await Api(_host).GetAsync("/api/console/keys", Bearer(Token(tid: "99999999-9999-9999-9999-999999999999")));

        reply.StatusCode.ShouldBe(403);
    }

    [Fact]
    public async Task ATokenWithoutAnObjectId_Gets403()
    {
        var reply = await Api(_host).GetAsync("/api/console/keys", Bearer(Token(oid: null)));

        reply.StatusCode.ShouldBe(403);
    }

    [Fact]
    public async Task AnExpiredToken_Gets401()
    {
        var reply = await Api(_host).GetAsync("/api/console/keys", Bearer(Token(lifetime: TimeSpan.FromMinutes(-5))));

        reply.StatusCode.ShouldBe(401);
        reply.Headers.WwwAuthenticate.ToString().ShouldContain("Bearer");
    }

    [Fact]
    public async Task ATokenSignedWithAnotherKey_Gets401()
    {
        var other = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("a-different-signing-key-that-the-server-does-not-know"));

        (await Api(_host).GetAsync("/api/console/keys", Bearer(Token(key: other)))).StatusCode.ShouldBe(401);
    }

    [Fact]
    public async Task ATokenForAnotherAudience_Gets401()
    {
        (await Api(_host).GetAsync("/api/console/keys", Bearer(Token(audience: "api://66666666-6666-6666-6666-666666666666")))).StatusCode.ShouldBe(401);
    }

    [Fact]
    public async Task ATokenFromAnotherIssuer_Gets401()
    {
        (await Api(_host).GetAsync("/api/console/keys", Bearer(Token(issuer: "https://evil.example/44444444-4444-4444-4444-444444444444/v2.0")))).StatusCode.ShouldBe(401);
    }

    [Fact]
    public async Task AGarbageBearerValue_Gets401()
    {
        (await Api(_host).GetAsync("/api/console/keys", Bearer("not-a-jwt"))).StatusCode.ShouldBe(401);
    }

    // ---- not accepted anywhere else ----

    [Theory]
    [InlineData("/")]
    [InlineData("/keys")]
    [InlineData("/exchange/1")]
    [InlineData("/metrics")]
    public async Task ABearerToken_IsNotAcceptedForPagesOrMetrics(string path)
    {
        var client = _host.Host.CreateConsoleClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        Bearer(Token())(request);

        using var response = await client.SendAsync(request);

        // Anonymous as far as the page is concerned: the OIDC challenge (a redirect to the sign-in), never the page or the scrape.
        response.StatusCode.ShouldBeOneOf([HttpStatusCode.Redirect, HttpStatusCode.Unauthorized], path);
    }

    [Fact]
    public async Task ABearerToken_IsNotAcceptedForTheBlazorHub()
    {
        var client = _host.Host.CreateConsoleClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/_blazor/negotiate?negotiateVersion=1");
        Bearer(Token())(request);

        using var response = await client.SendAsync(request);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task TheEkmPort_NeverSeesTheConsoleApi_WhateverTheToken()
    {
        var (ekm, certificate, owner) = _host.CreateTrustedEkmClient();
        using (owner)
        {
            var http = _host.Host.CreateHttpClient(certificate);
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/console/keys");
            Bearer(Token())(request);

            using var response = await http.SendAsync(request);

            response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
            _ = ekm;
        }
    }

    // ---- the CSRF rule ----

    [Fact]
    public async Task AMutation_WithAValidToken_NeedsNoAntiforgeryTokenAndNoCliHeader_AndIsAuditedAsTheUser()
    {
        var api = Api(_host);
        var token = Token(name: "Alice Admin");

        var created = await api.SendAsync(HttpMethod.Post, "/api/console/keys", new { @namespace = "_default", name = "bearer-key", type = "oct", size = 256 }, Bearer(token), cli: false);

        created.StatusCode.ShouldBe(201, created.Text);
        var audit = await api.GetAsync("/api/console/audit?action=key.create", Bearer(token));
        audit.StatusCode.ShouldBe(200, audit.Text);
        audit.Text.ShouldContain("bearer-key");
        audit.Text.ShouldContain($"Alice Admin ({ConsoleTestHost.AllowedOid})");
    }

    [Fact]
    public async Task AMutation_WithAValidToken_ButACrossOriginOrigin_IsStillRefused()
    {
        var api = Api(_host);

        var reply = await api.SendAsync(
            HttpMethod.Post,
            "/api/console/keys",
            new { @namespace = "_default", name = "evil-key", type = "oct", size = 256 },
            request =>
            {
                Bearer(Token())(request);
                request.Headers.Add("Origin", "https://evil.example");
            },
            cli: false);

        reply.StatusCode.ShouldBe(403);
    }

    [Fact]
    public async Task ACookieStyleBrowserRequest_StillNeedsTheAntiforgeryToken()
    {
        // The test host has no browser sign-in, so use the loopback host: a mutation with neither proof is still a 400.
        var api = new AdminApi(_loopback.Host.CreateConsoleClient());

        var reply = await api.SendAsync(HttpMethod.Post, "/api/console/keys", new { @namespace = "_default", name = "csrf-key", type = "oct", size = 256 }, cli: false);

        reply.StatusCode.ShouldBe(400);
        reply.ErrorCode.ShouldBe("AntiforgeryTokenInvalid");
    }

    [Fact]
    public async Task InLoopbackMode_ABearerHeaderIsIgnored_AndGrantsNothingExtra()
    {
        var api = new AdminApi(_loopback.Host.CreateConsoleClient());

        // A bearer header does not stand in for the CSRF proof when there is no bearer scheme: still 400 without the CLI header.
        var reply = await api.SendAsync(HttpMethod.Post, "/api/console/keys", new { @namespace = "_default", name = "loop-key", type = "oct", size = 256 }, Bearer(Token()), cli: false);

        reply.StatusCode.ShouldBe(400);
        reply.ErrorCode.ShouldBe("AntiforgeryTokenInvalid");
    }
}
