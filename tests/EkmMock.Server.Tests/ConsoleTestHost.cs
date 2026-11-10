using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Text.Json;
using EkmMock.Crypto;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>
/// A test authentication scheme standing in for the Entra OIDC sign-in (no real tenant is available offline): the "signed-in user" is described by request headers
/// (<c>X-Test-Oid</c>, <c>X-Test-Name</c>, <c>X-Test-Tid</c>, <c>X-Test-Groups</c>). Without <c>X-Test-Oid</c> the request is anonymous, so the framework challenges it (401).
/// Everything else (the authorization policy, the fallback policy, the allow-list rules) is the production code.
/// </summary>
internal sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "EkmMock.Test";

    public TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-Test-Oid", out var oid) || string.IsNullOrEmpty(oid))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var claims = new List<Claim> { new("oid", oid.ToString()), new("name", Request.Headers["X-Test-Name"].ToString() is { Length: > 0 } name ? name : "Test User") };
        // A real Entra token always carries the tenant claim: the stand-in does too (the test host's tenant) unless a test asks for none or another one.
        if (Request.Headers.TryGetValue("X-Test-Tid", out var tid))
        {
            claims.Add(new Claim("tid", tid.ToString()));
        }
        else if (!Request.Headers.ContainsKey("X-Test-No-Tid"))
        {
            claims.Add(new Claim("tid", ConsoleTestHost.TenantId));
        }

        if (Request.Headers.TryGetValue("X-Test-Groups", out var groups))
        {
            claims.AddRange(groups.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries).Select(static g => new Claim("groups", g)));
        }

        var identity = new ClaimsIdentity(claims, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}

/// <summary>
/// The production host with a real console listener, a trusted client CA/CN and two sample keys. Used by the port-separation, auth, header and API tests.
/// <see cref="Entra"/> switches the console to <c>EntraId</c> with the test authentication scheme in place of the OIDC handler.
/// </summary>
internal sealed class ConsoleTestHost : IAsyncDisposable
{
    public const string ClientCn = "mhsm-console-test.managedhsmclient.test";
    public const string AllowedOid = "11111111-1111-1111-1111-111111111111";
    public const string OtherOid = "22222222-2222-2222-2222-222222222222";
    public const string GroupId = "33333333-3333-3333-3333-333333333333";
    public const string TenantId = "44444444-4444-4444-4444-444444444444";

    private ConsoleTestHost(RealEkmHost host, TestPki pki)
    {
        Host = host;
        Pki = pki;
    }

    public RealEkmHost Host { get; }

    public TestPki Pki { get; }

    public IInspector Inspector => Host.App.Services.GetRequiredService<IInspector>();

    public static async Task<ConsoleTestHost> StartAsync(
        bool entra = false,
        bool allowReveal = false,
        bool plainListener = false,
        string? groupId = null,
        Dictionary<string, string?>? configuration = null,
        bool allowKeyImport = false,
        bool faults = false,
        EkmMock.Server.Faults.IFaultRandom? faultRandom = null,
        Microsoft.Extensions.Logging.LogLevel? minLogLevel = null,
        Action<IServiceCollection>? configureServices = null,
        bool testAuthScheme = true)
    {
        if (entra)
        {
            // The client secret comes from the environment, like in production. This value is not a secret (there is no tenant behind it).
            Environment.SetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable, "test-value-no-tenant-behind-it");
        }

        var pki = new TestPki();
        var config = new Dictionary<string, string?>();
        if (entra)
        {
            config["Console:Auth"] = "EntraId";
            config["Console:EntraId:TenantId"] = TenantId;
            config["Console:EntraId:ClientId"] = "55555555-5555-5555-5555-555555555555";
            config["Console:EntraId:AllowedObjectIds:0"] = AllowedOid;
            if (groupId is not null)
            {
                config["Console:EntraId:AllowedGroupId"] = groupId;
            }
        }

        if (allowReveal)
        {
            config["Inspector:SecretDisplay"] = "Reveal";
        }

        foreach (var pair in configuration ?? [])
        {
            config[pair.Key] = pair.Value;
        }

        var host = await RealEkmHost.StartAsync(new RealEkmHostOptions
        {
            Pki = pki,
            AddPlainHttpListener = plainListener,
            AllowKeyImport = allowKeyImport,
            Configuration = config,
            MinLogLevel = minLogLevel,
            Namespaces = [TestNamespace.Default(pki.ClientCaA, ClientCn)],
            ConfigureServices = services =>
            {
                // Fault injection is off in every test host unless the test asks for it, whatever EKMMOCK_ENABLE_FAULTS says in the environment of the test process.
                services.AddSingleton<EkmMock.Server.Faults.IFaultGate>(new FixedFaultGate(faults));
                if (faultRandom is not null)
                {
                    services.AddSingleton(faultRandom);
                }

                if (entra && testAuthScheme)
                {
                    services.AddAuthentication().AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, null);
                    services.PostConfigure<AuthenticationOptions>(o =>
                    {
                        o.DefaultScheme = TestAuthHandler.SchemeName;
                        o.DefaultAuthenticateScheme = TestAuthHandler.SchemeName;
                        o.DefaultChallengeScheme = TestAuthHandler.SchemeName;
                        o.DefaultForbidScheme = TestAuthHandler.SchemeName;
                    });
                }

                if (allowReveal)
                {
                    services.AddSingleton<IInspectorRevealGate>(new TestRevealGate(true));
                }

                configureServices?.Invoke(services);
            },
        });
        host.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
        host.Keys.Create("_default", "rsa-key-1", KeyType.Rsa, 2048);
        return new ConsoleTestHost(host, pki);
    }

    /// <summary>A client of the EKM endpoint presenting the trusted client certificate.</summary>
    public (EkmClient Client, X509Certificate2 Certificate, IDisposable Owner) CreateTrustedEkmClient()
    {
        var issued = Pki.ClientCaA.IssueClient(ClientCn);
        return (Host.CreateEkmClient(issued.Certificate), issued.Certificate, issued);
    }

    /// <summary>Sends a handful of requests (info, metadata, wrap, unwrap, a 404 and an unauthenticated one) and waits until the inspector has stored them all.</summary>
    public async Task<byte[]> SendSampleTrafficAsync()
    {
        try
        {
            return await SendSampleTrafficCoreAsync();
        }
        catch (HttpRequestException ex)
        {
            // Open question 47: say what the server decided about the handshake, so the rare "chain not trusted" failure is diagnosable when it happens.
            var failures = string.Join(" | ", Inspector.ConnectionEvents(limit: 20)
                .Where(static e => e.Kind == "handshake_failed")
                .Select(static e => $"{e.FailureReason}: {e.FailureDescription} / {e.FailureDetail}"));
            throw new InvalidOperationException($"Sample traffic failed: {ex.Message}. Server-side handshake failures: {(failures.Length == 0 ? "(none recorded)" : failures)}", ex);
        }
    }

    private async Task<byte[]> SendSampleTrafficCoreAsync()
    {
        var (ekm, _, owner) = CreateTrustedEkmClient();
        using (owner)
        {
            var dek = Fx.Random(32);
            (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
            (await ekm.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);
            var wrapped = await ekm.WrapAsync("aes-key-1", "A256KWP", dek);
            wrapped.StatusCode.ShouldBe(200);
            (await ekm.UnwrapAsync("aes-key-1", "A256KWP", wrapped.Value())).StatusCode.ShouldBe(200);
            (await ekm.MetadataAsync("no-such-key")).StatusCode.ShouldBe(404);

            using var anonymous = Host.CreateHttpClient();
            (await new EkmClient(anonymous).InfoAsync()).StatusCode.ShouldBe(401);
            (await Wait.UntilAsync(() => Inspector.Status().RingCount >= 6)).ShouldBeTrue("the inspector did not store the sample traffic");
            return dek;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await Host.DisposeAsync();
        Pki.Dispose();
    }
}

internal static class ConsoleTestJson
{
    public static async Task<JsonDocument> GetJsonAsync(this HttpClient client, string path, Action<HttpRequestMessage>? configure = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        configure?.Invoke(request);
        using var response = await client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, path);
        return JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());
    }

    public static async Task<HttpResponseMessage> SendAsync(this HttpClient client, HttpMethod method, string path, Action<HttpRequestMessage>? configure = null, HttpContent? content = null)
    {
        var request = new HttpRequestMessage(method, path) { Content = content };
        configure?.Invoke(request);
        return await client.SendAsync(request);
    }

    /// <summary>Fetches an antiforgery token (and its cookie, kept by the client) the way a CLI would.</summary>
    public static async Task<string> GetAntiforgeryTokenAsync(this HttpClient client, Action<HttpRequestMessage>? configure = null)
    {
        using var doc = await client.GetJsonAsync("/api/console/antiforgery", configure);
        doc.RootElement.GetProperty("header_name").GetString().ShouldBe("X-CSRF-TOKEN");
        return doc.RootElement.GetProperty("token").GetString()!;
    }

    public static StringContent Json(string json) => new(json, System.Text.Encoding.UTF8, "application/json");
}
