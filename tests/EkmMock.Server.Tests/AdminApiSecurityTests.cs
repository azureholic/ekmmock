#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// M6, spec 5.4 and 12: who may call the new endpoints and how a non-browser client (the CLI) proves it is not a cross-site browser request. Browser CSRF protection is
/// not weakened: a request that carries an <c>Origin</c> header still needs the antiforgery token, and a cross-origin one is refused outright.
/// </summary>
public sealed class AdminApiSecurityTests : IAsyncLifetime
{
    private ConsoleTestHost _loopback = null!;
    private ConsoleTestHost _entra = null!;

    public async ValueTask InitializeAsync()
    {
        _loopback = await ConsoleTestHost.StartAsync();
        _entra = await ConsoleTestHost.StartAsync(entra: true);
    }

    public async ValueTask DisposeAsync()
    {
        await _loopback.DisposeAsync();
        await _entra.DisposeAsync();
    }

    public static TheoryData<string> ReadEndpoints =>
    [
        "/api/console/keys",
        "/api/console/keys/_default/aes-key-1",
        "/api/console/namespaces",
        "/api/console/namespaces/_default",
        "/api/console/certificates",
        "/api/console/certificates/root-ca.pem",
        "/api/console/audit",
        "/api/console/about",
        "/api/console/self-test",
    ];

    public static TheoryData<string, string> MutatingEndpoints => new()
    {
        { "POST", "/api/console/keys" },
        { "POST", "/api/console/keys/import" },
        { "POST", "/api/console/keys/_default/aes-key-1/enable" },
        { "POST", "/api/console/keys/_default/aes-key-1/disable" },
        { "POST", "/api/console/keys/_default/aes-key-1/expiry" },
        { "POST", "/api/console/keys/_default/aes-key-1/destroy" },
        { "POST", "/api/console/namespaces" },
        { "PUT", "/api/console/namespaces/_default" },
        { "POST", "/api/console/namespaces/_default/delete" },
        { "POST", "/api/console/namespaces/_default/trust/import" },
        { "POST", "/api/console/certificates/upload" },
        { "POST", "/api/console/certificates/generate" },
    };

    private static Action<HttpRequestMessage> As(string oid) => request =>
    {
        request.Headers.Add("X-Test-Oid", oid);
        request.Headers.Add("X-Test-Name", "Alice Admin");
        request.Headers.Add("X-Test-Tid", ConsoleTestHost.TenantId);
    };

    [Theory]
    [MemberData(nameof(ReadEndpoints))]
    public async Task EveryReadEndpoint_RequiresTheConsolePolicy_InEntraMode(string path)
    {
        var api = new AdminApi(_entra.Host.CreateConsoleClient());

        (await api.GetAsync(path)).StatusCode.ShouldBe(401, path);
        (await api.GetAsync(path, As(ConsoleTestHost.OtherOid))).StatusCode.ShouldBe(403, path);
        var allowed = await api.GetAsync(path, As(ConsoleTestHost.AllowedOid));
        allowed.StatusCode.ShouldBeOneOf([200, 404], path); // root-ca.pem is 404 until test PKI exists; the point is that the policy let the request through
        allowed.StatusCode.ShouldNotBe(401);
        allowed.StatusCode.ShouldNotBe(403);
    }

    [Theory]
    [MemberData(nameof(MutatingEndpoints))]
    public async Task EveryMutatingEndpoint_RequiresTheConsolePolicy_EvenWithTheCliHeader(string method, string path)
    {
        var api = new AdminApi(_entra.Host.CreateConsoleClient());
        var http = new HttpMethod(method);

        (await api.SendAsync(http, path, new { })).StatusCode.ShouldBe(401, path);
        (await api.SendAsync(http, path, new { }, As(ConsoleTestHost.OtherOid))).StatusCode.ShouldBe(403, path);
    }

    [Theory]
    [MemberData(nameof(MutatingEndpoints))]
    public async Task EveryMutatingEndpoint_RefusesARequestWithoutAnyCsrfProof(string method, string path)
    {
        var api = new AdminApi(_loopback.Host.CreateConsoleClient());

        var reply = await api.SendAsync(new HttpMethod(method), path, new { }, cli: false);

        reply.StatusCode.ShouldBe(400, path);
        reply.ErrorCode.ShouldBe("AntiforgeryTokenInvalid");
        reply.ErrorMessage.ShouldContain("X-EkmMock-Client");
    }

    [Fact]
    public async Task ACliClient_NeedsNoCookieJar_JustTheCustomHeader()
    {
        var api = new AdminApi(_loopback.Host.CreateConsoleClient());

        var created = await api.PostAsync("/api/console/keys", new { @namespace = "_default", name = "cli-key", type = "oct", size = 256 });

        created.StatusCode.ShouldBe(201, created.Text);
    }

    [Fact]
    public async Task ABrowserStyleRequest_WithAnOriginHeader_StillNeedsTheAntiforgeryToken_EvenWithTheCliHeader()
    {
        var api = new AdminApi(_loopback.Host.CreateConsoleClient());
        var origin = $"https://127.0.0.1:{_loopback.Host.ConsolePort}";

        var withoutToken = await api.PostAsync("/api/console/keys", new { @namespace = "_default", name = "origin-key", type = "oct", size = 256 }, request => request.Headers.Add("Origin", origin));
        withoutToken.StatusCode.ShouldBe(400);
        withoutToken.ErrorCode.ShouldBe("AntiforgeryTokenInvalid");

        var token = await api.Http.GetAntiforgeryTokenAsync();
        var withToken = await api.PostAsync(
            "/api/console/keys",
            new { @namespace = "_default", name = "origin-key", type = "oct", size = 256 },
            request =>
            {
                request.Headers.Add("Origin", origin);
                request.Headers.Add("X-CSRF-TOKEN", token);
            },
            cli: false);
        withToken.StatusCode.ShouldBe(201, withToken.Text);
    }

    [Fact]
    public async Task ACrossOriginRequest_IsRefusedOutright_EvenWithTheCliHeaderAndAValidToken()
    {
        var api = new AdminApi(_loopback.Host.CreateConsoleClient());
        var token = await api.Http.GetAntiforgeryTokenAsync();

        var reply = await api.PostAsync(
            "/api/console/keys",
            new { @namespace = "_default", name = "evil-key", type = "oct", size = 256 },
            request =>
            {
                request.Headers.Add("Origin", "https://evil.example");
                request.Headers.Add("X-CSRF-TOKEN", token);
            });

        reply.StatusCode.ShouldBe(403);
        (await api.GetAsync("/api/console/keys/_default/evil-key")).StatusCode.ShouldBe(404, "nothing was created");
    }

    [Fact]
    public async Task ACrossSiteFetch_WithTheCliHeader_IsNotTrustedAsAScriptedClient()
    {
        var api = new AdminApi(_loopback.Host.CreateConsoleClient());

        var reply = await api.PostAsync("/api/console/keys", new { @namespace = "_default", name = "site-key", type = "oct", size = 256 }, request => request.Headers.Add("Sec-Fetch-Site", "cross-site"));

        reply.StatusCode.ShouldBe(400);
        reply.ErrorCode.ShouldBe("AntiforgeryTokenInvalid");
    }

    [Fact]
    public async Task AnEmptyCliHeader_IsNoProof()
    {
        var api = new AdminApi(_loopback.Host.CreateConsoleClient());

        var reply = await api.PostAsync("/api/console/keys", new { }, request => request.Headers.Add("X-EkmMock-Client", string.Empty), cli: false);

        reply.StatusCode.ShouldBe(400);
    }

    [Fact]
    public async Task TheAntiforgeryTokenFlow_StillWorksForABrowserlessClientWithACookieJar()
    {
        var api = new AdminApi(_loopback.Host.CreateConsoleClient());
        var token = await api.Http.GetAntiforgeryTokenAsync();

        var reply = await api.PostAsync("/api/console/keys", new { @namespace = "_default", name = "token-key", type = "oct", size = 256 }, request => request.Headers.Add("X-CSRF-TOKEN", token), cli: false);

        reply.StatusCode.ShouldBe(201, reply.Text);
    }

    [Fact]
    public async Task TheAdminApi_IsOnTheConsolePortOnly()
    {
        using var ekm = _loopback.Host.CreateHttpClient();

        foreach (var path in new[] { "/api/console/keys", "/api/console/audit", "/api/console/about", "/api/console/certificates", "/keys", "/namespaces", "/certificates", "/playground", "/audit", "/about" })
        {
            using var reply = await ekm.GetAsync(path);
            reply.StatusCode.ShouldBe(HttpStatusCode.NotFound, path);
            using var post = await ekm.PostAsync(path, new StringContent("{}"));
            post.StatusCode.ShouldBe(HttpStatusCode.NotFound, path);
        }
    }

    [Fact]
    public async Task TheAuditUser_InEntraMode_IsTheSignedInUser()
    {
        var api = new AdminApi(_entra.Host.CreateConsoleClient());

        var created = await api.PostAsync("/api/console/keys", new { @namespace = "_default", name = "entra-key", type = "oct", size = 256 }, As(ConsoleTestHost.AllowedOid));

        created.StatusCode.ShouldBe(201, created.Text);
        _entra.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent().Single(static e => e.Action == "key.create" && e.Target == "key:_default/entra-key").User
            .ShouldBe($"Alice Admin ({ConsoleTestHost.AllowedOid})");
    }
}

/// <summary>M6, spec 8.5.11: the About page's data, the redaction of every secret, and the self-test results.</summary>
[Collection(ProcessEnvironmentCollection.Name)]
public sealed class AdminApiAboutTests : IAsyncLifetime
{
    private const string FakeClientSecret = "FAKE-ENTRA-CLIENT-SECRET-5c1d9e47";
    private const string FakeMasterKeyVariable = "FAKE-MASTER-KEY-FROM-ENVIRONMENT-8841";
    private ConsoleTestHost _host = null!;
    private string? _oldClientSecret;
    private string? _oldMasterKey;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync(entra: true);
        _oldClientSecret = Environment.GetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable);
        _oldMasterKey = Environment.GetEnvironmentVariable("EKMMOCK_MASTER_KEY");
        Environment.SetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable, FakeClientSecret);
        Environment.SetEnvironmentVariable("EKMMOCK_MASTER_KEY", FakeMasterKeyVariable);
    }

    public async ValueTask DisposeAsync()
    {
        Environment.SetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable, _oldClientSecret);
        Environment.SetEnvironmentVariable("EKMMOCK_MASTER_KEY", _oldMasterKey);
        await _host.DisposeAsync();
    }

    private async Task<ApiReply> AboutAsync()
    {
        var api = new AdminApi(_host.Host.CreateConsoleClient());
        return await api.GetAsync("/api/console/about", request =>
        {
            request.Headers.Add("X-Test-Oid", ConsoleTestHost.AllowedOid);
            request.Headers.Add("X-Test-Tid", ConsoleTestHost.TenantId);
        });
    }

    [Fact]
    public async Task About_ShowsVersionRuntimeListenersPolicyDataVolumeAndInspector()
    {
        var reply = await AboutAsync();

        reply.StatusCode.ShouldBe(200, reply.Text);
        reply.Root.GetProperty("version").GetString()!.ShouldNotBeNullOrEmpty();
        reply.Root.GetProperty("auth_mode").GetString().ShouldBe("EntraId");
        reply.Root.GetProperty("runtime").GetProperty("dotnet").GetString()!.ShouldContain(".NET");
        reply.Root.GetProperty("runtime").GetProperty("os").GetString()!.ShouldNotBeNullOrEmpty();
        reply.Root.GetProperty("tls").GetProperty("protocol").GetString().ShouldBe("TLS 1.3 only");
        var listeners = reply.Root.GetProperty("listeners").EnumerateArray().ToList();
        listeners.Count.ShouldBe(2);
        listeners[0].GetProperty("bound_ports")[0].GetInt32().ShouldBe(_host.Host.Port);
        listeners[1].GetProperty("bound_ports")[0].GetInt32().ShouldBe(_host.Host.ConsolePort);
        var entries = reply.Root.GetProperty("data").GetProperty("entries").EnumerateArray().ToList();
        entries.Single(static e => e.GetProperty("name").GetString() == "keystore.json").GetProperty("exists").GetBoolean().ShouldBeTrue();
        entries.Single(static e => e.GetProperty("name").GetString() == "namespaces.json").GetProperty("bytes").GetInt64().ShouldBeGreaterThan(0);
        reply.Root.GetProperty("inspector").GetProperty("ring_capacity").GetInt32().ShouldBe(10_000);
        reply.Root.GetProperty("master_key").GetProperty("dev_mode").GetBoolean().ShouldBeFalse();
        reply.Root.GetProperty("links").GetArrayLength().ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task About_NeverShowsASecret_NotTheMasterKey_NotTheClientSecret_NotAnEnvironmentValue()
    {
        var reply = await AboutAsync();

        reply.StatusCode.ShouldBe(200);
        reply.Text.ShouldNotContain(FakeClientSecret);
        reply.Text.ShouldNotContain(FakeMasterKeyVariable);
        var masterKey = EkmFactory.MasterKeyBytes("real-host");
        reply.Text.ShouldNotContain(Convert.ToBase64String(masterKey));
        reply.Text.ShouldNotContain(Convert.ToHexString(masterKey), Case.Insensitive);
        SecretScanner.LeaksInText(reply.Text, masterKey).ShouldBeFalse();

        var secrets = reply.Root.GetProperty("configuration").EnumerateArray().Where(static e => e.GetProperty("section").GetString() == "Secrets").ToList();
        secrets.Count.ShouldBe(3);
        secrets.ShouldAllBe(static e => e.GetProperty("redacted").GetBoolean() && e.GetProperty("value").GetString()!.EndsWith("value hidden", StringComparison.Ordinal));
        secrets.Single(static e => e.GetProperty("name").GetString()!.StartsWith("Entra client secret", StringComparison.Ordinal)).GetProperty("value").GetString()!.ShouldStartWith("set");
    }

    [Fact]
    public async Task About_ShowsTheStartupSelfTest_PerCaseWithDuration_AndFlagsFailures()
    {
        var reply = await AboutAsync();
        var selfTest = reply.Root.GetProperty("self_test");
        selfTest.GetProperty("passed").GetBoolean().ShouldBeTrue();
        var cases = selfTest.GetProperty("cases").EnumerateArray().Select(static c => c.GetProperty("name").GetString()!).ToList();
        cases.ShouldContain(static n => n.StartsWith("aes-kw/rfc3394", StringComparison.Ordinal));
        cases.ShouldContain(static n => n.StartsWith("aes-kwp/rfc5649", StringComparison.Ordinal));
        cases.ShouldContain(static n => n.StartsWith("rsa-oaep-256", StringComparison.Ordinal));
        cases.ShouldContain(static n => n.StartsWith("rsa-oaep/", StringComparison.Ordinal)); // (the keys of this test host were created after the start-up self-test, so there are no key cases)
        selfTest.GetProperty("cases")[0].GetProperty("duration_ms").GetDouble().ShouldBeGreaterThan(0);

        // A failing algorithm or key is flagged.
        var startup = _host.Host.App.Services.GetRequiredService<EkmStartupState>();
        startup.MarkReady(new SelfTestResult(
            [new SelfTestCaseResult("rsa-oaep/roundtrip", SelfTestOutcome.Failed, TimeSpan.FromMilliseconds(3), "mismatch"), new SelfTestCaseResult("key:_default/aes-key-1", SelfTestOutcome.Passed, TimeSpan.FromMilliseconds(1), null)],
            DateTimeOffset.UtcNow,
            Strict: false));

        var failing = (await AboutAsync()).Root.GetProperty("self_test");
        failing.GetProperty("passed").GetBoolean().ShouldBeFalse();
        failing.GetProperty("failing").EnumerateArray().Select(static f => f.GetString()).ShouldBe(["rsa-oaep/roundtrip"]);
        (await new AdminApi(_host.Host.CreateConsoleClient()).GetAsync("/api/console/self-test", request =>
        {
            request.Headers.Add("X-Test-Oid", ConsoleTestHost.AllowedOid);
            request.Headers.Add("X-Test-Tid", ConsoleTestHost.TenantId);
        })).Root.GetProperty("cases").GetArrayLength().ShouldBe(2);
    }
}
