#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using System.Text;
using System.Text.Json;
using EkmMock.Server.Inspector;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// Spec 5.4: the console auth modes through the real production authorization policy. The Entra OIDC handshake itself cannot be tested offline (there is no tenant), so a test
/// authentication scheme stands in for the sign-in and everything after it is production code: the fallback policy, the allow-list (object ids, group, tenant), 401 for the
/// anonymous, 403 for the signed-in but not allowed, the anonymous-but-minimal health endpoints and the user identity that reaches the audit log.
/// </summary>
public sealed class ConsoleAuthTests : IAsyncLifetime
{
    private ConsoleTestHost _oid = null!;
    private ConsoleTestHost _group = null!;

    public async ValueTask InitializeAsync()
    {
        _oid = await ConsoleTestHost.StartAsync(entra: true);
        _group = await ConsoleTestHost.StartAsync(entra: true, groupId: ConsoleTestHost.GroupId);
    }

    public async ValueTask DisposeAsync()
    {
        await _oid.DisposeAsync();
        await _group.DisposeAsync();
    }

    private static Action<HttpRequestMessage> As(string oid, string? name = null, string? tid = null, string? groups = null) => request =>
    {
        request.Headers.Add("X-Test-Oid", oid);
        if (name is not null)
        {
            request.Headers.Add("X-Test-Name", name);
        }

        if (tid is not null)
        {
            request.Headers.Add("X-Test-Tid", tid);
        }

        if (groups is not null)
        {
            request.Headers.Add("X-Test-Groups", groups);
        }
    };

    public static TheoryData<string> ProtectedPaths =>
    [
        "/",
        "/connections",
        "/dashboard",
        "/exchange/1",
        "/api/console/status",
        "/api/console/exchanges",
        "/api/console/dashboard",
        "/api/console/connections",
        "/api/console/export?format=jsonl",
        "/api/console/antiforgery",
        "/_blazor/negotiate?negotiateVersion=1",
        "/signout",
    ];

    [Theory]
    [MemberData(nameof(ProtectedPaths))]
    public async Task AnAnonymousUser_IsChallenged_OnEveryConsoleRoute(string path)
    {
        using var console = _oid.Host.CreateConsoleClient();
        var method = path.StartsWith("/_blazor", StringComparison.Ordinal) ? HttpMethod.Post : HttpMethod.Get;

        using var response = await console.SendAsync(method, path);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized, path);
    }

    [Theory]
    [MemberData(nameof(ProtectedPaths))]
    public async Task ASignedInUser_WhoIsNotOnTheAllowList_Gets403_OnEveryConsoleRoute(string path)
    {
        using var console = _oid.Host.CreateConsoleClient();
        var method = path.StartsWith("/_blazor", StringComparison.Ordinal) ? HttpMethod.Post : HttpMethod.Get;

        using var response = await console.SendAsync(method, path, As(ConsoleTestHost.OtherOid));

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden, path);
    }

    [Theory]
    [InlineData("/", "text/html")]
    [InlineData("/connections", "text/html")]
    [InlineData("/dashboard", "text/html")]
    [InlineData("/api/console/status", "application/json")]
    [InlineData("/api/console/exchanges", "application/json")]
    public async Task AnAllowedObjectId_GetsThePageOrTheApi(string path, string contentType)
    {
        using var console = _oid.Host.CreateConsoleClient();

        using var response = await console.SendAsync(HttpMethod.Get, path, As(ConsoleTestHost.AllowedOid, "Alice Admin", ConsoleTestHost.TenantId));

        response.StatusCode.ShouldBe(HttpStatusCode.OK, path);
        response.Content.Headers.ContentType!.MediaType.ShouldBe(contentType);
    }

    [Fact]
    public async Task TheSignalRHub_RequiresThePolicyToo()
    {
        using var console = _oid.Host.CreateConsoleClient();

        using var allowed = await console.SendAsync(HttpMethod.Post, "/_blazor/negotiate?negotiateVersion=1", As(ConsoleTestHost.AllowedOid));
        using var other = await console.SendAsync(HttpMethod.Post, "/_blazor/negotiate?negotiateVersion=1", As(ConsoleTestHost.OtherOid));
        using var anonymous = await console.SendAsync(HttpMethod.Post, "/_blazor/negotiate?negotiateVersion=1");

        allowed.StatusCode.ShouldBe(HttpStatusCode.OK);
        other.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        anonymous.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task TheObjectIdMatch_IsCaseInsensitive_AndAnEmptyOrMissingOidIsNeverAllowed()
    {
        using var console = _oid.Host.CreateConsoleClient();

        using var upper = await console.SendAsync(HttpMethod.Get, "/api/console/status", As(ConsoleTestHost.AllowedOid.ToUpperInvariant()));
        using var empty = await console.SendAsync(HttpMethod.Get, "/api/console/status", request => request.Headers.Add("X-Test-Name", "No Oid"));

        upper.StatusCode.ShouldBe(HttpStatusCode.OK);
        empty.StatusCode.ShouldBe(HttpStatusCode.Unauthorized); // no oid claim: the test scheme treats it as anonymous
    }

    [Fact]
    public async Task AGroupMember_IsAllowed_WhenAnAllowedGroupIsConfigured_AndAnObjectIdStillWorks()
    {
        using var console = _group.Host.CreateConsoleClient();

        using var member = await console.SendAsync(HttpMethod.Get, "/api/console/status", As(ConsoleTestHost.OtherOid, groups: $"aaaaaaaa-0000-0000-0000-000000000000,{ConsoleTestHost.GroupId}"));
        using var outsider = await console.SendAsync(HttpMethod.Get, "/api/console/status", As(ConsoleTestHost.OtherOid, groups: "aaaaaaaa-0000-0000-0000-000000000000"));
        using var listed = await console.SendAsync(HttpMethod.Get, "/api/console/status", As(ConsoleTestHost.AllowedOid));

        member.StatusCode.ShouldBe(HttpStatusCode.OK);
        outsider.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        listed.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AUserOfAnotherTenant_IsRefused_EvenWithAnAllowedObjectId()
    {
        using var console = _oid.Host.CreateConsoleClient();

        using var otherTenant = await console.SendAsync(HttpMethod.Get, "/api/console/status", As(ConsoleTestHost.AllowedOid, tid: "99999999-9999-9999-9999-999999999999"));
        using var ownTenant = await console.SendAsync(HttpMethod.Get, "/api/console/status", As(ConsoleTestHost.AllowedOid, tid: ConsoleTestHost.TenantId));

        otherTenant.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        ownTenant.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task HealthAndReadiness_StayAnonymous_AndRevealNothingSensitive()
    {
        using var console = _oid.Host.CreateConsoleClient();

        using var health = await console.GetAsync("/healthz");
        using var ready = await console.GetAsync("/readyz");

        health.StatusCode.ShouldBe(HttpStatusCode.OK);
        ready.StatusCode.ShouldBe(HttpStatusCode.OK);
        var text = await health.Content.ReadAsStringAsync() + await ready.Content.ReadAsStringAsync();
        text.ShouldBe("""{"status":"alive"}{"status":"ready"}""");
    }

    [Fact]
    public async Task AnUnknownPath_IsNotFound_ForEveryone_AndThePolicyDoesNotLeakWhichRoutesExist()
    {
        using var console = _oid.Host.CreateConsoleClient();

        using var anonymous = await console.GetAsync("/no/such/page");
        using var allowed = await console.SendAsync(HttpMethod.Get, "/no/such/page", As(ConsoleTestHost.AllowedOid));

        anonymous.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        allowed.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task TheStatusEndpoint_ReportsTheMode_WithoutAnySecretOrIdentityDetail()
    {
        using var console = _oid.Host.CreateConsoleClient();

        using var doc = await console.GetJsonAsync("/api/console/status", As(ConsoleTestHost.AllowedOid));
        var text = doc.RootElement.GetRawText();

        doc.RootElement.GetProperty("auth_mode").GetString().ShouldBe("EntraId");
        text.ShouldNotContain("test-value-no-tenant-behind-it");
        text.ShouldNotContain(ConsoleTestHost.AllowedOid);
        text.ShouldNotContain(ConsoleTestHost.TenantId);
    }

    [Fact]
    public async Task TheClientSecret_NeverAppearsInLogsPagesOrTheApi()
    {
        using var console = _oid.Host.CreateConsoleClient();
        var all = new StringBuilder();
        foreach (var path in new[] { "/", "/dashboard", "/api/console/status", "/api/console/dashboard", "/healthz", "/readyz" })
        {
            using var response = await console.SendAsync(HttpMethod.Get, path, As(ConsoleTestHost.AllowedOid));
            all.Append(await response.Content.ReadAsStringAsync());
        }

        all.ToString().ShouldNotContain("test-value-no-tenant-behind-it");
        _oid.Host.Logs.AllText.ShouldNotContain("test-value-no-tenant-behind-it");
    }

    [Fact]
    public async Task TheCurrentUser_ForTheAuditLog_IsTheDisplayNameAndObjectId_InEntraMode()
    {
        // The same abstraction (IConsoleUser) the Blazor pages and the reveal endpoint use.
        using var console = _oid.Host.CreateConsoleClient();
        using var response = await console.SendAsync(HttpMethod.Get, "/api/console/status", As(ConsoleTestHost.AllowedOid, "Alice Admin"));
        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        var user = WebConsole.ConsoleUserInfo.From(
            new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim("oid", ConsoleTestHost.AllowedOid), new System.Security.Claims.Claim("name", "Alice Admin")], "test")),
            WebConsole.ConsoleAuthMode.EntraId);

        user.AuditName.ShouldBe($"Alice Admin ({ConsoleTestHost.AllowedOid})");
        WebConsole.ConsoleUserInfo.From(null, WebConsole.ConsoleAuthMode.LoopbackOnly).AuditName.ShouldBe("loopback");
        WebConsole.ConsoleUserInfo.From(new System.Security.Claims.ClaimsPrincipal(), WebConsole.ConsoleAuthMode.EntraId).AuditName.ShouldBe("anonymous (anonymous)");
    }
}

/// <summary>The console API (spec 7, 8.5), headers (spec 5.4) and the audited reveal (spec 8.4), against the production host in LoopbackOnly mode.</summary>
public sealed class ConsoleApiTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;
    private byte[] _dek = [];

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync();
        _dek = await _host.SendSampleTrafficAsync();
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private HttpClient Console() => _host.Host.CreateConsoleClient();

    [Fact]
    public async Task Exchanges_AreListedNewestFirst_WithTheirBodies_AndFilterByTheSpecFilters()
    {
        using var console = Console();

        using var all = await console.GetJsonAsync("/api/console/exchanges?limit=50");
        var ids = all.RootElement.GetProperty("items").EnumerateArray().Select(static e => e.GetProperty("identity").GetProperty("exchange_id").GetInt64()).ToList();

        ids.Count.ShouldBeGreaterThanOrEqualTo(6);
        ids.ShouldBe([.. ids.OrderByDescending(static i => i)]);

        async Task<List<JsonElement>> Items(string query)
        {
            var doc = await console.GetJsonAsync("/api/console/exchanges?" + query);
            return [.. doc.RootElement.GetProperty("items").EnumerateArray().Select(static e => e.Clone())];
        }

        (await Items("op=wrapkey")).ShouldAllBe(static e => e.GetProperty("request").GetProperty("operation").GetString() == "wrapkey");
        (await Items("op=wrapkey")).Count.ShouldBe(1);
        (await Items("status_class=4")).ShouldAllBe(static e => e.GetProperty("response").GetProperty("status").GetInt32() / 100 == 4);
        (await Items("status_class=4")).Count.ShouldBe(2); // the 404 and the 401
        (await Items("only_errors=true")).Count.ShouldBe(2);
        (await Items("hide_info=true")).ShouldNotContain(static e => e.GetProperty("request").GetProperty("operation").GetString() == "info");
        (await Items("namespace=_default&key=aes-key-1")).Count.ShouldBeGreaterThanOrEqualTo(3);
        (await Items($"client_cn={ConsoleTestHost.ClientCn}")).Count.ShouldBeGreaterThanOrEqualTo(4);
        (await Items("text=mhsm-pool-name")).Count.ShouldBeGreaterThanOrEqualTo(2); // pool_name of the sample context (info, metadata)
        (await Items("limit=2")).Count.ShouldBe(2);
        (await Items($"before_id={ids[0]}&limit=100")).Count.ShouldBe(ids.Count - 1);
    }

    [Fact]
    public async Task AnInvalidQuery_IsA400_WithAnErrorBody()
    {
        using var console = Console();

        foreach (var query in new[] { "status_class=7", "limit=0", "limit=abc", "before_id=-3", "after_id=x" })
        {
            using var response = await console.GetAsync("/api/console/exchanges?" + query);
            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, query);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            doc.RootElement.GetProperty("code").GetString().ShouldBe("InvalidQuery");
        }
    }

    [Fact]
    public async Task OneExchange_HasTheSpecGroups_AndMissingOnesAre404WithACode()
    {
        using var console = Console();
        var wrap = _host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items.Single();

        using var doc = await console.GetJsonAsync($"/api/console/exchanges/{wrap.Id}");
        var root = doc.RootElement;

        foreach (var group in new[] { "identity", "tls", "client_certificate", "request", "context", "response", "timing", "key" })
        {
            root.TryGetProperty(group, out _).ShouldBeTrue(group);
        }

        root.GetProperty("tls").GetProperty("protocol").GetString().ShouldBe("TLS 1.3");
        root.GetProperty("client_certificate").GetProperty("common_name").GetString().ShouldBe(ConsoleTestHost.ClientCn);
        root.GetProperty("request").GetProperty("body").GetProperty("masked_fields").GetArrayLength().ShouldBe(1);

        using var missing = await console.GetAsync("/api/console/exchanges/99999");
        missing.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await missing.Content.ReadAsStringAsync()).ShouldContain("ExchangeNotFound");
    }

    [Fact]
    public async Task TheKqlSnippet_ComesFromTheM4Generator()
    {
        using var console = Console();
        var wrap = _host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items.Single();

        using var doc = await console.GetJsonAsync($"/api/console/exchanges/{wrap.Id}/kql");

        var correlation = doc.RootElement.GetProperty("by_correlation_id").GetString()!;
        correlation.ShouldContain("EkmWrapKey");
        correlation.ShouldContain("\"c\""); // the correlation_id of the sample wrap request (EkmClient.WrapBody)
        (await console.GetAsync("/api/console/exchanges/99999/kql")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Connections_Dashboard_Status_AndInspectorStatus_AreServed()
    {
        using var console = Console();

        using var events = await console.GetJsonAsync("/api/console/connections?limit=50");
        events.RootElement.GetProperty("events").GetArrayLength().ShouldBeGreaterThan(0);
        using var failures = await console.GetJsonAsync("/api/console/connections?failures_only=true");
        failures.RootElement.GetProperty("events").EnumerateArray().ShouldAllBe(static e => e.GetProperty("kind").GetString() == "handshake_failed");

        using var open = await console.GetJsonAsync("/api/console/connections/open");
        open.RootElement.GetProperty("connections").ValueKind.ShouldBe(JsonValueKind.Array);
        using var stats = await console.GetJsonAsync("/api/console/connections/statistics");
        stats.RootElement.GetProperty("opened").GetInt64().ShouldBeGreaterThan(0);
        stats.RootElement.GetProperty("resumption_rate").GetDouble().ShouldBe(0);

        using var dashboard = await console.GetJsonAsync("/api/console/dashboard");
        dashboard.RootElement.GetProperty("exchanges_since_start").GetInt64().ShouldBeGreaterThanOrEqualTo(6);
        dashboard.RootElement.GetProperty("heartbeat").GetProperty("ever_seen").GetBoolean().ShouldBeTrue();
        dashboard.RootElement.GetProperty("last15_minutes").GetProperty("total").GetInt64().ShouldBeGreaterThanOrEqualTo(6);

        using var status = await console.GetJsonAsync("/api/console/status");
        status.RootElement.GetProperty("auth_mode").GetString().ShouldBe("LoopbackOnly");
        status.RootElement.GetProperty("ready").GetBoolean().ShouldBeTrue();
        status.RootElement.GetProperty("faults_active").GetBoolean().ShouldBeFalse();
        status.RootElement.GetProperty("reveal_allowed").GetBoolean().ShouldBeFalse();

        using var inspector = await console.GetJsonAsync("/api/console/inspector/status");
        inspector.RootElement.GetProperty("ring_count").GetInt32().ShouldBeGreaterThanOrEqualTo(6);
    }

    [Fact]
    public async Task TheExport_IsMasked_InBothFormats_AndHonoursTheFilter()
    {
        using var console = Console();

        using var json = await console.GetAsync("/api/console/export?format=json&op=wrapkey");
        json.Content.Headers.ContentDisposition!.DispositionType.ShouldBe("attachment");
        using var doc = JsonDocument.Parse(await json.Content.ReadAsStringAsync());
        doc.RootElement.GetProperty("masked").GetBoolean().ShouldBeTrue();
        doc.RootElement.GetProperty("count").GetInt32().ShouldBe(1);

        using var jsonl = await console.GetAsync("/api/console/export?format=jsonl");
        jsonl.Content.Headers.ContentType!.MediaType.ShouldBe("application/x-ndjson");
        var lines = (await jsonl.Content.ReadAsStringAsync()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        lines.Length.ShouldBeGreaterThanOrEqualTo(6);
        lines.ShouldAllBe(static l => l.Contains("\"type\":\"exchange\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Reveal_IsRefused_WhenItIsNotAllowedForTheProcess_AndNeedsAnAntiforgeryToken()
    {
        using var console = Console();
        var wrap = _host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items.Single();
        var path = $"/api/console/exchanges/{wrap.Id}/reveal";
        var body = ConsoleTestJson.Json("""{"field":"request.value"}""");

        using var noToken = await console.SendAsync(HttpMethod.Post, path, content: body);
        noToken.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await noToken.Content.ReadAsStringAsync()).ShouldContain("AntiforgeryTokenInvalid");

        var token = await console.GetAntiforgeryTokenAsync();
        using var denied = await console.SendAsync(HttpMethod.Post, path, request => request.Headers.Add("X-CSRF-TOKEN", token), ConsoleTestJson.Json("""{"field":"request.value"}"""));
        denied.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await denied.Content.ReadAsStringAsync()).ShouldContain("RevealDisabled");

        // The denied attempt is audited (as the loopback user) and nothing was revealed.
        var audit = _host.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent();
        audit.ShouldContain(static e => e.Action == "inspector.reveal.denied" && e.User == "loopback");
    }

    [Fact]
    public async Task AnEmptyOrUnknownRevealField_IsA400()
    {
        using var console = Console();
        var token = await console.GetAntiforgeryTokenAsync();

        foreach (var json in new[] { "{}", """{"field":""}""" })
        {
            using var response = await console.SendAsync(HttpMethod.Post, "/api/console/exchanges/1/reveal", request => request.Headers.Add("X-CSRF-TOKEN", token), ConsoleTestJson.Json(json));
            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, json);
        }
    }

    [Fact]
    public async Task EveryConsoleResponse_CarriesTheSecurityHeaders_AndTheCspHasNoExternalHost()
    {
        using var console = Console();

        foreach (var path in new[] { "/", "/dashboard", "/exchange/1", "/api/console/status", "/healthz", "/api/console/exchanges", "/no/such/page" })
        {
            using var response = await console.GetAsync(path);
            var headers = response.Headers.Concat(response.Content.Headers).ToDictionary(static h => h.Key, static h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);

            headers["X-Content-Type-Options"].ShouldBe("nosniff", path);
            headers["X-Frame-Options"].ShouldBe("DENY", path);
            headers["Referrer-Policy"].ShouldBe("no-referrer", path);
            headers["Cross-Origin-Opener-Policy"].ShouldBe("same-origin", path);
            headers["Cache-Control"].ShouldContain("no-store", Case.Insensitive, path);
            var csp = headers["Content-Security-Policy"];
            csp.ShouldContain("frame-ancestors 'none'");
            csp.ShouldContain("default-src 'self'");
            csp.ShouldContain("script-src 'self'");
            csp.ShouldContain("object-src 'none'");
            csp.ShouldContain($"wss://127.0.0.1:{_host.Host.ConsolePort}");
            csp.ShouldNotContain("http:");
            csp.ShouldNotContain("*");
            csp.ShouldNotContain("unsafe-eval");
            csp.Replace($"wss://127.0.0.1:{_host.Host.ConsolePort}", string.Empty, StringComparison.Ordinal).ShouldNotContain("://");

            // HSTS is host-wide, so it is not sent for a loopback name.
            headers.ContainsKey("Strict-Transport-Security").ShouldBeFalse(path);
        }
    }

    [Fact]
    public async Task TheShellHtml_HasNoInlineScript_NoExternalReference_AndTheReconnectUi()
    {
        using var console = Console();

        var html = await console.GetStringAsync("/");

        html.ShouldContain("<title>EkmMock console</title>");
        html.ShouldContain("components-reconnect-modal");
        html.ShouldNotContain("importmap");
        html.ShouldNotContain("cdn.", Case.Insensitive);
        System.Text.RegularExpressions.Regex.Matches(html, "<script(?![^>]*\\bsrc=)[^>]*>").Count.ShouldBe(0, "an inline script would need 'unsafe-inline'");
        System.Text.RegularExpressions.Regex.Matches(html, "(?:src|href)=\"(https?:)?//").Count.ShouldBe(0);
    }

    [Fact]
    public async Task NoRawKeyMaterial_IsInAnyConsoleResponse_ExportOrLog_AfterRealTraffic()
    {
        // Spec 5.2 / 14 test 18 extended to M5: every console API response, every page and the export after real wrap/unwrap traffic.
        using var console = Console();
        var texts = new List<string>();
        var wrapped = _host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items.Single();
        foreach (var path in new[]
        {
            "/", "/connections", "/dashboard", $"/exchange/{wrapped.Id}", "/api/console/status", "/api/console/inspector/status", "/api/console/exchanges?limit=1000",
            $"/api/console/exchanges/{wrapped.Id}", $"/api/console/exchanges/{wrapped.Id + 1}", $"/api/console/exchanges/{wrapped.Id}/kql", "/api/console/connections", "/api/console/connections/open",
            "/api/console/connections/statistics", "/api/console/dashboard", "/api/console/export?format=json", "/api/console/export?format=jsonl",
        })
        {
            using var response = await console.GetAsync(path);
            texts.Add(await response.Content.ReadAsStringAsync());
        }

        texts.Add(_host.Host.Logs.AllText);
        var all = string.Join('\n', texts);

        SecretScanner.LeaksInText(all, _dek).ShouldBeFalse("the DEK appeared in a console response, export or log");
        all.ShouldContain("32 bytes \\u00B7 fp", Case.Insensitive, "the masked form is what the console API serves (the serializer escapes the middle dot)");
    }
}

/// <summary>Reveal enabled (spec 8.4): the audited, <c>no-store</c> answer, the user in the audit log, nothing in any export.</summary>
public sealed class ConsoleRevealTests : IAsyncLifetime
{
    private ConsoleTestHost _loopback = null!;
    private ConsoleTestHost _entra = null!;

    public async ValueTask InitializeAsync()
    {
        _loopback = await ConsoleTestHost.StartAsync(allowReveal: true);
        _entra = await ConsoleTestHost.StartAsync(entra: true, allowReveal: true);
    }

    public async ValueTask DisposeAsync()
    {
        await _loopback.DisposeAsync();
        await _entra.DisposeAsync();
    }

    private static async Task<(long ExchangeId, byte[] Dek)> WrapAsync(ConsoleTestHost host)
    {
        var dek = Fx.Random(32);
        var (ekm, _, owner) = host.CreateTrustedEkmClient();
        using (owner)
        {
            (await ekm.WrapAsync("aes-key-1", "A256KWP", dek)).StatusCode.ShouldBe(200);
        }

        (await Wait.UntilAsync(() => host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items.Count == 1)).ShouldBeTrue();
        return (host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items.Single().Id, dek);
    }

    [Fact]
    public async Task Reveal_ReturnsTheValueOnce_AuditedAsTheCurrentUser_AndNoStore()
    {
        var (id, dek) = await WrapAsync(_loopback);
        using var console = _loopback.Host.CreateConsoleClient();
        var token = await console.GetAntiforgeryTokenAsync();

        using var response = await console.SendAsync(HttpMethod.Post, $"/api/console/exchanges/{id}/reveal", request => request.Headers.Add("X-CSRF-TOKEN", token), ConsoleTestJson.Json("""{"field":"request.value"}"""));

        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        response.Headers.CacheControl!.NoStore.ShouldBeTrue();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        doc.RootElement.GetProperty("value").GetString().ShouldBe(Convert.ToBase64String(dek).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
        doc.RootElement.GetProperty("bytes").GetInt32().ShouldBe(32);

        var entry = _loopback.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent().Single(static e => e.Action == "inspector.reveal");
        entry.User.ShouldBe("loopback");
        entry.Target.ShouldBe($"exchange:{id}/request.value");

        // The audit entry never holds the value, and neither does anything else the console serves afterwards.
        JsonSerializer.Serialize(entry, InspectorJsonContext.Default.AuditEntry).ShouldNotContain(doc.RootElement.GetProperty("value").GetString()!);
        foreach (var path in new[] { $"/api/console/exchanges/{id}", "/api/console/export?format=json", "/api/console/export?format=jsonl", "/api/console/exchanges?limit=100" })
        {
            SecretScanner.LeaksInText(await console.GetStringAsync(path), dek).ShouldBeFalse(path);
        }
    }

    [Fact]
    public async Task Reveal_InEntraMode_IsAuditedWithTheDisplayNameAndObjectId()
    {
        var (id, _) = await WrapAsync(_entra);
        using var console = _entra.Host.CreateConsoleClient();
        void As(HttpRequestMessage request)
        {
            request.Headers.Add("X-Test-Oid", ConsoleTestHost.AllowedOid);
            request.Headers.Add("X-Test-Name", "Alice Admin");
        }

        var token = await console.GetAntiforgeryTokenAsync(As);
        using var response = await console.SendAsync(
            HttpMethod.Post,
            $"/api/console/exchanges/{id}/reveal",
            request =>
            {
                As(request);
                request.Headers.Add("X-CSRF-TOKEN", token);
            },
            ConsoleTestJson.Json("""{"field":"request.value"}"""));

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        _entra.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent()
            .Single(static e => e.Action == "inspector.reveal").User.ShouldBe($"Alice Admin ({ConsoleTestHost.AllowedOid})");
    }

    [Fact]
    public async Task Reveal_OfAnUnknownExchange_Is404_AndOfAResponseThatCarriesNoSecret_Is409()
    {
        var (_, _) = await WrapAsync(_loopback);
        using var console = _loopback.Host.CreateConsoleClient();
        var token = await console.GetAntiforgeryTokenAsync();
        void Csrf(HttpRequestMessage request) => request.Headers.Add("X-CSRF-TOKEN", token);

        using var missing = await console.SendAsync(HttpMethod.Post, "/api/console/exchanges/99999/reveal", Csrf, ConsoleTestJson.Json("""{"field":"request.value"}"""));
        missing.StatusCode.ShouldBe(HttpStatusCode.NotFound);

        var wrap = _loopback.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items.Single();
        using var noSecretThere = await console.SendAsync(HttpMethod.Post, $"/api/console/exchanges/{wrap.Id}/reveal", Csrf, ConsoleTestJson.Json("""{"field":"response.value"}"""));
        noSecretThere.StatusCode.ShouldBe(HttpStatusCode.Conflict);

        using var unknownField = await console.SendAsync(HttpMethod.Post, $"/api/console/exchanges/{wrap.Id}/reveal", Csrf, ConsoleTestJson.Json("""{"field":"request.alg"}"""));
        unknownField.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }
}
