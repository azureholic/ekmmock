#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Diagnostics;
using System.Net;
using EkmMock.Server.Faults;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// Spec 10.2 and 5.4: <c>/api/console/faults</c> on the real host: list, create, update, enable, disable, delete, presets and clear-all; the CSRF mechanism of M6; one audit entry per
/// change with user, action and target; validation of every parameter; and the read-only behaviour when the process was not started with <c>EKMMOCK_ENABLE_FAULTS=true</c>.
/// </summary>
[Collection(FaultsHostCollection.Name)]
public sealed class AdminApiFaultsTests : IAsyncLifetime
{
    private readonly FaultsHostFixture _fx;
    private AdminApi _api = null!;

    public AdminApiFaultsTests(FaultsHostFixture fixture) => _fx = fixture;

    public async ValueTask InitializeAsync()
    {
        await _fx.ResetAsync();
        _api = _fx.NewApi();
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private IReadOnlyList<AuditEntry> Audit() => _fx.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent(500);

    private static readonly object DelayBody = new { kind = "delay", delay_ms = 120, description = "slow HSM" };

    // ---- list ----

    [Fact]
    public async Task TheList_SaysFaultsAreEnabled_HasNoRules_AndOffersTheFivePresets()
    {
        var reply = await _api.GetAsync("/api/console/faults");

        reply.StatusCode.ShouldBe(200, reply.Text);
        reply.Root.GetProperty("enabled").GetBoolean().ShouldBeTrue();
        reply.Root.GetProperty("hsm_offline").GetBoolean().ShouldBeFalse();
        reply.Root.GetProperty("active_rules").GetInt32().ShouldBe(0);
        reply.Root.GetProperty("max_rules").GetInt32().ShouldBe(100);
        reply.Root.GetProperty("rules").GetArrayLength().ShouldBe(0);
        reply.Root.GetProperty("presets").EnumerateArray().Select(static p => p.GetProperty("id").GetString()).ShouldBe(["distant-hsm-100", "distant-hsm-200", "distant-hsm-260", "hsm-offline", "error-503-50"]);
        reply.ContentType.ShouldBe("application/json");
    }

    // ---- create, read, update, delete ----

    [Fact]
    public async Task CreateARule_Returns201WithTheRule_ListsIt_AndTheRuleActsOnTrafficAtOnce()
    {
        var reply = await _api.PostAsync("/api/console/faults", new { kind = "delay", delay_ms = 120, @namespace = "_default", key = "aes-key-1", op = "wrapkey", description = "slow HSM", expires_after_seconds = 600 });

        reply.StatusCode.ShouldBe(201, reply.Text);
        var rule = reply.Root;
        rule.GetProperty("id").GetString().ShouldStartWith("f");
        rule.GetProperty("kind").GetString().ShouldBe("delay");
        rule.GetProperty("enabled").GetBoolean().ShouldBeTrue();
        rule.GetProperty("namespace").GetString().ShouldBe("_default");
        rule.GetProperty("key").GetString().ShouldBe("aes-key-1");
        rule.GetProperty("op").GetString().ShouldBe("wrapkey");
        rule.GetProperty("delay_ms").GetInt32().ShouldBe(120);
        rule.GetProperty("state").GetString().ShouldBe("active");
        rule.GetProperty("parameters").GetString().ShouldBe("120 ms");
        rule.GetProperty("scope").GetString().ShouldBe("namespace _default, key aes-key-1, op wrapkey");
        rule.GetProperty("description").GetString().ShouldBe("slow HSM");
        rule.GetProperty("fired").GetInt64().ShouldBe(0);
        rule.GetProperty("expires_at").GetDateTimeOffset().ShouldBeInRange(DateTimeOffset.UtcNow.AddMinutes(9), DateTimeOffset.UtcNow.AddMinutes(11));

        var ekm = _fx.NewClient();
        var stopwatch = Stopwatch.StartNew();
        (await ekm.WrapAsync("aes-key-1", "A256KWP", Fx.Random(32))).StatusCode.ShouldBe(200);
        stopwatch.Stop();
        stopwatch.Elapsed.TotalMilliseconds.ShouldBeGreaterThan(110);

        var list = await _api.GetAsync("/api/console/faults");
        list.Root.GetProperty("rules").EnumerateArray().Single().GetProperty("fired").GetInt64().ShouldBe(1);
        list.Root.GetProperty("active_rules").GetInt32().ShouldBe(1);
        (await _api.GetAsync($"/api/console/faults/{rule.GetProperty("id").GetString()}")).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task UpdateEnableDisableAndDelete_ChangeTheRuleWithoutARestart()
    {
        var created = await _api.PostAsync("/api/console/faults", DelayBody);
        var id = created.Root.GetProperty("id").GetString()!;

        var updated = await _api.PutAsync($"/api/console/faults/{id}", new { kind = "error", error_percent = 100, status_code = 503, op = "info" });
        updated.StatusCode.ShouldBe(200, updated.Text);
        updated.Root.GetProperty("id").GetString().ShouldBe(id);
        updated.Root.GetProperty("kind").GetString().ShouldBe("error");
        (await _fx.NewClient().InfoAsync()).ShouldBeProxyError(503, "HsmUnavailable");

        var disabled = await _api.PostAsync($"/api/console/faults/{id}/disable");
        disabled.Root.GetProperty("state").GetString().ShouldBe("disabled");
        (await _fx.NewClient().InfoAsync()).StatusCode.ShouldBe(200);

        var enabled = await _api.PostAsync($"/api/console/faults/{id}/enable");
        enabled.Root.GetProperty("state").GetString().ShouldBe("active");
        (await _fx.NewClient().InfoAsync()).StatusCode.ShouldBe(503);

        (await _api.SendAsync(HttpMethod.Delete, $"/api/console/faults/{id}", null)).StatusCode.ShouldBe(204);
        (await _fx.NewClient().InfoAsync()).StatusCode.ShouldBe(200);
        (await _api.GetAsync($"/api/console/faults/{id}")).ShouldSatisfyAllConditions(r => r.StatusCode.ShouldBe(404), r => r.ErrorCode.ShouldBe("NotFound"));
    }

    [Fact]
    public async Task Presets_CreateTheDocumentedRules()
    {
        var offline = await _api.PostAsync("/api/console/faults/presets/hsm-offline");
        var distant = await _api.PostAsync("/api/console/faults/presets/distant-hsm-260");
        var fifty = await _api.PostAsync("/api/console/faults/presets/error-503-50");

        offline.StatusCode.ShouldBe(201, offline.Text);
        offline.Root.GetProperty("kind").GetString().ShouldBe("offline");
        distant.Root.GetProperty("delay_ms").GetInt32().ShouldBe(260);
        fifty.Root.GetProperty("error_percent").GetDouble().ShouldBe(50);
        fifty.Root.GetProperty("status_code").GetInt32().ShouldBe(503);
        (await _api.PostAsync("/api/console/faults/presets/no-such-preset")).StatusCode.ShouldBe(404);
        (await _api.GetAsync("/api/console/faults")).Root.GetProperty("hsm_offline").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task ClearAll_RemovesEveryRule()
    {
        await _api.PostAsync("/api/console/faults", DelayBody);
        await _api.PostAsync("/api/console/faults", new { kind = "blackhole" });

        var cleared = await _api.PostAsync("/api/console/faults/clear");

        cleared.StatusCode.ShouldBe(200);
        cleared.Root.GetProperty("removed").GetInt32().ShouldBe(2);
        (await _api.GetAsync("/api/console/faults")).Root.GetProperty("rules").GetArrayLength().ShouldBe(0);
    }

    [Fact]
    public async Task EveryChange_IsAudited_WithTheUser_TheActionAndTheTarget_ButNoDescription()
    {
        var created = await _api.PostAsync("/api/console/faults", new { kind = "delay", min_ms = 10, max_ms = 20, key = "aes-key-1", description = "operator-note-that-stays-out-of-the-audit" });
        var id = created.Root.GetProperty("id").GetString()!;
        await _api.PutAsync($"/api/console/faults/{id}", new { kind = "delay", delay_ms = 5 });
        await _api.PostAsync($"/api/console/faults/{id}/disable");
        await _api.PostAsync($"/api/console/faults/{id}/enable");
        await _api.SendAsync(HttpMethod.Delete, $"/api/console/faults/{id}", null);
        await _api.PostAsync("/api/console/faults/presets/hsm-offline");
        await _api.PostAsync("/api/console/faults/clear");

        var entries = Audit().Where(static e => e.Action.StartsWith("fault.", StringComparison.Ordinal)).ToList();

        entries.Select(static e => e.Action).TakeLast(7).ShouldBe(["fault.create", "fault.update", "fault.disable", "fault.enable", "fault.delete", "fault.preset", "fault.clear"]);
        entries.TakeLast(7).ShouldAllBe(static e => e.User == "loopback");
        entries.TakeLast(7).Take(5).ShouldAllBe(e => e.Target == $"fault:{id}");
        entries[^7].Detail.ShouldBe("delay 10-20 ms (uniform); key aes-key-1");
        entries[^2].Detail.ShouldNotBeNull().ShouldContain("preset hsm-offline");
        entries[^1].Target.ShouldBe("fault:*");
        entries.ShouldAllBe(static e => e.Detail == null || !e.Detail.Contains("operator-note", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheAuditActionsOfFaults_AreInTheAuditPageFilterList()
    {
        AuditActions.All.ShouldContain("fault.create");
        AuditActions.All.ShouldContain("fault.update");
        AuditActions.All.ShouldContain("fault.delete");
        AuditActions.All.ShouldContain("fault.enable");
        AuditActions.All.ShouldContain("fault.disable");
        AuditActions.All.ShouldContain("fault.clear");
        AuditActions.All.ShouldContain("fault.preset");
        await _api.PostAsync("/api/console/faults", DelayBody);
        (await _api.GetAsync("/api/console/audit?action=fault")).Root.GetProperty("entries").GetArrayLength().ShouldBeGreaterThan(0);
    }

    // ---- validation ----

    public static TheoryData<string, string> InvalidBodies => new()
    {
        { """{"kind":"explode"}""", "kind must be one of" },
        { """{}""", "kind must be one of" },
        { """{"kind":"delay"}""", "either delay_ms, or min_ms and max_ms" },
        { """{"kind":"delay","delay_ms":10,"min_ms":1,"max_ms":2}""", "either delay_ms, or min_ms and max_ms" },
        { """{"kind":"delay","min_ms":1}""", "both min_ms and max_ms" },
        { """{"kind":"delay","min_ms":200,"max_ms":100}""", "min_ms must not be larger than max_ms" },
        { """{"kind":"delay","delay_ms":-1}""", "delay_ms must be from 0 to 60000" },
        { """{"kind":"delay","delay_ms":60001}""", "delay_ms must be from 0 to 60000" },
        { """{"kind":"error","status_code":503}""", "error_percent must be a number from 0 to 100" },
        { """{"kind":"error","error_percent":101,"status_code":503}""", "error_percent must be a number from 0 to 100" },
        { """{"kind":"error","error_percent":-0.5,"status_code":503}""", "error_percent must be a number from 0 to 100" },
        { """{"kind":"error","error_percent":50,"status_code":418}""", "status_code must be 429, 500 or 503" },
        { """{"kind":"error","error_percent":50}""", "status_code must be 429, 500 or 503" },
        { """{"kind":"delay","delay_ms":1,"op":"wrap"}""", "op must be one of" },
        { """{"kind":"delay","delay_ms":1,"key":"bad_key"}""", "key must be 1 to 64" },
        { """{"kind":"delay","delay_ms":1,"namespace":"bad name"}""", "namespace must be 1 to 64" },
        { """{"kind":"offline","key":"aes-key-1"}""", "HSM offline applies to the whole engine" },
        { """{"kind":"key_disabled","op":"metadata"}""", "Key disabled only affects wrapkey and unwrapkey" },
        { """{"kind":"key_disabled","op":"info"}""", "Key disabled only affects wrapkey and unwrapkey" },
        { """{"kind":"delay","delay_ms":1,"expires_after_seconds":0}""", "expires_after_seconds must be from 1" },
        { """{"kind":"delay","delay_ms":1,"expires_after_seconds":99999999}""", "expires_after_seconds must be from 1" },
        { """{"kind":"delay","delay_ms":1,"description":"line1\nline2"}""", "description must be at most 200" },
    };

    [Theory]
    [MemberData(nameof(InvalidBodies))]
    public async Task InvalidParameters_Are400WithAMessageNamingTheField_AndNoRuleIsCreated(string body, string expectedMessage)
    {
        var reply = await _api.PostAsync("/api/console/faults", body);

        reply.StatusCode.ShouldBe(400, reply.Text);
        reply.ErrorCode.ShouldBe("InvalidRequest");
        reply.ErrorMessage.ShouldContain(expectedMessage);
        (await _api.GetAsync("/api/console/faults")).Root.GetProperty("rules").GetArrayLength().ShouldBe(0);
        Audit().ShouldNotContain(static e => e.Action == "fault.create" && e.At > DateTimeOffset.UtcNow.AddSeconds(-30) && e.Detail != null && e.Detail.StartsWith("explode", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("""{"kind":"error","error_percent":0,"status_code":429}""")]
    [InlineData("""{"kind":"error","error_percent":100,"status_code":500}""")]
    [InlineData("""{"kind":"delay","delay_ms":0}""")]
    [InlineData("""{"kind":"delay","delay_ms":60000}""")]
    [InlineData("""{"kind":"delay","min_ms":5,"max_ms":5,"namespace":"*","key":"*","op":"*"}""")]
    [InlineData("""{"kind":"blackhole","op":"unwrapkey"}""")]
    [InlineData("""{"kind":"close","key":"aes-key-1"}""")]
    [InlineData("""{"kind":"key_disabled","op":"wrapkey"}""")]
    [InlineData("""{"kind":"offline","enabled":false}""")]
    public async Task BoundaryAndWildcardParameters_AreAccepted(string body)
    {
        var reply = await _api.PostAsync("/api/console/faults", body);

        reply.StatusCode.ShouldBe(201, reply.Text);
    }

    [Fact]
    public async Task UnknownRules_Are404_AndABrokenBodyIs400()
    {
        (await _api.PutAsync("/api/console/faults/f9999", DelayBody)).StatusCode.ShouldBe(404);
        (await _api.SendAsync(HttpMethod.Delete, "/api/console/faults/f9999", null)).StatusCode.ShouldBe(404);
        (await _api.PostAsync("/api/console/faults/f9999/enable")).StatusCode.ShouldBe(404);
        (await _api.PostAsync("/api/console/faults/f9999/disable")).StatusCode.ShouldBe(404);
        (await _api.PostAsync("/api/console/faults", "{not json")).ShouldSatisfyAllConditions(r => r.StatusCode.ShouldBe(400), r => r.ErrorCode.ShouldBe("InvalidRequest"));
    }

    [Fact]
    public async Task TheNumberOfRules_IsLimited_AndTheHundredAndFirstIsAConflict()
    {
        for (var i = 0; i < 100; i++)
        {
            (await _api.PostAsync("/api/console/faults", new { kind = "delay", delay_ms = 1, key = "aes-key-1" })).StatusCode.ShouldBe(201);
        }

        var reply = await _api.PostAsync("/api/console/faults", DelayBody);

        reply.StatusCode.ShouldBe(409);
        reply.ErrorCode.ShouldBe("Conflict");
        (await _api.PostAsync("/api/console/faults/clear")).Root.GetProperty("removed").GetInt32().ShouldBe(100);
    }

    // ---- CSRF (M6 mechanism) ----

    [Fact]
    public async Task WithoutAntiforgeryTokenOrTheClientHeader_EveryMutationIsRefused_AndNothingChanges()
    {
        var id = (await _api.PostAsync("/api/console/faults", DelayBody)).Root.GetProperty("id").GetString()!;

        var attempts = new[]
        {
            await _api.PostAsync("/api/console/faults", DelayBody, cli: false),
            await _api.PutAsync($"/api/console/faults/{id}", DelayBody, cli: false),
            await _api.SendAsync(HttpMethod.Delete, $"/api/console/faults/{id}", null, cli: false),
            await _api.PostAsync($"/api/console/faults/{id}/disable", cli: false),
            await _api.PostAsync($"/api/console/faults/{id}/enable", cli: false),
            await _api.PostAsync("/api/console/faults/clear", cli: false),
            await _api.PostAsync("/api/console/faults/presets/hsm-offline", cli: false),
        };

        attempts.ShouldAllBe(static r => r.StatusCode == 400 && r.ErrorCode == "AntiforgeryTokenInvalid");
        var list = await _api.GetAsync("/api/console/faults");
        list.Root.GetProperty("rules").GetArrayLength().ShouldBe(1);
        list.Root.GetProperty("rules")[0].GetProperty("state").GetString().ShouldBe("active");
    }

    [Fact]
    public async Task ABrowserStyleRequest_NeedsTheAntiforgeryToken_EvenWithTheClientHeader()
    {
        // A cross-origin page cannot add a custom header without a preflight, but a request that carries an Origin header must use the antiforgery token, never the header.
        var withOrigin = await _api.PostAsync("/api/console/faults", DelayBody, request => request.Headers.Add("Origin", "https://evil.example"));
        withOrigin.StatusCode.ShouldBe(403, "the console request guard refuses a cross-origin state change before anything else");

        var token = await _api.Http.GetAntiforgeryTokenAsync();
        var withToken = await _api.PostAsync("/api/console/faults", DelayBody, request => request.Headers.Add("X-CSRF-TOKEN", token), cli: false);
        withToken.StatusCode.ShouldBe(201, withToken.Text);
    }

    // ---- readiness and status (decision: a fault is not an unready process) ----

    [Fact]
    public async Task HsmOffline_IsReportedInTheStatus_ButTheProcessStaysReady_AndHealthy()
    {
        var before = await _api.GetAsync("/api/console/status");
        before.Root.GetProperty("faults_enabled").GetBoolean().ShouldBeTrue();
        before.Root.GetProperty("faults_active").GetBoolean().ShouldBeFalse();

        await _api.PostAsync("/api/console/faults/presets/hsm-offline");

        var status = await _api.GetAsync("/api/console/status");
        status.Root.GetProperty("faults_active").GetBoolean().ShouldBeTrue();
        status.Root.GetProperty("hsm_offline_fault").GetBoolean().ShouldBeTrue();
        (await _api.GetAsync("/readyz")).StatusCode.ShouldBe(200);
        (await _api.GetAsync("/healthz")).StatusCode.ShouldBe(200);
        (await _fx.NewClient().InfoAsync()).ShouldBeProxyError(503, "HsmUnavailable");

        await _api.PostAsync("/api/console/faults/clear");
        (await _api.GetAsync("/api/console/status")).Root.GetProperty("hsm_offline_fault").GetBoolean().ShouldBeFalse();
        (await _fx.NewClient().InfoAsync()).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task RuleExpiry_SwitchesTheRuleOffByItself_AndTheStatusFollows()
    {
        var created = await _api.PostAsync("/api/console/faults", new { kind = "offline", expires_after_seconds = 1 });
        created.StatusCode.ShouldBe(201);
        (await _api.GetAsync("/api/console/status")).Root.GetProperty("faults_active").GetBoolean().ShouldBeTrue();

        (await Wait.UntilAsync(() => !_fx.Faults.IsHsmOffline, TimeSpan.FromSeconds(10))).ShouldBeTrue();

        (await _api.GetAsync("/api/console/status")).Root.GetProperty("faults_active").GetBoolean().ShouldBeFalse();
        (await _api.GetAsync("/api/console/faults")).Root.GetProperty("rules")[0].GetProperty("state").GetString().ShouldBe("expired");
        (await _fx.NewClient().InfoAsync()).StatusCode.ShouldBe(200);
    }
}

/// <summary>Spec 10.2: without <c>EKMMOCK_ENABLE_FAULTS=true</c> the API is read-only and rules cannot exist or apply.</summary>
public sealed class AdminApiFaultsDisabledTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;
    private AdminApi _api = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync(faults: false);
        _api = new AdminApi(_host.Host.CreateConsoleClient());
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    [Fact]
    public async Task TheListSaysDisabled_AndEveryMutationIsRefusedWith403_WithoutAnAuditEntry()
    {
        var list = await _api.GetAsync("/api/console/faults");
        list.StatusCode.ShouldBe(200);
        list.Root.GetProperty("enabled").GetBoolean().ShouldBeFalse();
        list.Root.GetProperty("rules").GetArrayLength().ShouldBe(0);
        list.Root.GetProperty("active_rules").GetInt32().ShouldBe(0);

        var attempts = new[]
        {
            await _api.PostAsync("/api/console/faults", new { kind = "delay", delay_ms = 500 }),
            await _api.PutAsync("/api/console/faults/f1", new { kind = "delay", delay_ms = 500 }),
            await _api.SendAsync(HttpMethod.Delete, "/api/console/faults/f1", null),
            await _api.PostAsync("/api/console/faults/f1/enable"),
            await _api.PostAsync("/api/console/faults/clear"),
            await _api.PostAsync("/api/console/faults/presets/hsm-offline"),
        };

        attempts.ShouldAllBe(static r => r.StatusCode == 403 && r.ErrorCode == "FaultsDisabled");
        attempts[0].ErrorMessage.ShouldContain("EKMMOCK_ENABLE_FAULTS=true");
        _host.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent().ShouldNotContain(static e => e.Action.StartsWith("fault.", StringComparison.Ordinal));
        _host.Host.App.Services.GetRequiredService<FaultRuleStore>().Count.ShouldBe(0);
    }

    [Fact]
    public async Task TrafficIsUnaffected_AndTheStatusSaysFaultsAreNotEnabled()
    {
        var status = await _api.GetAsync("/api/console/status");
        status.Root.GetProperty("faults_enabled").GetBoolean().ShouldBeFalse();
        status.Root.GetProperty("faults_active").GetBoolean().ShouldBeFalse();

        var (ekm, _, owner) = _host.CreateTrustedEkmClient();
        using (owner)
        {
            var stopwatch = Stopwatch.StartNew();
            (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
            (await ekm.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);
            stopwatch.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task APlainHttpStatus404_ForUnknownFaultPaths_StaysA404()
    {
        (await _api.GetAsync("/api/console/faults/f1")).StatusCode.ShouldBe((int)HttpStatusCode.NotFound);
    }
}

/// <summary>The gate reads the process environment; these tests change it, so they run alone (see <see cref="ProcessEnvironmentCollection"/>).</summary>
[Collection(ProcessEnvironmentCollection.Name)]
public sealed class FaultGateEnvironmentTests
{
    [Fact]
    public void TheProductionGate_IsOffByDefault_AndOnlyTheWordTrueSwitchesItOn()
    {
        EnvironmentFaultGate.Variable.ShouldBe("EKMMOCK_ENABLE_FAULTS");
        var before = Environment.GetEnvironmentVariable(EnvironmentFaultGate.Variable);
        try
        {
            Environment.SetEnvironmentVariable(EnvironmentFaultGate.Variable, null);
            new EnvironmentFaultGate().Enabled.ShouldBeFalse();
            foreach (var other in new[] { "1", "yes", "false", "", "tru" })
            {
                Environment.SetEnvironmentVariable(EnvironmentFaultGate.Variable, other);
                new EnvironmentFaultGate().Enabled.ShouldBeFalse($"'{other}' does not switch faults on");
            }

            Environment.SetEnvironmentVariable(EnvironmentFaultGate.Variable, "true");
            new EnvironmentFaultGate().Enabled.ShouldBeTrue();
            Environment.SetEnvironmentVariable(EnvironmentFaultGate.Variable, "TRUE");
            new EnvironmentFaultGate().Enabled.ShouldBeTrue();
        }
        finally
        {
            Environment.SetEnvironmentVariable(EnvironmentFaultGate.Variable, before);
        }
    }

    [Fact]
    public void ThePlainConfiguration_CannotSwitchFaultsOn()
    {
        // Like the reveal switch, the gate never reads configuration: a settings file cannot enable fault injection.
        var source = File.ReadAllText(Path.Combine(RepoPaths.Src("EkmMock.Server"), "Faults", "FaultRuleStore.cs"));
        source.ShouldContain("Environment.GetEnvironmentVariable(Variable)");
        source.ShouldNotContain("IConfiguration");
    }
}
