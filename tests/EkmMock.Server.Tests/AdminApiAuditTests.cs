#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using System.Security.Cryptography;
using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>M6, spec 8.5.10: the audit log API reads <c>audit.jsonl</c> newest first with filters and paging, cannot change it, and records every state-changing action.</summary>
public sealed class AdminApiAuditTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;
    private AdminApi _api = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync(allowReveal: true, allowKeyImport: true);
        _api = new AdminApi(_host.Host.CreateConsoleClient());
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private IAuditLog Log => _host.Host.App.Services.GetRequiredService<IAuditLog>();

    private async Task<string[]> ActionsAsync(string query = "")
    {
        var reply = await _api.GetAsync("/api/console/audit" + query);
        reply.StatusCode.ShouldBe(200, reply.Text);
        return [.. reply.Root.GetProperty("entries").EnumerateArray().Select(static e => e.GetProperty("action").GetString()!)];
    }

    [Fact]
    public async Task TheAuditLog_ListsNewestFirst_WithUserActionTargetAndTime()
    {
        await _api.PostAsync("/api/console/keys", new { @namespace = "_default", name = "audit-a", type = "oct", size = 256 });
        await _api.PostAsync("/api/console/keys/_default/audit-a/disable");
        await _api.PostAsync("/api/console/keys/_default/audit-a/enable");

        var reply = await _api.GetAsync("/api/console/audit");

        var entries = reply.Root.GetProperty("entries").EnumerateArray().ToList();
        entries.Select(static e => e.GetProperty("action").GetString()).Take(3).ShouldBe(["key.enable", "key.disable", "key.create"]);
        entries[0].GetProperty("user").GetString().ShouldBe("loopback");
        entries[0].GetProperty("target").GetString().ShouldBe("key:_default/audit-a");
        entries[0].GetProperty("at").GetDateTimeOffset().ShouldBeGreaterThan(DateTimeOffset.UtcNow.AddMinutes(-5));
        reply.Root.GetProperty("total").GetInt32().ShouldBeGreaterThanOrEqualTo(3);
    }

    [Fact]
    public async Task PagingAndFilters_NarrowTheEntries()
    {
        foreach (var name in new[] { "pg-one", "pg-two", "pg-three" })
        {
            await _api.PostAsync("/api/console/keys", new { @namespace = "_default", name, type = "oct", size = 256 });
        }

        await _api.PostAsync("/api/console/keys/_default/pg-two/disable");
        Log.Append("bob", "key.destroy", "key:_default/other", "irreversible");

        (await ActionsAsync("?take=2")).Length.ShouldBe(2);
        var paged = await _api.GetAsync("/api/console/audit?take=2&skip=1");
        paged.Root.GetProperty("skip").GetInt32().ShouldBe(1);
        paged.Root.GetProperty("entries").GetArrayLength().ShouldBe(2);
        (await ActionsAsync("?user=bob")).ShouldBe(["key.destroy"]);
        (await ActionsAsync("?user=BOB")).ShouldBe(["key.destroy"]);
        (await ActionsAsync("?action=key.disable")).ShouldBe(["key.disable"]);
        (await ActionsAsync("?action=key")).ShouldContain("key.create");
        (await ActionsAsync("?text=pg-two")).ShouldBe(["key.disable", "key.create"]);
        (await ActionsAsync("?action=namespace.delete")).ShouldBeEmpty();
        (await ActionsAsync($"?from={Uri.EscapeDataString(DateTimeOffset.UtcNow.AddHours(1).ToString("O"))}")).ShouldBeEmpty();
        (await ActionsAsync($"?to={Uri.EscapeDataString(DateTimeOffset.UtcNow.AddHours(-1).ToString("O"))}")).ShouldBeEmpty();
        (await _api.GetAsync("/api/console/audit?from=not-a-date")).StatusCode.ShouldBe(400);
        (await _api.GetAsync("/api/console/audit?take=100000")).Root.GetProperty("take").GetInt32().ShouldBe(AuditQuery.MaxTake);
    }

    [Fact]
    public async Task TheAuditLog_IsReadOnlyThroughTheApi()
    {
        await _api.PostAsync("/api/console/keys", new { @namespace = "_default", name = "ro-key", type = "oct", size = 256 });
        var before = Log.ReadRecent().Count;

        foreach (var method in new[] { HttpMethod.Post, HttpMethod.Put, HttpMethod.Delete, HttpMethod.Patch })
        {
            var reply = await _api.SendAsync(method, "/api/console/audit", new { });
            ((int)reply.Status).ShouldBeGreaterThanOrEqualTo(400, method.Method);
        }

        (await _api.SendAsync(HttpMethod.Delete, "/api/console/audit/1", null)).StatusCode.ShouldBeGreaterThanOrEqualTo(400);
        Log.ReadRecent().Count.ShouldBe(before, "nothing can be edited or deleted through the console");
    }

    [Fact]
    public async Task RevealEventsOfTheInspector_AppearInTheAuditLog()
    {
        await _host.SendSampleTrafficAsync();
        var wrap = _host.Inspector.Query(new ExchangeFilter { Operation = "wrapkey" }).Items[0];
        var token = await _api.Http.GetAntiforgeryTokenAsync();

        var reveal = await _api.PostAsync($"/api/console/exchanges/{wrap.Id}/reveal", new { field = "request.value" }, request => request.Headers.Add("X-CSRF-TOKEN", token), cli: false);

        reveal.StatusCode.ShouldBe(200, reveal.Text);
        var reply = await _api.GetAsync("/api/console/audit?action=inspector.reveal");
        var entry = reply.Root.GetProperty("entries").EnumerateArray().Single();
        entry.GetProperty("target").GetString().ShouldBe($"exchange:{wrap.Id}/request.value");
        entry.GetProperty("user").GetString().ShouldBe("loopback");
    }

    /// <summary>
    /// The enumerating test of the task: it walks every state-changing action of the console services, one at a time, and proves that each writes exactly one entry
    /// (the namespace delete with destroyed keys also writes one entry per destroyed key) with the right user, action and target, and that none holds a secret.
    /// </summary>
    [Fact]
    public async Task EveryStateChangingAction_WritesExactlyOneAuditEntry_WithTheRightUserActionAndTarget_AndNoSecret()
    {
        var services = _host.Host.App.Services;
        var keys = services.GetRequiredService<KeyAdminService>();
        var namespaces = services.GetRequiredService<NamespaceAdminService>();
        var certificates = services.GetRequiredService<CertificateAdminService>();
        var playground = services.GetRequiredService<PlaygroundService>();
        const string actor = "walker (00000000-0000-0000-0000-000000000042)";
        var walked = new List<string>();

        async Task Step(string expectedAction, string expectedTarget, Func<Task> act, int entries = 1)
        {
            var before = Log.ReadRecent(100_000).Count;
            await act();
            var added = Log.ReadRecent(100_000).Skip(before).ToList();
            added.Count.ShouldBe(entries, $"{expectedAction}: {string.Join(", ", added.Select(static a => a.Action))}");
            added.Last().User.ShouldBe(actor, expectedAction);
            added.Last().Action.ShouldBe(expectedAction);
            added.Last().Target.ShouldBe(expectedTarget, expectedAction);
            walked.Add(expectedAction);
        }

        var secretMaterial = Fx.Random(32);
        var dek = Fx.Random(32);

        await Step("namespace.create", "namespace:walk", () => Task.FromResult(namespaces.Create(actor, new NamespaceChange("walk", "walk/ns", null, null))));
        await Step("namespace.update", "namespace:walk", () => Task.FromResult(namespaces.Update(actor, new NamespaceChange("walk", "walk/ns2", ["cn.one"], null))));
        await Step("namespace.trust.import", "namespace:walk", () => Task.FromResult(namespaces.Import(actor, "walk", $$"""{"subjectCommonName":"cn.two","caCertificates":["{{_host.Pki.ClientCaB.DerBase64}}"]}""")));
        await Step("namespace.trust.test-client", "namespace:walk", () => Task.FromResult(namespaces.TrustConsoleTestClient(actor, "walk")));
        await Step("key.create", "key:walk/walk-key", () => Task.FromResult(keys.Create(actor, new CreateKeyRequest("walk", "walk-key", "oct", 256))));
        await Step("key.disable", "key:walk/walk-key", () => Task.FromResult(keys.SetEnabled(actor, "walk", "walk-key", false)));
        await Step("key.enable", "key:walk/walk-key", () => Task.FromResult(keys.SetEnabled(actor, "walk", "walk-key", true)));
        await Step("key.expiry.set", "key:walk/walk-key", () => Task.FromResult(keys.SetExpiry(actor, "walk", "walk-key", DateTimeOffset.UtcNow.AddDays(3))));
        await Step("key.expiry.clear", "key:walk/walk-key", () => Task.FromResult(keys.SetExpiry(actor, "walk", "walk-key", null)));
        byte[]? wrappedValue = null;
        PlaygroundResult? unwrapped = null;
        var direct = new PlaygroundTarget(PlaygroundMode.Direct, "walk", "walk-key", "A256KWP");
        await Step("playground.wrap", "key:walk/walk-key", async () =>
        {
            using var result = await playground.WrapAsync(actor, direct, dek);
            wrappedValue = result.WrappedValue;
        });
        await Step("playground.unwrap", "key:walk/walk-key", async () => unwrapped = await playground.UnwrapAsync(actor, direct, wrappedValue!, 32, SecretFingerprint.Compute(dek)));
        await Step("playground.reveal", "key:walk/walk-key", () => Task.FromResult(playground.Reveal(actor, unwrapped!)));
        unwrapped!.Dispose();
        await Step("key.import", "key:walk/walk-imported", () => Task.FromResult(keys.Import(actor, "walk", "walk-imported", KeyType.Oct, secretMaterial)));
        await Step("key.destroy", "key:walk/walk-key", () => Task.FromResult(keys.Destroy(actor, "walk", "walk-key", "walk-key")));
        await Step("key.destroy", "key:walk/walk-imported", () => Task.FromResult(keys.Destroy(actor, "walk", "walk-imported", "walk-imported")));
        await Step("certificate.generate", "certificate:walk.example.test", async () => await certificates.GenerateTestPkiAsync(actor, ["walk.example.test"]));
        using (var upload = _host.Pki.ServerCa.IssueServer(["localhost", "127.0.0.1", "::1"]))
        {
            await Step("certificate.upload", $"certificate:{upload.Thumbprint[..16]}", async () => await certificates.UploadAsync(actor, upload.ChainPem, upload.PrivateKeyPem));
        }

        await Step("namespace.delete", "namespace:walk", () => Task.FromResult(namespaces.Delete(actor, "walk", "walk", destroyKeys: false)));

        // Every action the console can write is either walked here or has a dedicated test (the denied reveal and the inspector's own actions).
        walked.Distinct().Order().ShouldBe(
            AuditActions.All.Where(static a => a is not ("playground.reveal.denied" or "inspector.reveal" or "inspector.reveal.denied" or "inspector.replay")).Order(StringComparer.Ordinal),
            "the walker must cover every state-changing console action in AuditActions.All");
        var all = string.Join('\n', Log.ReadRecent(100_000).Select(static e => e.ToString()));
        SecretScanner.LeaksInText(all, dek).ShouldBeFalse();
        SecretScanner.LeaksInText(all, secretMaterial).ShouldBeFalse();
        all.ShouldNotContain("PRIVATE KEY");
        all.ShouldNotContain("BEGIN CERTIFICATE");
    }
}
