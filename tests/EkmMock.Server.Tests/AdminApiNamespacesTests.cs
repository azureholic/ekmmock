#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net.Http;
using System.Text.Json;
using EkmMock.Crypto;
using EkmMock.Pki;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// M6, spec 8.5.6, 4.2, 5.1 and 14 test 13: namespaces and client trust through <c>/api/console/namespaces</c>: validation, the delete rules, the trust import with its
/// preview and warnings, persistence to <c>namespaces.json</c> and, with a real mutual-TLS client, that trust added at runtime works on the next request without a restart.
/// </summary>
public sealed class AdminApiNamespacesTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;
    private AdminApi _api = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync();
        _api = new AdminApi(_host.Host.CreateConsoleClient());
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private IReadOnlyList<AuditEntry> Audit() => _host.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent();

    private static string Unique(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..20];

    private string AzureCliJson(CertificateAuthority ca, string cn) => JsonSerializer.Serialize(new { subjectCommonName = cn, caCertificates = new[] { ca.DerBase64 } });

    private async Task<string> CreateNamespaceAsync(string? prefix = null, string? name = null)
    {
        name ??= Unique("ns");
        var reply = await _api.PostAsync("/api/console/namespaces", new { name, prefix = prefix ?? "p/" + name });
        reply.StatusCode.ShouldBe(201, reply.Text);
        return name;
    }

    [Fact]
    public async Task Create_NormalisesThePrefix_ListsIt_AndPersistsToNamespacesJson()
    {
        var name = Unique("norm");

        var reply = await _api.PostAsync("/api/console/namespaces", new { name, prefix = $"/Contoso/{name}/" });

        reply.StatusCode.ShouldBe(201, reply.Text);
        reply.Root.GetProperty("prefix").GetString().ShouldBe($"Contoso/{name}");
        reply.Root.GetProperty("display_prefix").GetString().ShouldBe($"/Contoso/{name}");
        var list = await _api.GetAsync("/api/console/namespaces");
        list.Root.GetProperty("namespaces").EnumerateArray().Select(static n => n.GetProperty("name").GetString()).ShouldContain(name);

        var file = await File.ReadAllTextAsync(Path.Combine(_host.Host.DataPath, "namespaces.json"));
        file.ShouldContain($"\"name\": \"{name}\"");
        file.ShouldContain($"Contoso/{name}");
        Audit().Single(e => e.Action == "namespace.create" && e.Target == $"namespace:{name}").User.ShouldBe("loopback");
    }

    [Theory]
    [InlineData("bad name", "p/x", "name")]
    [InlineData("has:colon", "p/x", "name")]
    [InlineData("", "p/x", "name")]
    [InlineData("okname", "has space", "prefix")]
    [InlineData("okname", "under_score", "prefix")]
    [InlineData("okname", "a//b", "prefix")]
    [InlineData("okname", "0123456789012345678901234567890123456789012345678901234567890123456789", "prefix")]
    [InlineData("okname", "", "prefix")]
    [InlineData("_default", "something", "prefix")]
    public async Task Create_RefusesAnInvalidNameOrPrefix(string name, string prefix, string what)
    {
        var reply = await _api.PostAsync("/api/console/namespaces", new { name, prefix });

        reply.StatusCode.ShouldBe(400, $"{what}: {reply.Text}");
        reply.ErrorCode.ShouldBe("InvalidRequest");
    }

    [Fact]
    public async Task Create_RefusesADuplicateNameAndTheSamePrefix_ButAllowsOverlappingPrefixes()
    {
        var name = await CreateNamespaceAsync(prefix: "dup/" + Guid.NewGuid().ToString("N")[..8]);
        var existing = (await _api.GetAsync($"/api/console/namespaces/{name}")).Root.GetProperty("prefix").GetString()!;

        (await _api.PostAsync("/api/console/namespaces", new { name, prefix = "other/" + name })).StatusCode.ShouldBe(409);
        var samePrefix = await _api.PostAsync("/api/console/namespaces", new { name = Unique("same"), prefix = "/" + existing + "/" });
        samePrefix.StatusCode.ShouldBe(409);
        samePrefix.ErrorCode.ShouldBe("Conflict");

        var nested = await _api.PostAsync("/api/console/namespaces", new { name = Unique("nest"), prefix = existing + "/deeper" });
        nested.StatusCode.ShouldBe(201, "overlapping prefixes are allowed: routing is by longest prefix");
        nested.Root.GetProperty("warnings").EnumerateArray().Select(static w => w.GetString()).ShouldContain(static w => w!.Contains("overlaps", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ANamespacePrefix_ThatEqualsAKeyNameInDefault_IsWarnedAbout()
    {
        var key = Unique("clash");
        (await _api.PostAsync("/api/console/keys", new { @namespace = "_default", name = key, type = "oct", size = 256 })).StatusCode.ShouldBe(201);

        var created = await _api.PostAsync("/api/console/namespaces", new { name = Unique("w"), prefix = key });

        created.StatusCode.ShouldBe(201, created.Text);
        created.Root.GetProperty("warnings").EnumerateArray().Select(static w => w.GetString()).ShouldContain(w => w!.Contains($"A key named '{key}'", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Update_ChangesThePrefixAndTrust_ButNeverTheName()
    {
        var name = await CreateNamespaceAsync();

        var updated = await _api.PutAsync($"/api/console/namespaces/{name}", new { prefix = "moved/" + name, subject_common_names = new[] { "cn-one", "cn-two" } });

        updated.StatusCode.ShouldBe(200, updated.Text);
        updated.Root.GetProperty("name").GetString().ShouldBe(name);
        updated.Root.GetProperty("prefix").GetString().ShouldBe("moved/" + name);
        updated.Root.GetProperty("subject_common_names").EnumerateArray().Select(static c => c.GetString()).ShouldBe(["cn-one", "cn-two"]);
        (await _api.PutAsync("/api/console/namespaces/missing", new { prefix = "x" })).StatusCode.ShouldBe(404);
        Audit().Single(e => e.Action == "namespace.update" && e.Target == $"namespace:{name}").Detail!.ShouldContain("cns=2");
    }

    [Fact]
    public async Task TrustImportedAtRuntime_WorksOnTheNextRequest_WithoutARestart()
    {
        var name = Unique("live");
        var prefix = "live/" + name;
        await CreateNamespaceAsync(prefix, name);
        (await _api.PostAsync("/api/console/keys", new { @namespace = name, name = "k-" + name[5..], type = "oct", size = 256 })).StatusCode.ShouldBe(201);
        using var client = _host.Pki.ClientCaB.IssueClient("mhsm-b.managedhsmclient.test");

        // Before: nobody trusts CA B at all, so the TLS handshake itself fails.
        await Should.ThrowAsync<HttpRequestException>(async () => await _host.Host.CreateEkmClient(client.Certificate).InfoAsync(prefix));

        var preview = await _api.PostAsync($"/api/console/namespaces/{name}/trust/import", new { content = AzureCliJson(_host.Pki.ClientCaB, "mhsm-b.managedhsmclient.test") });
        preview.StatusCode.ShouldBe(200, preview.Text);
        preview.Root.GetProperty("saved").GetBoolean().ShouldBeTrue();

        // After: the same running process authenticates the client, for this namespace only.
        var ekm = _host.Host.CreateEkmClient(client.Certificate);
        (await ekm.InfoAsync(prefix)).StatusCode.ShouldBe(200);
        (await ekm.InfoAsync()).StatusCode.ShouldBe(401, "CA B is trusted in the new namespace, not in _default");
    }

    [Fact]
    public async Task ARemovedCommonName_StopsAuthenticatingImmediately()
    {
        var name = Unique("rm");
        var prefix = "rm/" + name;
        const string cn = "mhsm-rm.managedhsmclient.test";
        await CreateNamespaceAsync(prefix, name);
        await _api.PostAsync($"/api/console/namespaces/{name}/trust/import", new { content = AzureCliJson(_host.Pki.ClientCaA, cn) });
        using var client = _host.Pki.ClientCaA.IssueClient(cn);
        var ekm = _host.Host.CreateEkmClient(client.Certificate);
        (await ekm.InfoAsync(prefix)).StatusCode.ShouldBe(200);

        (await _api.PutAsync($"/api/console/namespaces/{name}", new { prefix, subject_common_names = Array.Empty<string>() })).StatusCode.ShouldBe(200);

        (await ekm.InfoAsync(prefix)).StatusCode.ShouldBe(401);
    }

    [Fact]
    public async Task TrustPreview_ShowsTheCnAndEveryCa_BeforeAnythingIsSaved()
    {
        var name = await CreateNamespaceAsync();

        var reply = await _api.PostAsync($"/api/console/namespaces/{name}/trust/import", new { content = AzureCliJson(_host.Pki.ClientCaA, "preview.cn"), dry_run = true });

        reply.StatusCode.ShouldBe(200, reply.Text);
        reply.Root.GetProperty("saved").GetBoolean().ShouldBeFalse();
        reply.Root.GetProperty("subject_common_names").EnumerateArray().Select(static c => c.GetString()).ShouldBe(["preview.cn"]);
        var ca = reply.Root.GetProperty("ca_certificates").EnumerateArray().Single();
        ca.GetProperty("subject").GetString()!.ShouldContain("EkmMock Test Client Root CA A");
        ca.GetProperty("issuer").GetString()!.ShouldContain("EkmMock Test Client Root CA A");
        ca.GetProperty("is_self_signed").GetBoolean().ShouldBeTrue();
        ca.GetProperty("is_ca").GetBoolean().ShouldBeTrue();
        ca.GetProperty("not_after").GetDateTimeOffset().ShouldBeGreaterThan(DateTimeOffset.UtcNow);
        reply.Root.GetProperty("warnings").GetArrayLength().ShouldBe(0);

        var after = await _api.GetAsync($"/api/console/namespaces/{name}");
        after.Root.GetProperty("subject_common_names").GetArrayLength().ShouldBe(0, "a dry run changes nothing");
        Audit().ShouldNotContain(e => e.Action == "namespace.trust.import" && e.Target == $"namespace:{name}");
    }

    [Fact]
    public async Task TrustPreview_WarnsAboutALeafInsteadOfARoot_AnIssuingCa_AnExpiredCa_AndAMissingCommonName()
    {
        var name = await CreateNamespaceAsync();
        using var leaf = _host.Pki.ClientCaA.IssueClient("some-leaf");
        using var issuing = _host.Pki.ClientCaA.IssueIntermediate("EkmMock Test Issuing CA " + Guid.NewGuid().ToString("N")[..6]);
        using var expired = CertificateAuthority.CreateRoot("EkmMock Test Expired CA " + Guid.NewGuid().ToString("N")[..6], PkiKeyAlgorithm.EcdsaP256, TimeSpan.FromDays(2), DateTimeOffset.UtcNow.AddDays(-30));

        var leafReply = await Preview(name, JsonSerializer.Serialize(new { subjectCommonName = "x", caCertificates = new[] { Convert.ToBase64String(leaf.Der) } }));
        var issuingReply = await Preview(name, JsonSerializer.Serialize(new { subjectCommonName = "x", caCertificates = new[] { issuing.DerBase64 } }));
        var expiredReply = await Preview(name, JsonSerializer.Serialize(new { subjectCommonName = "x", caCertificates = new[] { expired.DerBase64 } }));
        var noCn = await Preview(name, JsonSerializer.Serialize(new { caCertificates = new[] { _host.Pki.ClientCaA.DerBase64 } }));

        Warnings(leafReply).ShouldContain(static w => w.Contains("not a CA certificate", StringComparison.Ordinal) && w.Contains("leaf", StringComparison.Ordinal));
        Warnings(issuingReply).ShouldContain(static w => w.Contains("issuing CA, not a self-signed root", StringComparison.Ordinal));
        Warnings(expiredReply).ShouldContain(static w => w.Contains("expired", StringComparison.Ordinal));
        Warnings(noCn).ShouldContain(static w => w.Contains("no subjectCommonName", StringComparison.Ordinal));
        expiredReply.Root.GetProperty("ca_certificates")[0].GetProperty("is_expired").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task TrustImport_AcceptsPem_WithTheCommonNameSuppliedSeparately()
    {
        var name = await CreateNamespaceAsync();

        var reply = await _api.PostAsync($"/api/console/namespaces/{name}/trust/import", new { format = "pem", content = _host.Pki.ClientCaB.CertificatePem, subject_common_names = new[] { "pem.cn" } });

        reply.StatusCode.ShouldBe(200, reply.Text);
        reply.Root.GetProperty("format").GetString().ShouldBe("pem");
        reply.Root.GetProperty("resulting_subject_common_names").EnumerateArray().Select(static c => c.GetString()).ShouldBe(["pem.cn"]);
        reply.Root.GetProperty("resulting_ca_count").GetInt32().ShouldBe(1);
    }

    [Fact]
    public async Task TrustImport_MergeKeepsWhatIsThere_ReplaceDoesNot_AndBadInputIs400()
    {
        var name = await CreateNamespaceAsync();
        await _api.PostAsync($"/api/console/namespaces/{name}/trust/import", new { content = AzureCliJson(_host.Pki.ClientCaA, "first.cn") });

        var merged = await _api.PostAsync($"/api/console/namespaces/{name}/trust/import", new { content = AzureCliJson(_host.Pki.ClientCaB, "second.cn") });
        merged.Root.GetProperty("resulting_subject_common_names").EnumerateArray().Select(static c => c.GetString()).ShouldBe(["first.cn", "second.cn"]);
        merged.Root.GetProperty("resulting_ca_count").GetInt32().ShouldBe(2);

        var replaced = await _api.PostAsync($"/api/console/namespaces/{name}/trust/import", new { content = AzureCliJson(_host.Pki.ClientCaB, "third.cn"), mode = "replace" });
        replaced.Root.GetProperty("resulting_subject_common_names").EnumerateArray().Select(static c => c.GetString()).ShouldBe(["third.cn"]);
        replaced.Root.GetProperty("resulting_ca_count").GetInt32().ShouldBe(1);

        foreach (var bad in new[] { "not json and not pem", "{ \"subjectCommonName\": \"x\" }", "{}", "" })
        {
            var reply = await _api.PostAsync($"/api/console/namespaces/{name}/trust/import", new { content = bad });
            reply.StatusCode.ShouldBe(400, bad);
        }

        (await _api.PostAsync($"/api/console/namespaces/{name}/trust/import", new { content = AzureCliJson(_host.Pki.ClientCaA, "x"), mode = "bogus" })).StatusCode.ShouldBe(400);
        (await _api.PostAsync("/api/console/namespaces/missing/trust/import", new { content = AzureCliJson(_host.Pki.ClientCaA, "x") })).StatusCode.ShouldBe(404);
        Audit().Count(e => e.Action == "namespace.trust.import" && e.Target == $"namespace:{name}").ShouldBe(3);
    }

    [Fact]
    public async Task TheAzCommand_UsesThePrefixTheRootCaFileAndTheHost()
    {
        var name = Unique("az");
        await CreateNamespaceAsync("contoso/prod", name);

        var reply = await _api.GetAsync($"/api/console/namespaces/{name}");
        var command = reply.Root.GetProperty("az_command").GetString()!;

        command.ShouldStartWith("az keyvault ekm-connection create --hsm-name <hsm> --host ");
        command.ShouldContain("--server-ca-certificate root-ca.pem");
        command.ShouldEndWith("--path-prefix /contoso/prod");
        var def = await _api.GetAsync("/api/console/namespaces/_default");
        def.Root.GetProperty("az_command").GetString()!.ShouldNotContain("--path-prefix");
    }

    [Fact]
    public async Task Delete_NeedsTheTypedName_AndRefusesWhileItHasKeys_UnlessAllAreDestroyedOnPurpose()
    {
        var name = Unique("del");
        var prefix = "del/" + name;
        await CreateNamespaceAsync(prefix, name);
        var keyName = "k-" + name[4..];
        await _api.PostAsync("/api/console/keys", new { @namespace = name, name = keyName, type = "oct", size = 256 });

        var noConfirm = await _api.PostAsync($"/api/console/namespaces/{name}/delete", new { });
        noConfirm.StatusCode.ShouldBe(400);
        noConfirm.ErrorCode.ShouldBe("ConfirmationMismatch");
        var withKeys = await _api.PostAsync($"/api/console/namespaces/{name}/delete", new { confirm_name = name });
        withKeys.StatusCode.ShouldBe(409);
        withKeys.ErrorMessage.ShouldContain("1 key(s)");
        (await _api.GetAsync($"/api/console/namespaces/{name}")).StatusCode.ShouldBe(200);

        var done = await _api.PostAsync($"/api/console/namespaces/{name}/delete", new { confirm_name = name, destroy_keys = true });

        done.StatusCode.ShouldBe(200, done.Text);
        done.Root.GetProperty("destroyed_keys").GetInt32().ShouldBe(1);
        (await _api.GetAsync($"/api/console/namespaces/{name}")).StatusCode.ShouldBe(404);
        var keys = await _api.GetAsync($"/api/console/keys?namespace={name}");
        keys.Root.GetProperty("keys").EnumerateArray().Single().GetProperty("state").GetString().ShouldBe("Destroyed");
        (await File.ReadAllTextAsync(Path.Combine(_host.Host.DataPath, "namespaces.json"))).ShouldNotContain($"\"name\": \"{name}\"");
        Audit().Where(e => e.Target == $"key:{name}/{keyName}").Select(static e => e.Action).ShouldBe(["key.create", "key.destroy"]);
        Audit().Single(e => e.Action == "namespace.delete" && e.Target == $"namespace:{name}").Detail.ShouldBe("destroyed_keys=1");
    }

    [Fact]
    public async Task Delete_OfAnEmptyNamespace_WorksWithTheTypedName_AndItsPathIsThen404()
    {
        var name = Unique("empty");
        var prefix = "empty/" + name;
        await CreateNamespaceAsync(prefix, name);
        using var client = _host.Pki.ClientCaA.IssueClient(ConsoleTestHost.ClientCn);
        await _api.PostAsync($"/api/console/namespaces/{name}/trust/import", new { content = AzureCliJson(_host.Pki.ClientCaA, ConsoleTestHost.ClientCn) });
        var ekm = _host.Host.CreateEkmClient(client.Certificate);
        (await ekm.InfoAsync(prefix)).StatusCode.ShouldBe(200);

        (await _api.PostAsync($"/api/console/namespaces/{name}/delete", new { confirm_name = name })).StatusCode.ShouldBe(200);

        (await ekm.InfoAsync(prefix)).StatusCode.ShouldBe(404);
    }

    private async Task<ApiReply> Preview(string ns, string content)
    {
        var reply = await _api.PostAsync($"/api/console/namespaces/{ns}/trust/import", new { content, dry_run = true });
        reply.StatusCode.ShouldBe(200, reply.Text);
        return reply;
    }

    private static List<string> Warnings(ApiReply reply) => [.. reply.Root.GetProperty("warnings").EnumerateArray().Select(static w => w.GetString()!)];
}
