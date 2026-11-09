#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Buffers.Text;
using System.Security.Cryptography;
using EkmMock.Crypto;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// M6, spec 8.5.5 and 5.4: key management through <c>/api/console/keys</c> on the real host (real Kestrel, real mTLS EKM endpoint): create, list, enable/disable, expiry and
/// destroy with the typed-name confirmation enforced on the server, the tombstone rules, the RSA public key output, and one audit entry per change with the right user.
/// </summary>
public sealed class AdminApiKeysTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;
    private AdminApi _api = null!;
    private EkmClient _ekm = null!;
    private IDisposable _ekmOwner = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync();
        _api = new AdminApi(_host.Host.CreateConsoleClient());
        (_ekm, _, _ekmOwner) = _host.CreateTrustedEkmClient();
    }

    public async ValueTask DisposeAsync()
    {
        _ekmOwner.Dispose();
        await _host.DisposeAsync();
    }

    private IReadOnlyList<AuditEntry> Audit() => _host.Host.App.Services.GetRequiredService<IAuditLog>().ReadRecent();

    private static string Unique(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];

    private async Task<string> CreateKeyAsync(string type = "oct", int size = 256)
    {
        var name = Unique(type == "oct" ? "aes" : "rsa");
        var reply = await _api.PostAsync("/api/console/keys", new { @namespace = "_default", name, type, size });
        reply.StatusCode.ShouldBe(201, reply.Text);
        return name;
    }

    [Fact]
    public async Task CreateKey_ReturnsTheKeyWithoutSecrets_ListsIt_AndTheEkmEndpointUsesIt()
    {
        var name = await CreateKeyAsync();

        var list = await _api.GetAsync("/api/console/keys?namespace=_default");
        list.StatusCode.ShouldBe(200);
        var key = list.Root.GetProperty("keys").EnumerateArray().Single(k => k.GetProperty("name").GetString() == name);
        key.GetProperty("type").GetString().ShouldBe("oct");
        key.GetProperty("size").GetInt32().ShouldBe(256);
        key.GetProperty("state").GetString().ShouldBe("Enabled");
        key.GetProperty("origin").GetString().ShouldBe("Generated");
        key.GetProperty("wrap_count").GetInt64().ShouldBe(0);
        key.EnumerateObject().Select(static p => p.Name).ShouldNotContain(static n => n.Contains("secret") || n.Contains("material") || n.Contains("private"));

        var dek = Fx.Random(32);
        var wrapped = await _ekm.WrapAsync(name, "A256KWP", dek);
        wrapped.StatusCode.ShouldBe(200);
        (await _ekm.UnwrapAsync(name, "A256KWP", wrapped.Value())).Value().ShouldBe(dek);
    }

    [Theory]
    [InlineData("rsa", 2048)]
    [InlineData("RSA", 3072)]
    public async Task CreateRsaKey_PublicKeyPemAndJwk_MatchTheEngineKey(string type, int size)
    {
        var name = await CreateKeyAsync(type, size);

        var detail = await _api.GetAsync($"/api/console/keys/_default/{name}");
        detail.StatusCode.ShouldBe(200);
        var pub = detail.Root.GetProperty("public_key");
        var n = Base64Url.DecodeFromChars(pub.GetProperty("jwk_n").GetString()!);
        var e = Base64Url.DecodeFromChars(pub.GetProperty("jwk_e").GetString()!);
        e.ShouldBe([1, 0, 1]);
        n.Length.ShouldBe(size / 8);
        n[0].ShouldNotBe((byte)0, "n has no leading zero byte");

        // The independent check: an RSA instance built only from the PEM encrypts, and the engine (through the real EKM endpoint) decrypts it.
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pub.GetProperty("pem").GetString());
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        parameters.Modulus!.SequenceEqual(n).ShouldBeTrue("the PEM and the JWK n describe the same modulus");
        parameters.D.ShouldBeNull();
        var dek = Fx.Random(32);
        var ciphertext = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
        var unwrapped = await _ekm.UnwrapAsync(name, "RSA-OAEP-256", ciphertext);
        unwrapped.StatusCode.ShouldBe(200);
        unwrapped.Value().ShouldBe(dek);

        // And it equals what the EKM metadata operation publishes.
        var metadata = await _ekm.MetadataAsync(name);
        metadata.Json().RootElement.GetProperty("n").GetString().ShouldBe(pub.GetProperty("jwk_n").GetString());

        detail.Root.GetProperty("az_command").GetString().ShouldBe($"az keyvault key create --hsm-name <hsm> --name <ref-name> --external-key-id {name}");
    }

    [Fact]
    public async Task AnAesKey_HasNoPublicKey_AndNeverAnyKeyBytesInItsDetail()
    {
        var name = await CreateKeyAsync();

        var detail = await _api.GetAsync($"/api/console/keys/_default/{name}");

        detail.Root.TryGetProperty("public_key", out _).ShouldBeFalse();
        detail.Text.ShouldNotContain("BEGIN");
    }

    [Fact]
    public async Task DisableAndEnable_ChangeWhatTheEkmEndpointAnswers_AndAreAuditedWithTheUser()
    {
        var name = await CreateKeyAsync();

        (await _api.PostAsync($"/api/console/keys/_default/{name}/disable")).Root.GetProperty("state").GetString().ShouldBe("Disabled");
        var blocked = await _ekm.WrapAsync(name, "A256KWP", Fx.Random(32));
        blocked.ShouldBeProxyError(403, "KeyDisabled");
        (await _ekm.MetadataAsync(name)).StatusCode.ShouldBe(200); // a disabled key still answers metadata

        (await _api.PostAsync($"/api/console/keys/_default/{name}/enable")).Root.GetProperty("state").GetString().ShouldBe("Enabled");
        (await _ekm.WrapAsync(name, "A256KWP", Fx.Random(32))).StatusCode.ShouldBe(200);

        var entries = Audit().Where(e => e.Target == $"key:_default/{name}").ToList();
        entries.Select(static e => e.Action).ShouldBe(["key.create", "key.disable", "key.enable"]);
        entries.ShouldAllBe(static e => e.User == "loopback");
    }

    [Fact]
    public async Task SetExpiry_InThePast_MakesTheKeyExpired_AndClearingItRestoresIt()
    {
        var name = await CreateKeyAsync();

        var set = await _api.PostAsync($"/api/console/keys/_default/{name}/expiry", new { not_after = DateTimeOffset.UtcNow.AddMinutes(-5) });
        set.StatusCode.ShouldBe(200, set.Text);
        set.Root.GetProperty("state").GetString().ShouldBe("Expired");
        (await _ekm.WrapAsync(name, "A256KWP", Fx.Random(32))).ShouldBeProxyError(403, "KeyExpired");

        var cleared = await _api.PostAsync($"/api/console/keys/_default/{name}/expiry", new { });
        cleared.Root.GetProperty("state").GetString().ShouldBe("Enabled");
        cleared.Root.TryGetProperty("not_after", out _).ShouldBeFalse();
        (await _ekm.WrapAsync(name, "A256KWP", Fx.Random(32))).StatusCode.ShouldBe(200);

        Audit().Where(e => e.Target == $"key:_default/{name}").Select(static e => e.Action).ShouldBe(["key.create", "key.expiry.set", "key.expiry.clear"]);
    }

    [Fact]
    public async Task Destroy_NeedsTheExactKeyNameInTheBody_ServerSide()
    {
        var name = await CreateKeyAsync();

        var missing = await _api.PostAsync($"/api/console/keys/_default/{name}/destroy", new { });
        var wrong = await _api.PostAsync($"/api/console/keys/_default/{name}/destroy", new { confirm_name = name.ToUpperInvariant() });
        var other = await _api.PostAsync($"/api/console/keys/_default/{name}/destroy", new { confirm_name = "aes-key-1" });

        foreach (var reply in new[] { missing, wrong, other })
        {
            reply.StatusCode.ShouldBe(400);
            reply.ErrorCode.ShouldBe("ConfirmationMismatch");
        }

        (await _ekm.WrapAsync(name, "A256KWP", Fx.Random(32))).StatusCode.ShouldBe(200, "nothing was destroyed");
        Audit().ShouldNotContain(e => e.Action == "key.destroy" && e.Target == $"key:_default/{name}");
    }

    [Fact]
    public async Task Destroy_LeavesATombstone_ReturnsKeyNotFoundOnTheWire_AndReservesTheName()
    {
        var name = await CreateKeyAsync();
        var wrapped = (await _ekm.WrapAsync(name, "A256KWP", Fx.Random(32))).Value();

        var destroyed = await _api.PostAsync($"/api/console/keys/_default/{name}/destroy", new { confirm_name = name });

        destroyed.StatusCode.ShouldBe(200, destroyed.Text);
        destroyed.Root.GetProperty("state").GetString().ShouldBe("Destroyed");
        destroyed.Root.GetProperty("destroyed_by").GetString().ShouldBe("loopback");
        (await _ekm.UnwrapAsync(name, "A256KWP", wrapped)).ShouldBeProxyError(404, "KeyNotFound");

        var list = await _api.GetAsync("/api/console/keys?namespace=_default");
        list.Root.GetProperty("keys").EnumerateArray().Single(k => k.GetProperty("name").GetString() == name).GetProperty("state_note").GetString()!.ShouldContain("name is reserved");

        var again = await _api.PostAsync("/api/console/keys", new { @namespace = "_default", name, type = "oct", size = 256 });
        again.StatusCode.ShouldBe(409);
        again.ErrorCode.ShouldBe("Conflict");
        (await _api.PostAsync($"/api/console/keys/_default/{name}/destroy", new { confirm_name = name })).StatusCode.ShouldBe(409);

        var reuse = await _api.PostAsync("/api/console/keys", new { @namespace = "_default", name, type = "oct", size = 256, allow_reuse_of_destroyed_name = true });
        reuse.StatusCode.ShouldBe(201, "only the explicit override can reuse a destroyed name");

        var entry = Audit().Single(e => e.Action == "key.destroy" && e.Target == $"key:_default/{name}");
        entry.User.ShouldBe("loopback");
    }

    [Theory]
    [InlineData("has_underscore")]
    [InlineData("dot.name")]
    [InlineData("a-name-that-is-way-too-long-for-an-external-key-identifier-0123456789")]
    [InlineData("white space")]
    public async Task CreateKey_ValidatesTheNameLikeTheEkmContract(string name)
    {
        var reply = await _api.PostAsync("/api/console/keys", new { @namespace = "_default", name, type = "oct", size = 256 });

        reply.StatusCode.ShouldBe(400);
        reply.ErrorCode.ShouldBe("InvalidRequest");
    }

    [Theory]
    [InlineData("oct", 128)]
    [InlineData("RSA", 1024)]
    [InlineData("ec", 256)]
    [InlineData("", 256)]
    public async Task CreateKey_RejectsUnsupportedTypesAndSizes(string type, int size)
    {
        var reply = await _api.PostAsync("/api/console/keys", new { @namespace = "_default", name = Unique("bad"), type, size });

        reply.StatusCode.ShouldBe(400, reply.Text);
    }

    [Fact]
    public async Task CreateKey_InAnUnknownNamespace_Is404_AndADuplicateIs409()
    {
        var unknown = await _api.PostAsync("/api/console/keys", new { @namespace = "nope", name = Unique("k"), type = "oct", size = 256 });
        unknown.StatusCode.ShouldBe(404);

        var name = await CreateKeyAsync();
        var duplicate = await _api.PostAsync("/api/console/keys", new { @namespace = "_default", name, type = "oct", size = 256 });
        duplicate.StatusCode.ShouldBe(409);
    }

    [Fact]
    public async Task UnknownKey_Is404_OnEveryAction()
    {
        (await _api.GetAsync("/api/console/keys/_default/no-such-key")).StatusCode.ShouldBe(404);
        (await _api.PostAsync("/api/console/keys/_default/no-such-key/enable")).StatusCode.ShouldBe(404);
        (await _api.PostAsync("/api/console/keys/_default/no-such-key/expiry", new { })).StatusCode.ShouldBe(404);
        (await _api.PostAsync("/api/console/keys/_default/no-such-key/destroy", new { confirm_name = "no-such-key" })).StatusCode.ShouldBe(404);
    }

    [Fact]
    public async Task AMalformedBody_Is400_WithoutEchoingTheInput()
    {
        var reply = await _api.PostAsync("/api/console/keys", "{ this is not json SECRET-LOOKING-VALUE");

        reply.StatusCode.ShouldBe(400);
        reply.ErrorCode.ShouldBe("InvalidRequest");
        reply.Text.ShouldNotContain("SECRET-LOOKING-VALUE");
    }

    [Fact]
    public async Task Import_IsNotAvailableThroughTheApi_AndTheEngineStaysGatedWithoutTheFlag()
    {
        // The REST API has no import endpoint at all (import is a UI-only, gated test feature), and the engine refuses it without EKMMOCK_ALLOW_KEY_IMPORT.
        (await _api.PostAsync("/api/console/keys/import", new { })).StatusCode.ShouldBe(404);
        var keys = _host.Host.App.Services.GetRequiredService<KeyAdminService>();
        keys.ImportEnabled.ShouldBeFalse();
        var exception = Should.Throw<ConsoleActionException>(() => keys.Import("loopback", "_default", Unique("imp"), KeyType.Oct, Fx.Random(32)));
        exception.Code.ShouldBe(ConsoleErrorCode.Forbidden);
    }
}
