#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Buffers.Text;
using System.Security.Cryptography;
using EkmMock.Server.Hosting;

namespace EkmMock.Server.Tests;

/// <summary>
/// M8: <c>POST /api/console/keys/import</c>, the REST twin of the Keys page's gated import dialog. The CLI's conformance run uses it to import the RFC 3394 key-wrap vector (AES-KW against known
/// answers) and an RSA key it holds the private half of (so it can decrypt what EkmMock wraps). Same gate (<c>EKMMOCK_ALLOW_KEY_IMPORT</c>), same rules: the material is never echoed, logged or audited.
/// </summary>
public sealed class AdminApiImportTests : IAsyncLifetime
{
    // RFC 3394 section 4.6: 256-bit KEK, 256 bits of key data.
    private const string KekHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    private const string DekHex = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    private const string WrappedHex = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";

    private ConsoleTestHost _enabled = null!;
    private ConsoleTestHost _disabled = null!;

    public async ValueTask InitializeAsync()
    {
        _enabled = await ConsoleTestHost.StartAsync(allowKeyImport: true);
        _disabled = await ConsoleTestHost.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _enabled.DisposeAsync();
        await _disabled.DisposeAsync();
    }

    private static AdminApi Api(ConsoleTestHost host) => new(host.Host.CreateConsoleClient());

    [Fact]
    public async Task AnImportedAesKey_ProducesTheRfc3394KnownAnswer_ThroughTheEkmEndpoint()
    {
        var api = Api(_enabled);

        var imported = await api.PostAsync("/api/console/keys/import", new { @namespace = "_default", name = "rfc3394-kek", type = "aes", material = KekHex });

        imported.StatusCode.ShouldBe(201, imported.Text);
        imported.Root.GetProperty("origin").GetString().ShouldBe("Imported");
        imported.Text.ShouldNotContain(KekHex, Case.Insensitive);

        var (ekm, _, owner) = _enabled.CreateTrustedEkmClient();
        using (owner)
        {
            var wrapped = await ekm.WrapAsync("rfc3394-kek", "A256KW", Convert.FromHexString(DekHex));

            wrapped.StatusCode.ShouldBe(200, wrapped.Text);
            Convert.ToHexString(wrapped.Value()).ShouldBe(WrappedHex);
            var unwrapped = await ekm.UnwrapAsync("rfc3394-kek", "A256KW", Convert.FromHexString(WrappedHex));
            Convert.ToHexString(unwrapped.Value()).ShouldBe(DekHex);
        }
    }

    [Fact]
    public async Task AnImportedRsaKey_CanBeDecryptedByTheClientThatHoldsThePrivateHalf()
    {
        using var rsa = RSA.Create(2048);
        var api = Api(_enabled);

        var imported = await api.PostAsync("/api/console/keys/import", new { @namespace = "_default", name = "imported-rsa", type = "RSA", material = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()) });

        imported.StatusCode.ShouldBe(201, imported.Text);
        var (ekm, _, owner) = _enabled.CreateTrustedEkmClient();
        using (owner)
        {
            var dek = Fx.Random(32);
            var wrapped = await ekm.WrapAsync("imported-rsa", "RSA-OAEP-256", dek);

            wrapped.StatusCode.ShouldBe(200, wrapped.Text);
            rsa.Decrypt(wrapped.Value(), RSAEncryptionPadding.OaepSHA256).ShouldBe(dek);
        }
    }

    [Fact]
    public async Task TheMaterial_NeverReachesTheAuditLog_OrTheKeyListing()
    {
        var api = Api(_enabled);
        await api.PostAsync("/api/console/keys/import", new { @namespace = "_default", name = "audited-kek", type = "oct", material = KekHex });

        var audit = await api.GetAsync("/api/console/audit?action=key.import");
        var keys = await api.GetAsync("/api/console/keys");

        audit.Text.ShouldContain("audited-kek");
        audit.Text.ShouldNotContain(KekHex, Case.Insensitive);
        keys.Text.ShouldNotContain(KekHex, Case.Insensitive);
        keys.Text.ShouldNotContain(Convert.ToBase64String(Convert.FromHexString(KekHex)));
        keys.Text.ShouldNotContain(Base64Url.EncodeToString(Convert.FromHexString(KekHex)));
    }

    [Fact]
    public async Task WithoutTheEnvironmentSwitch_ImportIs403_AndNothingIsCreated()
    {
        var api = Api(_disabled);

        var reply = await api.PostAsync("/api/console/keys/import", new { @namespace = "_default", name = "no-import", type = "aes", material = KekHex });

        reply.StatusCode.ShouldBe(403);
        reply.ErrorCode.ShouldBe("Forbidden");
        reply.ErrorMessage.ShouldContain("EKMMOCK_ALLOW_KEY_IMPORT");
        reply.Text.ShouldNotContain(KekHex, Case.Insensitive);
        (await api.GetAsync("/api/console/keys")).Text.ShouldNotContain("no-import");
    }

    [Theory]
    [InlineData("aes", "not-a-key")]
    [InlineData("aes", "0011")]
    [InlineData("rsa", "not-pkcs8")]
    [InlineData("des", KekHex)]
    public async Task InvalidMaterialOrType_Is400_AndTheAnswerDoesNotEchoTheInput(string type, string material)
    {
        var reply = await Api(_enabled).PostAsync("/api/console/keys/import", new { @namespace = "_default", name = "bad-input", type, material });

        reply.StatusCode.ShouldBe(400, reply.Text);
        reply.Text.ShouldNotContain(material, Case.Sensitive);
    }

    [Fact]
    public async Task AnUnknownNamespace_Is404_AndAnExistingName_Is409()
    {
        var api = Api(_enabled);

        (await api.PostAsync("/api/console/keys/import", new { @namespace = "nope", name = "kek-x", type = "aes", material = KekHex })).StatusCode.ShouldBe(404);
        (await api.PostAsync("/api/console/keys/import", new { @namespace = "_default", name = "aes-key-1", type = "aes", material = KekHex })).StatusCode.ShouldBe(409);
    }
}
