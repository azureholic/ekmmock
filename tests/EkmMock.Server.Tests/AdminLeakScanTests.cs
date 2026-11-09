#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Security.Cryptography;
using System.Text;
using EkmMock.Crypto;
using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>
/// Spec 14 test 18, console part (M6): after a full scenario no raw key material (AES key bytes, RSA private parameters, the PKCS#8 encoding, the master key) appears in any
/// console API response, export, inspector JSONL file, audit entry, log line or file of the data volume, as raw text, base64, base64url or hex.
/// </summary>
public sealed class AdminLeakScanTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;

    public async ValueTask InitializeAsync()
        => _host = await ConsoleTestHost.StartAsync(allowKeyImport: true, configuration: new Dictionary<string, string?> { ["Inspector:Persist"] = "true" });

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    [Fact]
    public async Task AfterAFullScenario_NoKeyMaterialAppearsAnywhereTheConsoleCanReach()
    {
        var services = _host.Host.App.Services;
        var keys = services.GetRequiredService<KeyAdminService>();
        var playground = services.GetRequiredService<PlaygroundService>();
        var namespaces = services.GetRequiredService<NamespaceAdminService>();
        var api = new AdminApi(_host.Host.CreateConsoleClient());

        // Known key material, imported through the (gated) import path so the test knows every byte.
        var aesKey = Fx.Random(32);
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: true);
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        keys.Import("loopback", "_default", "leak-aes", KeyType.Oct, aesKey);
        keys.Import("loopback", "_default", "leak-rsa", KeyType.Rsa, pkcs8);
        namespaces.TrustConsoleTestClient("loopback", "_default");

        // Traffic: through the EKM endpoint with a trusted client, through the playground (both modes) and the management API.
        var (ekm, _, owner) = _host.CreateTrustedEkmClient();
        using (owner)
        {
            var dek = Fx.Random(32);
            var wrappedAes = await ekm.WrapAsync("leak-aes", "A256KWP", dek);
            (await ekm.UnwrapAsync("leak-aes", "A256KWP", wrappedAes.Value())).StatusCode.ShouldBe(200);
            var wrappedRsa = await ekm.WrapAsync("leak-rsa", "RSA-OAEP-256", dek);
            (await ekm.UnwrapAsync("leak-rsa", "RSA-OAEP-256", wrappedRsa.Value())).StatusCode.ShouldBe(200);
            (await ekm.MetadataAsync("leak-rsa")).StatusCode.ShouldBe(200);
            (await ekm.MetadataAsync("leak-aes")).StatusCode.ShouldBe(200);
            (await ekm.WrapAsync("leak-aes", "A256KW", Fx.Random(15))).StatusCode.ShouldBe(400);
        }

        foreach (var mode in new[] { PlaygroundMode.Direct, PlaygroundMode.ViaEkm })
        {
            using var wrapped = await playground.WrapAsync("loopback", new PlaygroundTarget(mode, "_default", "leak-rsa", "RSA-OAEP-256"), Fx.Random(32));
            using var back = await playground.UnwrapAsync("loopback", new PlaygroundTarget(mode, "_default", "leak-rsa", "RSA-OAEP-256"), wrapped.WrappedValue!);
            back.Ok.ShouldBeTrue(back.Message);
        }

        await api.PostAsync("/api/console/keys", new { @namespace = "_default", name = "leak-extra", type = "RSA", size = 2048 });
        await api.PostAsync("/api/console/keys/_default/leak-aes/disable");
        await api.PostAsync("/api/console/keys/_default/leak-aes/enable");
        await _host.SendSampleTrafficAsync();
        (await Wait.UntilAsync(() => _host.Inspector.Status().ExchangesCaptured >= 12)).ShouldBeTrue();
        await Task.Delay(500); // the JSONL writer flushes when the queue runs empty

        // Everything the console API can say.
        var responses = new StringBuilder();
        foreach (var path in new[]
        {
            "/api/console/keys", "/api/console/keys/_default/leak-aes", "/api/console/keys/_default/leak-rsa", "/api/console/keys/_default/leak-extra",
            "/api/console/namespaces", "/api/console/namespaces/_default", "/api/console/certificates", "/api/console/audit?take=500", "/api/console/about", "/api/console/self-test",
            "/api/console/status", "/api/console/inspector/status", "/api/console/exchanges?limit=1000", "/api/console/export?format=json", "/api/console/export?format=jsonl",
            "/api/console/connections", "/api/console/dashboard",
        })
        {
            var reply = await api.GetAsync(path);
            reply.StatusCode.ShouldBe(200, path);
            responses.AppendLine(reply.Text);
        }

        // Every file of the data volume except the (encrypted) key store is plain text we can scan; the key store is scanned too, as bytes below.
        var files = new StringBuilder();
        var raw = new List<byte[]>();
        foreach (var file in Directory.EnumerateFiles(_host.Host.DataPath, "*", SearchOption.AllDirectories))
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var memory = new MemoryStream();
            await stream.CopyToAsync(memory);
            raw.Add(memory.ToArray());
            files.AppendLine(Encoding.UTF8.GetString(memory.ToArray()));
        }

        files.Length.ShouldBeGreaterThan(0);
        _host.Host.Logs.Entries.Count.ShouldBeGreaterThan(0);
        var corpus = new[] { ("API responses", responses.ToString()), ("data volume files", files.ToString()), ("logs", _host.Host.Logs.AllText) };

        var secrets = new (string Name, byte[] Bytes)[]
        {
            ("the imported AES key", aesKey),
            ("RSA PKCS#8 encoding", pkcs8),
            ("RSA D", parameters.D!),
            ("RSA P", parameters.P!),
            ("RSA Q", parameters.Q!),
            ("RSA DP", parameters.DP!),
            ("RSA DQ", parameters.DQ!),
            ("RSA InverseQ", parameters.InverseQ!),
            ("the master key", EkmFactory.MasterKeyBytes("real-host")),
        };
        foreach (var (where, text) in corpus)
        {
            foreach (var (name, bytes) in secrets)
            {
                SecretScanner.LeaksInText(text, bytes).ShouldBeFalse($"{name} leaked into {where}");
            }
        }

        // And as raw bytes in the files: the key store holds the keys only encrypted.
        foreach (var file in raw)
        {
            foreach (var (name, bytes) in secrets)
            {
                file.AsSpan().IndexOf(bytes.AsSpan(0, Math.Min(bytes.Length, 24))).ShouldBe(-1, $"{name} appears as raw bytes in a data volume file");
            }
        }

        // What the console may show: the public modulus of the RSA key is present in the key detail (that is the point of the page).
        var detail = await api.GetAsync("/api/console/keys/_default/leak-rsa");
        detail.Text.ShouldContain(System.Buffers.Text.Base64Url.EncodeToString(parameters.Modulus!));
    }
}
