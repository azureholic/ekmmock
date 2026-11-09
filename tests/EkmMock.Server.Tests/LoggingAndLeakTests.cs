using System.Buffers.Text;
using System.Security.Cryptography;
using EkmMock.Crypto;
using Microsoft.Extensions.Logging;

namespace EkmMock.Server.Tests;

/// <summary>Spec 9 (one structured line per request, never value/n/e/bodies) and the leak rules of 0.4 / 5.2.</summary>
public sealed class LoggingAndLeakTests
{
    private static readonly string[] AllowedLogFields =
    [
        "exchange_id", "request_id", "correlation_id", "pool_name", "namespace", "op", "key", "alg",
        "status", "error_code", "duration_ms", "crypto_ms", "exception_type",
    ];

    private static IEnumerable<CapturedLog> RequestLines(EkmFactory factory)
        => factory.Logs.Entries.Where(static e => e.Category == "EkmMock.Exchange");

    [Fact]
    public async Task EveryRequest_LogsExactlyOneStructuredLine_WithTheSection9FieldsThatExist()
    {
        using var factory = new EkmFactory();
        factory.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);

        await ekm.InfoAsync();
        var wrapped = await ekm.WrapAsync("aes-key-1", "A256KWP", dek);
        await ekm.UnwrapAsync("aes-key-1", "A256KWP", wrapped.Value());
        await ekm.MetadataAsync("missing-key");
        await ekm.SendAsync(HttpMethod.Get, "/nope");

        var lines = RequestLines(factory).ToList();
        lines.Count.ShouldBe(5);
        lines.ShouldAllBe(l => l.Level == LogLevel.Information);
        foreach (var line in lines)
        {
            line.Fields.Keys.Order().ShouldBe(AllowedLogFields.Order());
        }

        // info
        lines[0].Fields["exchange_id"].ShouldBe(1L);
        lines[0].Fields["op"].ShouldBe("info");
        lines[0].Fields["namespace"].ShouldBe("_default");
        lines[0].Fields["status"].ShouldBe(200);
        lines[0].Fields["error_code"].ShouldBeNull();
        lines[0].Fields["request_id"].ShouldBe("6476b291-7c15-4d0b-aef9-03688390cb8e");
        lines[0].Fields["correlation_id"].ShouldBe("aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85");
        lines[0].Fields["pool_name"].ShouldBe("mhsm-pool-name");

        // wrap
        lines[1].Fields["exchange_id"].ShouldBe(2L);
        lines[1].Fields["op"].ShouldBe("wrapkey");
        lines[1].Fields["key"].ShouldBe("aes-key-1");
        lines[1].Fields["alg"].ShouldBe("A256KWP");
        lines[1].Fields["status"].ShouldBe(200);
        ((double)lines[1].Fields["duration_ms"]!).ShouldBeGreaterThan(0);
        ((double)lines[1].Fields["crypto_ms"]!).ShouldBeGreaterThan(0);
        ((double)lines[1].Fields["duration_ms"]!).ShouldBeGreaterThanOrEqualTo((double)lines[1].Fields["crypto_ms"]!);

        // unwrap
        lines[2].Fields["op"].ShouldBe("unwrapkey");

        // an error: the code is logged, the key does not exist
        lines[3].Fields["op"].ShouldBe("metadata");
        lines[3].Fields["status"].ShouldBe(404);
        lines[3].Fields["error_code"].ShouldBe("KeyNotFound");

        // an unroutable request: no namespace or op yet, still logged
        lines[4].Fields["op"].ShouldBeNull();
        lines[4].Fields["namespace"].ShouldBeNull();
        lines[4].Fields["status"].ShouldBe(404);
        lines[4].Fields["error_code"].ShouldBe("NotFound");
        lines[4].Fields["exchange_id"].ShouldBe(5L);
    }

    [Fact]
    public async Task TheLogLine_NeverHasValueNOrEOrBodiesOrHeaders()
    {
        using var factory = new EkmFactory();
        factory.Keys.Create("_default", "rsa-key-1", KeyType.Rsa, 2048);
        var ekm = factory.CreateEkmClient();
        var dek = Fx.Random(32);

        var metadata = await ekm.MetadataAsync("rsa-key-1");
        var wrapped = await ekm.WrapAsync("rsa-key-1", "RSA-OAEP-256", dek);
        await ekm.UnwrapAsync("rsa-key-1", "RSA-OAEP-256", wrapped.Value());

        using var doc = metadata.Json();
        var n = doc.RootElement.GetProperty("n").GetString()!;
        var logText = factory.Logs.AllText;

        foreach (var forbidden in new[] { "value", "n", "e", "body", "headers", "authorization", "content-type" })
        {
            RequestLines(factory).ShouldAllBe(l => !l.Fields.ContainsKey(forbidden));
        }

        logText.ShouldNotContain(n);
        logText.ShouldNotContain(wrapped.ValueText());
        logText.ShouldNotContain("request_context");
        SecretScanner.LeaksInText(logText, dek).ShouldBeFalse();
    }

    [Fact]
    public async Task ClientSuppliedAlgText_IsNotLogged_OnlyRecognisedNames()
    {
        using var factory = new EkmFactory();
        factory.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
        var dek = Fx.Random(32);

        // A client that puts a DEK where the algorithm belongs must not get it into the log.
        var reply = await factory.CreateEkmClient().WrapRawAsync("aes-key-1", Base64Url.EncodeToString(dek), "AAAA");

        reply.ShouldBeProxyError(400, "UnsupportedAlgorithm");
        RequestLines(factory).Single().Fields["alg"].ShouldBe("unsupported");
        SecretScanner.LeaksInText(factory.Logs.AllText, dek).ShouldBeFalse();
        SecretScanner.LeaksInText(reply.Text, dek).ShouldBeFalse();
    }

    [Fact]
    public async Task AfterAFullRun_NoDekOrKeyMaterial_AppearsInLogsOrErrorBodiesOrWrapReplies()
    {
        // Known key material: imported keys, so the test can scan for the exact bytes. Plus the master key.
        var aesKey = Fx.Random(32);
        using var rsaKey = RSA.Create(2048);
        var rsaPkcs8 = rsaKey.ExportPkcs8PrivateKey();
        var rsaPrivate = rsaKey.ExportParameters(includePrivateParameters: true); // d, p, q, dp are secret; n and e are public
        var masterKey = EkmFactory.MasterKeyBytes();
        using var factory = new EkmFactory(new EkmFactoryOptions { AllowKeyImport = true });
        factory.Keys.Import("_default", "known-aes", KeyType.Oct, aesKey);
        factory.Keys.Import("_default", "known-rsa", KeyType.Rsa, rsaPkcs8);
        factory.Keys.Create("_default", "generated-aes", KeyType.Oct, 256);
        var ekm = factory.CreateEkmClient();

        var deks = new List<byte[]>();
        var nonSecretBodies = new List<string>(); // everything that must be free of DEKs and keys
        var unwrapBodies = new List<EkmReply>();

        foreach (var key in new[] { "known-aes", "generated-aes" })
        {
            foreach (var alg in new[] { "A256KW", "A256KWP" })
            {
                var dek = Fx.Random(32);
                deks.Add(dek);
                var wrapped = await ekm.WrapAsync(key, alg, dek);
                nonSecretBodies.Add(wrapped.Text);
                unwrapBodies.Add(await ekm.UnwrapAsync(key, alg, wrapped.Value()));

                // failure paths that handle the DEK
                var tampered = wrapped.Value().ToArray();
                tampered[3] ^= 1;
                nonSecretBodies.Add((await ekm.UnwrapAsync(key, alg, tampered)).Text);
                nonSecretBodies.Add((await ekm.WrapRawAsync(key, alg, Base64Url.EncodeToString(dek) + "*")).Text);
                nonSecretBodies.Add((await ekm.WrapRawAsync(key, "RSA-OAEP-256", Base64Url.EncodeToString(dek))).Text);
                nonSecretBodies.Add((await ekm.WrapRawAsync("missing-key", alg, Base64Url.EncodeToString(dek))).Text);
                nonSecretBodies.Add((await ekm.PostAsync(EkmClient.Path(null, key, "wrapkey"), "{\"request_context\":{},\"alg\":\"" + alg + "\",\"value\":\"" + Base64Url.EncodeToString(dek) + "\"")).Text);
            }
        }

        foreach (var alg in new[] { "RSA-OAEP-256", "RSA-OAEP" })
        {
            var dek = Fx.Random(32);
            deks.Add(dek);
            var wrapped = await ekm.WrapAsync("known-rsa", alg, dek);
            nonSecretBodies.Add(wrapped.Text);
            unwrapBodies.Add(await ekm.UnwrapAsync("known-rsa", alg, wrapped.Value()));
            nonSecretBodies.Add((await ekm.WrapRawAsync("known-rsa", "A256KWP", Base64Url.EncodeToString(dek))).Text);
        }

        factory.Keys.SetEnabled(new KeyRef("_default", "known-aes"), enabled: false);
        nonSecretBodies.Add((await ekm.WrapAsync("known-aes", "A256KWP", deks[0])).Text);
        factory.Keys.SetEnabled(new KeyRef("_default", "known-aes"), enabled: true);
        nonSecretBodies.Add((await ekm.MetadataAsync("known-rsa")).Text);
        nonSecretBodies.Add((await ekm.MetadataAsync("known-aes")).Text);
        nonSecretBodies.Add((await ekm.InfoAsync()).Text);

        // The unwrap replies are the one place a DEK is allowed, and they must carry exactly that DEK.
        unwrapBodies.ShouldAllBe(r => r.StatusCode == 200);

        var scanned = string.Join("\n", nonSecretBodies) + "\n" + factory.Logs.AllText;
        foreach (var secret in deks.Concat([aesKey, masterKey, rsaPrivate.D!, rsaPrivate.P!, rsaPrivate.Q!, rsaPrivate.DP!]))
        {
            SecretScanner.LeaksInText(scanned, secret).ShouldBeFalse();
        }

        // The key store file holds no raw key bytes either (spec 14 test 19, also exercised by the M1 tests).
        factory.Backend.Flush();
        var keyStore = File.ReadAllText(factory.Backend.KeyStorePath);
        SecretScanner.LeaksInText(keyStore, aesKey).ShouldBeFalse();
        SecretScanner.LeaksInText(keyStore, masterKey).ShouldBeFalse();
    }

    [Fact]
    public async Task ErrorBodies_AreFixedTextPerCode_WhateverTheInput()
    {
        using var factory = new EkmFactory();
        factory.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
        var ekm = factory.CreateEkmClient();
        var marker = "ZZ-UNIQUE-INPUT-MARKER-ZZ";

        var replies = new[]
        {
            await ekm.PostAsync($"/{marker}/info?api-version=0.1-preview"),
            await ekm.PostAsync(EkmClient.Path(null, marker.Replace("-", "_"), "metadata")),
            await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "metadata", $"api-version={marker}")),
            await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), EkmClient.WrapBody(marker, "AAAA")),
            await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), EkmClient.WrapBody("A256KWP", marker)),
            await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), "{\"" + marker + "\": nope"),
            await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), "{}", marker.ToLowerInvariant() + "/x"),
            await ekm.SendAsync(new HttpMethod(marker), EkmClient.Path(null, null, "info")),
        };

        foreach (var reply in replies)
        {
            reply.StatusCode.ShouldBeGreaterThanOrEqualTo(400);
            reply.Text.ShouldNotContain(marker, Case.Insensitive);
        }

        factory.Logs.AllText.ShouldNotContain(marker, Case.Insensitive);
    }
}
