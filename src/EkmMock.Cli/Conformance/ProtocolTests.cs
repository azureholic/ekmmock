using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EkmMock.Cli.Ekm;

namespace EkmMock.Cli.Conformance;

/// <summary>Section 14, "EKM protocol" tests 1 to 13: the wire contract of the four operations, run from outside through mutual TLS.</summary>
internal static class ProtocolTests
{
    private static readonly string[] KeyOps = ["wrapKey", "unwrapKey"];

    public static IEnumerable<ConformanceCase> All()
    {
        yield return new("14.1.a", "14.1", "info returns 200 with api_version, proxy_vendor, proxy_name, ekm_vendor, ekm_product", Info200);
        yield return new("14.1.b", "14.1", "info returns 503 HsmUnavailable while the HSM-offline fault is on", InfoOffline);
        yield return new("14.2.a", "14.2", "a missing api-version is 400 UnsupportedApiVersion", MissingApiVersion);
        yield return new("14.2.b", "14.2", "api-version=9.9 is 400 UnsupportedApiVersion", UnsupportedApiVersion);
        yield return new("14.3.a", "14.3", "a 65 character key name is 400 InvalidKeyName", KeyName65);
        yield return new("14.3.b", "14.3", "key names with '_' or '.' are 400 InvalidKeyName", KeyNameCharacters);
        yield return new("14.4.a", "14.4", "an unknown key is 404 KeyNotFound for metadata, wrapkey and unwrapkey", UnknownKey);
        yield return new("14.4.b", "14.4", "a key of another namespace is 404 KeyNotFound", OtherNamespaceKey);
        yield return new("14.4.c", "14.4", "a destroyed key is 404 KeyNotFound", DestroyedKey);
        yield return new("14.5.a", "14.5", "AES-256 metadata is exactly key_type oct, key_size 256, key_ops [wrapKey, unwrapKey]", AesMetadata);
        yield return new("14.5.b", "14.5", "RSA metadata: n decodes to the modulus without a leading zero byte, e is AQAB", RsaMetadata);
        yield return new("14.6.a", "14.6", "A256KW round trip for DEK sizes 16, 24, 32, 64 (and 8-byte multiples up to 4096)", Kw);
        yield return new("14.6.b", "14.6", "A256KWP round trip for DEK sizes 16, 24, 32, 64", KwpBasic);
        yield return new("14.6.c", "14.6", "A256KWP round trip for DEK sizes 1 to 4096 (sample incl. every boundary)", KwpRange);
        yield return new("14.6.d", "14.6", "AES wrap rejects DEKs outside the allowed sizes with 400", AesLimits);
        yield return new("14.6.e", "14.6", "RSA-OAEP-256 round trip up to k-66 bytes; one more is 400", RsaOaep256);
        yield return new("14.6.f", "14.6", "RSA-OAEP (SHA-1) round trip up to k-42 bytes; one more is 400", RsaOaep);
        yield return new("14.7.a", "14.7", "A256KW with an imported KEK reproduces the RFC 3394 section 4.6 vector", Rfc3394);
        yield return new("14.7.b", "14.7", "A256KW and A256KWP equal an independent RFC 3394 / RFC 5649 implementation (imported KEK)", ReferenceOracle);
        yield return new("14.8.a", "14.8", "RSA-OAEP-256 and RSA-OAEP ciphertext made client-side from the published n/e unwraps", RsaClientEncrypts);
        yield return new("14.8.b", "14.8", "RSA ciphertext from EkmMock decrypts with an independent RSA instance (imported key)", RsaClientDecrypts);
        yield return new("14.9.a", "14.9", "an algorithm that does not fit the key type is 400 UnsupportedAlgorithm", AlgorithmMismatch);
        yield return new("14.10.a", "14.10", "a tampered or truncated wrapped value is 400 InvalidCiphertext, not 500", Tampered);
        yield return new("14.11.a", "14.11", "a disabled key: wrap/unwrap 403 KeyDisabled, metadata 200", DisabledKey);
        yield return new("14.11.b", "14.11", "an expired key: wrap/unwrap 403 KeyExpired, metadata 200", ExpiredKey);
        yield return new("14.12.a", "14.12", "padded and unpadded base64url input are both accepted", PaddedInput);
        yield return new("14.12.b", "14.12", "standard base64 ('+' and '/') is 400", StandardBase64);
        yield return new("14.12.c", "14.12", "output is always unpadded base64url", UnpaddedOutput);
        yield return new("14.13.a", "14.13", "keys and namespaces survive a restart; a wrapped DEK from before unwraps after it", Persistence);
    }

    // ---- 1 ----

    private static async Task Info200(ConformanceContext ctx, CancellationToken ct)
    {
        var reply = await ctx.Ekm.InfoAsync(ct).ConfigureAwait(false);
        Expect.Status(reply, 200, "info");
        Expect.That(reply.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) == true, $"info: Content-Type is '{reply.ContentType}', expected application/json");
        foreach (var field in new[] { "api_version", "proxy_vendor", "proxy_name", "ekm_vendor", "ekm_product" })
        {
            Expect.That(reply.GetString(field) is { Length: > 0 }, $"info: field '{field}' is missing or empty");
        }
    }

    private static async Task InfoOffline(ConformanceContext ctx, CancellationToken ct)
    {
        await ctx.RequireFaultsAsync(ct).ConfigureAwait(false);
        var rule = await ctx.Console!.ApplyFaultPresetAsync("hsm-offline", ct).ConfigureAwait(false);
        ctx.TrackFault(rule.Id);
        try
        {
            var offline = await ctx.Ekm.InfoAsync(ct).ConfigureAwait(false);
            Expect.ProxyError(offline, 503, "HsmUnavailable", "info while the HSM is offline");
        }
        finally
        {
            await ctx.RemoveFaultAsync(rule.Id).ConfigureAwait(false);
        }

        Expect.Status(await ctx.Ekm.InfoAsync(ct).ConfigureAwait(false), 200, "info after the fault was removed");
    }

    // ---- 2, 3 ----

    private static async Task MissingApiVersion(ConformanceContext ctx, CancellationToken ct)
    {
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        Expect.ProxyError(await ctx.Ekm.PostAsync(ctx.Ekm.Path(null, "info", query: null), cancellationToken: ct).ConfigureAwait(false), 400, "UnsupportedApiVersion", "info without api-version");
        Expect.ProxyError(await ctx.Ekm.PostAsync(ctx.Ekm.Path(key.Name, "metadata", query: null), cancellationToken: ct).ConfigureAwait(false), 400, "UnsupportedApiVersion", "metadata without api-version");
        Expect.ProxyError(await ctx.Ekm.PostAsync(ctx.Ekm.Path(key.Name, "metadata", query: "foo=bar"), cancellationToken: ct).ConfigureAwait(false), 400, "UnsupportedApiVersion", "metadata with other query parameters only");
    }

    private static async Task UnsupportedApiVersion(ConformanceContext ctx, CancellationToken ct)
    {
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        Expect.ProxyError(await ctx.Ekm.PostAsync(ctx.Ekm.Path(null, "info", query: "api-version=9.9"), cancellationToken: ct).ConfigureAwait(false), 400, "UnsupportedApiVersion", "info with api-version=9.9");
        Expect.ProxyError(await ctx.Ekm.PostAsync(ctx.Ekm.Path(key.Name, "metadata", query: "api-version=9.9"), cancellationToken: ct).ConfigureAwait(false), 400, "UnsupportedApiVersion", "metadata with api-version=9.9");
        Expect.ProxyError(await ctx.Ekm.PostAsync(ctx.Ekm.Path(key.Name, "metadata", query: "api-version="), cancellationToken: ct).ConfigureAwait(false), 400, "UnsupportedApiVersion", "metadata with an empty api-version");
    }

    private static async Task KeyName65(ConformanceContext ctx, CancellationToken ct)
    {
        var name = new string('a', 65);
        foreach (var operation in new[] { "metadata", "wrapkey", "unwrapkey" })
        {
            Expect.ProxyError(await ctx.Ekm.PostAsync(ctx.Ekm.Path(name, operation), alg: operation == "metadata" ? null : "A256KWP", valueText: operation == "metadata" ? null : "AAAAAAAAAAAAAAAAAAAAAA", ct).ConfigureAwait(false), 400, "InvalidKeyName", $"{operation} with a 65 character key name");
        }

        // 64 characters is still a valid name (an unknown key, so 404, not 400).
        var edge = await ctx.Ekm.MetadataAsync(new string('a', 64), ct).ConfigureAwait(false);
        Expect.ProxyError(edge, 404, "KeyNotFound", "metadata with a 64 character key name (valid name, unknown key)");
    }

    private static async Task KeyNameCharacters(ConformanceContext ctx, CancellationToken ct)
    {
        foreach (var name in new[] { "bad_key", "bad.key", "_leading", "trailing.", "a%20b" })
        {
            Expect.ProxyError(await ctx.Ekm.PostAsync(ctx.Ekm.Path(name, "metadata"), cancellationToken: ct).ConfigureAwait(false), 400, "InvalidKeyName", $"metadata with key name '{name}'");
        }
    }

    // ---- 4 ----

    private static async Task UnknownKey(ConformanceContext ctx, CancellationToken ct)
    {
        var name = ctx.Name("does-not-exist");
        Expect.ProxyError(await ctx.Ekm.MetadataAsync(name, ct).ConfigureAwait(false), 404, "KeyNotFound", "metadata of an unknown key");
        Expect.ProxyError(await ctx.Ekm.WrapAsync(name, "A256KWP", ctx.Random(32), ct).ConfigureAwait(false), 404, "KeyNotFound", "wrapkey of an unknown key");
        Expect.ProxyError(await ctx.Ekm.UnwrapAsync(name, "A256KWP", new byte[40], ct).ConfigureAwait(false), 404, "KeyNotFound", "unwrapkey of an unknown key");
    }

    private static async Task OtherNamespaceKey(ConformanceContext ctx, CancellationToken ct)
    {
        ctx.RequireConsole("to create a second namespace with a key");
        var other = await ctx.OtherNamespaceAsync(sameTrust: true, ct).ConfigureAwait(false);
        var name = ctx.Name("only-in-other");
        await ctx.Console!.CreateKeyAsync(new(other.Name, name, "aes", 256, false), ct).ConfigureAwait(false);

        var inOther = await ctx.Ekm.PostAsync(ctx.Ekm.Path(name, "metadata", prefixOverride: other.Prefix), cancellationToken: ct).ConfigureAwait(false);
        Expect.Status(inOther, 200, "metadata of the key through its own namespace prefix (setup check)");
        Expect.ProxyError(await ctx.Ekm.MetadataAsync(name, ct).ConfigureAwait(false), 404, "KeyNotFound", "metadata of a key that lives in another namespace");
        Expect.ProxyError(await ctx.Ekm.WrapAsync(name, "A256KWP", ctx.Random(32), ct).ConfigureAwait(false), 404, "KeyNotFound", "wrapkey of a key that lives in another namespace");
    }

    private static async Task DestroyedKey(ConformanceContext ctx, CancellationToken ct)
    {
        ctx.RequireConsole("to destroy a key");
        var key = await ctx.CreateExtraKeyAsync("to-destroy", isRsa: false, ct).ConfigureAwait(false);
        var dek = ctx.Random(32);
        var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(key.Name, "A256KWP", dek, ct).ConfigureAwait(false), "wrap before destroy");
        await ctx.Console!.DestroyKeyAsync(key.Namespace, key.Name, key.Name, ct).ConfigureAwait(false);

        Expect.ProxyError(await ctx.Ekm.MetadataAsync(key.Name, ct).ConfigureAwait(false), 404, "KeyNotFound", "metadata of a destroyed key");
        Expect.ProxyError(await ctx.Ekm.WrapAsync(key.Name, "A256KWP", dek, ct).ConfigureAwait(false), 404, "KeyNotFound", "wrapkey of a destroyed key");
        Expect.ProxyError(await ctx.Ekm.UnwrapAsync(key.Name, "A256KWP", wrapped, ct).ConfigureAwait(false), 404, "KeyNotFound", "unwrapkey of a destroyed key (crypto-shred)");
    }

    // ---- 5 ----

    private static async Task AesMetadata(ConformanceContext ctx, CancellationToken ct)
    {
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var reply = await ctx.Ekm.MetadataAsync(key.Name, ct).ConfigureAwait(false);
        Expect.Status(reply, 200, "AES metadata");
        using var json = reply.TryJson() ?? throw new TestFailure("AES metadata: the body is not JSON");
        var root = json.RootElement;
        var names = root.EnumerateObject().Select(static p => p.Name).Order(StringComparer.Ordinal).ToArray();
        Expect.That(names.SequenceEqual(["key_ops", "key_size", "key_type"]), $"AES metadata has the properties [{string.Join(", ", names)}], expected exactly [key_ops, key_size, key_type]");
        Expect.That(root.GetProperty("key_type").GetString() == "oct", "AES metadata: key_type is not 'oct'");
        Expect.That(root.GetProperty("key_size").TryGetInt32(out var size) && size == 256, "AES metadata: key_size is not 256");
        Expect.That(root.GetProperty("key_ops").EnumerateArray().Select(static e => e.GetString()).SequenceEqual(KeyOps), "AES metadata: key_ops is not exactly [\"wrapKey\", \"unwrapKey\"]");
    }

    private static async Task RsaMetadata(ConformanceContext ctx, CancellationToken ct)
    {
        foreach (var size in ctx.RsaSizes)
        {
            SuiteKey key;
            try
            {
                key = await ctx.RsaKeyAsync(size, ct).ConfigureAwait(false);
            }
            catch (SkipTest) when (size != ctx.RsaSizes[0])
            {
                continue;
            }

            var reply = await ctx.Ekm.MetadataAsync(key.Name, ct).ConfigureAwait(false);
            Expect.Status(reply, 200, $"RSA-{size} metadata");
            using var json = reply.TryJson() ?? throw new TestFailure("RSA metadata: the body is not JSON");
            var root = json.RootElement;
            var names = root.EnumerateObject().Select(static p => p.Name).Order(StringComparer.Ordinal).ToArray();
            Expect.That(names.SequenceEqual(["e", "key_ops", "key_size", "key_type", "n"]), $"RSA-{size} metadata has the properties [{string.Join(", ", names)}], expected exactly [e, key_ops, key_size, key_type, n]");
            Expect.That(root.GetProperty("key_type").GetString() == "RSA", $"RSA-{size} metadata: key_type is not 'RSA'");
            Expect.That(root.GetProperty("key_size").TryGetInt32(out var reported) && reported == key.Size, $"RSA-{size} metadata: key_size is {reported}, expected {key.Size}");
            Expect.That(root.GetProperty("key_ops").EnumerateArray().Select(static e => e.GetString()).SequenceEqual(KeyOps), $"RSA-{size} metadata: key_ops is not exactly [\"wrapKey\", \"unwrapKey\"]");

            var e = root.GetProperty("e").GetString()!;
            var n = root.GetProperty("n").GetString()!;
            Expect.That(e == "AQAB", $"RSA-{size} metadata: e is '{e}', expected AQAB (65537)");
            Expect.That(IsUnpaddedBase64Url(n), $"RSA-{size} metadata: n is not unpadded base64url");
            var modulus = EkmClient.FromBase64Url(n);
            Expect.That(modulus.Length == key.Size / 8, $"RSA-{size} metadata: n decodes to {modulus.Length} bytes, expected {key.Size / 8} (a leading zero byte must not be sent)");
            Expect.That(modulus[0] != 0 && (modulus[0] & 0x80) != 0, $"RSA-{size} metadata: n has a leading zero byte or does not use the full {key.Size} bits");

            if (ctx.Console is not null && key.Temporary)
            {
                var detail = await ctx.Console.GetKeyAsync(key.Namespace, key.Name, ct).ConfigureAwait(false);
                Expect.That(detail.PublicKey?.JwkN == n && detail.PublicKey.JwkE == e, $"RSA-{size} metadata: n/e differ from the public key the console shows for the same key");
            }
        }
    }

    internal static bool IsUnpaddedBase64Url(string text)
        => text.Length > 0 && text.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    // ---- 6 ----

    private static async Task Kw(ConformanceContext ctx, CancellationToken ct)
    {
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        foreach (var size in new[] { 16, 24, 32, 64, 72, 128, 1024, 4096 })
        {
            await RoundTripAsync(ctx, key.Name, "A256KW", size, expectedWrappedLength: size + 8, ct).ConfigureAwait(false);
        }
    }

    private static async Task KwpBasic(ConformanceContext ctx, CancellationToken ct)
    {
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        foreach (var size in new[] { 16, 24, 32, 64 })
        {
            await RoundTripAsync(ctx, key.Name, "A256KWP", size, expectedWrappedLength: (size + 7) / 8 * 8 + 8, ct).ConfigureAwait(false);
        }
    }

    private static async Task KwpRange(ConformanceContext ctx, CancellationToken ct)
    {
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        foreach (var size in new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 17, 20, 31, 33, 100, 255, 256, 257, 1000, 1023, 1024, 2047, 2048, 4095, 4096 })
        {
            await RoundTripAsync(ctx, key.Name, "A256KWP", size, expectedWrappedLength: (size + 7) / 8 * 8 + 8, ct).ConfigureAwait(false);
        }
    }

    private static async Task RoundTripAsync(ConformanceContext ctx, string key, string alg, int dekSize, int? expectedWrappedLength, CancellationToken ct)
    {
        var dek = ctx.Random(dekSize);
        var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(key, alg, dek, ct).ConfigureAwait(false), $"{alg} wrap of {dekSize} bytes");
        if (expectedWrappedLength is { } length)
        {
            Expect.That(wrapped.Length == length, $"{alg} wrap of {dekSize} bytes: the wrapped value is {wrapped.Length} bytes, expected {length}");
        }

        Expect.That(!wrapped.AsSpan().SequenceEqual(dek), $"{alg} wrap of {dekSize} bytes returned the DEK unchanged");
        var unwrapped = Expect.Value(await ctx.Ekm.UnwrapAsync(key, alg, wrapped, ct).ConfigureAwait(false), $"{alg} unwrap of {dekSize} bytes");
        Expect.That(CryptographicOperations.FixedTimeEquals(unwrapped, dek), $"{alg} round trip of {dekSize} bytes: unwrap did not return the original DEK");
    }

    private static async Task AesLimits(ConformanceContext ctx, CancellationToken ct)
    {
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        Expect.AnyProxyError(await ctx.Ekm.WrapAsync(key.Name, "A256KW", ctx.Random(8), ct).ConfigureAwait(false), 400, "A256KW with an 8 byte DEK (minimum is 16)");
        Expect.AnyProxyError(await ctx.Ekm.WrapAsync(key.Name, "A256KW", ctx.Random(17), ct).ConfigureAwait(false), 400, "A256KW with a 17 byte DEK (must be a multiple of 8)");
        Expect.AnyProxyError(await ctx.Ekm.WrapAsync(key.Name, "A256KW", ctx.Random(31), ct).ConfigureAwait(false), 400, "A256KW with a 31 byte DEK (must be a multiple of 8)");
        Expect.AnyProxyError(await ctx.Ekm.WrapAsync(key.Name, "A256KWP", ctx.Random(4097), ct).ConfigureAwait(false), 400, "A256KWP with a 4097 byte DEK (maximum is 4096)");
        Expect.AnyProxyError(await ctx.Ekm.WrapTextAsync(key.Name, "A256KWP", string.Empty, ct).ConfigureAwait(false), 400, "A256KWP with an empty value");
        Expect.AnyProxyError(await ctx.Ekm.UnwrapAsync(key.Name, "A256KWP", new byte[8], ct).ConfigureAwait(false), 400, "A256KWP unwrap of 8 bytes (minimum is 16)");
        Expect.AnyProxyError(await ctx.Ekm.UnwrapAsync(key.Name, "A256KW", new byte[16], ct).ConfigureAwait(false), 400, "A256KW unwrap of 16 bytes (minimum is 24)");
        Expect.AnyProxyError(await ctx.Ekm.UnwrapAsync(key.Name, "A256KWP", new byte[20], ct).ConfigureAwait(false), 400, "A256KWP unwrap of a length that is not a multiple of 8");
    }

    private static Task RsaOaep256(ConformanceContext ctx, CancellationToken ct) => RsaLimitsAsync(ctx, "RSA-OAEP-256", overhead: 66, ct);

    private static Task RsaOaep(ConformanceContext ctx, CancellationToken ct) => RsaLimitsAsync(ctx, "RSA-OAEP", overhead: 42, ct);

    private static async Task RsaLimitsAsync(ConformanceContext ctx, string alg, int overhead, CancellationToken ct)
    {
        var tested = 0;
        foreach (var size in ctx.RsaSizes)
        {
            SuiteKey key;
            try
            {
                key = await ctx.RsaKeyAsync(size, ct).ConfigureAwait(false);
            }
            catch (SkipTest) when (tested > 0)
            {
                continue;
            }

            var k = key.Size / 8;
            foreach (var dekSize in new[] { 16, 24, 32, 64 })
            {
                await RoundTripAsync(ctx, key.Name, alg, dekSize, expectedWrappedLength: k, ct).ConfigureAwait(false);
            }

            await RoundTripAsync(ctx, key.Name, alg, k - overhead, expectedWrappedLength: k, ct).ConfigureAwait(false);
            Expect.AnyProxyError(await ctx.Ekm.WrapAsync(key.Name, alg, ctx.Random(k - overhead + 1), ct).ConfigureAwait(false), 400, $"{alg} with RSA-{key.Size} and a {k - overhead + 1} byte DEK (the limit is {k - overhead})");
            Expect.AnyProxyError(await ctx.Ekm.UnwrapAsync(key.Name, alg, new byte[k - 1], ct).ConfigureAwait(false), 400, $"{alg} unwrap of {k - 1} bytes with RSA-{key.Size} (must be exactly {k})");
            tested++;
        }
    }

    // ---- 7 ----

    private const string Rfc3394Kek = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    private const string Rfc3394Data = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    private const string Rfc3394Wrapped = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";

    private static async Task Rfc3394(ConformanceContext ctx, CancellationToken ct)
    {
        await ctx.RequireImportAsync(ct).ConfigureAwait(false);
        ctx.Remember(Convert.FromHexString(Rfc3394Kek));
        var key = await ctx.ImportKeyAsync("rfc3394", isRsa: false, Rfc3394Kek, ct).ConfigureAwait(false);

        var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(key.Name, "A256KW", Convert.FromHexString(Rfc3394Data), ct).ConfigureAwait(false), "A256KW wrap of the RFC 3394 4.6 key data");
        Expect.That(Convert.ToHexString(wrapped) == Rfc3394Wrapped, "A256KW output differs from the RFC 3394 section 4.6 ciphertext");
        var unwrapped = Expect.Value(await ctx.Ekm.UnwrapAsync(key.Name, "A256KW", Convert.FromHexString(Rfc3394Wrapped), ct).ConfigureAwait(false), "A256KW unwrap of the RFC 3394 4.6 ciphertext");
        Expect.That(Convert.ToHexString(unwrapped) == Rfc3394Data, "A256KW unwrap of the RFC 3394 4.6 ciphertext did not return the RFC key data");
    }

    private static async Task ReferenceOracle(ConformanceContext ctx, CancellationToken ct)
    {
        await ctx.RequireImportAsync(ct).ConfigureAwait(false);
        var selfCheck = ReferenceKeyWrap.SelfCheck();
        Expect.That(selfCheck is null, "the suite's own reference implementation failed its RFC vectors: " + selfCheck);

        var kek = ctx.Random(32);
        var key = await ctx.ImportKeyAsync("kek", isRsa: false, Convert.ToHexString(kek), ct).ConfigureAwait(false);
        foreach (var size in new[] { 16, 24, 32, 40, 64, 128, 1024 })
        {
            var dek = ctx.Random(size);
            var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(key.Name, "A256KW", dek, ct).ConfigureAwait(false), $"A256KW wrap of {size} bytes");
            Expect.That(wrapped.AsSpan().SequenceEqual(ReferenceKeyWrap.Wrap(kek, dek)), $"A256KW of {size} bytes differs from the reference RFC 3394 output");
            var back = Expect.Value(await ctx.Ekm.UnwrapAsync(key.Name, "A256KW", ReferenceKeyWrap.Wrap(kek, dek), ct).ConfigureAwait(false), $"A256KW unwrap of reference output ({size} bytes)");
            Expect.That(back.AsSpan().SequenceEqual(dek), $"A256KW unwrap of reference output ({size} bytes) did not return the DEK");
        }

        foreach (var size in new[] { 1, 7, 8, 9, 16, 20, 32, 33, 64, 100, 4096 })
        {
            var dek = ctx.Random(size);
            var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(key.Name, "A256KWP", dek, ct).ConfigureAwait(false), $"A256KWP wrap of {size} bytes");
            Expect.That(wrapped.AsSpan().SequenceEqual(ReferenceKeyWrap.WrapWithPadding(kek, dek)), $"A256KWP of {size} bytes differs from the reference RFC 5649 output");
            var back = Expect.Value(await ctx.Ekm.UnwrapAsync(key.Name, "A256KWP", ReferenceKeyWrap.WrapWithPadding(kek, dek), ct).ConfigureAwait(false), $"A256KWP unwrap of reference output ({size} bytes)");
            Expect.That(back.AsSpan().SequenceEqual(dek), $"A256KWP unwrap of reference output ({size} bytes) did not return the DEK");
        }
    }

    // ---- 8 ----

    private static async Task RsaClientEncrypts(ConformanceContext ctx, CancellationToken ct)
    {
        foreach (var size in ctx.RsaSizes)
        {
            SuiteKey key;
            try
            {
                key = await ctx.RsaKeyAsync(size, ct).ConfigureAwait(false);
            }
            catch (SkipTest) when (size != ctx.RsaSizes[0])
            {
                continue;
            }

            var meta = await ctx.Ekm.MetadataAsync(key.Name, ct).ConfigureAwait(false);
            Expect.Status(meta, 200, "RSA metadata");
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = EkmClient.FromBase64Url(meta.GetString("n")!), Exponent = EkmClient.FromBase64Url(meta.GetString("e")!) });

            foreach (var (alg, padding) in new[] { ("RSA-OAEP-256", RSAEncryptionPadding.OaepSHA256), ("RSA-OAEP", RSAEncryptionPadding.OaepSHA1) })
            {
                var dek = ctx.Random(32);
                var ciphertext = rsa.Encrypt(dek, padding);
                var unwrapped = Expect.Value(await ctx.Ekm.UnwrapAsync(key.Name, alg, ciphertext, ct).ConfigureAwait(false), $"{alg} unwrap of a ciphertext made by an independent client (RSA-{key.Size})");
                Expect.That(unwrapped.AsSpan().SequenceEqual(dek), $"{alg} (RSA-{key.Size}): EkmMock did not recover the DEK the client encrypted with the published key");
            }
        }
    }

    private static async Task RsaClientDecrypts(ConformanceContext ctx, CancellationToken ct)
    {
        await ctx.RequireImportAsync(ct).ConfigureAwait(false);
        using var rsa = RSA.Create(2048);
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        ctx.Remember(pkcs8);
        var key = await ctx.ImportKeyAsync("rsaimp", isRsa: true, Convert.ToBase64String(pkcs8), ct).ConfigureAwait(false);

        foreach (var (alg, padding) in new[] { ("RSA-OAEP-256", RSAEncryptionPadding.OaepSHA256), ("RSA-OAEP", RSAEncryptionPadding.OaepSHA1) })
        {
            var dek = ctx.Random(32);
            var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(key.Name, alg, dek, ct).ConfigureAwait(false), $"{alg} wrap with the imported key");
            byte[] recovered;
            try
            {
                recovered = rsa.Decrypt(wrapped, padding);
            }
            catch (CryptographicException)
            {
                throw new TestFailure($"{alg}: an independent RSA instance could not decrypt what EkmMock wrapped");
            }

            Expect.That(recovered.AsSpan().SequenceEqual(dek), $"{alg}: the independent RSA instance decrypted EkmMock's output to something else than the DEK");
        }
    }

    // ---- 9, 10 ----

    private static async Task AlgorithmMismatch(ConformanceContext ctx, CancellationToken ct)
    {
        var aes = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var rsa = await ctx.RsaKeyAsync(2048, ct).ConfigureAwait(false);
        foreach (var alg in new[] { "RSA-OAEP-256", "RSA-OAEP" })
        {
            Expect.ProxyError(await ctx.Ekm.WrapAsync(aes.Name, alg, ctx.Random(32), ct).ConfigureAwait(false), 400, "UnsupportedAlgorithm", $"wrapkey {alg} with an AES key");
            Expect.ProxyError(await ctx.Ekm.UnwrapAsync(aes.Name, alg, new byte[256], ct).ConfigureAwait(false), 400, "UnsupportedAlgorithm", $"unwrapkey {alg} with an AES key");
        }

        foreach (var alg in new[] { "A256KW", "A256KWP" })
        {
            Expect.ProxyError(await ctx.Ekm.WrapAsync(rsa.Name, alg, ctx.Random(32), ct).ConfigureAwait(false), 400, "UnsupportedAlgorithm", $"wrapkey {alg} with an RSA key");
            Expect.ProxyError(await ctx.Ekm.UnwrapAsync(rsa.Name, alg, new byte[40], ct).ConfigureAwait(false), 400, "UnsupportedAlgorithm", $"unwrapkey {alg} with an RSA key");
        }

        Expect.ProxyError(await ctx.Ekm.WrapAsync(aes.Name, "NOT-AN-ALG", ctx.Random(32), ct).ConfigureAwait(false), 400, "UnsupportedAlgorithm", "wrapkey with an unknown algorithm");
    }

    private static async Task Tampered(ConformanceContext ctx, CancellationToken ct)
    {
        var aes = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var rsa = await ctx.RsaKeyAsync(2048, ct).ConfigureAwait(false);
        foreach (var (key, alg, size) in new[] { (aes.Name, "A256KW", 32), (aes.Name, "A256KWP", 32), (aes.Name, "A256KWP", 5), (rsa.Name, "RSA-OAEP-256", 32), (rsa.Name, "RSA-OAEP", 32) })
        {
            var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(key, alg, ctx.Random(size), ct).ConfigureAwait(false), $"{alg} wrap");
            foreach (var position in new[] { 0, wrapped.Length / 2, wrapped.Length - 1 })
            {
                var copy = (byte[])wrapped.Clone();
                copy[position] ^= 0x01;
                Expect.ProxyError(await ctx.Ekm.UnwrapAsync(key, alg, copy, ct).ConfigureAwait(false), 400, "InvalidCiphertext", $"{alg} unwrap with byte {position} of {wrapped.Length} flipped");
            }

            Expect.ProxyError(await ctx.Ekm.UnwrapAsync(key, alg, wrapped.AsSpan(0, wrapped.Length - 8), ct).ConfigureAwait(false), 400, "InvalidCiphertext", $"{alg} unwrap of a truncated value");
        }

        // A wrapped value made by another key must not unwrap either.
        var other = await ctx.Ekm.WrapAsync(aes.Name, "A256KWP", ctx.Random(32), ct).ConfigureAwait(false);
        if (ctx.Console is not null)
        {
            var second = await ctx.CreateExtraKeyAsync("second-aes", isRsa: false, ct).ConfigureAwait(false);
            Expect.ProxyError(await ctx.Ekm.UnwrapAsync(second.Name, "A256KWP", Expect.Value(other, "wrap"), ct).ConfigureAwait(false), 400, "InvalidCiphertext", "A256KWP unwrap with another key than the one that wrapped");
        }
    }

    // ---- 11 ----

    private static async Task DisabledKey(ConformanceContext ctx, CancellationToken ct)
    {
        ctx.RequireConsole("to disable a key");
        var key = await ctx.CreateExtraKeyAsync("to-disable", isRsa: false, ct).ConfigureAwait(false);
        var dek = ctx.Random(32);
        var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(key.Name, "A256KWP", dek, ct).ConfigureAwait(false), "wrap while enabled");
        await ctx.Console!.SetEnabledAsync(key.Namespace, key.Name, enabled: false, ct).ConfigureAwait(false);
        try
        {
            Expect.ProxyError(await ctx.Ekm.WrapAsync(key.Name, "A256KWP", dek, ct).ConfigureAwait(false), 403, "KeyDisabled", "wrapkey with a disabled key");
            Expect.ProxyError(await ctx.Ekm.UnwrapAsync(key.Name, "A256KWP", wrapped, ct).ConfigureAwait(false), 403, "KeyDisabled", "unwrapkey with a disabled key");
            Expect.Status(await ctx.Ekm.MetadataAsync(key.Name, ct).ConfigureAwait(false), 200, "metadata of a disabled key");
        }
        finally
        {
            await ctx.Console.SetEnabledAsync(key.Namespace, key.Name, enabled: true, CancellationToken.None).ConfigureAwait(false);
        }

        var unwrapped = Expect.Value(await ctx.Ekm.UnwrapAsync(key.Name, "A256KWP", wrapped, ct).ConfigureAwait(false), "unwrap after enabling again");
        Expect.That(unwrapped.AsSpan().SequenceEqual(dek), "after enabling again the key did not unwrap the earlier wrapped DEK");
    }

    private static async Task ExpiredKey(ConformanceContext ctx, CancellationToken ct)
    {
        ctx.RequireConsole("to set an expiry");
        var key = await ctx.CreateExtraKeyAsync("to-expire", isRsa: false, ct).ConfigureAwait(false);
        var dek = ctx.Random(32);
        var wrapped = Expect.Value(await ctx.Ekm.WrapAsync(key.Name, "A256KWP", dek, ct).ConfigureAwait(false), "wrap before expiry");
        await ctx.Console!.SetExpiryAsync(key.Namespace, key.Name, DateTimeOffset.UtcNow.AddMinutes(-5), ct).ConfigureAwait(false);
        try
        {
            Expect.ProxyError(await ctx.Ekm.WrapAsync(key.Name, "A256KWP", dek, ct).ConfigureAwait(false), 403, "KeyExpired", "wrapkey with an expired key");
            Expect.ProxyError(await ctx.Ekm.UnwrapAsync(key.Name, "A256KWP", wrapped, ct).ConfigureAwait(false), 403, "KeyExpired", "unwrapkey with an expired key");
            Expect.Status(await ctx.Ekm.MetadataAsync(key.Name, ct).ConfigureAwait(false), 200, "metadata of an expired key");
        }
        finally
        {
            await ctx.Console.SetExpiryAsync(key.Namespace, key.Name, null, CancellationToken.None).ConfigureAwait(false);
        }

        Expect.Status(await ctx.Ekm.UnwrapAsync(key.Name, "A256KWP", wrapped, ct).ConfigureAwait(false), 200, "unwrap after the expiry was cleared");
    }

    // ---- 12 ----

    private static async Task PaddedInput(ConformanceContext ctx, CancellationToken ct)
    {
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var dek = ctx.Random(20); // 20 bytes: 27 unpadded characters, one '=' when padded; the wrapped value (32 bytes) pads too
        var unpadded = EkmClient.Base64Url(dek);
        var padded = unpadded + "=";
        Expect.That(padded.Length % 4 == 0, "internal: the padded form is not a multiple of 4 characters");

        var viaPadded = await ctx.Ekm.WrapTextAsync(key.Name, "A256KWP", padded, ct).ConfigureAwait(false);
        var viaUnpadded = await ctx.Ekm.WrapTextAsync(key.Name, "A256KWP", unpadded, ct).ConfigureAwait(false);
        var wrappedPadded = Expect.Value(viaPadded, "wrap with a padded value");
        var wrappedUnpadded = Expect.Value(viaUnpadded, "wrap with an unpadded value");
        Expect.That(wrappedPadded.AsSpan().SequenceEqual(wrappedUnpadded), "the same DEK sent padded and unpadded produced different wrapped values (A256KWP is deterministic)");

        var wrappedText = EkmClient.Base64Url(wrappedUnpadded);
        var wrappedPaddedText = wrappedText + new string('=', (4 - wrappedText.Length % 4) % 4);
        foreach (var text in new[] { wrappedText, wrappedPaddedText })
        {
            var unwrapped = Expect.Value(await ctx.Ekm.UnwrapTextAsync(key.Name, "A256KWP", text, ct).ConfigureAwait(false), $"unwrap with {(text.EndsWith('=') ? "a padded" : "an unpadded")} value");
            Expect.That(unwrapped.AsSpan().SequenceEqual(dek), "unwrap did not return the DEK");
        }
    }

    private static async Task StandardBase64(ConformanceContext ctx, CancellationToken ct)
    {
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        byte[] bytes = [0xFB, 0xEF, 0xBE, 0xFF, 0xFF, 0xFF, 0xFB, 0xFF, 0xFF, 0xFE, 0xFB, 0xEF, 0xBE, 0xFF, 0xFF, 0xFF];
        var standard = Convert.ToBase64String(bytes);
        Expect.That(standard.Contains('+', StringComparison.Ordinal) && standard.Contains('/', StringComparison.Ordinal), "internal: the test value has no '+' and '/'");
        Expect.AnyProxyError(await ctx.Ekm.WrapTextAsync(key.Name, "A256KWP", standard, ct).ConfigureAwait(false), 400, "wrapkey with standard base64 ('+' and '/')");
        Expect.AnyProxyError(await ctx.Ekm.UnwrapTextAsync(key.Name, "A256KWP", standard + standard, ct).ConfigureAwait(false), 400, "unwrapkey with standard base64 ('+' and '/')");
        Expect.AnyProxyError(await ctx.Ekm.WrapTextAsync(key.Name, "A256KWP", "AAAA+AAAAAAAAAAAAAAAAA", ct).ConfigureAwait(false), 400, "wrapkey with a single '+'");
        Expect.AnyProxyError(await ctx.Ekm.WrapTextAsync(key.Name, "A256KWP", "AAAA/AAAAAAAAAAAAAAAAA", ct).ConfigureAwait(false), 400, "wrapkey with a single '/'");
    }

    private static async Task UnpaddedOutput(ConformanceContext ctx, CancellationToken ct)
    {
        var aes = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var rsa = await ctx.RsaKeyAsync(2048, ct).ConfigureAwait(false);
        for (var size = 16; size <= 27; size++)
        {
            var wrapped = await ctx.Ekm.WrapAsync(aes.Name, "A256KWP", ctx.Random(size), ct).ConfigureAwait(false);
            Expect.Value(wrapped, $"A256KWP wrap of {size} bytes"); // throws when padded or not base64url
            var unwrapped = await ctx.Ekm.UnwrapAsync(aes.Name, "A256KWP", Expect.Value(wrapped, "wrap"), ct).ConfigureAwait(false);
            Expect.Value(unwrapped, $"A256KWP unwrap to {size} bytes");
        }

        Expect.Value(await ctx.Ekm.WrapAsync(rsa.Name, "RSA-OAEP-256", ctx.Random(32), ct).ConfigureAwait(false), "RSA-OAEP-256 wrap");
    }

    // ---- 13 ----

    private sealed record PersistedEntry(string Prefix, string Key, string Alg, string Wrapped, string DekSha256);

    private sealed record PersistedState(string Version, string Run, string Namespace, string? OtherNamespace, List<PersistedEntry> Entries);

    private static async Task Persistence(ConformanceContext ctx, CancellationToken ct)
    {
        if (ctx.Options.PersistenceState is not { Length: > 0 } statePath)
        {
            throw new SkipTest("a restart cannot be done from outside: run with --persistence-state <file> before and after restarting the server (phase 1 saves state, phase 2 verifies it)");
        }

        var console = ctx.RequireConsole("to create and later remove the persistence test key and namespace");
        if (!File.Exists(statePath))
        {
            await SavePhaseAsync(ctx, statePath, ct).ConfigureAwait(false);
            throw new SkipTest($"phase 1 of 2 done: key, namespace and a wrapped DEK were saved to '{statePath}'. Restart the server, then run again with the same --persistence-state to verify");
        }

        PersistedState state;
        try
        {
            state = JsonSerializer.Deserialize(File.ReadAllText(statePath), PersistenceJson.Default.PersistedStateModel) is { } model
                ? new PersistedState(model.Version, model.Run, model.Namespace, model.OtherNamespace, [.. model.Entries.Select(static e => new PersistedEntry(e.Prefix, e.Key, e.Alg, e.Wrapped, e.DekSha256))])
                : throw new TestFailure($"the persistence state file '{statePath}' is empty");
        }
        catch (JsonException)
        {
            throw new TestFailure($"the persistence state file '{statePath}' is not a state file of this tool; delete it to start phase 1 again");
        }

        foreach (var entry in state.Entries)
        {
            var reply = await ctx.Ekm.PostAsync(ctx.Ekm.Path(entry.Key, "unwrapkey", prefixOverride: entry.Prefix), entry.Alg, entry.Wrapped, ct).ConfigureAwait(false);
            var dek = Expect.Value(reply, $"unwrap of a DEK wrapped before the restart (key {entry.Key})");
            Expect.That(Convert.ToHexString(SHA256.HashData(dek)) == entry.DekSha256, $"the DEK wrapped before the restart did not come back identical (key {entry.Key})");
        }

        var keys = await console.ListKeysAsync(null, ct).ConfigureAwait(false);
        foreach (var entry in state.Entries)
        {
            Expect.That(keys.Any(k => k.Name == entry.Key && k.State != "Destroyed"), $"key {entry.Key} is no longer listed after the restart");
        }

        if (state.OtherNamespace is { } other)
        {
            Expect.That((await console.ListNamespacesAsync(ct).ConfigureAwait(false)).Any(n => n.Name == other), $"namespace {other} is gone after the restart");
        }

        // Verified: remove what phase 1 created.
        foreach (var entry in state.Entries)
        {
            var ns = keys.First(k => k.Name == entry.Key).Namespace;
            await console.DestroyKeyAsync(ns, entry.Key, entry.Key, ct).ConfigureAwait(false);
            ctx.Destroyed.Add($"key {ns}/{entry.Key}");
        }

        if (state.OtherNamespace is { } otherName)
        {
            await console.DeleteNamespaceAsync(otherName, new(otherName, DestroyKeys: true), ct).ConfigureAwait(false);
            ctx.Destroyed.Add($"namespace {otherName}");
        }

        File.Delete(statePath);
    }

    private static async Task SavePhaseAsync(ConformanceContext ctx, string statePath, CancellationToken ct)
    {
        var console = ctx.Console!;
        var ns = await ctx.TargetNamespaceAsync(ct).ConfigureAwait(false);
        var target = await console.GetNamespaceAsync(ns, ct).ConfigureAwait(false);
        var entries = new List<PersistedEntry>();

        var mainKey = $"conf-persist-{ctx.RunId}";
        await console.CreateKeyAsync(new(ns, mainKey, "aes", 256, false), ct).ConfigureAwait(false);
        entries.Add(await WrapEntryAsync(ctx, ctx.Options.Target.Prefix, mainKey, ct).ConfigureAwait(false));

        var otherName = $"conf-persist-{ctx.RunId}-ns";
        await console.CreateNamespaceAsync(new(otherName, otherName, target.SubjectCommonNames, [.. target.CaCertificates.Select(static c => c.DerBase64)]), ct).ConfigureAwait(false);
        var otherKey = $"conf-persist-{ctx.RunId}-other";
        await console.CreateKeyAsync(new(otherName, otherKey, "aes", 256, false), ct).ConfigureAwait(false);
        entries.Add(await WrapEntryAsync(ctx, otherName, otherKey, ct).ConfigureAwait(false));

        var state = new PersistedStateModel("1", ctx.RunId, ns, otherName, [.. entries.Select(static e => new PersistedEntryModel(e.Prefix, e.Key, e.Alg, e.Wrapped, e.DekSha256))]);
        File.WriteAllText(statePath, JsonSerializer.Serialize(state, PersistenceJson.Default.PersistedStateModel));
    }

    private static async Task<PersistedEntry> WrapEntryAsync(ConformanceContext ctx, string prefix, string key, CancellationToken ct)
    {
        var dek = ctx.Random(32);
        var reply = await ctx.Ekm.PostAsync(ctx.Ekm.Path(key, "wrapkey", prefixOverride: prefix), "A256KWP", EkmClient.Base64Url(dek), ct).ConfigureAwait(false);
        var wrapped = Expect.Value(reply, $"wrap for the persistence test (key {key})");
        return new PersistedEntry(prefix, key, "A256KWP", EkmClient.Base64Url(wrapped), Convert.ToHexString(SHA256.HashData(dek)));
    }
}

/// <summary>The state file of the restart test: where the key and namespace are and a wrapped DEK with the SHA-256 of the DEK (never the DEK itself).</summary>
internal sealed record PersistedEntryModel(string Prefix, string Key, string Alg, string Wrapped, string DekSha256);

internal sealed record PersistedStateModel(string Version, string Run, string Namespace, string? OtherNamespace, List<PersistedEntryModel> Entries);

[System.Text.Json.Serialization.JsonSourceGenerationOptions(PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.SnakeCaseLower, WriteIndented = true)]
[System.Text.Json.Serialization.JsonSerializable(typeof(PersistedStateModel))]
internal sealed partial class PersistenceJson : System.Text.Json.Serialization.JsonSerializerContext
{
}
