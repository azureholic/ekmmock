using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace EkmMock.Crypto.Tests;

public sealed class KeyStoreTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string StorePath => _dir.File("keystore.json");

    private SoftwareCryptoBackend Open(string master = "default", bool allowImport = false, TimeProvider? time = null)
        => Fx.NewBackend(_dir.Path, master, allowImport, time);

    private JsonNode ReadStore() => JsonNode.Parse(File.ReadAllText(StorePath))!;

    private void WriteStore(JsonNode node) => File.WriteAllText(StorePath, node.ToJsonString());

    private static JsonObject FindKey(JsonNode store, string name)
        => store["keys"]!.AsArray().Select(k => k!.AsObject()).Single(k => (string?)k["name"] == name);

    // ---- persistence across restart (acceptance test 13) ---------------------------------------------------------------

    [Fact]
    public void KeysAndWrappedDeks_SurviveARestart_ForEveryAlgorithm()
    {
        var aes = new KeyRef("_default", "aes-1");
        var rsa = new KeyRef("_default", "rsa-1");
        var dek = Fx.Random(32);
        byte[] kw, kwp, oaep256, oaepSha1;
        using (var first = Open())
        {
            first.Create(aes.Namespace, aes.Name, KeyType.Oct, 256);
            first.Create(rsa.Namespace, rsa.Name, KeyType.Rsa, 2048);
            kw = first.Wrap(aes, WrapAlgorithm.A256KW, dek);
            kwp = first.Wrap(aes, WrapAlgorithm.A256KWP, dek);
            oaep256 = first.Wrap(rsa, WrapAlgorithm.RsaOaep256, dek);
            oaepSha1 = first.Wrap(rsa, WrapAlgorithm.RsaOaep, dek);
        }

        using var second = Open();

        second.LoadReport.ShouldBe(new KeyStoreLoadReport(2, 0, 0, 0));
        Fx.Same(second.Unwrap(aes, WrapAlgorithm.A256KW, kw), dek).ShouldBeTrue();
        Fx.Same(second.Unwrap(aes, WrapAlgorithm.A256KWP, kwp), dek).ShouldBeTrue();
        Fx.Same(second.Unwrap(rsa, WrapAlgorithm.RsaOaep256, oaep256), dek).ShouldBeTrue();
        Fx.Same(second.Unwrap(rsa, WrapAlgorithm.RsaOaep, oaepSha1), dek).ShouldBeTrue();
    }

    [Fact]
    public void RsaPublicKey_IsIdenticalAfterRestart()
    {
        var rsa = new KeyRef("_default", "rsa-1");
        byte[] modulus;
        using (var first = Open())
        {
            first.Create(rsa.Namespace, rsa.Name, KeyType.Rsa, 2048);
            modulus = first.GetMetadata(rsa)!.PublicKey!.Modulus.ToArray();
        }

        using var second = Open();

        second.GetMetadata(rsa)!.PublicKey!.Modulus.ToArray().ShouldBe(modulus);
    }

    [Fact]
    public void CountersFlagsExpiryAndOrigin_SurviveARestart()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero));
        var expiry = time.GetUtcNow().AddDays(30);
        var key = new KeyRef("_default", "k1");
        var imported = new KeyRef("_default", "imp");
        using (var first = Open(allowImport: true, time: time))
        {
            first.Create(key.Namespace, key.Name, KeyType.Oct, 256);
            first.Import(imported.Namespace, imported.Name, KeyType.Oct, Fx.Random(32));
            var wrapped = first.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32));
            first.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32));
            first.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32));
            first.Unwrap(key, WrapAlgorithm.A256KWP, wrapped);
            first.SetExpiry(key, expiry);
            first.SetEnabled(imported, false);
        }

        using var second = Open(time: time);

        var info = second.Get(key)!;
        info.WrapCount.ShouldBe(3);
        info.UnwrapCount.ShouldBe(1);
        info.LastUsedAt.ShouldBe(time.GetUtcNow());
        info.NotAfter.ShouldBe(expiry);
        info.CreatedAt.ShouldBe(time.GetUtcNow());
        second.Get(imported)!.State.ShouldBe(KeyState.Disabled);
        second.Get(imported)!.Origin.ShouldBe(KeyOrigin.Imported);
    }

    [Fact]
    public void UsageCounters_AreNotWrittenOnTheHotPath_OnlyOnFlush()
    {
        var key = new KeyRef("_default", "k1");
        using var backend = Open();
        backend.Create(key.Namespace, key.Name, KeyType.Oct, 256);
        var before = File.ReadAllText(StorePath);

        for (var i = 0; i < 25; i++)
        {
            backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32));
        }

        File.ReadAllText(StorePath).ShouldBe(before);
        backend.Flush();
        ReadStore()["keys"]![0]!["wrap_count"]!.GetValue<long>().ShouldBe(25);
    }

    [Fact]
    public void UsageCounters_AreFlushedLazilyByTheTimer()
    {
        var key = new KeyRef("_default", "k1");
        using var backend = new SoftwareCryptoBackend(new SoftwareCryptoBackendOptions
        {
            DataPath = _dir.Path,
            MasterKeyProvider = new ExplicitMasterKeyProvider(Fx.MasterKeyBytes()),
            CounterFlushInterval = TimeSpan.FromMilliseconds(50),
        });
        backend.Create(key.Namespace, key.Name, KeyType.Oct, 256);
        backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32));

        var deadline = DateTime.UtcNow.AddSeconds(10);
        long persisted = 0;
        while (DateTime.UtcNow < deadline && persisted == 0)
        {
            Thread.Sleep(50);
            persisted = ReadStore()["keys"]![0]!["wrap_count"]!.GetValue<long>();
        }

        persisted.ShouldBe(1);
    }

    [Fact]
    public void DestroyedKey_StaysDestroyedAfterRestart_AndItsNameStaysReserved()
    {
        var key = new KeyRef("_default", "gone");
        using (var first = Open())
        {
            first.Create(key.Namespace, key.Name, KeyType.Oct, 256);
            first.Destroy(key, "bob");
        }

        using var second = Open();

        second.LoadReport.Tombstones.ShouldBe(1);
        Fx.Fails(() => second.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.KeyNotFound);
        Fx.Fails(() => second.Create(key.Namespace, key.Name, KeyType.Oct, 256)).Kind.ShouldBe(EkmErrorKind.KeyNameReserved);
        var info = second.List().Single();
        info.State.ShouldBe(KeyState.Destroyed);
        info.DestroyedBy.ShouldBe("bob");
    }

    [Fact]
    public void Destroy_RemovesTheEncryptedBlobFromTheFile()
    {
        var key = new KeyRef("_default", "gone");
        using var backend = Open();
        backend.Create(key.Namespace, key.Name, KeyType.Oct, 256);
        var ciphertext = (string)FindKey(ReadStore(), key.Name)["ciphertext"]!;
        ciphertext.Length.ShouldBeGreaterThan(0);

        backend.Destroy(key);

        var store = ReadStore();
        store["keys"]!.AsArray().ShouldBeEmpty();
        File.ReadAllText(StorePath).ShouldNotContain("\"ciphertext\"");
        File.ReadAllText(StorePath).ShouldContain("\"destroyed_at\"");
        store["tombstones"]![0]!["destroyed_by"]!.GetValue<string>().ShouldBe("unknown");
    }

    // ---- at-rest protection --------------------------------------------------------------------------------------------

    [Fact]
    public void KeystoreFile_ContainsNoRawKeyBytes_InAnyEncoding()
    {
        using var rsaToImport = RSA.Create(2048);
        var parameters = rsaToImport.ExportParameters(includePrivateParameters: true);
        var knownAes = Fx.Random(32);
        using var backend = Open(allowImport: true);
        backend.Create("_default", "generated-aes", KeyType.Oct, 256);
        backend.Create("_default", "generated-rsa", KeyType.Rsa, 2048);
        backend.Import("_default", "imported-aes", KeyType.Oct, knownAes);
        backend.Import("_default", "imported-rsa", KeyType.Rsa, rsaToImport.ExportPkcs8PrivateKey());
        backend.Flush();
        var json = File.ReadAllText(StorePath);
        var secrets = new Dictionary<string, byte[]>
        {
            ["imported aes key"] = knownAes,
            ["imported rsa D"] = parameters.D!,
            ["imported rsa P"] = parameters.P!,
            ["imported rsa Q"] = parameters.Q!,
            ["imported rsa DP"] = parameters.DP!,
            ["imported rsa DQ"] = parameters.DQ!,
            ["imported rsa InverseQ"] = parameters.InverseQ!,
            ["generated aes key"] = backend.CopySecretForTests(new KeyRef("_default", "generated-aes"))!,
            ["generated rsa pkcs8"] = backend.CopySecretForTests(new KeyRef("_default", "generated-rsa"))!,
            ["master key"] = Fx.MasterKeyBytes(),
        };

        foreach (var (label, secret) in secrets)
        {
            SecretScanner.LeaksInJsonFile(json, secret).ShouldBeFalse($"{label} found in keystore.json");
        }
    }

    [Fact]
    public void ScannerSelfCheck_DetectsASecretInEveryEncoding()
    {
        var secret = Fx.Random(32);

        SecretScanner.LeaksInText($"x{Convert.ToBase64String(secret)}y", secret).ShouldBeTrue();
        SecretScanner.LeaksInText(System.Buffers.Text.Base64Url.EncodeToString(secret), secret).ShouldBeTrue();
        SecretScanner.LeaksInText(Convert.ToHexString(secret), secret).ShouldBeTrue();
        SecretScanner.LeaksInText(Convert.ToHexStringLower(secret), secret).ShouldBeTrue();
        SecretScanner.LeaksInText("{\"v\":\"" + Convert.ToBase64String([1, 2, .. secret]) + "\"}", secret).ShouldBeTrue();
        SecretScanner.LeaksInText("{\"v\":\"" + Convert.ToBase64String([1, .. secret]) + "\"}", secret).ShouldBeTrue();
        SecretScanner.LeaksInJsonFile("{\"v\":\"" + Convert.ToBase64String([9, 9, 9, .. secret, 7]) + "\"}", secret).ShouldBeTrue();
        SecretScanner.LeaksInText("nothing to see", secret).ShouldBeFalse();
    }

    [Fact]
    public void BlobFormat_IsAes256GcmWithTwelveByteNonceAndSixteenByteTag_AndBindsTheIdentityAsAad()
    {
        var key = new KeyRef("my-ns", "my-key");
        byte[] secret;
        using (var backend = Open())
        {
            backend.Create(key.Namespace, key.Name, KeyType.Oct, 256);
            secret = backend.CopySecretForTests(key)!;
        }

        var node = FindKey(ReadStore(), key.Name);
        var nonce = Convert.FromBase64String((string)node["nonce"]!);
        var ciphertext = Convert.FromBase64String((string)node["ciphertext"]!);
        var tag = Convert.FromBase64String((string)node["tag"]!);
        nonce.Length.ShouldBe(12);
        tag.Length.ShouldBe(16);
        ciphertext.Length.ShouldBe(32);

        // Decrypt independently, exactly as the spec's AAD string prescribes.
        var plaintext = new byte[32];
        using (var gcm = new AesGcm(Fx.MasterKeyBytes(), 16))
        {
            gcm.Decrypt(nonce, ciphertext, tag, plaintext, System.Text.Encoding.UTF8.GetBytes("ekmmock:v1:my-ns:my-key:oct:256"));
        }

        Fx.Same(plaintext, secret).ShouldBeTrue();
        using var wrongAad = new AesGcm(Fx.MasterKeyBytes(), 16);
        Should.Throw<CryptographicException>(() =>
            wrongAad.Decrypt(nonce, ciphertext, tag, new byte[32], System.Text.Encoding.UTF8.GetBytes("ekmmock:v1:my-ns:other:oct:256")));
    }

    [Fact]
    public void EveryBlobGetsAFreshRandomNonce()
    {
        using var backend = Open();
        for (var i = 0; i < 20; i++)
        {
            backend.Create("_default", $"k{i}", KeyType.Oct, 256);
        }

        var nonces = ReadStore()["keys"]!.AsArray().Select(k => (string)k!["nonce"]!).ToList();

        nonces.Distinct().Count().ShouldBe(20);
    }

    // ---- tamper / wrong master key (acceptance test 19) ------------------------------------------------------------------

    [Fact]
    public void FlippingOneByteOfOneBlob_MarksOnlyThatKeyCorrupt_AndOthersStillLoad()
    {
        var victim = new KeyRef("_default", "victim");
        var healthy = new KeyRef("_default", "healthy");
        byte[] wrappedByHealthy;
        using (var first = Open())
        {
            first.Create(victim.Namespace, victim.Name, KeyType.Oct, 256);
            first.Create(healthy.Namespace, healthy.Name, KeyType.Oct, 256);
            wrappedByHealthy = first.Wrap(healthy, WrapAlgorithm.A256KWP, Fx.Random(32));
        }

        var store = ReadStore();
        var blob = Convert.FromBase64String((string)FindKey(store, victim.Name)["ciphertext"]!);
        blob[7] ^= 0x01;
        FindKey(store, victim.Name)["ciphertext"] = Convert.ToBase64String(blob);
        WriteStore(store);

        using var second = Open();

        second.LoadReport.ShouldBe(new KeyStoreLoadReport(2, 1, 0, 0));
        second.Get(victim)!.State.ShouldBe(KeyState.Corrupt);
        second.Get(healthy)!.State.ShouldBe(KeyState.Enabled);
        Fx.Fails(() => second.Wrap(victim, WrapAlgorithm.A256KWP, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.HsmUnavailable);
        Fx.Fails(() => second.Unwrap(victim, WrapAlgorithm.A256KWP, Fx.Random(48))).Kind.ShouldBe(EkmErrorKind.HsmUnavailable);
        Fx.Fails(() => second.GetMetadata(victim)).Kind.ShouldBe(EkmErrorKind.HsmUnavailable);
        second.Unwrap(healthy, WrapAlgorithm.A256KWP, wrappedByHealthy).Length.ShouldBe(32);
    }

    [Theory]
    [InlineData("tag")]
    [InlineData("nonce")]
    public void FlippingTheTagOrNonce_MarksTheKeyCorrupt(string field)
    {
        var key = new KeyRef("_default", "victim");
        using (var first = Open())
        {
            first.Create(key.Namespace, key.Name, KeyType.Oct, 256);
        }

        var store = ReadStore();
        var bytes = Convert.FromBase64String((string)FindKey(store, key.Name)[field]!);
        bytes[0] ^= 0x80;
        FindKey(store, key.Name)[field] = Convert.ToBase64String(bytes);
        WriteStore(store);

        using var second = Open();

        second.Get(key)!.State.ShouldBe(KeyState.Corrupt);
    }

    [Fact]
    public void BlobEncodingGarbage_MarksTheKeyCorruptInsteadOfFailingTheLoad()
    {
        var key = new KeyRef("_default", "victim");
        using (var first = Open())
        {
            first.Create(key.Namespace, key.Name, KeyType.Oct, 256);
            first.Create("_default", "other", KeyType.Oct, 256);
        }

        var store = ReadStore();
        FindKey(store, key.Name)["ciphertext"] = "%%% not base64 %%%";
        WriteStore(store);

        using var second = Open();

        second.Get(key)!.State.ShouldBe(KeyState.Corrupt);
        second.Get(new KeyRef("_default", "other"))!.State.ShouldBe(KeyState.Enabled);
    }

    [Fact]
    public void ChangingBoundMetadata_NameTypeOrSize_BreaksTheAadAndMarksTheKeyCorrupt()
    {
        using (var first = Open())
        {
            first.Create("_default", "a-key", KeyType.Oct, 256);
            first.Create("_default", "b-key", KeyType.Oct, 256);
            first.Create("_default", "c-key", KeyType.Oct, 256);
        }

        var store = ReadStore();
        FindKey(store, "a-key")["name"] = "renamed";           // identity swap
        FindKey(store, "b-key")["namespace"] = "other-ns";     // moved to another namespace
        FindKey(store, "c-key")["size"] = 512;                 // size lie
        WriteStore(store);

        using var second = Open();

        second.Get(new KeyRef("_default", "renamed"))!.State.ShouldBe(KeyState.Corrupt);
        second.Get(new KeyRef("other-ns", "b-key"))!.State.ShouldBe(KeyState.Corrupt);
        second.Get(new KeyRef("_default", "c-key"))!.State.ShouldBe(KeyState.Corrupt);
    }

    [Fact]
    public void WrongMasterKey_MarksEveryKeyCorrupt_ButTheLoaderSucceeds()
    {
        using (var first = Open("right"))
        {
            first.Create("_default", "a", KeyType.Oct, 256);
            first.Create("_default", "b", KeyType.Rsa, 2048);
            first.Create("ns-2", "c", KeyType.Oct, 256);
        }

        using var second = Open("wrong");

        second.IsAvailable.ShouldBeTrue();
        second.LoadReport.ShouldBe(new KeyStoreLoadReport(3, 3, 0, 0));
        second.List().ShouldAllBe(k => k.State == KeyState.Corrupt);
        Fx.Fails(() => second.Wrap(new KeyRef("_default", "a"), WrapAlgorithm.A256KWP, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.HsmUnavailable);
        Fx.Fails(() => second.Unwrap(new KeyRef("_default", "b"), WrapAlgorithm.RsaOaep256, Fx.Random(256))).Kind.ShouldBe(EkmErrorKind.HsmUnavailable);
    }

    [Fact]
    public void WrongMasterKey_RefusesToAddKeys_SoTheFileNeverMixesTwoMasterKeys()
    {
        using (var first = Open("right"))
        {
            first.Create("_default", "a", KeyType.Oct, 256);
        }

        using (var second = Open("wrong"))
        {
            Fx.Fails(() => second.Create("_default", "new", KeyType.Oct, 256)).Kind.ShouldBe(EkmErrorKind.HsmUnavailable);
        }

        // Restoring the right master key brings the original key back untouched.
        using var third = Open("right");
        third.Get(new KeyRef("_default", "a"))!.State.ShouldBe(KeyState.Enabled);
        third.Get(new KeyRef("_default", "new")).ShouldBeNull();
    }

    [Fact]
    public void CorruptBlob_IsPreservedByteForByteWhenTheFileIsRewritten()
    {
        using (var first = Open())
        {
            first.Create("_default", "victim", KeyType.Oct, 256);
            first.Create("_default", "other", KeyType.Oct, 256);
        }

        var store = ReadStore();
        var blob = Convert.FromBase64String((string)FindKey(store, "victim")["ciphertext"]!);
        blob[0] ^= 0xFF;
        var tamperedBase64 = Convert.ToBase64String(blob);
        FindKey(store, "victim")["ciphertext"] = tamperedBase64;
        WriteStore(store);

        using (var second = Open())
        {
            second.SetEnabled(new KeyRef("_default", "other"), false);
            second.Create("_default", "added", KeyType.Oct, 256);
        }

        ((string)FindKey(ReadStore(), "victim")["ciphertext"]!).ShouldBe(tamperedBase64);
    }

    [Fact]
    public void CorruptKey_CanStillBeDisabledAndDestroyed()
    {
        var key = new KeyRef("_default", "victim");
        using (var first = Open())
        {
            first.Create(key.Namespace, key.Name, KeyType.Oct, 256);
            first.Create("_default", "other", KeyType.Oct, 256);
        }

        using var second = Open("wrong");

        second.SetEnabled(key, false);
        second.Destroy(key, "cleanup");
        second.Get(key)!.State.ShouldBe(KeyState.Destroyed);
    }

    [Fact]
    public void UnaddressableEntries_AreCountedAndPreservedInTheFile()
    {
        using (var first = Open())
        {
            first.Create("_default", "ok", KeyType.Oct, 256);
            first.Create("_default", "weird", KeyType.Oct, 256);
        }

        var store = ReadStore();
        FindKey(store, "weird")["type"] = "bogus";
        WriteStore(store);

        using (var second = Open())
        {
            second.LoadReport.ShouldBe(new KeyStoreLoadReport(1, 0, 1, 0));
            second.SetEnabled(new KeyRef("_default", "ok"), false);
        }

        ((string)FindKey(ReadStore(), "weird")["type"]!).ShouldBe("bogus");
    }

    // ---- file handling ------------------------------------------------------------------------------------------------

    [Fact]
    public void AtomicWrites_LeaveNoTempFilesBehind_AndTheFileIsAlwaysValidJson()
    {
        using var backend = Open();

        for (var i = 0; i < 10; i++)
        {
            backend.Create("_default", $"k{i}", KeyType.Oct, 256);
            backend.SetEnabled(new KeyRef("_default", $"k{i}"), i % 2 == 0);
        }

        Directory.GetFiles(_dir.Path).Select(Path.GetFileName).ShouldBe(["keystore.json"]);
        Should.NotThrow(() => JsonDocument.Parse(File.ReadAllText(StorePath)));
    }

    [Fact]
    public void ConcurrentMutations_AreSerialisedAndAllEndUpInTheFile()
    {
        using var backend = Open();

        Parallel.For(0, 24, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i => backend.Create("_default", $"key-{i}", KeyType.Oct, 256));

        ReadStore()["keys"]!.AsArray().Count.ShouldBe(24);
        Directory.GetFiles(_dir.Path).Length.ShouldBe(1);
        using var reopened = Open();
        reopened.LoadReport.Keys.ShouldBe(24);
    }

    [Fact]
    public void StaleTempFilesFromACrash_AreRemovedAtStartup()
    {
        var stale = StorePath + ".0123456789abcdef.tmp";
        File.WriteAllText(stale, "half-written");

        using var backend = Open();

        File.Exists(stale).ShouldBeFalse();
    }

    [Fact]
    public void FreshDataFolder_IsCreatedAndNoFileIsWrittenUntilTheFirstChange()
    {
        var nested = Path.Combine(_dir.Path, "a", "b");

        using var backend = Fx.NewBackend(nested);

        Directory.Exists(nested).ShouldBeTrue();
        File.Exists(Path.Combine(nested, "keystore.json")).ShouldBeFalse();
        backend.LoadReport.ShouldBe(new KeyStoreLoadReport(0, 0, 0, 0));
    }

    [Fact]
    public void UnparsableKeystore_RefusesToStartAndIsNotOverwritten()
    {
        File.WriteAllText(StorePath, "{ this is not json");

        Should.Throw<InvalidDataException>(() => Open());

        File.ReadAllText(StorePath).ShouldBe("{ this is not json");
    }

    [Fact]
    public void UnknownFormatVersion_RefusesToStart()
    {
        File.WriteAllText(StorePath, """{ "version": 99, "keys": [], "tombstones": [] }""");

        Should.Throw<InvalidDataException>(() => Open());
    }

    [Fact]
    public void JsonUsesSnakeCaseAndStringEnums()
    {
        using (var backend = Open())
        {
            backend.Create("_default", "k", KeyType.Oct, 256);
        }

        var node = FindKey(ReadStore(), "k");

        node["type"]!.GetValue<string>().ShouldBe("oct");
        node["origin"]!.GetValue<string>().ShouldBe("generated");
        node.ContainsKey("created_at").ShouldBeTrue();
        node.ContainsKey("wrap_count").ShouldBeTrue();
        node.ContainsKey("last_used_at").ShouldBeFalse(); // never used: omitted, not null
    }

    // ---- master key ----------------------------------------------------------------------------------------------------

    [Fact]
    public void MissingMasterKey_RefusesToStartAndWritesNothing()
    {
        var provider = new EnvironmentMasterKeyProvider(_ => null);

        Should.Throw<MasterKeyUnavailableException>(() => new SoftwareCryptoBackend(new SoftwareCryptoBackendOptions
        {
            DataPath = _dir.Path,
            MasterKeyProvider = provider,
        }));

        Directory.GetFiles(_dir.Path).ShouldBeEmpty();
    }

    [Fact]
    public void DevThrowAwayMasterKey_IsFlagged_AndItsKeysAreUnreadableAfterRestart()
    {
        var key = new KeyRef("_default", "dev-key");
        using (var first = new SoftwareCryptoBackend(new SoftwareCryptoBackendOptions
        {
            DataPath = _dir.Path,
            MasterKeyProvider = new ThrowAwayMasterKeyProvider(),
            CounterFlushInterval = TimeSpan.Zero,
        }))
        {
            first.IsMasterKeyThrowAway.ShouldBeTrue();
            first.MasterKeySource.ShouldBe("dev-throwaway");
            first.Create(key.Namespace, key.Name, KeyType.Oct, 256);
        }

        using var second = new SoftwareCryptoBackend(new SoftwareCryptoBackendOptions
        {
            DataPath = _dir.Path,
            MasterKeyProvider = new ThrowAwayMasterKeyProvider(),
            CounterFlushInterval = TimeSpan.Zero,
        });

        second.Get(key)!.State.ShouldBe(KeyState.Corrupt);
    }

    [Fact]
    public void ExplicitMasterKey_IsNotFlaggedAsThrowAway()
    {
        using var backend = Open();

        backend.IsMasterKeyThrowAway.ShouldBeFalse();
        backend.MasterKeySource.ShouldBe("explicit");
    }
}
