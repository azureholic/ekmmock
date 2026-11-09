namespace EkmMock.Crypto.Tests;

/// <summary>Create/enable/expire/destroy/import behaviour and name rules.</summary>
public sealed class KeyLifecycleTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly ManualTimeProvider _time = new(new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero));
    private readonly SoftwareCryptoBackend _backend;

    public KeyLifecycleTests() => _backend = Fx.NewBackend(_dir.Path, time: _time);

    public void Dispose()
    {
        _backend.Dispose();
        foreach (var disposable in _cleanup)
        {
            disposable.Dispose();
        }

        _dir.Dispose();
    }

    private readonly List<IDisposable> _cleanup = [];

    private SoftwareCryptoBackend ImportingBackend()
    {
        var dir = new TempDir();
        var backend = Fx.NewBackend(dir.Path, allowImport: true);
        _cleanup.Add(backend);
        _cleanup.Add(dir);
        return backend;
    }

    private KeyRef NewAes(string ns = "_default")
    {
        var name = Fx.NewName("aes");
        _backend.Create(ns, name, KeyType.Oct, 256);
        return new KeyRef(ns, name);
    }

    [Fact]
    public void Create_ReturnsInfoWithoutSecretsAndWithGeneratedOrigin()
    {
        var info = _backend.Create("_default", "my-key", KeyType.Oct, 256);

        info.Name.ShouldBe("my-key");
        info.Namespace.ShouldBe("_default");
        info.Type.ShouldBe(KeyType.Oct);
        info.Size.ShouldBe(256);
        info.State.ShouldBe(KeyState.Enabled);
        info.Origin.ShouldBe(KeyOrigin.Generated);
        info.CreatedAt.ShouldBe(_time.GetUtcNow());
        info.PublicKey.ShouldBeNull();
        info.NotAfter.ShouldBeNull();
        info.WrapCount.ShouldBe(0);
    }

    [Fact]
    public void Create_Rsa_ExposesOnlyThePublicKey()
    {
        var info = _backend.Create("_default", "rsa-a", KeyType.Rsa, 2048);

        info.PublicKey.ShouldNotBeNull();
        info.PublicKey.KeySizeBits.ShouldBe(2048);
    }

    // ---- name and size rules --------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("has_underscore")]
    [InlineData("has.dot")]
    [InlineData("has space")]
    [InlineData("trailing-newline\n")]
    [InlineData("slash/inside")]
    [InlineData("ünïcode")]
    public void Create_WithInvalidKeyName_IsInvalidKeyName(string name)
        => Fx.Fails(() => _backend.Create("_default", name, KeyType.Oct, 256)).Kind.ShouldBe(EkmErrorKind.InvalidKeyName);

    [Fact]
    public void Create_KeyNameOf65Characters_IsInvalidAnd64IsAccepted()
    {
        Fx.Fails(() => _backend.Create("_default", new string('a', 65), KeyType.Oct, 256)).Kind.ShouldBe(EkmErrorKind.InvalidKeyName);

        _backend.Create("_default", new string('a', 64), KeyType.Oct, 256).Name.Length.ShouldBe(64);
    }

    [Theory]
    [InlineData(KeyType.Oct, 128)]
    [InlineData(KeyType.Oct, 512)]
    [InlineData(KeyType.Rsa, 1024)]
    [InlineData(KeyType.Rsa, 0)]
    public void Create_WithUnsupportedSize_IsInvalidInput(KeyType type, int size)
        => Fx.Fails(() => _backend.Create("_default", Fx.NewName(), type, size)).Kind.ShouldBe(EkmErrorKind.InvalidInput);

    [Theory]
    [InlineData("")]
    [InlineData("has:colon")]
    [InlineData("has space")]
    public void Create_WithInvalidNamespace_IsInvalidInput(string ns)
        => Fx.Fails(() => _backend.Create(ns, "k", KeyType.Oct, 256)).Kind.ShouldBe(EkmErrorKind.InvalidInput);

    [Fact]
    public void Create_Twice_IsKeyAlreadyExists()
    {
        var key = NewAes();

        Fx.Fails(() => _backend.Create(key.Namespace, key.Name, KeyType.Oct, 256)).Kind.ShouldBe(EkmErrorKind.KeyAlreadyExists);
    }

    // ---- namespaces -------------------------------------------------------------------------------------------------------

    [Fact]
    public void SameKeyNameInTwoNamespaces_AreIndependentKeys()
    {
        _backend.Create("ns-one", "shared", KeyType.Oct, 256);
        _backend.Create("ns-two", "shared", KeyType.Oct, 256);
        var one = new KeyRef("ns-one", "shared");
        var two = new KeyRef("ns-two", "shared");
        var wrapped = _backend.Wrap(one, WrapAlgorithm.A256KWP, Fx.Random(32));

        Fx.Fails(() => _backend.Unwrap(two, WrapAlgorithm.A256KWP, wrapped)).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext);

        _backend.SetEnabled(one, false);
        Fx.Fails(() => _backend.Wrap(one, WrapAlgorithm.A256KWP, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.KeyDisabled);
        _backend.Wrap(two, WrapAlgorithm.A256KWP, Fx.Random(32)).ShouldNotBeEmpty();

        _backend.Destroy(one);
        _backend.GetMetadata(two).ShouldNotBeNull();
        _backend.GetMetadata(one).ShouldBeNull();
    }

    [Fact]
    public void List_FiltersByNamespaceAndIsSorted()
    {
        _backend.Create("ns-b", "zz", KeyType.Oct, 256);
        _backend.Create("ns-b", "aa", KeyType.Oct, 256);
        _backend.Create("ns-a", "mm", KeyType.Oct, 256);

        _backend.List("ns-b").Select(k => k.Name).ShouldBe(["aa", "zz"]);
        _backend.List().Select(k => $"{k.Namespace}/{k.Name}").ShouldBe(["ns-a/mm", "ns-b/aa", "ns-b/zz"]);
        _backend.List("nothing").ShouldBeEmpty();
    }

    // ---- enable / disable ------------------------------------------------------------------------------------------------

    [Fact]
    public void DisabledKey_RejectsWrapAndUnwrapWithKeyDisabled_ButMetadataStillWorks()
    {
        var key = NewAes();
        var wrapped = _backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32));

        _backend.SetEnabled(key, false);

        Fx.Fails(() => _backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.KeyDisabled);
        Fx.Fails(() => _backend.Unwrap(key, WrapAlgorithm.A256KWP, wrapped)).Kind.ShouldBe(EkmErrorKind.KeyDisabled);
        var metadata = _backend.GetMetadata(key);
        metadata.ShouldNotBeNull();
        metadata.State.ShouldBe(KeyState.Disabled);

        _backend.SetEnabled(key, true);
        _backend.Unwrap(key, WrapAlgorithm.A256KWP, wrapped).Length.ShouldBe(32);
    }

    [Fact]
    public void DisabledKeyMessage_MatchesTheSpecExample()
    {
        var key = NewAes();
        _backend.SetEnabled(key, false);

        Fx.Fails(() => _backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32)))
            .Message.ShouldBe("Operation WrapKey is not allowed on a disabled key");
    }

    [Fact]
    public void SetEnabled_OnMissingKey_IsKeyNotFound()
        => Fx.Fails(() => _backend.SetEnabled(new KeyRef("_default", "nope"), false)).Kind.ShouldBe(EkmErrorKind.KeyNotFound);

    // ---- expiry ----------------------------------------------------------------------------------------------------------

    [Fact]
    public void ExpiredKey_RejectsWrapAndUnwrapWithKeyExpired_ButMetadataStillWorks()
    {
        var key = NewAes();
        var wrapped = _backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32));
        _backend.SetExpiry(key, _time.GetUtcNow().AddHours(1));
        _backend.Unwrap(key, WrapAlgorithm.A256KWP, wrapped).Length.ShouldBe(32);

        _time.Advance(TimeSpan.FromHours(1));

        Fx.Fails(() => _backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.KeyExpired);
        Fx.Fails(() => _backend.Unwrap(key, WrapAlgorithm.A256KWP, wrapped)).Kind.ShouldBe(EkmErrorKind.KeyExpired);
        _backend.GetMetadata(key)!.State.ShouldBe(KeyState.Expired);
        _backend.Get(key)!.State.ShouldBe(KeyState.Expired);

        _backend.SetExpiry(key, null);
        _backend.Unwrap(key, WrapAlgorithm.A256KWP, wrapped).Length.ShouldBe(32);
    }

    [Fact]
    public void Expiry_JustBeforeTheInstant_StillWorks()
    {
        var key = NewAes();
        _backend.SetExpiry(key, _time.GetUtcNow().AddSeconds(10));
        _time.Advance(TimeSpan.FromSeconds(9));

        _backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32)).ShouldNotBeEmpty();
    }

    [Fact]
    public void DisabledTakesPrecedenceInStateOverExpired()
    {
        var key = NewAes();
        _backend.SetExpiry(key, _time.GetUtcNow().AddSeconds(-1));
        _backend.SetEnabled(key, false);

        _backend.Get(key)!.State.ShouldBe(KeyState.Disabled);
    }

    // ---- destroy ---------------------------------------------------------------------------------------------------------

    [Fact]
    public void DestroyedKey_IsKeyNotFoundEverywhere_AndLeavesATombstone()
    {
        var key = NewAes();
        var wrapped = _backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32));

        _backend.Destroy(key, "alice");

        Fx.Fails(() => _backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.KeyNotFound);
        Fx.Fails(() => _backend.Unwrap(key, WrapAlgorithm.A256KWP, wrapped)).Kind.ShouldBe(EkmErrorKind.KeyNotFound);
        _backend.GetMetadata(key).ShouldBeNull();
        var tombstone = _backend.List(key.Namespace).Single(k => k.Name == key.Name);
        tombstone.State.ShouldBe(KeyState.Destroyed);
        tombstone.DestroyedBy.ShouldBe("alice");
        tombstone.DestroyedAt.ShouldBe(_time.GetUtcNow());
        tombstone.PublicKey.ShouldBeNull();
        Fx.Fails(() => _backend.Destroy(key)).Kind.ShouldBe(EkmErrorKind.KeyNotFound);
    }

    [Fact]
    public void DestroyedName_CannotBeReusedByAccident_OnlyWithExplicitOverride()
    {
        var key = NewAes();
        var wrapped = _backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32));
        _backend.Destroy(key);

        Fx.Fails(() => _backend.Create(key.Namespace, key.Name, KeyType.Oct, 256)).Kind.ShouldBe(EkmErrorKind.KeyNameReserved);
        Fx.Fails(() => _backend.Create(key.Namespace, key.Name, KeyType.Oct, 256, allowReuseOfDestroyedName: false)).Kind.ShouldBe(EkmErrorKind.KeyNameReserved);

        _backend.Create(key.Namespace, key.Name, KeyType.Oct, 256, allowReuseOfDestroyedName: true).State.ShouldBe(KeyState.Enabled);
        // The new key is a different key: the old wrapped DEK is gone for good (crypto-shred).
        Fx.Fails(() => _backend.Unwrap(key, WrapAlgorithm.A256KWP, wrapped)).Kind.ShouldBe(EkmErrorKind.InvalidCiphertext);
        _backend.List(key.Namespace).Count(k => k.Name == key.Name).ShouldBe(1);
    }

    // ---- import gating ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Import_IsOffByDefault()
    {
        var ex = Fx.Fails(() => _backend.Import("_default", "imp", KeyType.Oct, Fx.Random(32)));

        ex.Kind.ShouldBe(EkmErrorKind.OperationNotAllowed);
        _backend.Get(new KeyRef("_default", "imp")).ShouldBeNull();
    }

    [Fact]
    public void Import_WhenEnabled_CreatesAKeyWithImportedOrigin()
    {
        var allowing = ImportingBackend();

        var info = allowing.Import("_default", "imp", KeyType.Oct, Fx.Random(32));

        info.Origin.ShouldBe(KeyOrigin.Imported);
        allowing.Wrap(new KeyRef("_default", "imp"), WrapAlgorithm.A256KWP, Fx.Random(32)).ShouldNotBeEmpty();
    }

    [Theory]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    public void Import_OfAnAesKeyThatIsNot32Bytes_IsInvalidInput(int length)
    {
        var allowing = ImportingBackend();
        var material = Fx.Random(length);

        Fx.Fails(() => allowing.Import("_default", "imp", KeyType.Oct, material)).Kind.ShouldBe(EkmErrorKind.InvalidInput);
    }

    [Fact]
    public void Import_OfInvalidRsaOrWeakRsa_IsInvalidInput()
    {
        var allowing = ImportingBackend();
        using var weak = System.Security.Cryptography.RSA.Create(1024);
        var garbage = Fx.Random(64);
        var weakPkcs8 = weak.ExportPkcs8PrivateKey();

        Fx.Fails(() => allowing.Import("_default", "imp1", KeyType.Rsa, garbage)).Kind.ShouldBe(EkmErrorKind.InvalidInput);
        Fx.Fails(() => allowing.Import("_default", "imp2", KeyType.Rsa, weakPkcs8)).Kind.ShouldBe(EkmErrorKind.InvalidInput);
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("TRUE", true)]
    [InlineData("false", false)]
    [InlineData("1", false)]
    [InlineData(null, false)]
    public void ImportEnvironmentSwitch_IsReadThroughAnInjectedReader(string? value, bool expected)
        => SoftwareCryptoBackendOptions.IsKeyImportEnabledInEnvironment(name => name == "EKMMOCK_ALLOW_KEY_IMPORT" ? value : null).ShouldBe(expected);

    // ---- disposal / availability -----------------------------------------------------------------------------------------

    [Fact]
    public void DisposedEngine_IsNotAvailableAndReportsHsmUnavailable()
    {
        var key = NewAes();
        _backend.IsAvailable.ShouldBeTrue();

        _backend.Dispose();

        _backend.IsAvailable.ShouldBeFalse();
        Fx.Fails(() => _backend.Wrap(key, WrapAlgorithm.A256KWP, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.HsmUnavailable);
        Fx.Fails(() => _backend.GetMetadata(key)).Kind.ShouldBe(EkmErrorKind.HsmUnavailable);
    }

    [Fact]
    public void Info_ReportsConfiguredVendorAndProduct()
        => _backend.Info.ShouldBe(new BackendInfo("EkmMock", "EkmMock Software HSM"));
}
