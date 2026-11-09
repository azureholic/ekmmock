using System.Security.Cryptography;

namespace EkmMock.Crypto.Tests;

public sealed class MasterKeyProviderTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static Func<string, string?> Env(params (string Name, string? Value)[] values)
        => name => values.FirstOrDefault(v => v.Name == name).Value;

    private static string NewBase64() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    [Fact]
    public void Environment_MissingKey_Refuses()
    {
        var ex = Should.Throw<MasterKeyUnavailableException>(() => new EnvironmentMasterKeyProvider(Env()).GetMasterKey());

        ex.Message.ShouldContain("EKMMOCK_MASTER_KEY");
    }

    [Fact]
    public void Environment_Base64Key_IsLoaded_NotFlaggedThrowAway_AndNeverEchoed()
    {
        var b64 = NewBase64();

        using var key = new EnvironmentMasterKeyProvider(Env(("EKMMOCK_MASTER_KEY", b64))).GetMasterKey();

        key.IsThrowAway.ShouldBeFalse();
        key.Source.ShouldBe("environment:EKMMOCK_MASTER_KEY");
        key.ToString().ShouldNotContain(b64);
        key.Bytes.ToArray().ShouldBe(Convert.FromBase64String(b64));
    }

    [Fact]
    public void File_Key_IsLoaded_AndTrimsWhitespace()
    {
        var b64 = NewBase64();
        File.WriteAllText(_dir.File("mk"), "  " + b64 + "\r\n");

        using var key = new EnvironmentMasterKeyProvider(Env(("EKMMOCK_MASTER_KEY_FILE", _dir.File("mk")))).GetMasterKey();

        key.Source.ShouldBe("file");
        key.Bytes.ToArray().ShouldBe(Convert.FromBase64String(b64));
    }

    [Fact]
    public void File_MissingOrUnreadable_Refuses()
        => Should.Throw<MasterKeyUnavailableException>(() => new FileMasterKeyProvider(_dir.File("nope")).GetMasterKey());

    [Fact]
    public void BothVariablesSet_IsAmbiguousAndRefuses()
        => Should.Throw<MasterKeyUnavailableException>(() =>
            new EnvironmentMasterKeyProvider(Env(("EKMMOCK_MASTER_KEY", NewBase64()), ("EKMMOCK_MASTER_KEY_FILE", _dir.File("mk")))).GetMasterKey());

    [Theory]
    [InlineData("not-base64!!")]
    [InlineData("AAAA")]
    public void MalformedKey_Refuses_EvenInDevMode_AndNeverEchoesTheInput(string value)
    {
        var provider = new EnvironmentMasterKeyProvider(Env(("EKMMOCK_MASTER_KEY", value)), devMode: true);

        var ex = Should.Throw<MasterKeyUnavailableException>(() => provider.GetMasterKey().Dispose());

        ex.Message.ShouldNotContain(value);
    }

    [Fact]
    public void WrongLengthKey_Refuses()
        => Should.Throw<MasterKeyUnavailableException>(() =>
            new EnvironmentMasterKeyProvider(Env(("EKMMOCK_MASTER_KEY", Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))))).GetMasterKey());

    [Fact]
    public void DevMode_WithoutAKey_CreatesAFlaggedThrowAwayKey()
    {
        using var first = new EnvironmentMasterKeyProvider(Env(), devMode: true).GetMasterKey();
        using var second = new EnvironmentMasterKeyProvider(Env(), devMode: true).GetMasterKey();

        first.IsThrowAway.ShouldBeTrue();
        first.Source.ShouldBe("dev-throwaway");
        first.Bytes.ToArray().ShouldNotBe(second.Bytes.ToArray());
    }

    [Fact]
    public void DevMode_WithAConfiguredKey_UsesTheConfiguredKey()
    {
        using var key = new EnvironmentMasterKeyProvider(Env(("EKMMOCK_MASTER_KEY", NewBase64())), devMode: true).GetMasterKey();

        key.IsThrowAway.ShouldBeFalse();
    }

    [Fact]
    public void Explicit_RequiresExactly32Bytes_AndCopiesItsInput()
    {
        Should.Throw<ArgumentException>(() => new ExplicitMasterKeyProvider(new byte[31]));
        var bytes = RandomNumberGenerator.GetBytes(32);
        var expected = (byte[])bytes.Clone();
        var provider = new ExplicitMasterKeyProvider(bytes);
        Array.Clear(bytes);

        using var key = provider.GetMasterKey();

        key.Bytes.ToArray().ShouldBe(expected);
        key.Source.ShouldBe("explicit");
    }

    [Fact]
    public void Dispose_ZeroesTheKeyBytes()
    {
        var key = new ExplicitMasterKeyProvider(RandomNumberGenerator.GetBytes(32)).GetMasterKey();

        key.Dispose();

        key.Bytes.ToArray().ShouldAllBe(b => b == 0);
    }

    [Fact]
    public void GenerateBase64_Returns32RandomBytesThatTheProviderAccepts()
    {
        var generated = MasterKey.GenerateBase64();

        Convert.FromBase64String(generated).Length.ShouldBe(32);
        generated.ShouldNotBe(MasterKey.GenerateBase64());
        using var key = new EnvironmentMasterKeyProvider(Env(("EKMMOCK_MASTER_KEY", generated))).GetMasterKey();
        key.Bytes.Length.ShouldBe(32);
    }

    [Fact]
    public void Backend_WithAnEnvironmentProviderThatHasNoKey_RefusesToStart()
        => Should.Throw<MasterKeyUnavailableException>(() => new SoftwareCryptoBackend(new SoftwareCryptoBackendOptions
        {
            DataPath = _dir.Path,
            MasterKeyProvider = new EnvironmentMasterKeyProvider(Env()),
        }));
}

public sealed class SelfTestTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly SoftwareCryptoBackend _backend;

    public SelfTestTests()
    {
        _backend = Fx.NewBackend(_dir.Path);
        _backend.Create("_default", "aes", KeyType.Oct, 256);
        _backend.Create("_default", "rsa", KeyType.Rsa, 2048);
    }

    public void Dispose()
    {
        _backend.Dispose();
        _dir.Dispose();
    }

    private static readonly KeyRef Aes = new("_default", "aes");
    private static readonly KeyRef Rsa = new("_default", "rsa");

    [Fact]
    public void SelfTest_OnAHealthyEngine_PassesEveryCase()
    {
        var result = _backend.RunSelfTest();

        result.Passed.ShouldBeTrue();
        result.RefuseToStart.ShouldBeFalse();
        result.Failures.ShouldBeEmpty();
        result.Cases.Select(c => c.Name).ShouldBe(
        [
            "aes-kw/rfc3394-4.6-256bit-kek-256bit-data",
            "aes-kwp/rfc5649-6-20-byte-key",
            "aes-kwp/rfc5649-6-7-byte-key",
            "rsa-oaep-256/roundtrip-and-independent-crosscheck",
            "rsa-oaep/roundtrip-and-independent-crosscheck",
            "key:_default/aes",
            "key:_default/rsa",
        ]);
        result.Cases.ShouldAllBe(c => c.Outcome == SelfTestOutcome.Passed && c.Error == null && c.Duration >= TimeSpan.Zero);
        _backend.LastSelfTest.ShouldBeSameAs(result);
    }

    [Fact]
    public void SelfTest_DoesNotTouchUsageCounters()
    {
        _backend.RunSelfTest();

        _backend.Get(Aes)!.WrapCount.ShouldBe(0);
        _backend.Get(Rsa)!.UnwrapCount.ShouldBe(0);
    }

    [Fact]
    public void SelfTest_AlsoCoversDisabledAndExpiredKeys()
    {
        _backend.SetEnabled(Aes, false);

        _backend.RunSelfTest().Cases.Single(c => c.Name == "key:_default/aes").Outcome.ShouldBe(SelfTestOutcome.Passed);
    }

    [Fact]
    public void ForcedAlgorithmFailure_MakesThatAlgorithmUnsupported_AndOthersKeepWorking()
    {
        var result = _backend.RunSelfTestCore(new SelfTestOptions(), name => name.StartsWith("aes-kw/", StringComparison.Ordinal));

        result.Passed.ShouldBeFalse();
        result.Failures.Select(f => f.Name).ShouldBe(["aes-kw/rfc3394-4.6-256bit-kek-256bit-data"]);
        Fx.Fails(() => _backend.Wrap(Aes, WrapAlgorithm.A256KW, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.UnsupportedAlgorithm);
        Fx.Fails(() => _backend.Unwrap(Aes, WrapAlgorithm.A256KW, Fx.Random(40))).Kind.ShouldBe(EkmErrorKind.UnsupportedAlgorithm);
        _backend.Wrap(Aes, WrapAlgorithm.A256KWP, Fx.Random(32)).ShouldNotBeEmpty();
        _backend.Wrap(Rsa, WrapAlgorithm.RsaOaep256, Fx.Random(32)).ShouldNotBeEmpty();
    }

    [Theory]
    [InlineData("aes-kwp/", WrapAlgorithm.A256KWP)]
    [InlineData("rsa-oaep-256/", WrapAlgorithm.RsaOaep256)]
    [InlineData("rsa-oaep/", WrapAlgorithm.RsaOaep)]
    public void ForcedFailure_DisablesExactlyTheMatchingAlgorithm(string prefix, WrapAlgorithm failed)
    {
        _backend.RunSelfTestCore(new SelfTestOptions(), name => name.StartsWith(prefix, StringComparison.Ordinal));

        foreach (var alg in Enum.GetValues<WrapAlgorithm>())
        {
            var key = alg.RequiredKeyType() == KeyType.Oct ? Aes : Rsa;
            var attempt = () => _backend.Wrap(key, alg, Fx.Random(24));
            if (alg == failed)
            {
                Fx.Fails(() => attempt()).Kind.ShouldBe(EkmErrorKind.UnsupportedAlgorithm, alg.ToString());
            }
            else
            {
                Should.NotThrow(() => attempt(), alg.ToString());
            }
        }
    }

    [Fact]
    public void ForcedKeyFailure_MakesThatKeyUnavailable_AndARerunRestoresIt()
    {
        var result = _backend.RunSelfTestCore(new SelfTestOptions(), name => name == "key:_default/aes");

        result.Failures.Single().Name.ShouldBe("key:_default/aes");
        _backend.Get(Aes)!.State.ShouldBe(KeyState.Unavailable);
        Fx.Fails(() => _backend.Wrap(Aes, WrapAlgorithm.A256KWP, Fx.Random(32))).Kind.ShouldBe(EkmErrorKind.HsmUnavailable);
        Fx.Fails(() => _backend.GetMetadata(Aes)).Kind.ShouldBe(EkmErrorKind.HsmUnavailable);
        _backend.Wrap(Rsa, WrapAlgorithm.RsaOaep256, Fx.Random(32)).ShouldNotBeEmpty();

        _backend.RunSelfTest().Passed.ShouldBeTrue();
        _backend.Get(Aes)!.State.ShouldBe(KeyState.Enabled);
        _backend.Wrap(Aes, WrapAlgorithm.A256KWP, Fx.Random(32)).ShouldNotBeEmpty();
    }

    [Fact]
    public void StrictOption_MakesAFailureRefuseToStart_NonStrictDoesNot()
    {
        var strict = _backend.RunSelfTestCore(new SelfTestOptions { Strict = true }, name => name.StartsWith("rsa-oaep/", StringComparison.Ordinal));
        var lenient = _backend.RunSelfTestCore(new SelfTestOptions { Strict = false }, name => name.StartsWith("rsa-oaep/", StringComparison.Ordinal));

        strict.RefuseToStart.ShouldBeTrue();
        lenient.RefuseToStart.ShouldBeFalse();
        lenient.Passed.ShouldBeFalse();
        _backend.RunSelfTest(new SelfTestOptions { Strict = true }).RefuseToStart.ShouldBeFalse();
    }

    [Fact]
    public void CorruptKeys_AreSkippedNotFailed()
    {
        _backend.Dispose();
        using var wrongMaster = Fx.NewBackend(_dir.Path, "different");

        var result = wrongMaster.RunSelfTest(new SelfTestOptions { Strict = true });

        result.Cases.Where(c => c.Name.StartsWith("key:", StringComparison.Ordinal)).ShouldAllBe(c => c.Outcome == SelfTestOutcome.Skipped);
        result.Passed.ShouldBeTrue();
        result.RefuseToStart.ShouldBeFalse();
    }

    [Fact]
    public void FailureReports_NeverCarryExceptionMessages()
    {
        var result = _backend.RunSelfTestCore(new SelfTestOptions(), _ => true);

        result.Failures.ShouldNotBeEmpty();
        result.Failures.ShouldAllBe(f => f.Error == nameof(InvalidOperationException));
    }

    [Fact]
    public void BeforeAnySelfTest_LastSelfTestIsNull()
        => _backend.LastSelfTest.ShouldBeNull();
}
