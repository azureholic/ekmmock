using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace EkmMock.Crypto.Tests;

/// <summary>Spec 0.4 / 5.2: secret and private key material never leaves the engine through a public type.</summary>
public sealed class NoMaterialLeakTests : IDisposable
{
    // The only public members allowed to carry byte data out, with the reason.
    private static readonly HashSet<string> AllowedByteExposure =
    [
        "ICryptoBackend.Wrap",              // wrapped DEK (ciphertext): the API contract
        "ICryptoBackend.Unwrap",            // plaintext DEK: the one plaintext the contract requires
        "SoftwareCryptoBackend.Wrap",
        "SoftwareCryptoBackend.Unwrap",
        "RsaPublicKey.Modulus",             // public key n
        "RsaPublicKey.Exponent",            // public key e
    ];

    private static readonly Type[] ForbiddenTypes =
    [
        typeof(byte[]), typeof(Span<byte>), typeof(ReadOnlySpan<byte>), typeof(Memory<byte>), typeof(ReadOnlyMemory<byte>),
        typeof(ArraySegment<byte>), typeof(RSAParameters), typeof(RSA), typeof(Aes), typeof(AesGcm), typeof(ECParameters),
        typeof(System.Security.SecureString), typeof(Stream),
    ];

    private readonly TempDir _dir = new();
    private readonly SoftwareCryptoBackend _backend;

    public NoMaterialLeakTests() => _backend = Fx.NewBackend(_dir.Path, allowImport: true);

    public void Dispose()
    {
        _backend.Dispose();
        _dir.Dispose();
    }

    private static bool Carries(Type type)
    {
        if (type.IsByRef || type.IsPointer)
        {
            return Carries(type.GetElementType()!);
        }

        if (ForbiddenTypes.Contains(type) || (type.IsGenericType && ForbiddenTypes.Contains(type.GetGenericTypeDefinition())))
        {
            return true;
        }

        if (type.IsArray)
        {
            return Carries(type.GetElementType()!);
        }

        return type.IsGenericType && type.GetGenericArguments().Any(Carries);
    }

    private static IEnumerable<(string Member, Type Type)> OutputSurface(Type type)
    {
        const BindingFlags flags = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        foreach (var field in type.GetFields(flags))
        {
            yield return ($"{type.Name}.{field.Name}", field.FieldType);
        }

        foreach (var property in type.GetProperties(flags))
        {
            yield return ($"{type.Name}.{property.Name}", property.PropertyType);
        }

        foreach (var method in type.GetMethods(flags).Where(m => !m.IsSpecialName))
        {
            yield return ($"{type.Name}.{method.Name}", method.ReturnType);
            // out / ref parameters are outputs too (input parameters are not).
            foreach (var parameter in method.GetParameters().Where(p => p.ParameterType.IsByRef))
            {
                yield return ($"{type.Name}.{method.Name}({parameter.Name})", parameter.ParameterType);
            }
        }

        foreach (var evt in type.GetEvents(flags))
        {
            yield return ($"{type.Name}.{evt.Name}", evt.EventHandlerType!);
        }
    }

    [Fact]
    public void NoPublicMember_ReturnsByteBuffersOrCryptoObjects_ExceptTheExplicitAllowList()
    {
        var offenders = new List<string>();
        foreach (var type in typeof(SoftwareCryptoBackend).Assembly.GetExportedTypes())
        {
            foreach (var (member, memberType) in OutputSurface(type))
            {
                if (Carries(memberType) && !AllowedByteExposure.Contains(member))
                {
                    offenders.Add($"{member}: {memberType.Name}");
                }
            }
        }

        offenders.ShouldBeEmpty();
    }

    [Fact]
    public void TheAllowList_IsNotStale_EveryEntryStillExists()
    {
        var surface = typeof(SoftwareCryptoBackend).Assembly.GetExportedTypes()
            .SelectMany(OutputSurface)
            .Where(m => Carries(m.Type))
            .Select(m => m.Member)
            .ToHashSet();

        foreach (var allowed in AllowedByteExposure)
        {
            surface.ShouldContain(allowed);
        }
    }

    [Fact]
    public void NoPublicMemberName_AdvertisesSecretMaterial()
    {
        var suspicious = new System.Text.RegularExpressions.Regex("private|secret|material|pkcs8|\\bkek\\b|dek", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        var offenders = typeof(SoftwareCryptoBackend).Assembly.GetExportedTypes()
            .SelectMany(OutputSurface)
            .Select(m => m.Member)
            .Where(m => suspicious.IsMatch(m))
            .ToList();

        offenders.ShouldBeEmpty();
    }

    [Fact]
    public void TheEngineAssembly_HasNoAspNetCoreOrThirdPartyCryptoReferences()
    {
        var references = typeof(SoftwareCryptoBackend).Assembly.GetReferencedAssemblies().Select(a => a.Name!).ToList();

        references.ShouldNotContain(r => r.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal));
        references.ShouldNotContain(r => r.Contains("BouncyCastle", StringComparison.OrdinalIgnoreCase));
        references.ShouldNotContain(r => r.StartsWith("Microsoft.Extensions", StringComparison.Ordinal));
    }

    // ---- diagnostics: ToString / JSON / exception messages ------------------------------------------------------------

    private sealed record Secrets(byte[] AesKey, byte[] Pkcs8, RSAParameters Rsa, byte[] Dek, byte[] Master);

    private (Secrets Secrets, KeyRef Aes, KeyRef Rsa) Seed()
    {
        using var rsa = RSA.Create(2048);
        var aesKey = Fx.Random(32);
        var aes = new KeyRef("_default", "aes");
        var rsaRef = new KeyRef("_default", "rsa");
        _backend.Import(aes.Namespace, aes.Name, KeyType.Oct, aesKey);
        _backend.Import(rsaRef.Namespace, rsaRef.Name, KeyType.Rsa, rsa.ExportPkcs8PrivateKey());
        return (new Secrets(aesKey, rsa.ExportPkcs8PrivateKey(), rsa.ExportParameters(true), Fx.Random(32), Fx.MasterKeyBytes()), aes, rsaRef);
    }

    private static IEnumerable<(string Label, byte[] Bytes)> Enumerate(Secrets s)
    {
        yield return ("aes key", s.AesKey);
        yield return ("rsa D", s.Rsa.D!);
        yield return ("rsa P", s.Rsa.P!);
        yield return ("rsa Q", s.Rsa.Q!);
        yield return ("rsa DP", s.Rsa.DP!);
        yield return ("rsa DQ", s.Rsa.DQ!);
        yield return ("rsa InverseQ", s.Rsa.InverseQ!);
        yield return ("rsa pkcs8", s.Pkcs8);
        yield return ("master key", s.Master);
    }

    private static void AssertClean(string label, string text, Secrets secrets)
    {
        foreach (var (name, bytes) in Enumerate(secrets))
        {
            SecretScanner.LeaksInText(text, bytes).ShouldBeFalse($"{name} leaked via {label}");
        }
    }

    [Fact]
    public void KeyInfo_KeyMetadata_AndLists_ToStringAndJson_ContainNoSecretBytes()
    {
        var (secrets, aes, rsa) = Seed();
        var generated = _backend.Create("_default", "generated-rsa", KeyType.Rsa, 2048);
        var generatedSecret = _backend.CopySecretForTests(new KeyRef("_default", "generated-rsa"))!;
        var infos = _backend.List();
        var metadata = new[] { _backend.GetMetadata(aes)!, _backend.GetMetadata(rsa)!, _backend.GetMetadata(generated.Ref)! };
        var texts = new List<(string, string)>
        {
            ("List().ToString", string.Join('|', infos.Select(i => i.ToString()))),
            ("List() json", JsonSerializer.Serialize(infos)),
            ("metadata ToString", string.Join('|', metadata.Select(m => m.ToString()))),
            ("metadata json", JsonSerializer.Serialize(metadata)),
            ("backend ToString", _backend.ToString()!),
            ("load report", _backend.LoadReport.ToString()),
        };

        foreach (var (label, text) in texts)
        {
            AssertClean(label, text, secrets);
            SecretScanner.LeaksInText(text, generatedSecret).ShouldBeFalse($"generated secret leaked via {label}");
        }
    }

    [Fact]
    public void RsaPublicKey_JsonContainsOnlyPublicNumbers()
    {
        var (secrets, _, rsa) = Seed();
        var publicKey = _backend.GetMetadata(rsa)!.PublicKey!;

        var json = JsonSerializer.Serialize(publicKey);

        json.ShouldStartWith("{\"n\":\"");
        json.ShouldEndWith("\"e\":\"AQAB\"}");
        var roundTripped = JsonSerializer.Deserialize<RsaPublicKey>(json)!;
        roundTripped.Modulus.ToArray().ShouldBe(publicKey.Modulus.ToArray());
        roundTripped.Exponent.ToArray().ShouldBe(publicKey.Exponent.ToArray());
        AssertClean("public key json", json, secrets);
        publicKey.ToString().ShouldBe("RsaPublicKey(2048)");
    }

    [Fact]
    public void EngineFailureMessages_NeverContainKeyDekOrWrappedBytes()
    {
        var (secrets, aes, rsa) = Seed();
        var dek = secrets.Dek;
        var wrapped = _backend.Wrap(aes, WrapAlgorithm.A256KWP, dek);
        var tampered = (byte[])wrapped.Clone();
        tampered[3] ^= 1;
        var failures = new List<EkmEngineException>
        {
            Fx.Fails(() => _backend.Unwrap(aes, WrapAlgorithm.A256KWP, tampered)),
            Fx.Fails(() => _backend.Wrap(aes, WrapAlgorithm.RsaOaep256, dek)),
            Fx.Fails(() => _backend.Wrap(rsa, WrapAlgorithm.RsaOaep256, Fx.Random(500))),
            Fx.Fails(() => _backend.Wrap(new KeyRef("_default", "missing"), WrapAlgorithm.A256KWP, dek)),
            Fx.Fails(() => _backend.Create("_default", "bad_name", KeyType.Oct, 256)),
            Fx.Fails(() => _backend.Import("_default", "bad", KeyType.Rsa, secrets.AesKey)),
        };
        _backend.SetEnabled(aes, false);
        failures.Add(Fx.Fails(() => _backend.Wrap(aes, WrapAlgorithm.A256KWP, dek)));

        foreach (var failure in failures)
        {
            var text = failure.ToString() + failure.Message + failure.Code;
            AssertClean(failure.Kind.ToString(), text, secrets);
            SecretScanner.LeaksInText(text, dek).ShouldBeFalse($"DEK leaked via {failure.Kind}");
            SecretScanner.LeaksInText(text, wrapped).ShouldBeFalse($"wrapped value leaked via {failure.Kind}");
            failure.InnerException.ShouldBeNull();
        }
    }

    [Fact]
    public void ExceptionMessages_AreFixedPerKind_SoNoInputCanBeEchoed()
    {
        var hostile = "evil-" + Convert.ToBase64String(Fx.Random(16));

        var ex = Fx.Fails(() => _backend.Create("_default", hostile.Replace('+', '_'), KeyType.Oct, 256));

        ex.Message.ShouldNotContain("evil-");
    }

    [Fact]
    public void SelfTestResults_AndMasterKeyProviders_ContainNoSecretBytes()
    {
        var (secrets, _, _) = Seed();
        var selfTest = _backend.RunSelfTest();
        using var master = new ExplicitMasterKeyProvider(secrets.Master).GetMasterKey();

        var text = selfTest + JsonSerializer.Serialize(selfTest) + master + master.Source;

        AssertClean("self-test + master key", text, secrets);
    }

    [Fact]
    public void UnwrapResult_IsAFreshBufferTheCallerMayZero_WithoutAffectingTheEngine()
    {
        var (secrets, aes, _) = Seed();
        var wrapped = _backend.Wrap(aes, WrapAlgorithm.A256KWP, secrets.Dek);

        var first = _backend.Unwrap(aes, WrapAlgorithm.A256KWP, wrapped);
        CryptographicOperations.ZeroMemory(first);
        var second = _backend.Unwrap(aes, WrapAlgorithm.A256KWP, wrapped);

        Fx.Same(second, secrets.Dek).ShouldBeTrue();
        second.ShouldNotBeSameAs(first);
    }
}
