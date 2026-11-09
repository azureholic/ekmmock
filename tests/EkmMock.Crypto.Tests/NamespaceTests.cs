using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;

namespace EkmMock.Crypto.Tests;

internal static class TestCertificates
{
    /// <summary>Self-signed synthetic CA, DER bytes.</summary>
    public static byte[] CreateCaDer(string commonName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return cert.Export(X509ContentType.Cert);
    }

    public static string ToPem(byte[] der) => PemEncoding.WriteString("CERTIFICATE", der);
}

public class NamespacePrefixTests
{
    [Theory]
    [InlineData("", "")]
    [InlineData("/", "")]
    [InlineData("contoso", "contoso")]
    [InlineData("/contoso/", "contoso")]
    [InlineData("///contoso/prod///", "contoso/prod")]
    [InlineData("a-b/C-d/9", "a-b/C-d/9")]
    public void Normalize_TrimsSlashesAndAcceptsValidPrefixes(string input, string expected)
    {
        EkmNames.TryNormalizePrefix(input, out var normalized, out var error).ShouldBeTrue(error);

        normalized.ShouldBe(expected);
    }

    [Theory]
    [InlineData("has space")]
    [InlineData("under_score")]
    [InlineData("dot.ted")]
    [InlineData("colon:")]
    [InlineData("a//b")]
    [InlineData("a/b c")]
    [InlineData("ünï")]
    [InlineData("query?x")]
    public void Normalize_RejectsIllegalCharactersAndEmptySegments(string input)
    {
        EkmNames.TryNormalizePrefix(input, out _, out var error).ShouldBeFalse();

        error.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void Normalize_Allows64CharactersAndRejects65()
    {
        EkmNames.TryNormalizePrefix(new string('a', 64), out _, out _).ShouldBeTrue();
        EkmNames.TryNormalizePrefix(new string('a', 65), out _, out var error).ShouldBeFalse();
        error.ShouldContain("64");
    }

    [Fact]
    public void Normalize_CountsTheNormalisedLength_NotTheSlashesAroundIt()
        => EkmNames.TryNormalizePrefix("/" + new string('a', 64) + "/", out _, out _).ShouldBeTrue();

    [Theory]
    [InlineData("abc", true)]
    [InlineData("A-1", true)]
    [InlineData("", false)]
    [InlineData("a_b", false)]
    [InlineData("a.b", false)]
    [InlineData("abc\n", false)]
    public void KeyName_FollowsTheSpecPattern(string name, bool valid)
        => EkmNames.IsValidKeyName(name).ShouldBe(valid);
}

public class NamespaceResolverTests
{
    private static NamespaceDefinition Ns(string name, string prefix) => new() { Name = name, Prefix = prefix };

    private static readonly NamespaceDefinition[] All =
    [
        Ns("_default", string.Empty),
        Ns("contoso", "contoso"),
        Ns("contoso-prod", "contoso/prod"),
        Ns("fabrikam", "fabrikam"),
    ];

    [Theory]
    [InlineData("/info", "_default", "info")]
    [InlineData("/my-key/wrapkey", "_default", "my-key,wrapkey")]
    [InlineData("/contoso/info", "contoso", "info")]
    [InlineData("/contoso/my-key/metadata", "contoso", "my-key,metadata")]
    [InlineData("/contoso/prod/info", "contoso-prod", "info")]
    [InlineData("/contoso/prod/my-key/unwrapkey", "contoso-prod", "my-key,unwrapkey")]
    [InlineData("/contoso/prod/", "contoso-prod", "")]
    [InlineData("/fabrikam/info/", "fabrikam", "info")]
    public void Resolve_PicksTheLongestMatchingPrefix(string path, string expectedNamespace, string expectedRemaining)
    {
        var match = NamespaceResolver.Resolve(All, path);

        match.ShouldNotBeNull();
        match.Namespace.Name.ShouldBe(expectedNamespace);
        string.Join(',', match.RemainingSegments).ShouldBe(expectedRemaining);
    }

    [Theory]
    [InlineData("/contosoX/info")]
    [InlineData("/contoso-prod/info")]
    public void Resolve_MatchesWholeSegmentsOnly_SoALookalikeFallsBackToDefault(string path)
        => NamespaceResolver.Resolve(All, path)!.Namespace.Name.ShouldBe("_default");

    [Fact]
    public void Resolve_IsCaseSensitive()
        => NamespaceResolver.Resolve(All, "/Contoso/info")!.Namespace.Name.ShouldBe("_default");

    [Fact]
    public void Resolve_WithoutADefaultNamespace_UnknownPrefixesAreNull()
    {
        var withoutDefault = All.Where(n => n.Name != "_default").ToArray();

        NamespaceResolver.Resolve(withoutDefault, "/unknown/info").ShouldBeNull();
        NamespaceResolver.Resolve(withoutDefault, "/info").ShouldBeNull();
        NamespaceResolver.Resolve(withoutDefault, "/").ShouldBeNull();
        NamespaceResolver.Resolve(withoutDefault, "/contoso/info")!.Namespace.Name.ShouldBe("contoso");
    }

    [Theory]
    [InlineData("//info")]
    [InlineData("/contoso//info")]
    [InlineData(null)]
    public void Resolve_RejectsEmptyInnerSegmentsAndNull(string? path)
        => NamespaceResolver.Resolve(All, path).ShouldBeNull();

    [Fact]
    public void Resolve_IsIndependentOfDefinitionOrder()
    {
        var reversed = All.Reverse().ToArray();

        NamespaceResolver.Resolve(reversed, "/contoso/prod/k/wrapkey")!.Namespace.Name.ShouldBe("contoso-prod");
    }
}

public sealed class NamespaceStoreTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static NamespaceDefinition Default(params string[] cns) => new()
    {
        Name = "_default",
        ClientTrust = new ClientTrust { SubjectCommonNames = cns },
    };

    [Fact]
    public void Add_PersistsAndSurvivesARestart()
    {
        var store = NamespaceStore.Open(_dir.Path);
        store.Add(Default("client.example"));
        store.Add(new NamespaceDefinition { Name = "contoso-prod", Prefix = "/contoso/prod/" });

        var reopened = NamespaceStore.Open(_dir.Path);

        reopened.List().Select(n => $"{n.Name}|{n.Prefix}").ShouldBe(["_default|", "contoso-prod|contoso/prod"]);
        reopened.Get("_default")!.ClientTrust.SubjectCommonNames.ShouldBe(["client.example"]);
        reopened.Resolve("/contoso/prod/k/wrapkey")!.Namespace.Name.ShouldBe("contoso-prod");
    }

    [Fact]
    public void Seed_IsAppliedOnlyOnFirstStart()
    {
        NamespaceStore.Open(_dir.Path, [Default("seeded.example")]);

        var second = NamespaceStore.Open(_dir.Path, [new NamespaceDefinition { Name = "ignored", Prefix = "ignored" }]);

        second.List().Select(n => n.Name).ShouldBe(["_default"]);
        second.Get("_default")!.ClientTrust.SubjectCommonNames.ShouldBe(["seeded.example"]);
    }

    [Fact]
    public void Seed_WithInvalidPrefix_FailsAtStartup()
        => Should.Throw<NamespaceException>(() => NamespaceStore.Open(_dir.Path, [new NamespaceDefinition { Name = "bad", Prefix = "has space" }]))
            .Kind.ShouldBe(NamespaceErrorKind.InvalidPrefix);

    [Fact]
    public void EmptyStoreWithoutSeed_WritesNoFile()
    {
        NamespaceStore.Open(_dir.Path).List().ShouldBeEmpty();

        Directory.GetFiles(_dir.Path).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("bad name", "x", NamespaceErrorKind.InvalidName)]
    [InlineData("bad:name", "x", NamespaceErrorKind.InvalidName)]
    [InlineData("", "x", NamespaceErrorKind.InvalidName)]
    [InlineData("ns", "has space", NamespaceErrorKind.InvalidPrefix)]
    [InlineData("ns", "", NamespaceErrorKind.InvalidPrefix)]           // only _default may have no prefix
    [InlineData("_default", "something", NamespaceErrorKind.InvalidPrefix)] // _default is the no-prefix namespace
    public void Add_RejectsInvalidDefinitions(string name, string prefix, NamespaceErrorKind expected)
    {
        var store = NamespaceStore.Open(_dir.Path);

        Should.Throw<NamespaceException>(() => store.Add(new NamespaceDefinition { Name = name, Prefix = prefix })).Kind.ShouldBe(expected);
        store.List().ShouldBeEmpty();
    }

    [Fact]
    public void Add_RejectsDuplicateNamesAndDuplicatePrefixes()
    {
        var store = NamespaceStore.Open(_dir.Path);
        store.Add(new NamespaceDefinition { Name = "one", Prefix = "shared" });

        Should.Throw<NamespaceException>(() => store.Add(new NamespaceDefinition { Name = "one", Prefix = "other" })).Kind.ShouldBe(NamespaceErrorKind.Duplicate);
        Should.Throw<NamespaceException>(() => store.Add(new NamespaceDefinition { Name = "two", Prefix = "/shared/" })).Kind.ShouldBe(NamespaceErrorKind.Duplicate);
    }

    [Fact]
    public void Update_ChangesPrefixAndTrust_AndRemoveDeletes()
    {
        var store = NamespaceStore.Open(_dir.Path);
        store.Add(new NamespaceDefinition { Name = "one", Prefix = "a" });

        store.Update(new NamespaceDefinition { Name = "one", Prefix = "b/c" });
        store.SetTrust("one", new ClientTrust { SubjectCommonNames = ["cn-1", "cn-1", "cn-2"] });

        var current = NamespaceStore.Open(_dir.Path).Get("one")!;
        current.Prefix.ShouldBe("b/c");
        current.ClientTrust.SubjectCommonNames.ShouldBe(["cn-1", "cn-2"]); // de-duplicated, order kept
        store.Remove("one").ShouldBeTrue();
        store.Remove("one").ShouldBeFalse();
        NamespaceStore.Open(_dir.Path).List().ShouldBeEmpty();
        Should.Throw<NamespaceException>(() => store.Update(new NamespaceDefinition { Name = "one", Prefix = "x" })).Kind.ShouldBe(NamespaceErrorKind.NotFound);
    }

    [Fact]
    public void CommonNames_AreCaseSensitiveAndValidated()
    {
        var store = NamespaceStore.Open(_dir.Path);

        var saved = store.Add(Default("Client.Example", "client.example"));

        saved.ClientTrust.SubjectCommonNames.ShouldBe(["Client.Example", "client.example"]);
        Should.Throw<NamespaceException>(() => store.Update(Default("")))
            .Kind.ShouldBe(NamespaceErrorKind.InvalidTrust);
        Should.Throw<NamespaceException>(() => store.Update(Default("bad\ncn")))
            .Kind.ShouldBe(NamespaceErrorKind.InvalidTrust);
    }

    [Fact]
    public void CaCertificates_MustBeValidBase64Der()
    {
        var store = NamespaceStore.Open(_dir.Path);
        var der = TestCertificates.CreateCaDer("Test Root");

        var saved = store.Add(new NamespaceDefinition
        {
            Name = "_default",
            ClientTrust = new ClientTrust { CaCertificatesDerBase64 = [Convert.ToBase64String(der), Convert.ToBase64String(der)] },
        });

        saved.ClientTrust.CaCertificatesDerBase64.Count.ShouldBe(1);
        foreach (var bad in new[] { "not base64!!", Convert.ToBase64String([1, 2, 3, 4]) })
        {
            Should.Throw<NamespaceException>(() => store.Update(new NamespaceDefinition
            {
                Name = "_default",
                ClientTrust = new ClientTrust { CaCertificatesDerBase64 = [bad] },
            })).Kind.ShouldBe(NamespaceErrorKind.InvalidTrust);
        }
    }

    [Fact]
    public void FailedAdd_LeavesTheStoreUnchanged()
    {
        var store = NamespaceStore.Open(_dir.Path);
        store.Add(Default("x"));
        var before = File.ReadAllText(_dir.File("namespaces.json"));

        Should.Throw<NamespaceException>(() => store.Add(new NamespaceDefinition { Name = "bad name", Prefix = "p" }));

        File.ReadAllText(_dir.File("namespaces.json")).ShouldBe(before);
        store.List().Count.ShouldBe(1);
    }

    [Fact]
    public void Persistence_IsAtomicSnakeCaseJsonWithoutTempFiles()
    {
        var store = NamespaceStore.Open(_dir.Path);
        store.Add(Default("client.example"));

        var json = JsonNode.Parse(File.ReadAllText(_dir.File("namespaces.json")))!;

        json["namespaces"]![0]!["client_trust"]!["subject_common_names"]![0]!.GetValue<string>().ShouldBe("client.example");
        Directory.GetFiles(_dir.Path).Select(Path.GetFileName).ShouldBe(["namespaces.json"]);
    }

    [Fact]
    public void UnparsableNamespacesFile_RefusesToStartAndIsNotOverwritten()
    {
        File.WriteAllText(_dir.File("namespaces.json"), "[[[");

        Should.Throw<InvalidDataException>(() => NamespaceStore.Open(_dir.Path));

        File.ReadAllText(_dir.File("namespaces.json")).ShouldBe("[[[");
    }

    [Fact]
    public void KeysAreNotTiedToNamespaceDefinitions_SoRemovingANamespaceKeepsItsKeys()
    {
        var store = NamespaceStore.Open(_dir.Path);
        store.Add(new NamespaceDefinition { Name = "one", Prefix = "one" });
        using var backend = Fx.NewBackend(_dir.Path);
        backend.Create("one", "k", KeyType.Oct, 256);

        store.Remove("one");

        backend.Get(new KeyRef("one", "k")).ShouldNotBeNull();
    }
}

public class TrustImporterTests
{
    private static readonly byte[] CaA = TestCertificates.CreateCaDer("Synthetic Root A");
    private static readonly byte[] CaB = TestCertificates.CreateCaDer("Synthetic Root B");

    [Fact]
    public void AzureCliJson_IsParsed_WithCommonNameAndEveryCaCertificate()
    {
        var json = $$"""
            {
              "caCertificates": [ "{{Convert.ToBase64String(CaA)}}", "{{Convert.ToBase64String(CaB)}}" ],
              "subjectCommonName": "contoso.managedhsmclient.azure.net"
            }
            """;

        var result = TrustImporter.FromAzureCliJson(json);

        result.Trust.SubjectCommonNames.ShouldBe(["contoso.managedhsmclient.azure.net"]);
        result.Trust.CaCertificatesDerBase64.ShouldBe([Convert.ToBase64String(CaA), Convert.ToBase64String(CaB)]);
        result.Certificates.Select(c => c.Subject).ShouldBe(["CN=Synthetic Root A", "CN=Synthetic Root B"]);
        result.Certificates[0].Issuer.ShouldBe("CN=Synthetic Root A");
        result.Certificates[0].NotAfter.ShouldBeGreaterThan(DateTimeOffset.UtcNow);
        result.Certificates[0].ThumbprintSha256.Length.ShouldBe(64);
    }

    [Fact]
    public void AzureCliJson_AcceptsSnakeCaseAndIsCaseInsensitive()
    {
        var json = $$"""{ "CA_Certificates": ["{{Convert.ToBase64String(CaA)}}"], "subject_common_name": "cn.example" }""";

        var result = TrustImporter.FromAzureCliJson(json);

        result.Trust.SubjectCommonNames.ShouldBe(["cn.example"]);
        result.Trust.CaCertificatesDerBase64.Count.ShouldBe(1);
    }

    [Fact]
    public void AzureCliJson_WithPemEntries_IsAcceptedToo()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new { caCertificates = new[] { TestCertificates.ToPem(CaA) }, subjectCommonName = "cn" });

        TrustImporter.FromAzureCliJson(json).Trust.CaCertificatesDerBase64.ShouldBe([Convert.ToBase64String(CaA)]);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("""{ "caCertificates": [], "subjectCommonName": "x" }""")]
    [InlineData("""{ "caCertificates": ["AAAA"], "subjectCommonName": "x" }""")]
    [InlineData("""{ "caCertificates": [1, 2], "subjectCommonName": "x" }""")]
    [InlineData("""{ "caCertificates": "%%%", "subjectCommonName": "x" }""")]
    public void AzureCliJson_Invalid_IsAnInvalidTrustError(string json)
        => Should.Throw<NamespaceException>(() => TrustImporter.FromAzureCliJson(json)).Kind.ShouldBe(NamespaceErrorKind.InvalidTrust);

    [Fact]
    public void Pem_WithSeveralCertificates_IsParsed_AndTheCallerSuppliesCommonNames()
    {
        var pem = TestCertificates.ToPem(CaA) + "\n# comment\n" + TestCertificates.ToPem(CaB);

        var result = TrustImporter.FromPem(pem, ["cn-1", "cn-2"]);

        result.Trust.SubjectCommonNames.ShouldBe(["cn-1", "cn-2"]);
        result.Trust.CaCertificatesDerBase64.Count.ShouldBe(2);
        result.Certificates.Count.ShouldBe(2);
    }

    [Fact]
    public void Pem_IgnoresNonCertificateBlocks_AndRejectsEmptyInput()
    {
        using var rsa = RSA.Create(2048);
        var privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();

        var result = TrustImporter.FromPem(privateKeyPem + "\n" + TestCertificates.ToPem(CaA));

        result.Certificates.Count.ShouldBe(1);
        Should.Throw<NamespaceException>(() => TrustImporter.FromPem(privateKeyPem)).Kind.ShouldBe(NamespaceErrorKind.InvalidTrust);
        Should.Throw<NamespaceException>(() => TrustImporter.FromPem("garbage")).Kind.ShouldBe(NamespaceErrorKind.InvalidTrust);
    }

    [Fact]
    public void ImportedTrust_CanBeSavedAsANamespaceAndRoundTrips()
    {
        using var dir = new TempDir();
        var result = TrustImporter.FromAzureCliJson($$"""{ "caCertificates": ["{{Convert.ToBase64String(CaA)}}"], "subjectCommonName": "cn" }""");
        var store = NamespaceStore.Open(dir.Path);

        store.Add(new NamespaceDefinition { Name = "_default", ClientTrust = result.Trust });

        NamespaceStore.Open(dir.Path).Get("_default")!.ClientTrust.ShouldBe(result.Trust, new TrustComparer());
    }

    private sealed class TrustComparer : IEqualityComparer<ClientTrust>
    {
        public bool Equals(ClientTrust? x, ClientTrust? y)
            => x is not null && y is not null
               && x.SubjectCommonNames.SequenceEqual(y.SubjectCommonNames)
               && x.CaCertificatesDerBase64.SequenceEqual(y.CaCertificatesDerBase64);

        public int GetHashCode(ClientTrust obj) => obj.SubjectCommonNames.Count;
    }
}
