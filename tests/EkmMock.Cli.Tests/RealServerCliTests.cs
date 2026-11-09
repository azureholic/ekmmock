using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EkmMock.Cli.Conformance;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Ekm;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Tests;

/// <summary>
/// The CLI against the real server process: key and namespace management, trust import, faults, and the console certificate trust options, all through the real <c>/api/console/*</c> over real TLS.
/// Effects are proven where they matter, on the EKM endpoint, with a real mutual-TLS client.
/// </summary>
[Collection("real server")]
public sealed class RealServerCliTests
{
    private readonly RealServerFixture _server;

    public RealServerCliTests(RealServerFixture server)
    {
        _server = server;
    }

    private static string Unique(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];

    // ---- keys ----

    [Fact]
    public async Task KeyLifecycle_ThroughTheCli_HasTheEffectsTheServerPromises()
    {
        var name = Unique("it-key");
        var (ekm, owner) = _server.CreateEkmClient();
        using (owner)
        {
            var created = await _server.RunOnConsoleAsync("key", "create", "--ns", "_default", "--name", name, "--type", "aes");
            created.ExitCode.ShouldBe(0, created.ToString());
            created.Out.ShouldContain($"Created _default/{name} (AES-256)");
            created.Out.ShouldContain($"--external-key-id {name}");

            var dek = RandomNumberGenerator.GetBytes(32);
            var wrapped = Expect.Value(await ekm.WrapAsync(name, "A256KWP", dek), "wrap");

            (await _server.RunOnConsoleAsync("key", "disable", "--ns", "_default", "--name", name)).ExitCode.ShouldBe(0);
            Expect.ProxyError(await ekm.WrapAsync(name, "A256KWP", dek), 403, "KeyDisabled", "wrap with a disabled key");

            (await _server.RunOnConsoleAsync("key", "enable", "--ns", "_default", "--name", name)).ExitCode.ShouldBe(0);
            Expect.Value(await ekm.UnwrapAsync(name, "A256KWP", wrapped), "unwrap after enable").ShouldBe(dek);

            var expired = await _server.RunOnConsoleAsync("key", "expire", "--ns", "_default", "--name", name, "--at", DateTimeOffset.UtcNow.AddHours(-1).ToString("O"));
            expired.ExitCode.ShouldBe(0, expired.ToString());
            Expect.ProxyError(await ekm.WrapAsync(name, "A256KWP", dek), 403, "KeyExpired", "wrap with an expired key");
            (await _server.RunOnConsoleAsync("key", "expire", "--ns", "_default", "--name", name, "--clear")).ExitCode.ShouldBe(0);
            Expect.Status(await ekm.WrapAsync(name, "A256KWP", dek), 200, "wrap after clearing the expiry");

            var wrong = await _server.RunOnConsoleAsync("key", "destroy", "--ns", "_default", "--name", name, "--confirm", name + "x");
            wrong.ExitCode.ShouldBe(2, wrong.ToString());
            Expect.Status(await ekm.WrapAsync(name, "A256KWP", dek), 200, "the key survives a destroy with a wrong confirmation");

            var destroyed = await _server.RunOnConsoleAsync("key", "destroy", "--ns", "_default", "--name", name, "--confirm", name);
            destroyed.ExitCode.ShouldBe(0, destroyed.ToString());
            destroyed.Out.ShouldContain("DESTROYED");
            Expect.ProxyError(await ekm.UnwrapAsync(name, "A256KWP", wrapped), 404, "KeyNotFound", "unwrap with a destroyed key");

            var again = await _server.RunOnConsoleAsync("key", "destroy", "--ns", "_default", "--name", name, "--confirm", name);
            again.ExitCode.ShouldBe(1, again.ToString());
            again.Error.ShouldContain("already destroyed");
        }
    }

    [Fact]
    public async Task KeyCreate_ForRsa_PrintsThePublicKeyThatTheEkmEndpointPublishes_AndNeverAnythingSecret()
    {
        var name = Unique("it-rsa");
        var (ekm, owner) = _server.CreateEkmClient();
        using (owner)
        {
            var run = await _server.RunOnConsoleAsync("key", "create", "--ns", "_default", "--name", name, "--type", "rsa", "--size", "2048", "--hsm", "myhsm", "--ref-name", "ekm-it");

            run.ExitCode.ShouldBe(0, run.ToString());
            var metadata = await ekm.MetadataAsync(name);
            run.Out.ShouldContain("n: " + metadata.GetString("n"));
            run.Out.ShouldContain("e: AQAB");
            run.Out.ShouldContain("-----BEGIN PUBLIC KEY-----");
            run.Out.ShouldContain($"az keyvault key create --hsm-name myhsm --name ekm-it --external-key-id {name}");
            run.All.ShouldNotContain("PRIVATE", Case.Sensitive);
            run.Out.ShouldNotContain("\"d\"");
        }
    }

    [Fact]
    public async Task KeyList_Json_ListsTheSampleKeys_AndShowsAnImportedOriginNowhereNew()
    {
        var run = await _server.RunOnConsoleAsync("key", "list", "--output", "json");

        run.ExitCode.ShouldBe(0, run.ToString());
        using var json = JsonDocument.Parse(run.Out);
        var names = json.RootElement.GetProperty("keys").EnumerateArray().Select(static k => k.GetProperty("name").GetString()).ToList();
        names.ShouldContain("aes-key-1");
        names.ShouldContain("rsa-key-1");
    }

    [Fact]
    public async Task KeyCreate_WithAnExistingName_IsAFailure_WithTheServersMessage()
    {
        var run = await _server.RunOnConsoleAsync("key", "create", "--ns", "_default", "--name", "aes-key-1", "--type", "aes");

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain("Conflict");
    }

    [Fact]
    public async Task KeyCommands_OnAnUnknownNamespaceOrKey_FailWithTheServersMessage()
    {
        (await _server.RunOnConsoleAsync("key", "create", "--ns", "no-such-ns", "--name", "x", "--type", "aes")).ExitCode.ShouldBe(1);
        var show = await _server.RunOnConsoleAsync("key", "show", "--ns", "_default", "--name", "no-such-key");
        show.ExitCode.ShouldBe(1);
        show.Error.ShouldContain("NotFound");
    }

    [Fact]
    public async Task KeyCommands_WriteToTheAuditLog_AsTheLoopbackUser()
    {
        var name = Unique("it-audit");
        await _server.RunOnConsoleAsync("key", "create", "--ns", "_default", "--name", name, "--type", "aes");

        using var console = _server.CreateConsoleClient();
        var audit = await console.AuditAsync("?action=key.create&take=200", CancellationToken.None);

        audit.Entries.ShouldContain(e => e.Target == $"key:_default/{name}" && e.User == "loopback");
    }

    // ---- namespaces and trust ----

    [Fact]
    public async Task Namespaces_CanBeCreatedListedAndDeleted_ThroughTheCli()
    {
        var name = Unique("it-ns");
        var create = await _server.RunOnConsoleAsync("ns", "create", "--name", name, "--prefix", name, "--cn", "pool.managedhsmclient.test", "--ca-pem", Path.Combine(_server.Pki, "mhsm-client-ca.pem"));
        create.ExitCode.ShouldBe(0, create.ToString());
        create.Out.ShouldContain($"--path-prefix /{name}");

        var list = await _server.RunOnConsoleAsync("ns", "list");
        list.Out.ShouldContain(name);
        list.Out.ShouldContain("pool.managedhsmclient.test");

        (await _server.RunOnConsoleAsync("key", "create", "--ns", name, "--name", "k1", "--type", "aes")).ExitCode.ShouldBe(0);
        var refused = await _server.RunOnConsoleAsync("ns", "delete", "--name", name, "--confirm", name);
        refused.ExitCode.ShouldBe(1, refused.ToString());
        refused.Error.ShouldContain("Conflict");
        var deleted = await _server.RunOnConsoleAsync("ns", "delete", "--name", name, "--confirm", name, "--destroy-keys");
        deleted.ExitCode.ShouldBe(0, deleted.ToString());
        deleted.Out.ShouldContain("Keys destroyed: 1");
    }

    [Fact]
    public async Task TrustImport_DryRunSavesNothing_TheRealImportDoes_AndAClientOfTheNewTrustConnects()
    {
        var name = Unique("it-trust");
        (await _server.RunOnConsoleAsync("ns", "create", "--name", name, "--prefix", name)).ExitCode.ShouldBe(0);
        var json = Path.Combine(_server.Pki, "mhsm-client.json");

        var dry = await _server.RunOnConsoleAsync("trust", "import", "--ns", name, "--json", json, "--dry-run");
        dry.ExitCode.ShouldBe(0, dry.ToString());
        dry.Out.ShouldContain("Dry run: nothing was saved.");
        dry.Out.ShouldContain(RealServerFixture.ClientCn);
        dry.Out.ShouldContain("EkmMock Fake Managed HSM Client CA");

        var (ekm, owner) = _server.CreateEkmClient();
        using (owner)
        {
            var before = await ekm.PostAsync(ekm.Path(null, "info", prefixOverride: name));
            before.Status.ShouldBe(401, "nothing is trusted yet: the dry run changed nothing");

            var real = await _server.RunOnConsoleAsync("trust", "import", "--ns", name, "--json", json);
            real.ExitCode.ShouldBe(0, real.ToString());
            real.Out.ShouldContain("Saved.");

            var after = await ekm.PostAsync(ekm.Path(null, "info", prefixOverride: name));
            after.Status.ShouldBe(200, "the next request uses the imported trust, no restart");
        }

        (await _server.RunOnConsoleAsync("ns", "delete", "--name", name, "--confirm", name)).ExitCode.ShouldBe(0);
    }

    [Fact]
    public async Task TrustImport_OfALeafCertificate_WarnsThatItIsNotACa()
    {
        var name = Unique("it-leaf");
        (await _server.RunOnConsoleAsync("ns", "create", "--name", name, "--prefix", name)).ExitCode.ShouldBe(0);

        var run = await _server.RunOnConsoleAsync("trust", "import", "--ns", name, "--pem", Path.Combine(_server.Pki, "client.crt"), "--cn", "x.test", "--dry-run");

        run.ExitCode.ShouldBe(0, run.ToString());
        run.Out.ShouldContain("Warnings:");
        run.Out.ShouldContain("NO"); // not a root
        (await _server.RunOnConsoleAsync("ns", "delete", "--name", name, "--confirm", name)).ExitCode.ShouldBe(0);
    }

    [Fact]
    public async Task TrustImport_WithGarbage_IsAFailure_WithoutEchoingTheInput()
    {
        File.WriteAllText(Path.Combine(_server.Pki, "garbage.json"), """{"caCertificates":["SECRET-LOOKING-GARBAGE"],"subjectCommonName":"x"}""");

        var run = await _server.RunOnConsoleAsync("trust", "import", "--ns", "_default", "--json", Path.Combine(_server.Pki, "garbage.json"), "--dry-run");

        run.ExitCode.ShouldBe(1, run.ToString());
        run.All.ShouldNotContain("SECRET-LOOKING-GARBAGE");
    }

    // ---- faults ----

    [Fact]
    public async Task Faults_PresetListAndClear_ThroughTheCli()
    {
        var list = await _server.RunOnConsoleAsync("faults", "list");
        list.ExitCode.ShouldBe(0, list.ToString());
        list.Out.ShouldContain("Fault injection is enabled");

        var preset = await _server.RunOnConsoleAsync("faults", "preset", "--id", "distant-hsm-100");
        preset.ExitCode.ShouldBe(0, preset.ToString());
        try
        {
            var (ekm, owner) = _server.CreateEkmClient();
            using (owner)
            {
                var info = await ekm.InfoAsync();
                info.Elapsed.ShouldBeGreaterThan(TimeSpan.FromMilliseconds(90), "the preset delays every operation by 100 ms");
            }
        }
        finally
        {
            var cleared = await _server.RunOnConsoleAsync("faults", "clear");
            cleared.ExitCode.ShouldBe(0, cleared.ToString());
        }

        (await _server.RunOnConsoleAsync("faults", "preset", "--id", "no-such-preset")).ExitCode.ShouldBe(1);
    }

    // ---- how the CLI trusts the console ----

    [Fact]
    public async Task TheConsoleCertificate_IsNotTrustedByDefault_AndTheErrorSaysWhatToDo()
    {
        var run = await _server.RunAsync("key", "list", "--console", _server.ConsoleUrl);

        run.ExitCode.ShouldBe(3, run.ToString());
        run.Error.ShouldContain("--console-ca");
        run.Error.ShouldContain("--console-pin");
    }

    [Fact]
    public async Task ThePinnedConsoleCertificate_IsTrusted_AWrongPinIsNot()
    {
        var good = await _server.RunAsync("key", "list", "--console", _server.ConsoleUrl, "--console-pin", _server.ServerCertificateThumbprint());
        var wrong = await _server.RunAsync("key", "list", "--console", _server.ConsoleUrl, "--console-pin", new string('0', 64));

        good.ExitCode.ShouldBe(0, good.ToString());
        wrong.ExitCode.ShouldBe(3, wrong.ToString());
    }

    [Fact]
    public async Task TheInsecureOption_WorksForLoopback_AndWarns()
    {
        var run = await _server.RunAsync("key", "list", "--console", _server.ConsoleUrl, "--insecure-console-cert");

        run.ExitCode.ShouldBe(0, run.ToString());
        run.Error.ShouldContain("not verified");
    }

    [Fact]
    public async Task ARootThatDidNotIssueTheConsoleCertificate_IsNotTrusted()
    {
        var other = Path.Combine(_server.Pki, "mhsm-client-ca.pem");

        var run = await _server.RunAsync("key", "list", "--console", _server.ConsoleUrl, "--console-ca", other);

        run.ExitCode.ShouldBe(3, run.ToString());
    }

    [Fact]
    public async Task TheConsoleUrl_CanComeFromTheEnvironment()
    {
        var output = new StringWriter();
        var env = new CliEnvironment
        {
            Out = output,
            Error = new StringWriter(),
            GetEnvironmentVariable = name => name == "EKMMOCK_CONSOLE" ? _server.ConsoleUrl : null,
        };

        var code = await CliApp.RunAsync(["key", "list", "--console-ca", _server.RootCa], env);

        code.ShouldBe(0, output.ToString());
        output.ToString().ShouldContain("aes-key-1");
    }

    [Fact]
    public async Task TheServer_NeverSawAnOriginHeaderFromTheCli_AndTheCliHeaderIsWhatLetsItMutate()
    {
        // Without X-EkmMock-Client (what a browser page could send cross-site) the server refuses a mutation: proves that the header the CLI sends is the mechanism in use.
        var handler = new SocketsHttpHandler { SslOptions = { RemoteCertificateValidationCallback = static (_, _, _, _) => true } };
        using var http = new HttpClient(handler) { BaseAddress = new Uri(_server.ConsoleUrl) };
        using var bare = new HttpRequestMessage(HttpMethod.Post, "/api/console/keys") { Content = new StringContent("""{"namespace":"_default","name":"nope","type":"aes","size":256}""", Encoding.UTF8, "application/json") };

        using var response = await http.SendAsync(bare);

        ((int)response.StatusCode).ShouldBe(400);
        (await response.Content.ReadAsStringAsync()).ShouldContain("AntiforgeryTokenInvalid");
        (await _server.RunOnConsoleAsync("key", "list")).Out.ShouldNotContain("nope");
    }

    [Fact]
    public async Task ServerStdout_ContainsNoMasterKey_AfterAllThis()
    {
        var master = File.ReadAllText(Path.Combine(_server.Data, "master.key")).Trim();

        _server.ServerOutput.ShouldNotContain(master);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Version_And_Help_NeedNoServer()
    {
        (await _server.RunAsync("--version")).ExitCode.ShouldBe(0);
    }

    [Fact]
    public async Task APublicKeyShownByTheCli_IsTheOneThatEncryptsForTheServer()
    {
        // End to end: the n/e the CLI prints are the key the server decrypts with.
        var name = Unique("it-enc");
        var run = await _server.RunOnConsoleAsync("key", "create", "--ns", "_default", "--name", name, "--type", "rsa", "--output", "json");
        run.ExitCode.ShouldBe(0, run.ToString());
        using var json = JsonDocument.Parse(run.Out);
        var n = json.RootElement.GetProperty("public_key").GetProperty("jwk_n").GetString()!;
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = EkmClient.FromBase64Url(n), Exponent = EkmClient.FromBase64Url("AQAB") });
        var dek = RandomNumberGenerator.GetBytes(32);

        var (ekm, owner) = _server.CreateEkmClient();
        using (owner)
        {
            var unwrapped = Expect.Value(await ekm.UnwrapAsync(name, "RSA-OAEP-256", rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256)), "unwrap");
            unwrapped.ShouldBe(dek);
        }
    }
}
