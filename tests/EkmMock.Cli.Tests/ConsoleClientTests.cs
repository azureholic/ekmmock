using System.Text.Json;
using Azure.Core;

namespace EkmMock.Cli.Tests;

/// <summary>
/// The CLI's way into <c>/api/console/*</c> (spec 12, M6 CSRF mechanism, open question 38): the header of a non-browser client, never an <c>Origin</c>, a bearer token only when there is one, and
/// failures that become exit codes. A scripted handler stands in for the server here; the real server is exercised in <see cref="RealServerCliTests"/>.
/// </summary>
public sealed class ConsoleClientTests : IDisposable
{
    private const string KeyJson = """{"namespace":"_default","name":"k","type":"oct","size":256,"state":"Enabled","origin":"Generated","created_at":"2026-01-01T00:00:00+00:00","wrap_count":0,"unwrap_count":0}""";
    private const string DetailJson = $$"""{"key":{{KeyJson}},"az_command":"az keyvault key create --hsm-name <hsm> --name <ref-name> --external-key-id k","routing_note":"note"}""";

    private readonly CliHarness _cli = new();

    public void Dispose() => _cli.Dispose();

    private StubHandler Stub(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        var handler = new StubHandler(respond);
        _cli.ConsoleHandler = () => handler;
        return handler;
    }

    [Fact]
    public async Task EveryRequest_CarriesTheNonBrowserHeader_AndNeverAnOrigin()
    {
        var stub = Stub(r => r.Method == HttpMethod.Get && r.RequestUri!.AbsolutePath.StartsWith("/api/console/keys/", StringComparison.Ordinal) ? StubHandler.Json(200, DetailJson) : StubHandler.Json(201, KeyJson));

        var run = await _cli.RunAsync("key", "create", "--name", "k", "--type", "aes");

        run.ExitCode.ShouldBe(0, run.ToString());
        stub.Requests.Count.ShouldBe(2);
        foreach (var request in stub.Requests)
        {
            request.Headers.ShouldContainKey("X-EkmMock-Client");
            request.Headers["X-EkmMock-Client"].ShouldStartWith("ekmmock-cli/");
            request.Headers.ShouldNotContainKey("Origin");
            request.Headers.ShouldNotContainKey("Authorization");
        }
    }

    [Fact]
    public async Task KeyCreate_SendsTheSnakeCaseBody_ToTheKeysEndpoint()
    {
        var stub = Stub(r => r.Method == HttpMethod.Get ? StubHandler.Json(200, DetailJson) : StubHandler.Json(201, KeyJson));

        await _cli.RunAsync("key", "create", "--ns", "contoso", "--name", "rsa-1", "--type", "rsa", "--size", "3072", "--allow-reuse-of-destroyed-name");

        var post = stub.Requests.First(static r => r.Method == "POST");
        post.Path.ShouldBe("/api/console/keys");
        using var body = JsonDocument.Parse(post.Body!);
        body.RootElement.GetProperty("namespace").GetString().ShouldBe("contoso");
        body.RootElement.GetProperty("name").GetString().ShouldBe("rsa-1");
        body.RootElement.GetProperty("type").GetString().ShouldBe("rsa");
        body.RootElement.GetProperty("size").GetInt32().ShouldBe(3072);
        body.RootElement.GetProperty("allow_reuse_of_destroyed_name").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task KeyDestroy_SendsTheConfirmationToTheServerToo()
    {
        var stub = Stub(_ => StubHandler.Json(200, KeyJson.Replace("Enabled", "Destroyed", StringComparison.Ordinal)));

        var run = await _cli.RunAsync("key", "destroy", "--ns", "_default", "--name", "k", "--confirm", "k");

        run.ExitCode.ShouldBe(0, run.ToString());
        stub.Requests.Single().Path.ShouldBe("/api/console/keys/_default/k/destroy");
        using var body = JsonDocument.Parse(stub.Requests.Single().Body!);
        body.RootElement.GetProperty("confirm_name").GetString().ShouldBe("k");
        run.Out.ShouldContain("DESTROYED");
    }

    [Fact]
    public async Task KeyExpire_SendsTheTimeInUtc_OrNullToClear()
    {
        var stub = Stub(_ => StubHandler.Json(200, KeyJson));

        await _cli.RunAsync("key", "expire", "--name", "k", "--at", "2030-01-01T02:00:00+02:00");
        await _cli.RunAsync("key", "expire", "--name", "k", "--clear");

        using var first = JsonDocument.Parse(stub.Requests[0].Body!);
        first.RootElement.GetProperty("not_after").GetDateTimeOffset().ShouldBe(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using var second = JsonDocument.Parse(stub.Requests[1].Body!);
        second.RootElement.TryGetProperty("not_after", out _).ShouldBeFalse();
    }

    [Fact]
    public async Task KeyNames_AreEscapedInThePath()
    {
        var stub = Stub(_ => StubHandler.Json(200, KeyJson));

        await _cli.RunAsync("key", "enable", "--ns", "my ns", "--name", "k");

        stub.Requests.Single().Path.ShouldBe("/api/console/keys/my%20ns/k/enable");
    }

    [Fact]
    public async Task ABearerToken_FromTheEnvironment_IsSentAsAuthorization()
    {
        _cli.Environment = name => name == "EKMMOCK_CONSOLE_TOKEN" ? "env-token-value" : null;
        var stub = Stub(_ => StubHandler.Json(200, """{"keys":[]}"""));

        var run = await _cli.RunAsync("key", "list");

        run.ExitCode.ShouldBe(0, run.ToString());
        stub.Requests.Single().Headers["Authorization"].ShouldBe("Bearer env-token-value");
        run.All.ShouldNotContain("env-token-value");
    }

    [Fact]
    public async Task AuthLoopback_IgnoresATokenInTheEnvironment()
    {
        _cli.Environment = name => name == "EKMMOCK_CONSOLE_TOKEN" ? "env-token-value" : null;
        var stub = Stub(_ => StubHandler.Json(200, """{"keys":[]}"""));

        await _cli.RunAsync("key", "list", "--auth", "loopback");

        stub.Requests.Single().Headers.ShouldNotContainKey("Authorization");
    }

    [Fact]
    public async Task DeviceCodeSignIn_AsksTheCredentialOnce_PrintsThePromptToStderr_AndSendsTheTokenAsBearer()
    {
        var credential = new FakeCredential("device-code-access-token");
        var stub = Stub(r => r.Method == HttpMethod.Get ? StubHandler.Json(200, DetailJson) : StubHandler.Json(201, KeyJson));
        Action<string>? prompt = null;
        _cli.Credential = (settings, show) =>
        {
            prompt = show;
            settings.TenantId.ShouldBe("44444444-4444-4444-4444-444444444444");
            settings.ClientId.ShouldBe("55555555-5555-5555-5555-555555555555");
            return credential;
        };

        var run = await _cli.RunAsync("key", "create", "--name", "k", "--type", "aes", "--tenant", "44444444-4444-4444-4444-444444444444", "--client-id", "55555555-5555-5555-5555-555555555555");

        run.ExitCode.ShouldBe(0, run.ToString());
        prompt.ShouldNotBeNull();
        stub.Requests.Count.ShouldBe(2);
        stub.Requests.ShouldAllBe(static r => r.Headers["Authorization"] == "Bearer device-code-access-token");
        credential.Calls.ShouldBe(1, "the token is kept in memory for the following requests");
        credential.Scopes.Single().ShouldBe(["api://55555555-5555-5555-5555-555555555555/.default"]);
        run.All.ShouldNotContain("device-code-access-token");
    }

    [Fact]
    public async Task DeviceCodeSignIn_UsesTheScopeThatWasGiven()
    {
        var credential = new FakeCredential("t");
        Stub(_ => StubHandler.Json(200, """{"keys":[]}"""));
        _cli.Credential = (_, _) => credential;

        await _cli.RunAsync("key", "list", "--tenant", "t", "--client-id", "c", "--scope", "api://c/access_as_user");

        credential.Scopes.Single().ShouldBe(["api://c/access_as_user"]);
    }

    [Fact]
    public async Task ADeviceCodeSignIn_ThatFails_IsAConnectionError_WithoutTheStackTrace()
    {
        Stub(_ => StubHandler.Json(200, "{}"));
        _cli.Credential = (_, _) => new ThrowingCredential();

        var run = await _cli.RunAsync("key", "list", "--tenant", "t", "--client-id", "c");

        run.ExitCode.ShouldBe(3, run.ToString());
        run.Error.ShouldContain("Entra sign-in failed");
        run.All.ShouldNotContain("   at ");
    }

    [Fact]
    public async Task The401OfAnEntraConsole_WithoutASignIn_ExplainsHowToSignIn_AndExitsWith3()
    {
        Stub(_ => StubHandler.Json(401, ""));

        var run = await _cli.RunAsync("key", "list");

        run.ExitCode.ShouldBe(3, run.ToString());
        run.Error.ShouldContain("--tenant");
        run.Error.ShouldContain("EKMMOCK_CONSOLE_TOKEN");
    }

    [Fact]
    public async Task The401_WithAToken_SaysTheTokenWasRejected()
    {
        _cli.Environment = name => name == "EKMMOCK_CONSOLE_TOKEN" ? "tok-9f3a-sentinel" : null;
        Stub(_ => StubHandler.Json(401, ""));

        var run = await _cli.RunAsync("key", "list");

        run.ExitCode.ShouldBe(3, run.ToString());
        run.Error.ShouldContain("rejected the access token");
        run.All.ShouldNotContain("tok-9f3a-sentinel");
    }

    [Fact]
    public async Task The403_IsAConnectionError_NotAFailureOfTheAction()
    {
        Stub(_ => StubHandler.Json(403, """{"code":"Forbidden","message":"not on the allow-list"}"""));

        var run = await _cli.RunAsync("key", "list");

        run.ExitCode.ShouldBe(3, run.ToString());
        run.Error.ShouldContain("not on the allow-list");
    }

    [Fact]
    public async Task AnErrorBodyOfTheServer_BecomesExitCode1_WithTheServersWords()
    {
        Stub(_ => StubHandler.Json(409, """{"code":"Conflict","message":"A key with this name already exists."}"""));

        var run = await _cli.RunAsync("key", "create", "--name", "k", "--type", "aes");

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain("Conflict: A key with this name already exists.");
        run.All.ShouldNotContain("   at ");
    }

    [Fact]
    public async Task ANonJsonAnswer_IsReportedAsNotAnEkmMockConsole()
    {
        Stub(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent("<html>proxy</html>") });

        var run = await _cli.RunAsync("key", "list");

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain("EkmMock console");
    }

    [Fact]
    public async Task ANotFoundWithAProxyPage_DoesNotCrash()
    {
        Stub(_ => new HttpResponseMessage(System.Net.HttpStatusCode.NotFound) { Content = new StringContent("<html>404</html>") });

        var run = await _cli.RunAsync("key", "list");

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain("NotFound");
    }

    [Fact]
    public async Task ConnectionRefused_IsExitCode3_WithAnActionableMessage()
    {
        // No stub: the real handler tries a port nothing listens on (a closed local port).
        var port = Net.FreePort();

        var run = await _cli.RunAsync("key", "list", "--console", $"https://127.0.0.1:{port}");

        run.ExitCode.ShouldBe(3, run.ToString());
        run.Error.ShouldContain("Cannot reach the console");
        run.All.ShouldNotContain("   at ");
    }

    [Fact]
    public async Task Verbose_ShowsTheExceptionChain_WithoutItNoStackIsShown()
    {
        var port = Net.FreePort();

        var plain = await _cli.RunAsync("key", "list", "--console", $"https://127.0.0.1:{port}");
        var verbose = await _cli.RunAsync("key", "list", "--console", $"https://127.0.0.1:{port}", "--verbose");

        plain.Error.ShouldNotContain("System.");
        verbose.Error.ShouldContain("EkmMock.Cli.CliException");
        verbose.Error.ShouldContain("System.Net.Http.HttpRequestException");
    }

    [Fact]
    public async Task KeyList_TableOutput_ListsTheKeys_AndJsonOutputIsParsable()
    {
        Stub(_ => StubHandler.Json(200, $$"""{"keys":[{{KeyJson}}]}"""));

        var table = await _cli.RunAsync("key", "list");
        var json = await _cli.RunAsync("key", "list", "--output", "json");
        var jsonFlag = await _cli.RunAsync("key", "list", "--json");

        table.Out.ShouldContain("NAMESPACE");
        table.Out.ShouldContain("AES-256");
        table.Out.ShouldContain("Enabled");
        using var parsed = JsonDocument.Parse(json.Out);
        parsed.RootElement.GetProperty("keys")[0].GetProperty("name").GetString().ShouldBe("k");
        jsonFlag.Out.ShouldBe(json.Out);
    }

    [Fact]
    public async Task KeyCreate_ForRsa_PrintsThePublicKey_TheAzCommandWithTheGivenNames_AndNoSecretField()
    {
        const string detail = """{"key":{"namespace":"_default","name":"rsa-1","type":"RSA","size":2048,"state":"Enabled","origin":"Generated","created_at":"2026-01-01T00:00:00+00:00","wrap_count":0,"unwrap_count":0},"public_key":{"pem":"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----","jwk_n":"NNNN","jwk_e":"AQAB","jwk":"{}"},"az_command":"az keyvault key create --hsm-name <hsm> --name <ref-name> --external-key-id rsa-1","routing_note":"r"}""";
        Stub(r => r.Method == HttpMethod.Get ? StubHandler.Json(200, detail) : StubHandler.Json(201, KeyJson));

        var run = await _cli.RunAsync("key", "create", "--name", "rsa-1", "--type", "rsa", "--hsm", "myhsm", "--ref-name", "ekm-rsa");

        run.Out.ShouldContain("n: NNNN");
        run.Out.ShouldContain("e: AQAB");
        run.Out.ShouldContain("BEGIN PUBLIC KEY");
        run.Out.ShouldContain("az keyvault key create --hsm-name myhsm --name ekm-rsa --external-key-id rsa-1");
        run.Out.ShouldNotContain("PRIVATE", Case.Sensitive);
    }

    [Fact]
    public async Task TrustImport_SendsTheFileContent_AndThePreviewIsPrinted_WithWarnings()
    {
        File.WriteAllText(_cli.File("mhsm.json"), """{"caCertificates":["MIIB"],"subjectCommonName":"x.managedhsmclient.test"}""");
        const string preview = """{"namespace":"_default","format":"json","mode":"merge","subject_common_names":["x.managedhsmclient.test"],"ca_certificates":[{"subject":"CN=Issuing CA","issuer":"CN=Root","not_before":"2026-01-01T00:00:00+00:00","not_after":"2030-01-01T00:00:00+00:00","thumbprint_sha256":"AB","is_self_signed":false,"is_ca":true,"is_expired":false,"is_not_yet_valid":false,"is_console_test_ca":false,"warnings":["not a root CA"],"der_base64":"MIIB"}],"warnings":["check it"],"resulting_subject_common_names":["x.managedhsmclient.test"],"resulting_ca_count":1,"saved":false}""";
        var stub = Stub(_ => StubHandler.Json(200, preview));

        var run = await _cli.RunAsync("trust", "import", "--ns", "_default", "--json", _cli.File("mhsm.json"), "--dry-run");

        run.ExitCode.ShouldBe(0, run.ToString());
        var request = stub.Requests.Single();
        request.Path.ShouldBe("/api/console/namespaces/_default/trust/import");
        using var body = JsonDocument.Parse(request.Body!);
        body.RootElement.GetProperty("format").GetString().ShouldBe("json");
        body.RootElement.GetProperty("dry_run").GetBoolean().ShouldBeTrue();
        body.RootElement.GetProperty("content").GetString()!.ShouldContain("subjectCommonName");
        run.Out.ShouldContain("Dry run: nothing was saved.");
        run.Out.ShouldContain("not a root CA");
        run.Out.ShouldContain("check it");
        run.Out.ShouldContain("NO"); // the ROOT column flags a CA that is not self-signed
    }

    [Fact]
    public async Task TrustImport_WithPem_SendsTheCnList()
    {
        File.WriteAllText(_cli.File("ca.pem"), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
        var stub = Stub(_ => StubHandler.Json(200, """{"namespace":"n","format":"pem","mode":"replace","subject_common_names":["a","b"],"ca_certificates":[],"warnings":[],"resulting_subject_common_names":["a","b"],"resulting_ca_count":0,"saved":true}"""));

        var run = await _cli.RunAsync("trust", "import", "--ns", "n", "--pem", _cli.File("ca.pem"), "--cn", "a", "--cn", "b", "--mode", "replace");

        run.ExitCode.ShouldBe(0, run.ToString());
        using var body = JsonDocument.Parse(stub.Requests.Single().Body!);
        body.RootElement.GetProperty("format").GetString().ShouldBe("pem");
        body.RootElement.GetProperty("subject_common_names").EnumerateArray().Select(static e => e.GetString()).ShouldBe(["a", "b"]);
        body.RootElement.GetProperty("mode").GetString().ShouldBe("replace");
        run.Out.ShouldContain("Saved.");
    }

    private sealed class ThrowingCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new Azure.Identity.AuthenticationFailedException("AADSTS70000: the user declined\r\nTrace ID: abc");

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new Azure.Identity.AuthenticationFailedException("AADSTS70000: the user declined\r\nTrace ID: abc");
    }
}

internal static class Net
{
    public static int FreePort()
    {
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        return ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
    }
}
