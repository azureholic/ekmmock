#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using Azure.Core;
using EkmMock.Cli;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Server.WebConsole;

namespace EkmMock.Server.Tests;

/// <summary>
/// M8, open question 38, end to end: the real CLI (<see cref="CliApp"/>, the same code as the executable) signs in with a device-code credential, sends the token as a bearer, and the in-process EntraId console
/// (real Kestrel, production JWT bearer scheme with a locally signed token instead of a tenant) accepts or refuses it. The only fake part is the credential that mints the token; a real tenant is not available offline.
/// </summary>
public sealed class CliBearerEndToEndTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;
    private string _caFile = null!;
    private string _folder = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync(entra: true, testAuthScheme: false, configureServices: ConsoleBearerTests.UseLocalSigningKey);
        _folder = Path.Combine(Path.GetTempPath(), "ekmmock-cli-bearer-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_folder);
        _caFile = Path.Combine(_folder, "root-ca.pem");
        File.WriteAllText(_caFile, _host.Pki.ServerCa.CertificatePem);
    }

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        Directory.Delete(_folder, recursive: true);
    }

    private sealed class MintingCredential : TokenCredential
    {
        private readonly Func<string> _mint;

        public MintingCredential(Func<string> mint)
        {
            _mint = mint;
        }

        public int Calls { get; private set; }

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Calls++;
            return new AccessToken(_mint(), DateTimeOffset.UtcNow.AddMinutes(30));
        }

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }

    private async Task<(int Exit, string Out, string Error, int SignIns)> RunAsync(Func<string> mint, params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var credential = new MintingCredential(mint);
        var env = new CliEnvironment
        {
            Out = output,
            Error = error,
            GetEnvironmentVariable = static _ => null,
            WorkingDirectory = _folder,
            CredentialFactory = (_, _) => credential,
        };
        var code = await CliApp.RunAsync(
            [.. args, "--console", $"https://127.0.0.1:{_host.Host.ConsolePort}", "--console-ca", _caFile, "--tenant", ConsoleTestHost.TenantId, "--client-id", ConsoleBearerTests.ClientId],
            env);
        return (code, output.ToString(), error.ToString(), credential.Calls);
    }

    [Fact]
    public async Task AnAllowedUsersDeviceCodeToken_LetsTheCliListAndCreateKeys_AndTheAuditNamesTheUser()
    {
        var token = ConsoleBearerTests.Token(name: "Alice Admin");

        var list = await RunAsync(() => token, "key", "list");
        var create = await RunAsync(() => token, "key", "create", "--ns", "_default", "--name", "cli-bearer-key", "--type", "aes");

        list.Exit.ShouldBe(0, list.Error);
        list.Out.ShouldContain("aes-key-1");
        create.Exit.ShouldBe(0, create.Error);
        create.SignIns.ShouldBe(1, "one sign-in serves the create and the follow-up read of the same command");
        using var console = _host.Host.CreateConsoleClient();
        var audit = await new AdminApi(console).GetAsync("/api/console/audit?action=key.create", request => request.Headers.Authorization = new("Bearer", token));
        audit.Text.ShouldContain("cli-bearer-key");
        audit.Text.ShouldContain($"Alice Admin ({ConsoleTestHost.AllowedOid})");
        (list.Out + list.Error + create.Out + create.Error).ShouldNotContain(token);
    }

    [Fact]
    public async Task ATokenOfAUserWhoIsNotOnTheAllowList_IsRefused_WithExitCode3()
    {
        var run = await RunAsync(() => ConsoleBearerTests.Token(oid: ConsoleTestHost.OtherOid), "key", "list");

        run.Exit.ShouldBe(3, run.Error);
        run.Error.ShouldContain("403");
    }

    [Fact]
    public async Task ATokenForAnotherAudience_IsRejected_AsAnInvalidToken()
    {
        var run = await RunAsync(() => ConsoleBearerTests.Token(audience: "api://99999999-9999-9999-9999-999999999999"), "key", "list");

        run.Exit.ShouldBe(3, run.Error);
        run.Error.ShouldContain("rejected the access token");
    }

    [Fact]
    public async Task WithoutAnySignIn_TheEntraConsoleAnswers401_AndTheCliExplainsHowToSignIn()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var env = new CliEnvironment { Out = output, Error = error, GetEnvironmentVariable = static _ => null, WorkingDirectory = _folder };

        var code = await CliApp.RunAsync(["key", "list", "--console", $"https://127.0.0.1:{_host.Host.ConsolePort}", "--console-ca", _caFile], env);

        code.ShouldBe(3, error.ToString());
        error.ToString().ShouldContain("--tenant");
    }

    [Fact]
    public async Task ATokenFromTheEnvironment_WorksToo_ForScripts()
    {
        var token = ConsoleBearerTests.Token();
        var output = new StringWriter();
        var error = new StringWriter();
        var env = new CliEnvironment
        {
            Out = output,
            Error = error,
            GetEnvironmentVariable = name => name == ConsoleSettings.TokenVariable ? token : null,
            WorkingDirectory = _folder,
        };

        var code = await CliApp.RunAsync(["key", "list", "--console", $"https://127.0.0.1:{_host.Host.ConsolePort}", "--console-ca", _caFile], env);

        code.ShouldBe(0, error.ToString());
        output.ToString().ShouldContain("rsa-key-1");
    }
}
