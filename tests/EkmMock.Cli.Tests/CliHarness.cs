using System.Text;
using EkmMock.TestSupport;

namespace EkmMock.Cli.Tests;

/// <summary>The result of running one CLI command in process: exit code and everything it printed.</summary>
internal sealed record CliRun(int ExitCode, string Out, string Error)
{
    public string All => Out + "\n" + Error;

    public override string ToString() => $"exit {ExitCode}\n--- stdout ---\n{Out}\n--- stderr ---\n{Error}";
}

/// <summary>Runs <c>ekmmock</c> commands in process (same code path as the executable: <see cref="CliApp.RunAsync"/>) with captured output and a private working directory.</summary>
internal sealed class CliHarness : IDisposable
{
    private readonly TempFolder _folder = new("ekmmock-cli");

    public string Folder => _folder.Path;

    public string File(string name) => _folder.File(name);

    public Func<string, string?> Environment { get; set; } = static _ => null;

    public Func<System.Net.Http.HttpMessageHandler>? ConsoleHandler { get; set; }

    public Func<ConsoleApi.EntraSettings, Action<string>, Azure.Core.TokenCredential>? Credential { get; set; }

    public async Task<CliRun> RunAsync(params string[] args)
    {
        var output = new StringWriter(new StringBuilder());
        var error = new StringWriter(new StringBuilder());
        var env = new CliEnvironment
        {
            Out = output,
            Error = error,
            GetEnvironmentVariable = Environment,
            WorkingDirectory = _folder.Path,
            ConsoleHandlerFactory = ConsoleHandler,
            CredentialFactory = Credential,
        };
        var code = await CliApp.RunAsync(args, env);
        return new CliRun(code, output.ToString(), error.ToString());
    }

    public void Dispose() => _folder.Dispose();
}
