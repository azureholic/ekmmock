using System.Net.Http;
using Azure.Core;
using EkmMock.Cli.ConsoleApi;

namespace EkmMock.Cli;

/// <summary>
/// Everything a command touches outside its own arguments: the two output streams, the environment variables, the clock and the seams the tests replace (the sign-in credential and the
/// console HTTP handler). The commands never use <see cref="Console"/> or <see cref="Environment"/> directly, so a test can run any command in process and read exactly what it printed.
/// </summary>
internal sealed class CliEnvironment
{
    public required TextWriter Out { get; init; }

    public required TextWriter Error { get; init; }

    public Func<string, string?> GetEnvironmentVariable { get; init; } = Environment.GetEnvironmentVariable;

    public TimeProvider Time { get; init; } = TimeProvider.System;

    /// <summary>Creates the credential for the Entra device-code sign-in. Tests supply a fake; production uses <c>DeviceCodeCredential</c> with an in-memory token cache.</summary>
    public Func<EntraSettings, Action<string>, TokenCredential>? CredentialFactory { get; init; }

    /// <summary>Replaces the HTTP handler of the console client (unit tests of the client). Null in production: the handler is built from the TLS trust options.</summary>
    public Func<HttpMessageHandler>? ConsoleHandlerFactory { get; init; }

    /// <summary>Where a relative path starts. Tests set it to a temp folder.</summary>
    public string WorkingDirectory { get; init; } = Environment.CurrentDirectory;

    public static CliEnvironment System() => new() { Out = Console.Out, Error = Console.Error };

    public string ResolvePath(string path) => Path.GetFullPath(path, WorkingDirectory);
}
