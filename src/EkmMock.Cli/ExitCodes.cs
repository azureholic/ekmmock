namespace EkmMock.Cli;

/// <summary>The exit codes of <c>ekmmock</c>, documented in <c>--help</c> and in DECISIONS.md.</summary>
internal static class ExitCodes
{
    /// <summary>The command did what it was asked to do (for <c>test conformance</c>: every test that ran passed).</summary>
    public const int Success = 0;

    /// <summary>The command ran and failed: a refused action, a failed conformance test, a failed bench threshold, an existing file that would be overwritten.</summary>
    public const int Failure = 1;

    /// <summary>The command line is wrong: unknown option, missing value, a value that does not parse, a confirmation that does not match.</summary>
    public const int Usage = 2;

    /// <summary>The server could not be reached or did not accept the caller: connection refused, TLS trust failure, 401/403 from the console.</summary>
    public const int Connection = 3;

    public const string Documentation =
        "Exit codes: 0 success, 1 failure (action refused, a test or threshold failed), 2 usage error (bad command line), 3 connection or authentication error.";
}

/// <summary>
/// A failure of a command with a message that is safe to print (never key material, tokens or stack traces) and the exit code to return. Thrown by command code, caught once in
/// <see cref="CliApp"/>.
/// </summary>
internal sealed class CliException : Exception
{
    public CliException(int exitCode, string message, Exception? inner = null)
        : base(message, inner)
    {
        ExitCode = exitCode;
    }

    public int ExitCode { get; }

    public static CliException Usage(string message) => new(ExitCodes.Usage, message);

    public static CliException Failure(string message, Exception? inner = null) => new(ExitCodes.Failure, message, inner);

    public static CliException Connection(string message, Exception? inner = null) => new(ExitCodes.Connection, message, inner);
}
