using System.CommandLine;
using System.CommandLine.Help;
using System.CommandLine.Invocation;
using EkmMock.Cli.Commands;
using EkmMock.Cli.ConsoleApi;

namespace EkmMock.Cli;

/// <summary>
/// The command line of <c>ekmmock</c> (spec 12): builds the command tree and runs it with the exit codes of <see cref="ExitCodes"/>. A parse error is a usage error (exit 2) with a hint,
/// a command that throws <see cref="CliException"/> exits with that exception's code and message, and no stack trace is shown unless <c>--verbose</c> is given.
/// </summary>
internal static class CliApp
{
    public const string Description =
        "ekmmock: command line tool of the EkmMock software HSM (test PKI only, never for real key protection).\n\n" +
        "Typical flow:\n" +
        "  ekmmock certs dev --out ./dev-pki --fqdn localhost       test PKI for a local server\n" +
        "  ekmmock init --data ./data                                master key and data folders\n" +
        "  ekmmock key create --ns _default --name aes-key-1 --type aes\n" +
        "  ekmmock trust import --ns _default --json mhsm-client.json\n" +
        "  ekmmock test conformance --url https://localhost:8443 --client-cert ./dev-pki/client.crt --client-key ./dev-pki/client.key --ca ./dev-pki/root-ca.pem\n\n" +
        ExitCodes.Documentation;

    public static async Task<int> RunAsync(string[] args, CliEnvironment env, CancellationToken cancellationToken = default)
    {
        var root = BuildRoot(env, out var global);
        ParseResult parse;
        try
        {
            parse = root.Parse(args);
        }
        catch (InvalidOperationException exception)
        {
            // A value that does not convert can surface as an exception from a validator; it is still a problem with the command line.
            env.Error.WriteLine("error: " + exception.Message.Split('\n')[0].TrimEnd('\r'));
            env.Error.WriteLine("Run 'ekmmock --help' for usage.");
            return ExitCodes.Usage;
        }


        // --help and --version win over parse errors (a command with required options must still show its help).
        if (parse.Errors.Count > 0 && parse.Action is not (DetailedHelpAction or VersionAction))
        {
            foreach (var error in parse.Errors)
            {
                env.Error.WriteLine("error: " + error.Message);
            }

            var path = string.Join(' ', new[] { "ekmmock" }.Concat(parse.CommandResult.Command is RootCommand ? [] : CommandPath(parse.CommandResult.Command)));
            env.Error.WriteLine($"Run '{path} --help' for usage.");
            return ExitCodes.Usage;
        }

        var configuration = new InvocationConfiguration { Output = env.Out, Error = env.Error, EnableDefaultExceptionHandler = false };
        try
        {
            return await parse.InvokeAsync(configuration, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            return Report(env, exception, parse.GetValue(global.Verbose));
        }
    }

    internal static CliCommandRoot BuildRoot(CliEnvironment env, out GlobalOptions global)
    {
        global = new GlobalOptions();
        var root = new CliCommandRoot(Description);
        root.Options.Add(global.Verbose);

        // The default --version prints the entry assembly's version; use our own so that the output is the tool's version whatever process hosts it.
        foreach (var option in root.Options.OfType<VersionOption>())
        {
            option.Action = new VersionAction(env);
        }

        root.Subcommands.Add(InitCommand.Create(env, global));
        root.Subcommands.Add(CertsCommands.Create(env, global));
        root.Subcommands.Add(KeyCommands.Create(env, global));
        root.Subcommands.Add(TrustCommands.Create(env, global));
        root.Subcommands.Add(NamespaceCommands.Create(env, global));
        root.Subcommands.Add(FaultCommands.Create(env, global));
        root.Subcommands.Add(TestCommands.Create(env, global));

        ShortenDescriptions(root);
        foreach (var option in root.Options.OfType<HelpOption>())
        {
            if (option.Action is SynchronousCommandLineAction standard)
            {
                option.Action = new DetailedHelpAction(env, standard);
            }
        }

        return root;
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<Command, string> Details = [];

    /// <summary>
    /// Every command is written with its full help text (description, examples, exit codes) in <see cref="Command.Description"/>. The list of commands in a parent's help would print all of it, so the
    /// first paragraph stays the description and the rest is printed at the end of the command's own help.
    /// </summary>
    private static void ShortenDescriptions(Command command)
    {
        if (command.Description is { } text && text.IndexOf("\n\n", StringComparison.Ordinal) is var split and > 0)
        {
            command.Description = text[..split];
            Details.Add(command, text[(split + 2)..]);
        }

        foreach (var sub in command.Subcommands)
        {
            ShortenDescriptions(sub);
        }
    }

    /// <summary>Runs <paramref name="body"/> and turns every failure into a message and an exit code. All command actions go through here.</summary>
    public static void SetAction(Command command, CliEnvironment env, GlobalOptions global, Func<ParseResult, CancellationToken, Task<int>> body)
        => command.SetAction(async (result, cancellationToken) =>
        {
            try
            {
                return await body(result, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                return Report(env, exception, result.GetValue(global.Verbose));
            }
        });

    internal static int Report(CliEnvironment env, Exception exception, bool verbose)
    {
        int code;
        string message;
        switch (exception)
        {
            case CliException cli:
                code = cli.ExitCode;
                message = cli.Message;
                break;
            case ConsoleApiException api:
                code = ExitCodes.Failure;
                message = $"{api.Code}: {api.Message}";
                break;
            case OperationCanceledException:
                code = ExitCodes.Failure;
                message = "Cancelled.";
                break;
            case IOException or UnauthorizedAccessException:
                code = ExitCodes.Failure;
                message = exception.Message;
                break;
            default:
                code = ExitCodes.Failure;
                message = $"Unexpected failure ({exception.GetType().Name}). Run again with --verbose for details.";
                break;
        }

        env.Error.WriteLine("error: " + message);
        if (verbose)
        {
            for (var inner = exception; inner is not null; inner = inner.InnerException)
            {
                env.Error.WriteLine($"  {inner.GetType().FullName}: {inner.Message}");
            }
        }

        return code;
    }

    private static IEnumerable<string> CommandPath(Command command)
    {
        var names = new Stack<string>();
        for (var current = (Symbol?)command; current is not null and not RootCommand; current = current.Parents.FirstOrDefault())
        {
            names.Push(current.Name);
        }

        return names;
    }

    /// <summary>The standard help, then the details (examples, exit codes) that <see cref="ShortenDescriptions"/> moved out of the description.</summary>
    private sealed class DetailedHelpAction : SynchronousCommandLineAction
    {
        private readonly CliEnvironment _env;
        private readonly SynchronousCommandLineAction _standard;

        public DetailedHelpAction(CliEnvironment env, SynchronousCommandLineAction standard)
        {
            _env = env;
            _standard = standard;
        }

        public override int Invoke(ParseResult parseResult)
        {
            var code = _standard.Invoke(parseResult);
            if (Details.TryGetValue(parseResult.CommandResult.Command, out var details))
            {
                _env.Out.WriteLine(details);
            }

            return code;
        }
    }
    private sealed class VersionAction : SynchronousCommandLineAction
    {
        private readonly CliEnvironment _env;

        public VersionAction(CliEnvironment env)
        {
            _env = env;
        }

        public override int Invoke(ParseResult parseResult)
        {
            _env.Out.WriteLine(CliVersion.Current);
            return ExitCodes.Success;
        }
    }
}

/// <summary>The root command (a type of its own only so that tests can reach the tree).</summary>
internal sealed class CliCommandRoot : RootCommand
{
    public CliCommandRoot(string description)
        : base(description)
    {
    }
}
