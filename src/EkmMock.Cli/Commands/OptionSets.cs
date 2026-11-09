using System.CommandLine;
using System.CommandLine.Parsing;
using EkmMock.Cli.ConsoleApi;

namespace EkmMock.Cli.Commands;

/// <summary>Options every command understands.</summary>
internal sealed class GlobalOptions
{
    public Option<bool> Verbose { get; } = new("--verbose") { Description = "Show details of a failure (exception type and inner messages; never secrets).", Recursive = true };
}

/// <summary>
/// The options that say how to reach the console API, shared by every command that calls it: <c>--console</c>, the TLS trust options and the sign-in options.
/// </summary>
internal sealed class ConsoleOptionSet
{
    public Option<string> ConsoleUrl { get; } = new("--console") { Description = $"Console base URL. Default: ${ConsoleSettings.UrlVariable} or {ConsoleSettings.DefaultUrl}." };

    public Option<string> ConsoleCa { get; } = new("--console-ca") { Description = "PEM file with the root CA(s) that issued the console's certificate (the only roots trusted; host name is checked)." };

    public Option<string> ConsolePin { get; } = new("--console-pin") { Description = "SHA-256 thumbprint (hex) of the console's certificate: trust exactly that certificate (for the throw-away --dev certificate)." };

    public Option<bool> InsecureConsoleCert { get; } = new("--insecure-console-cert") { Description = "Do not verify the console's certificate. Only accepted for a loopback console URL (127.0.0.1, ::1, localhost)." };

    public Option<string> Auth { get; } = new("--auth")
    {
        Description = "How to sign in: 'auto' (default: a token from EKMMOCK_CONSOLE_TOKEN, or device-code sign-in when --tenant and --client-id are known, else none), 'loopback' (no sign-in) or 'entra' (device-code sign-in).",
        DefaultValueFactory = _ => "auto",
    };

    public Option<string> Tenant { get; } = new("--tenant") { Description = $"Entra tenant id of the console's app registration (or ${ConsoleSettings.TenantVariable})." };

    public Option<string> ClientId { get; } = new("--client-id") { Description = $"Application (client) id of the console's app registration, which must allow public client flows (or ${ConsoleSettings.ClientIdVariable})." };

    public Option<string> Scope { get; } = new("--scope") { Description = $"Scope to request. Default: api://<client-id>/.default (or ${ConsoleSettings.ScopeVariable})." };

    public ConsoleOptionSet()
    {
        Auth.AcceptOnlyFromAmong("auto", "loopback", "entra");
    }

    public void AddTo(Command command)
    {
        command.Options.Add(ConsoleUrl);
        command.Options.Add(ConsoleCa);
        command.Options.Add(ConsolePin);
        command.Options.Add(InsecureConsoleCert);
        command.Options.Add(Auth);
        command.Options.Add(Tenant);
        command.Options.Add(ClientId);
        command.Options.Add(Scope);
    }

    /// <summary>True when the user asked for a console: <c>--console</c> or <c>EKMMOCK_CONSOLE</c> (commands where the console is optional use this instead of the default URL).</summary>
    public bool IsGiven(ParseResult result, CliEnvironment env)
        => result.GetResult(ConsoleUrl) is not null || !string.IsNullOrWhiteSpace(env.GetEnvironmentVariable(ConsoleSettings.UrlVariable));

    /// <summary>Resolves the options and the environment into settings. Throws a usage error for a bad URL or an incomplete Entra configuration.</summary>
    public ConsoleSettings Resolve(ParseResult result, CliEnvironment env)
    {
        var urlText = result.GetValue(ConsoleUrl) ?? env.GetEnvironmentVariable(ConsoleSettings.UrlVariable) ?? ConsoleSettings.DefaultUrl;
        if (!Uri.TryCreate(urlText, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
        {
            throw CliException.Usage($"--console must be an absolute https URL (for example {ConsoleSettings.DefaultUrl}), not '{urlText}'. The console only speaks HTTPS.");
        }

        var mode = (result.GetValue(Auth) ?? "auto") switch
        {
            "loopback" => ConsoleAuthMode.Loopback,
            "entra" => ConsoleAuthMode.Entra,
            _ => ConsoleAuthMode.Auto,
        };

        var token = env.GetEnvironmentVariable(ConsoleSettings.TokenVariable);
        var tenant = result.GetValue(Tenant) ?? env.GetEnvironmentVariable(ConsoleSettings.TenantVariable);
        var clientId = result.GetValue(ClientId) ?? env.GetEnvironmentVariable(ConsoleSettings.ClientIdVariable);
        EntraSettings? entra = null;
        if (!string.IsNullOrWhiteSpace(tenant) && !string.IsNullOrWhiteSpace(clientId))
        {
            var scope = result.GetValue(Scope) ?? env.GetEnvironmentVariable(ConsoleSettings.ScopeVariable) ?? EntraSettings.DefaultScope(clientId);
            entra = new EntraSettings(tenant, clientId, scope);
        }

        if (mode == ConsoleAuthMode.Entra && entra is null && string.IsNullOrWhiteSpace(token))
        {
            throw CliException.Usage($"--auth entra needs --tenant and --client-id (or ${ConsoleSettings.TenantVariable} and ${ConsoleSettings.ClientIdVariable}), or an access token in ${ConsoleSettings.TokenVariable}.");
        }

        if (mode == ConsoleAuthMode.Loopback)
        {
            token = null;
            entra = null;
        }

        return new ConsoleSettings(url, result.GetValue(ConsoleCa), result.GetValue(ConsolePin), result.GetValue(InsecureConsoleCert), mode, entra, string.IsNullOrWhiteSpace(token) ? null : token.Trim());
    }
}

/// <summary>
/// Validators run before default values are applied and before conversion errors are reported, so reading an option the usual way would see <c>default</c> for an option that was not given and throw for one that
/// did not convert. These helpers only look at values the user gave, and never throw.
/// </summary>
internal static class ValidatorSupport
{
    public static bool TryGiven<T>(this CommandResult result, Option<T> option, out T value)
    {
        value = default!;
        if (result.GetResult(option) is not { } optionResult)
        {
            return false;
        }

        try
        {
            value = optionResult.GetValueOrDefault<T>()!;
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    public static bool IsGiven<T>(this CommandResult result, Option<T> option) => result.GetResult(option) is not null;
}

/// <summary>The output format options of a command: human tables (default) or JSON for scripts.</summary>
internal sealed class OutputOptionSet
{
    public Option<string> Output { get; } = new("--output", "-o") { Description = "Output format: 'table' (default) or 'json'.", DefaultValueFactory = _ => "table" };

    public Option<bool>? JsonFlag { get; }

    public OutputOptionSet(bool withJsonFlag = true)
    {
        Output.AcceptOnlyFromAmong("table", "json");
        if (withJsonFlag)
        {
            JsonFlag = new Option<bool>("--json") { Description = "Same as --output json." };
        }
    }

    public void AddTo(Command command)
    {
        command.Options.Add(Output);
        if (JsonFlag is not null)
        {
            command.Options.Add(JsonFlag);
        }
    }

    public bool WantsJson(ParseResult result)
        => result.GetValue(Output) == "json" || (JsonFlag is not null && result.GetValue(JsonFlag));
}
