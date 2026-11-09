using System.CommandLine;
using System.Text.Json;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Commands;

/// <summary><c>ekmmock faults list|preset|delete|clear</c>: fault injection (spec 10.2) through the console API. The server must run with <c>EKMMOCK_ENABLE_FAULTS=true</c> for any change.</summary>
internal static class FaultCommands
{
    public static Command Create(CliEnvironment env, GlobalOptions global)
    {
        var faults = new Command("faults", "Fault injection of a running EkmMock (needs EKMMOCK_ENABLE_FAULTS=true on the server).\n\nExamples:\n  ekmmock faults list\n  ekmmock faults preset --id distant-hsm-260\n  ekmmock faults preset --id hsm-offline\n  ekmmock faults clear");
        faults.Subcommands.Add(CreateList(env, global));
        faults.Subcommands.Add(CreatePreset(env, global));
        faults.Subcommands.Add(CreateDelete(env, global));
        faults.Subcommands.Add(CreateClear(env, global));
        return faults;
    }

    private static Command CreateList(CliEnvironment env, GlobalOptions global)
    {
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var command = new Command("list", "List the fault rules and the presets.\n\nExample:\n  ekmmock faults list");
        console.AddTo(command);
        output.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var list = await client.ListFaultsAsync(ct).ConfigureAwait(false);
            if (output.WantsJson(result))
            {
                env.Out.WriteLine(JsonSerializer.Serialize(list, CliOutputJson.Default.FaultList));
                return ExitCodes.Success;
            }

            env.Out.WriteLine(list.Enabled ? $"Fault injection is enabled. {list.ActiveRules} active rule(s) of {list.MaxRules}.{(list.HsmOffline ? " HSM OFFLINE is on." : string.Empty)}" : "Fault injection is DISABLED on this server (start it with EKMMOCK_ENABLE_FAULTS=true).");
            if (list.Rules.Count > 0)
            {
                TableWriter.Write(env.Out, ["ID", "STATE", "KIND", "SCOPE", "PARAMETERS", "FIRED"], list.Rules.Select(static r => (IReadOnlyList<string>)[r.Id, r.State, r.Kind, r.Scope, r.Parameters, r.Fired.ToString(System.Globalization.CultureInfo.InvariantCulture)]));
            }

            env.Out.WriteLine();
            env.Out.WriteLine("Presets: " + string.Join(", ", list.Presets.Select(static p => p.Id)));
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command CreatePreset(CliEnvironment env, GlobalOptions global)
    {
        var id = new Option<string>("--id") { Description = "Preset id: distant-hsm-100, distant-hsm-200, distant-hsm-260, hsm-offline or error-503-50.", Required = true };
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var command = new Command("preset", "Apply a ready-made fault rule (global scope).\n\nExample:\n  ekmmock faults preset --id distant-hsm-260");
        command.Options.Add(id);
        console.AddTo(command);
        output.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var rule = await client.ApplyFaultPresetAsync(result.GetRequiredValue(id), ct).ConfigureAwait(false);
            Print(env, output.WantsJson(result), rule, $"Rule {rule.Id} created: {rule.Kind} {rule.Parameters} ({rule.Scope}). Remove it with: ekmmock faults delete --id {rule.Id}");
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command CreateDelete(CliEnvironment env, GlobalOptions global)
    {
        var id = new Option<string>("--id") { Description = "Rule id, for example f1.", Required = true };
        var console = new ConsoleOptionSet();
        var command = new Command("delete", "Delete one fault rule.\n\nExample:\n  ekmmock faults delete --id f1");
        command.Options.Add(id);
        console.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            await client.DeleteFaultAsync(result.GetRequiredValue(id), ct).ConfigureAwait(false);
            env.Out.WriteLine($"Rule {result.GetRequiredValue(id)} deleted.");
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command CreateClear(CliEnvironment env, GlobalOptions global)
    {
        var console = new ConsoleOptionSet();
        var command = new Command("clear", "Remove every fault rule.\n\nExample:\n  ekmmock faults clear");
        console.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var cleared = await client.ClearFaultsAsync(ct).ConfigureAwait(false);
            env.Out.WriteLine($"{cleared.Removed} rule(s) removed.");
            return ExitCodes.Success;
        });
        return command;
    }

    private static void Print(CliEnvironment env, bool json, FaultRuleView rule, string text)
    {
        if (json)
        {
            env.Out.WriteLine(JsonSerializer.Serialize(rule, CliOutputJson.Default.FaultRuleView));
        }
        else
        {
            env.Out.WriteLine(text);
        }
    }
}
