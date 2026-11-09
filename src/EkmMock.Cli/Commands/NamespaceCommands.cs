using System.CommandLine;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Infrastructure;
using EkmMock.Crypto;

namespace EkmMock.Cli.Commands;

/// <summary><c>ekmmock ns list|create|delete</c>: namespaces (path prefix, client trust, keys) through the console API.</summary>
internal static class NamespaceCommands
{
    public static Command Create(CliEnvironment env, GlobalOptions global)
    {
        var ns = new Command("ns", "Manage namespaces (a path prefix with its own client trust and keys).\n\nExamples:\n  ekmmock ns list\n  ekmmock ns create --name contoso --prefix contoso/prod --cn test.managedhsmclient.local --ca-pem client-ca.pem\n  ekmmock ns delete --name contoso --confirm contoso");
        ns.Subcommands.Add(CreateList(env, global));
        ns.Subcommands.Add(CreateCreate(env, global));
        ns.Subcommands.Add(CreateDelete(env, global));
        return ns;
    }

    private static Command CreateList(CliEnvironment env, GlobalOptions global)
    {
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var command = new Command("list", "List the namespaces with prefix, trusted CNs, CA count and key count.\n\nExample:\n  ekmmock ns list --output json");
        console.AddTo(command);
        output.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var namespaces = await client.ListNamespacesAsync(ct).ConfigureAwait(false);
            if (output.WantsJson(result))
            {
                env.Out.WriteLine(JsonSerializer.Serialize(new NamespaceList(namespaces), CliOutputJson.Default.NamespaceList));
                return ExitCodes.Success;
            }

            TableWriter.Write(
                env.Out,
                ["NAME", "PREFIX", "CLIENT CN", "CAS", "KEYS"],
                namespaces.Select(static n => (IReadOnlyList<string>)[n.Name, n.DisplayPrefix, string.Join(", ", n.SubjectCommonNames), n.CaCertificates.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), n.KeyCount.ToString(System.Globalization.CultureInfo.InvariantCulture)]));
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command CreateCreate(CliEnvironment env, GlobalOptions global)
    {
        var name = new Option<string>("--name") { Description = "Namespace name (letters, digits, '-' and '_').", Required = true };
        var prefix = new Option<string>("--prefix") { Description = "Path prefix (up to 64 characters of letters, digits, '-' and '/'). Empty is the default namespace.", DefaultValueFactory = _ => string.Empty };
        var cn = new Option<string[]>("--cn") { Description = "Allowed client certificate common name (repeat for several).", AllowMultipleArgumentsPerToken = true };
        var caPem = new Option<string[]>("--ca-pem") { Description = "PEM file with root CA certificate(s) of the clients (repeat for several files).", AllowMultipleArgumentsPerToken = true };
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var command = new Command("create", "Create a namespace.\n\nExample:\n  ekmmock ns create --name contoso --prefix contoso/prod --cn test.managedhsmclient.local --ca-pem client-ca.pem\n\nTo import the output of 'az keyvault ekm-connection certificate show' use 'ekmmock trust import'.");
        command.Options.Add(name);
        command.Options.Add(prefix);
        command.Options.Add(cn);
        command.Options.Add(caPem);
        console.AddTo(command);
        output.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            var nsName = result.GetRequiredValue(name);
            if (!EkmNames.IsValidNamespaceName(nsName))
            {
                throw CliException.Usage("--name must be 1 to 64 characters of letters, digits, '-' and '_'.");
            }

            if (!EkmNames.TryNormalizePrefix(result.GetValue(prefix), out var normalized, out var problem))
            {
                throw CliException.Usage("--prefix: " + problem);
            }

            var ders = new List<string>();
            foreach (var file in result.GetValue(caPem) ?? [])
            {
                var certificates = TlsTrust.LoadRoots(env.ResolvePath(file), "--ca-pem");
                ders.AddRange(certificates.Select(static c => Convert.ToBase64String(c.RawData)));
                foreach (var certificate in certificates)
                {
                    certificate.Dispose();
                }
            }

            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var created = await client.CreateNamespaceAsync(new NamespaceBody(nsName, normalized, result.GetValue(cn)?.ToList(), ders), ct).ConfigureAwait(false);
            if (output.WantsJson(result))
            {
                env.Out.WriteLine(JsonSerializer.Serialize(created, CliOutputJson.Default.NamespaceView));
            }
            else
            {
                env.Out.WriteLine($"Created namespace {created.Name} (prefix {created.DisplayPrefix}).");
                env.Out.WriteLine("Register it with Managed HSM: " + created.AzCommand);
                foreach (var warning in created.Warnings)
                {
                    env.Out.WriteLine("  - " + warning);
                }
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command CreateDelete(CliEnvironment env, GlobalOptions global)
    {
        var name = new Option<string>("--name") { Description = "Namespace to delete.", Required = true };
        var confirm = new Option<string>("--confirm") { Description = "Type the namespace name again to confirm.", Required = true };
        var destroyKeys = new Option<bool>("--destroy-keys") { Description = "Also destroy every key in the namespace (irreversible). Without it a namespace that still has keys is refused." };
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var command = new Command("delete", "Delete a namespace.\n\nExample:\n  ekmmock ns delete --name contoso --confirm contoso");
        command.Options.Add(name);
        command.Options.Add(confirm);
        command.Options.Add(destroyKeys);
        console.AddTo(command);
        output.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            var nsName = result.GetRequiredValue(name);
            if (!string.Equals(result.GetRequiredValue(confirm), nsName, StringComparison.Ordinal))
            {
                throw CliException.Usage($"--confirm must repeat the namespace name exactly ('{nsName}'). Nothing was changed.");
            }

            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var deleted = await client.DeleteNamespaceAsync(nsName, new DeleteNamespaceBody(nsName, result.GetValue(destroyKeys)), ct).ConfigureAwait(false);
            if (output.WantsJson(result))
            {
                env.Out.WriteLine(JsonSerializer.Serialize(deleted, CliOutputJson.Default.NamespaceDeleted));
            }
            else
            {
                env.Out.WriteLine($"Deleted namespace {nsName}. Keys destroyed: {deleted.DestroyedKeys}.");
            }

            return ExitCodes.Success;
        });
        return command;
    }
}
