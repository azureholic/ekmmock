using System.CommandLine;
using System.Globalization;
using System.Text.Json;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Infrastructure;
using EkmMock.Crypto;

namespace EkmMock.Cli.Commands;

/// <summary>
/// <c>ekmmock key create|list|show|enable|disable|expire|destroy</c> (spec 12): scripted key management through <c>/api/console/keys</c>. The API never returns secret key material, so neither does this
/// command; for an RSA key it prints the public key and the exact <c>az keyvault key create --external-key-id</c> command that registers it.
/// </summary>
internal static class KeyCommands
{
    public static Command Create(CliEnvironment env, GlobalOptions global)
    {
        var key = new Command("key", "Manage keys of a running EkmMock through its console API.\n\n" +
            "Examples:\n" +
            "  ekmmock key list --console https://127.0.0.1:8080\n" +
            "  ekmmock key create --ns _default --name aes-key-1 --type aes\n" +
            "  ekmmock key create --ns _default --name rsa-key-1 --type rsa --size 2048 --hsm myhsm --ref-name ekm-rsa\n" +
            "  ekmmock key expire --ns _default --name aes-key-1 --at 2030-01-01T00:00:00Z\n" +
            "  ekmmock key destroy --ns _default --name aes-key-1 --confirm aes-key-1\n\n" +
            "The console must be reachable (default https://127.0.0.1:8080, or $" + ConsoleSettings.UrlVariable + "). A console started with --dev uses a throw-away certificate:\n" +
            "trust it with --console-ca/--console-pin, or for a loopback console --insecure-console-cert.\n" + ExitCodes.Documentation);
        key.Subcommands.Add(CreateList(env, global));
        key.Subcommands.Add(CreateShow(env, global));
        key.Subcommands.Add(CreateCreate(env, global));
        key.Subcommands.Add(CreateToggle(env, global, enable: true));
        key.Subcommands.Add(CreateToggle(env, global, enable: false));
        key.Subcommands.Add(CreateExpire(env, global));
        key.Subcommands.Add(CreateDestroy(env, global));
        return key;
    }

    internal static Option<string> NamespaceOption(bool required = false)
        => new("--ns", "--namespace") { Description = "Namespace of the key (the no-prefix namespace is _default).", DefaultValueFactory = required ? null : _ => EkmNames.DefaultNamespace, Required = required };

    internal static Option<string> NameOption() => new("--name") { Description = "Key name: 1 to 64 characters of letters, digits and '-'.", Required = true };

    private static string RequireKeyName(string name)
        => EkmNames.IsValidKeyName(name) ? name : throw CliException.Usage("--name must be 1 to 64 characters of letters, digits and '-' (spec 4.2).");

    // ---- list ----

    private static Command CreateList(CliEnvironment env, GlobalOptions global)
    {
        var ns = new Option<string>("--ns", "--namespace") { Description = "Only keys of this namespace." };
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var command = new Command("list", "List keys (destroyed keys stay listed as tombstones).\n\nExample:\n  ekmmock key list --ns _default --output json");
        command.Options.Add(ns);
        console.AddTo(command);
        output.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var keys = await client.ListKeysAsync(result.GetValue(ns), ct).ConfigureAwait(false);
            if (output.WantsJson(result))
            {
                env.Out.WriteLine(JsonSerializer.Serialize(new KeyList(keys), CliOutputJson.Default.KeyList));
                return ExitCodes.Success;
            }

            if (keys.Count == 0)
            {
                env.Out.WriteLine("No keys.");
                return ExitCodes.Success;
            }

            TableWriter.Write(
                env.Out,
                ["NAMESPACE", "NAME", "TYPE", "STATE", "ORIGIN", "CREATED", "NOT AFTER", "WRAPS", "UNWRAPS", "LAST USED"],
                keys.Select(static k => (IReadOnlyList<string>)[k.Namespace, k.Name, k.Display, k.State, k.Origin, Time(k.CreatedAt), Time(k.NotAfter), k.WrapCount.ToString(CultureInfo.InvariantCulture), k.UnwrapCount.ToString(CultureInfo.InvariantCulture), Time(k.LastUsedAt)]));
            return ExitCodes.Success;
        });
        return command;
    }

    // ---- show ----

    private static Command CreateShow(CliEnvironment env, GlobalOptions global)
    {
        var ns = NamespaceOption();
        var name = NameOption();
        var hsm = new Option<string>("--hsm") { Description = "Managed HSM name to put into the printed az command." };
        var refName = new Option<string>("--ref-name") { Description = "Name of the Key Vault key reference to put into the printed az command." };
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var command = new Command("show", "Show one key: state, usage, the RSA public key and the az command that registers it.\n\nExample:\n  ekmmock key show --ns _default --name rsa-key-1 --hsm myhsm --ref-name ekm-rsa");
        command.Options.Add(ns);
        command.Options.Add(name);
        command.Options.Add(hsm);
        command.Options.Add(refName);
        console.AddTo(command);
        output.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var detail = await client.GetKeyAsync(result.GetValue(ns)!, RequireKeyName(result.GetRequiredValue(name)), ct).ConfigureAwait(false);
            PrintDetail(env, output.WantsJson(result), detail, result.GetValue(hsm), result.GetValue(refName), created: false);
            return ExitCodes.Success;
        });
        return command;
    }

    // ---- create ----

    private static Command CreateCreate(CliEnvironment env, GlobalOptions global)
    {
        var ns = NamespaceOption();
        var name = NameOption();
        var type = new Option<string>("--type") { Description = "Key type: 'aes' (AES-256, A256KW / A256KWP) or 'rsa' (RSA-OAEP-256 / RSA-OAEP).", Required = true };
        type.AcceptOnlyFromAmong("aes", "rsa");
        var size = new Option<int?>("--size") { Description = "Key size in bits: 256 for aes (default), 2048, 3072 or 4096 for rsa (default 2048)." };
        var reuse = new Option<bool>("--allow-reuse-of-destroyed-name") { Description = "Reuse the name of a destroyed key (refused by default so that a name is not reused by accident)." };
        var hsm = new Option<string>("--hsm") { Description = "Managed HSM name to put into the printed az command." };
        var refName = new Option<string>("--ref-name") { Description = "Name of the Key Vault key reference to put into the printed az command." };
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var command = new Command("create", "Create a key. For an RSA key the public key is printed (n, e, PEM); every key gets the az command that registers it. The secret is never shown.\n\n" +
            "Examples:\n  ekmmock key create --ns _default --name aes-key-1 --type aes\n  ekmmock key create --ns contoso --name rsa-key-1 --type rsa --size 3072 --hsm myhsm --ref-name ekm-rsa");
        command.Options.Add(ns);
        command.Options.Add(name);
        command.Options.Add(type);
        command.Options.Add(size);
        command.Options.Add(reuse);
        command.Options.Add(hsm);
        command.Options.Add(refName);
        console.AddTo(command);
        output.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            var keyName = RequireKeyName(result.GetRequiredValue(name));
            var isRsa = result.GetRequiredValue(type) == "rsa";
            var bits = result.GetValue(size) ?? (isRsa ? 2048 : 256);
            if (isRsa ? bits is not (2048 or 3072 or 4096) : bits != 256)
            {
                throw CliException.Usage(isRsa ? "--size for rsa must be 2048, 3072 or 4096." : "--size for aes must be 256.");
            }

            var ns2 = result.GetValue(ns)!;
            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            await client.CreateKeyAsync(new CreateKeyBody(ns2, keyName, isRsa ? "rsa" : "aes", bits, result.GetValue(reuse)), ct).ConfigureAwait(false);
            var detail = await client.GetKeyAsync(ns2, keyName, ct).ConfigureAwait(false);
            PrintDetail(env, output.WantsJson(result), detail, result.GetValue(hsm), result.GetValue(refName), created: true);
            return ExitCodes.Success;
        });
        return command;
    }

    // ---- enable / disable ----

    private static Command CreateToggle(CliEnvironment env, GlobalOptions global, bool enable)
    {
        var ns = NamespaceOption();
        var name = NameOption();
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var verb = enable ? "enable" : "disable";
        var command = new Command(verb, enable
            ? "Enable a key again: wrap and unwrap work.\n\nExample:\n  ekmmock key enable --ns _default --name aes-key-1"
            : "Disable a key: wrap and unwrap answer 403 KeyDisabled (metadata still works), nothing is destroyed.\n\nExample:\n  ekmmock key disable --ns _default --name aes-key-1");
        command.Options.Add(ns);
        command.Options.Add(name);
        console.AddTo(command);
        output.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var view = await client.SetEnabledAsync(result.GetValue(ns)!, RequireKeyName(result.GetRequiredValue(name)), enable, ct).ConfigureAwait(false);
            PrintChanged(env, output.WantsJson(result), view, enable ? "enabled" : "disabled");
            return ExitCodes.Success;
        });
        return command;
    }

    // ---- expire ----

    private static Command CreateExpire(CliEnvironment env, GlobalOptions global)
    {
        var ns = NamespaceOption();
        var name = NameOption();
        var at = new Option<string>("--at") { Description = "Expiry as an ISO 8601 date-time (UTC unless it carries an offset), for example 2030-01-01T00:00:00Z. A time in the past expires the key at once (403 KeyExpired)." };
        var clear = new Option<bool>("--clear") { Description = "Remove the expiry." };
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var command = new Command("expire", "Set or clear the expiry of a key.\n\nExamples:\n  ekmmock key expire --ns _default --name aes-key-1 --at 2030-01-01T00:00:00Z\n  ekmmock key expire --ns _default --name aes-key-1 --clear");
        command.Options.Add(ns);
        command.Options.Add(name);
        command.Options.Add(at);
        command.Options.Add(clear);
        console.AddTo(command);
        output.AddTo(command);
        command.Validators.Add(r =>
        {
            var hasAt = r.IsGiven(at);
            var hasClear = r.IsGiven(clear);
            if (hasAt == hasClear)
            {
                r.AddError("Give exactly one of --at <ISO time> or --clear.");
            }
        });
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            DateTimeOffset? notAfter = null;
            if (result.GetValue(at) is { } text)
            {
                if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
                {
                    throw CliException.Usage($"--at must be an ISO 8601 date-time such as 2030-01-01T00:00:00Z, not '{text}'.");
                }

                notAfter = parsed;
            }

            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var view = await client.SetExpiryAsync(result.GetValue(ns)!, RequireKeyName(result.GetRequiredValue(name)), notAfter, ct).ConfigureAwait(false);
            PrintChanged(env, output.WantsJson(result), view, notAfter is null ? "expiry cleared" : $"expires {Time(notAfter)}");
            return ExitCodes.Success;
        });
        return command;
    }

    // ---- destroy ----

    private static Command CreateDestroy(CliEnvironment env, GlobalOptions global)
    {
        var ns = NamespaceOption();
        var name = NameOption();
        var confirm = new Option<string>("--confirm") { Description = "Type the key name again to confirm. Destroying is an irreversible crypto-shred: data wrapped by the key can never be unwrapped.", Required = true };
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet();
        var command = new Command("destroy", "Destroy a key irreversibly (crypto-shred). The server also checks the confirmation.\n\nExample:\n  ekmmock key destroy --ns _default --name aes-key-1 --confirm aes-key-1");
        command.Options.Add(ns);
        command.Options.Add(name);
        command.Options.Add(confirm);
        console.AddTo(command);
        output.AddTo(command);
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            var keyName = RequireKeyName(result.GetRequiredValue(name));
            var typed = result.GetRequiredValue(confirm);
            if (!string.Equals(typed, keyName, StringComparison.Ordinal))
            {
                throw CliException.Usage($"--confirm must repeat the key name exactly ('{keyName}'). Nothing was changed.");
            }

            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var view = await client.DestroyKeyAsync(result.GetValue(ns)!, keyName, typed, ct).ConfigureAwait(false);
            PrintChanged(env, output.WantsJson(result), view, "DESTROYED (irreversible)");
            return ExitCodes.Success;
        });
        return command;
    }

    // ---- output ----

    private static void PrintChanged(CliEnvironment env, bool json, KeyView view, string what)
    {
        if (json)
        {
            env.Out.WriteLine(JsonSerializer.Serialize(view, CliOutputJson.Default.KeyView));
            return;
        }

        env.Out.WriteLine($"{view.Namespace}/{view.Name} ({view.Display}): {what}. State: {view.State}.");
    }

    private static void PrintDetail(CliEnvironment env, bool json, KeyDetail detail, string? hsm, string? refName, bool created)
    {
        var az = detail.AzCommand;
        if (!string.IsNullOrWhiteSpace(hsm))
        {
            az = az.Replace("<hsm>", hsm, StringComparison.Ordinal);
        }

        if (!string.IsNullOrWhiteSpace(refName))
        {
            az = az.Replace("<ref-name>", refName, StringComparison.Ordinal);
        }

        if (json)
        {
            env.Out.WriteLine(JsonSerializer.Serialize(new KeyCreatedResult(detail.Key, detail.PublicKey, az), CliOutputJson.Default.KeyCreatedResult));
            return;
        }

        var key = detail.Key;
        env.Out.WriteLine(created ? $"Created {key.Namespace}/{key.Name} ({key.Display})." : $"{key.Namespace}/{key.Name}");
        TableWriter.WriteProperties(
            env.Out,
            [
                ("Type", key.Display),
                ("State", key.State),
                ("Origin", key.Origin),
                ("Created", Time(key.CreatedAt)),
                ("Not after", key.NotAfter is null ? null : Time(key.NotAfter)),
                ("Wraps / unwraps", $"{key.WrapCount} / {key.UnwrapCount}"),
                ("Last used", key.LastUsedAt is null ? null : Time(key.LastUsedAt)),
                ("Reached via", detail.RoutingNote),
                ("Note", key.StateNote),
            ]);
        if (detail.PublicKey is { } pub)
        {
            env.Out.WriteLine();
            env.Out.WriteLine("Public key (JWK n/e, base64url; the private key never leaves EkmMock):");
            env.Out.WriteLine($"  n: {pub.JwkN}");
            env.Out.WriteLine($"  e: {pub.JwkE}");
            env.Out.WriteLine(pub.Pem.TrimEnd());
        }

        env.Out.WriteLine();
        env.Out.WriteLine("Register the key with Managed HSM:");
        env.Out.WriteLine("  " + az);
    }

    private static string Time(DateTimeOffset? value) => value is null ? "-" : value.Value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
