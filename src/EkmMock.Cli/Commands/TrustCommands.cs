using System.CommandLine;
using System.Globalization;
using System.Text.Json;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Commands;

/// <summary>
/// <c>ekmmock trust import</c> (spec 12, 15 step 1): sends the output of <c>az keyvault ekm-connection certificate show</c> (or a PEM bundle) to a namespace's client trust. Always shows what
/// was found first (CN, every CA with subject, issuer, expiry and warnings such as "not a root"); <c>--dry-run</c> stops there.
/// </summary>
internal static class TrustCommands
{
    public const int MaxInputBytes = 200_000;

    public static Command Create(CliEnvironment env, GlobalOptions global)
    {
        var trust = new Command("trust", "Manage which Managed HSM clients a namespace trusts.\n\nExample:\n  az keyvault ekm-connection certificate show --hsm-name $HSM > mhsm-client.json\n  ekmmock trust import --ns _default --json mhsm-client.json");
        trust.Subcommands.Add(CreateImport(env, global));
        return trust;
    }

    private static Command CreateImport(CliEnvironment env, GlobalOptions global)
    {
        var ns = KeyCommands.NamespaceOption();
        var json = new Option<string>("--json") { Description = "File with the output of 'az keyvault ekm-connection certificate show' ({\"caCertificates\": [...], \"subjectCommonName\": \"...\"})." };
        var pem = new Option<string>("--pem") { Description = "Alternative to --json: a PEM file with the root CA certificate(s). Needs at least one --cn." };
        var cn = new Option<string[]>("--cn") { Description = "Allowed client certificate subject common name (repeat for several). Needed with --pem; added to the JSON's CN otherwise.", AllowMultipleArgumentsPerToken = true };
        var mode = new Option<string>("--mode") { Description = "'merge' (default: add to the namespace's existing trust) or 'replace' (the imported CN and CAs become the trust).", DefaultValueFactory = _ => "merge" };
        mode.AcceptOnlyFromAmong("merge", "replace");
        var dryRun = new Option<bool>("--dry-run") { Description = "Show what would be imported and the warnings, but save nothing." };
        var console = new ConsoleOptionSet();
        var output = new OutputOptionSet(withJsonFlag: false);
        var command = new Command("import", "Import the Managed HSM client trust (CN and root CA certificates) into a namespace.\n\n" +
            "Examples:\n" +
            "  ekmmock trust import --ns _default --json mhsm-client.json --dry-run\n" +
            "  ekmmock trust import --ns _default --json mhsm-client.json\n" +
            "  ekmmock trust import --ns contoso --pem client-ca.pem --cn test.managedhsmclient.local --mode replace\n\n" +
            "(Here --json names the input file; for machine-readable output use --output json.)\n" + ExitCodes.Documentation);
        command.Options.Add(ns);
        command.Options.Add(json);
        command.Options.Add(pem);
        command.Options.Add(cn);
        command.Options.Add(mode);
        command.Options.Add(dryRun);
        console.AddTo(command);
        output.AddTo(command);
        command.Validators.Add(r =>
        {
            var hasJson = r.IsGiven(json);
            var hasPem = r.IsGiven(pem);
            if (hasJson == hasPem)
            {
                r.AddError("Give exactly one of --json <file> or --pem <file>.");
            }
            else if (hasPem && !r.IsGiven(cn))
            {
                r.AddError("--pem needs at least one --cn (a PEM file carries no common name list).");
            }
        });

        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            var file = env.ResolvePath((result.GetValue(json) ?? result.GetValue(pem))!);
            var isJson = result.GetValue(json) is not null;
            if (!File.Exists(file))
            {
                throw CliException.Usage($"The file does not exist: {file}");
            }

            if (new FileInfo(file).Length > MaxInputBytes)
            {
                throw CliException.Usage($"The file is larger than {MaxInputBytes} bytes: that is not a trust description.");
            }

            var body = new TrustImportBody(isJson ? "json" : "pem", await File.ReadAllTextAsync(file, ct).ConfigureAwait(false), result.GetValue(cn)?.ToList(), result.GetValue(mode), result.GetValue(dryRun));
            using var client = ConsoleApiClient.Create(console.Resolve(result, env), env);
            var preview = await client.ImportTrustAsync(result.GetValue(ns)!, body, ct).ConfigureAwait(false);
            if (output.WantsJson(result))
            {
                env.Out.WriteLine(JsonSerializer.Serialize(preview, CliOutputJson.Default.TrustPreview));
            }
            else
            {
                Print(env, preview);
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static void Print(CliEnvironment env, TrustPreview preview)
    {
        var o = env.Out;
        o.WriteLine($"Namespace:        {preview.Namespace}");
        o.WriteLine($"Input format:     {preview.Format}");
        o.WriteLine($"Subject CN(s):    {(preview.SubjectCommonNames.Count == 0 ? "(none)" : string.Join(", ", preview.SubjectCommonNames))}");
        o.WriteLine();
        TableWriter.Write(
            o,
            ["CA SUBJECT", "ISSUER", "NOT AFTER", "ROOT", "SHA-256"],
            preview.CaCertificates.Select(static c => (IReadOnlyList<string>)[c.Subject, c.Issuer, c.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), c.IsSelfSigned ? "yes" : "NO", c.ThumbprintSha256]));
        if (preview.Warnings.Count > 0 || preview.CaCertificates.Any(static c => c.Warnings.Count > 0))
        {
            o.WriteLine();
            o.WriteLine("Warnings:");
            foreach (var warning in preview.Warnings)
            {
                o.WriteLine("  - " + warning);
            }

            foreach (var certificate in preview.CaCertificates)
            {
                foreach (var warning in certificate.Warnings)
                {
                    o.WriteLine($"  - {certificate.Subject}: {warning}");
                }
            }
        }

        o.WriteLine();
        o.WriteLine($"Result ({preview.Mode}): CN list {string.Join(", ", preview.ResultingSubjectCommonNames)}; {preview.ResultingCaCount} CA certificate(s).");
        o.WriteLine(preview.Saved ? "Saved. The next client connection uses the new trust (no restart)." : "Dry run: nothing was saved.");
    }
}
