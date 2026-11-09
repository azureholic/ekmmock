using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using EkmMock.Cli.Commands;
using EkmMock.Cli.Ekm;

namespace EkmMock.Cli.Conformance;

/// <summary>All conformance tests in Section 14 order.</summary>
internal static class ConformanceSuite
{
    public static IReadOnlyList<ConformanceCase> All { get; } = [.. ProtocolTests.All(), .. SecurityTests.All(), .. ObservabilityTests.All()];
}

/// <summary>
/// Runs the suite: one test at a time, each reported as PASS, FAIL or SKIP with its Section 14 number, then a summary and the JSON report. A test cannot hide a failure behind a skip: SKIP only comes from a
/// <see cref="SkipTest"/> that names what is missing. Everything created on the server for the run (keys, namespaces, fault rules) is removed at the end.
/// </summary>
internal static class ConformanceRunner
{
    public static async Task<ConformanceReport> RunAsync(ConformanceOptions options, CliEnvironment env, CancellationToken ct, Action<IReadOnlyList<byte[]>>? secretsSink = null)
    {
        var started = env.Time.GetUtcNow();
        var watch = Stopwatch.StartNew();
        var o = env.Out;
        var selected = Select(options.Only);

        o.WriteLine($"EkmMock conformance suite {CliVersion.Current}");
        o.WriteLine($"Target:   {options.Target.DisplayUrl}");
        o.WriteLine($"Console:  {(options.Console is null ? "not given (tests that need to manage keys or read Live traffic are skipped)" : options.Console.Url.GetLeftPart(UriPartial.Authority))}");
        o.WriteLine($"Run id:   {options.RunId} (everything the run creates on the server is named conf-{options.RunId}-* and removed at the end)");
        o.WriteLine();

        var results = new List<ReportTest>();
        await using var context = new ConformanceContext(options, env);
        await PreflightAsync(context, ct).ConfigureAwait(false);

        foreach (var test in selected)
        {
            var testWatch = Stopwatch.StartNew();
            TestStatus status;
            string? message = null;
            try
            {
                await test.Run(context, ct).ConfigureAwait(false);
                status = TestStatus.Pass;
            }
            catch (SkipTest skip)
            {
                status = TestStatus.Skip;
                message = skip.Message;
            }
            catch (TestFailure failure)
            {
                status = TestStatus.Fail;
                message = failure.Message;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                status = TestStatus.Fail;
                message = $"unexpected {exception.GetType().Name}: {FirstLine(exception.GetBaseException().Message)}";
            }

            var elapsed = testWatch.Elapsed;
            results.Add(new ReportTest(test.Id, test.Spec, test.Name, status.ToString().ToUpperInvariant(), Math.Round(elapsed.TotalMilliseconds, 1), message));
            o.WriteLine($"{status.ToString().ToUpperInvariant(),-4}  {test.Id,-8} {test.Name}  ({elapsed.TotalMilliseconds:0} ms)");
            if (message is not null)
            {
                o.WriteLine("      " + message);
            }
        }

        secretsSink?.Invoke(context.Secrets); // tests only: lets a test scan everything the run printed for the synthetic secrets it used
        await context.DisposeAsync().ConfigureAwait(false);
        var passed = results.Count(static r => r.Status == "PASS");
        var failed = results.Count(static r => r.Status == "FAIL");
        var skipped = results.Count(static r => r.Status == "SKIP");
        o.WriteLine();
        o.WriteLine($"Summary: {results.Count} tests: {passed} passed, {failed} failed, {skipped} skipped.");
        if (context.Destroyed.Count > 0)
        {
            o.WriteLine($"Cleaned up: {string.Join(", ", context.Destroyed)}");
        }

        if (context.Leftover.Count > 0)
        {
            o.WriteLine("LEFT OVER on the server (remove them by hand):");
            foreach (var item in context.Leftover)
            {
                o.WriteLine("  - " + item);
            }
        }

        return new ConformanceReport(
            "ekmmock test conformance",
            CliVersion.Current,
            started,
            env.Time.GetUtcNow(),
            Math.Round(watch.Elapsed.TotalMilliseconds, 1),
            new ReportTarget(options.Target.DisplayUrl, options.Target.Prefix, options.Console?.Url.GetLeftPart(UriPartial.Authority)),
            new ReportInputs(options.Console is not null, options.AltClient is not null, options.RogueClient is not null, options.AllowDisruptive, options.PersistenceState is not null, options.Roots is not null),
            new ReportEnvironment(RuntimeInformation.OSDescription, RuntimeInformation.OSArchitecture.ToString(), RuntimeInformation.FrameworkDescription, Environment.ProcessorCount),
            new ReportSummary(results.Count, passed, failed, skipped),
            results,
            new ReportCleanup(context.Destroyed, context.Leftover));
    }

    /// <summary>One <c>info</c> call before any test: a TLS or trust problem is a connection error (exit 3) with a hint, not forty identical test failures.</summary>
    private static async Task PreflightAsync(ConformanceContext context, CancellationToken ct)
    {
        try
        {
            await context.Ekm.InfoAsync(ct).ConfigureAwait(false);
        }
        catch (HttpRequestException exception)
        {
            throw CliException.Connection(
                $"Cannot complete a TLS 1.3 handshake with {context.Options.Target.DisplayUrl}: {exception.GetBaseException().Message.TrimEnd('.')}. " +
                "Check the URL, that --ca is the root CA of the server certificate, that the certificate's SAN contains the host name (or pass --server-name), and that --client-cert/--client-key are trusted by the server.",
                exception);
        }
    }

    private static List<ConformanceCase> Select(string? only)
    {
        if (string.IsNullOrWhiteSpace(only))
        {
            return [.. ConformanceSuite.All];
        }

        var prefixes = only.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var tokens = prefixes.Select(static p => p.StartsWith("14.", StringComparison.Ordinal) ? p : "14." + p).ToList();
        var chosen = ConformanceSuite.All.Where(t => tokens.Any(p => t.Id.Equals(p, StringComparison.OrdinalIgnoreCase) || t.Spec == p)).ToList();
        if (chosen.Count == 0)
        {
            throw CliException.Usage($"--only '{only}' matches no test. Ids look like 14.6.a; a number such as 14.6 selects every check of that Section 14 test. Use --list to see them all.");
        }

        return chosen;
    }

    private static string FirstLine(string text)
    {
        var end = text.IndexOfAny(['\r', '\n']);
        return end < 0 ? text : text[..end];
    }

    /// <summary>The <c>az</c> commands of spec 15 with this target's host, prefix and key names filled in (printed after a successful run).</summary>
    public static IEnumerable<string> AzCommands(ConformanceOptions options)
    {
        var host = options.Target.Origin.Host;
        var prefix = options.Target.Prefix.Length == 0 ? string.Empty : $" --path-prefix /{options.Target.Prefix}";
        yield return "# 1. trust the Managed HSM client identity (on the EkmMock side):";
        yield return "az keyvault ekm-connection certificate show --hsm-name $HSM > mhsm-client.json";
        yield return $"ekmmock trust import --ns {options.Namespace ?? (options.Target.Prefix.Length == 0 ? "_default" : "<namespace>")} --json mhsm-client.json --console https://127.0.0.1:8080";
        yield return "# 2. create the connection (public internet, port 443; --server-ca-certificate takes the ROOT CA, not the leaf):";
        yield return $"az keyvault ekm-connection create --hsm-name $HSM --host {host} --server-ca-certificate root-ca.pem{prefix}";
        yield return "az keyvault ekm-connection check --hsm-name $HSM";
        yield return "# 3. register external key references:";
        yield return $"az keyvault key create --hsm-name $HSM --name ekm-aes --external-key-id {options.AesKey}";
        yield return $"az keyvault key create --hsm-name $HSM --name ekm-rsa --external-key-id {options.RsaKey}";
        yield return "# 4. round trip through Managed HSM (see spec 15 for the request bodies):";
        yield return "az rest --method POST --resource https://managedhsm.azure.net --uri \"https://$HSM.managedhsm.azure.net/keys/ekm-aes/wrapkey?api-version=7.5\" --headers Content-Type=application/json --body @wrap-a256kw.json";
        if (options.Target.Origin.Port != 443)
        {
            yield return $"# NOTE: this target listens on port {options.Target.Origin.Port}; Managed HSM only reaches port 443, so publish it there (docker -p 443:8443, VM, ACI).";
        }
    }

    public static string ToJson(ConformanceReport report) => JsonSerializer.Serialize(report, CliOutputJson.Default.ConformanceReport) + Environment.NewLine;

    internal static string Describe(IEnumerable<ConformanceCase> cases)
    {
        var text = new StringBuilder();
        foreach (var test in cases)
        {
            text.AppendLine($"{test.Id,-8} {test.Name}");
        }

        return text.ToString();
    }
}
