using EkmMock.Pki;
using System.CommandLine;
using System.Text.Json;
using EkmMock.Cli.Bench;
using EkmMock.Cli.Conformance;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Ekm;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Commands;

/// <summary>
/// <c>ekmmock test conformance|bench</c> (spec 12): the CLI acting as a fake Managed HSM. Both commands speak mutual TLS 1.3 with a client certificate and trust only the roots given with
/// <c>--ca</c>; there is no switch that accepts an unknown server certificate.
/// </summary>
internal static class TestCommands
{
    public static Command Create(CliEnvironment env, GlobalOptions global)
    {
        var test = new Command("test", "Test a running EkmMock (or any EKM proxy): the conformance suite of spec section 14 and a load test.\n\n" +
            "Examples:\n" +
            "  ekmmock test conformance --url https://ekm.contoso.test --client-cert client.crt --client-key client.key --ca root-ca.pem\n" +
            "  ekmmock test bench --url https://ekm.contoso.test --client-cert client.crt --client-key client.key --ca root-ca.pem --op unwrapkey --key aes-key-1 --alg A256KWP --concurrency 16 --duration 60s");
        test.Subcommands.Add(CreateConformance(env, global));
        test.Subcommands.Add(CreateBench(env, global));
        return test;
    }

    /// <summary>The options that say where the EKM endpoint is and who the client is; shared by both commands.</summary>
    private sealed class EndpointOptions
    {
        public Option<string> Url { get; } = new("--url") { Description = "The EKM endpoint: https://<fqdn>[:port][/path-prefix]. The path is the namespace's path prefix.", Required = true };

        public Option<string> ClientCert { get; } = new("--client-cert") { Description = "PEM file with the client certificate (the fake Managed HSM identity); may include the chain, leaf first." };

        public Option<string> ClientKey { get; } = new("--client-key") { Description = "PEM file with the client certificate's private key." };

        public Option<string> Ca { get; } = new("--ca") { Description = "PEM file with the root CA certificate(s) of the server certificate: the ONLY roots trusted (the OS store is not used). Same file as --server-ca-certificate. Default: the OS trust store." };

        public Option<string> ServerName { get; } = new("--server-name") { Description = "Host name to verify in the server certificate (and send as SNI) when it differs from the URL's host, for example when --url uses an IP address." };

        public void AddTo(Command command)
        {
            command.Options.Add(Url);
            command.Options.Add(ClientCert);
            command.Options.Add(ClientKey);
            command.Options.Add(Ca);
            command.Options.Add(ServerName);
        }

        public EkmTarget Target(ParseResult result) => EkmTarget.Parse(result.GetRequiredValue(Url), result.GetValue(ServerName));

        public ClientIdentity? Identity(ParseResult result, CliEnvironment env, bool required)
        {
            var cert = result.GetValue(ClientCert);
            var key = result.GetValue(ClientKey);
            if (cert is null && key is null)
            {
                return required ? throw CliException.Usage("--client-cert and --client-key are required: the EKM endpoint needs mutual TLS.") : null;
            }

            if (cert is null || key is null)
            {
                throw CliException.Usage("--client-cert and --client-key go together.");
            }

            return ClientIdentity.Load(env.ResolvePath(cert), env.ResolvePath(key));
        }

        public System.Security.Cryptography.X509Certificates.X509Certificate2Collection? Roots(ParseResult result, CliEnvironment env)
            => result.GetValue(Ca) is { } path ? TlsTrust.LoadRoots(env.ResolvePath(path), "--ca") : null;
    }

    // ---- conformance ----

    private static Command CreateConformance(CliEnvironment env, GlobalOptions global)
    {
        var endpoint = new EndpointOptions();
        var altCert = new Option<string>("--alt-client-cert") { Description = "Client certificate of a trusted CA with a CN that is NOT allowed (the wrong-CN test). 'ekmmock certs dev' writes client-wrong-cn.crt." };
        var altKey = new Option<string>("--alt-client-key") { Description = "Private key of --alt-client-cert." };
        var rogueCert = new Option<string>("--rogue-client-cert") { Description = "Client certificate of a CA the server does NOT trust (the untrusted-CA test). 'ekmmock certs dev' writes client-untrusted-ca.crt." };
        var rogueKey = new Option<string>("--rogue-client-key") { Description = "Private key of --rogue-client-cert." };
        var replCert = new Option<string>("--replacement-server-cert") { Description = "A second server certificate for the same host, issued by the CA of --ca: the certificate reload test (14.15) uploads it through the console. The server serves it afterwards. 'ekmmock certs dev' writes server-replacement.crt." };
        var replKey = new Option<string>("--replacement-server-key") { Description = "Private key of --replacement-server-cert." };
        var ns = new Option<string>("--namespace", "--ns") { Description = "Namespace of the URL's path prefix. Default: found through the console." };
        var aesKey = new Option<string>("--aes-key") { Description = "Existing AES-256 key to use when no --console is given (default aes-key-1). Also the key named in the az commands.", DefaultValueFactory = _ => "aes-key-1" };
        var rsaKey = new Option<string>("--rsa-key") { Description = "Existing RSA key to use when no --console is given (default rsa-key-1). Also the key named in the az commands.", DefaultValueFactory = _ => "rsa-key-1" };
        var disruptive = new Option<bool>("--allow-disruptive") { Description = "Also run the concurrency-limit test, which holds every concurrency slot of the server for a moment. Never against a server in use." };
        var persistence = new Option<string>("--persistence-state") { Description = "State file for the restart test (14.13): first run saves a wrapped DEK, restart the server, second run verifies it and cleans up." };
        var only = new Option<string>("--only") { Description = "Run only these tests: ids (14.6.a) or Section 14 numbers (6 or 14.6), comma separated." };
        var list = new Option<bool>("--list") { Description = "List the tests and exit." };
        var report = new Option<string>("--report") { Description = "Where to write the JSON report.", DefaultValueFactory = _ => "conformance-report.json" };
        var console = new ConsoleOptionSet();
        var command = new Command("conformance", "Run every acceptance test of spec section 14 that can run from outside, acting as a fake Managed HSM.\n\n" +
            "Prints PASS, FAIL or SKIP per test (with its Section 14 number), a summary, and writes a JSON report (no secrets). Exit code 0 only when every test that ran passed.\n" +
            "A test that needs something that was not supplied is SKIPPED with the reason, never silently passed:\n" +
            "  --console          create temporary keys/namespaces, read Live traffic, faults, key import (give it for the full run)\n" +
            "  --alt-client-*     wrong-CN test            --rogue-client-*   untrusted-CA test\n" +
            "  --persistence-state restart test (two runs)  --allow-disruptive concurrency-limit test\n" +
            "  --replacement-server-*  certificate reload test (uploads a second certificate through the console)\n" +
            "Temporary objects are named conf-<run id>-* and destroyed at the end. Only synthetic data is used.\n\n" +
            "Example (everything 'ekmmock certs dev' wrote, against a local server):\n" +
            "  ekmmock test conformance --url https://localhost:8443 --client-cert dev-pki/client.crt --client-key dev-pki/client.key --ca dev-pki/root-ca.pem \\\n" +
            "     --alt-client-cert dev-pki/client-wrong-cn.crt --alt-client-key dev-pki/client-wrong-cn.key \\\n" +
            "     --rogue-client-cert dev-pki/client-untrusted-ca.crt --rogue-client-key dev-pki/client-untrusted-ca.key \\\n" +
            "     --console https://127.0.0.1:8080 --console-ca dev-pki/root-ca.pem\n\n" + ExitCodes.Documentation);
        endpoint.AddTo(command);
        command.Options.Add(altCert);
        command.Options.Add(altKey);
        command.Options.Add(rogueCert);
        command.Options.Add(rogueKey);
        command.Options.Add(replCert);
        command.Options.Add(replKey);
        command.Options.Add(ns);
        command.Options.Add(aesKey);
        command.Options.Add(rsaKey);
        command.Options.Add(disruptive);
        command.Options.Add(persistence);
        command.Options.Add(only);
        command.Options.Add(list);
        command.Options.Add(report);
        console.AddTo(command);
        command.Validators.Add(r =>
        {
            if (r.IsGiven(altCert) != r.IsGiven(altKey))
            {
                r.AddError("--alt-client-cert and --alt-client-key go together.");
            }

            if (r.IsGiven(replCert) != r.IsGiven(replKey))
            {
                r.AddError("--replacement-server-cert and --replacement-server-key go together.");
            }

            if (r.IsGiven(rogueCert) != r.IsGiven(rogueKey))
            {
                r.AddError("--rogue-client-cert and --rogue-client-key go together.");
            }
        });

        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            if (result.GetValue(list))
            {
                env.Out.Write(ConformanceRunner.Describe(ConformanceSuite.All));
                return ExitCodes.Success;
            }

            var target = endpoint.Target(result);
            using var client = endpoint.Identity(result, env, required: true)!;
            using var alt = Optional(result, altCert, altKey, env, "--alt-client-cert", "--alt-client-key");
            using var rogue = Optional(result, rogueCert, rogueKey, env, "--rogue-client-cert", "--rogue-client-key");
            var roots = endpoint.Roots(result, env);
            var consoleSettings = console.IsGiven(result, env) ? console.Resolve(result, env) : null;

            var options = new ConformanceOptions
            {
                Target = target,
                Client = client,
                AltClient = alt,
                RogueClient = rogue,
                Roots = roots,
                Console = consoleSettings,
                ReplacementCertFile = result.GetValue(replCert) is { } rc ? env.ResolvePath(rc) : null,
                ReplacementKeyFile = result.GetValue(replKey) is { } rk ? env.ResolvePath(rk) : null,
                Namespace = result.GetValue(ns),
                AesKey = result.GetValue(aesKey)!,
                RsaKey = result.GetValue(rsaKey)!,
                AllowDisruptive = result.GetValue(disruptive),
                PersistenceState = result.GetValue(persistence) is { } p ? env.ResolvePath(p) : null,
                Only = result.GetValue(only),
                ReportPath = env.ResolvePath(result.GetValue(report)!),
            };

            ConformanceReport summary;
            try
            {
                summary = await ConformanceRunner.RunAsync(options, env, ct).ConfigureAwait(false);
            }
            finally
            {
                if (roots is not null)
                {
                    foreach (var root in roots)
                    {
                        root.Dispose();
                    }
                }
            }

            try
            {
                SecureFile.WritePublic(options.ReportPath, ConformanceRunner.ToJson(summary), overwrite: true);
                env.Out.WriteLine($"Report: {options.ReportPath}");
            }
            catch (IOException exception)
            {
                env.Error.WriteLine("warning: the report could not be written: " + exception.Message);
            }

            if (summary.Summary.Failed > 0)
            {
                env.Out.WriteLine("RESULT: FAILED");
                return ExitCodes.Failure;
            }

            if (summary.Summary.Passed == 0)
            {
                // Nothing failed but nothing was proven either (for example the first, state-saving phase of the restart test): say so, and exit 0 like the spec says (every test that ran passed).
                env.Out.WriteLine("RESULT: no test passed: every selected test was skipped (see the reasons above).");
                return ExitCodes.Success;
            }

            env.Out.WriteLine("RESULT: PASSED" + (summary.Summary.Skipped > 0 ? $" ({summary.Summary.Skipped} skipped: see the reasons above)" : string.Empty));
            env.Out.WriteLine();
            env.Out.WriteLine("Next: register this endpoint with Managed HSM (spec section 15):");
            foreach (var line in ConformanceRunner.AzCommands(options))
            {
                env.Out.WriteLine(line);
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static ClientIdentity? Optional(ParseResult result, Option<string> cert, Option<string> key, CliEnvironment env, string certName, string keyName)
        => result.GetValue(cert) is { } c && result.GetValue(key) is { } k ? ClientIdentity.Load(env.ResolvePath(c), env.ResolvePath(k), certName, keyName) : null;

    // ---- bench ----

    private static Command CreateBench(CliEnvironment env, GlobalOptions global)
    {
        var endpoint = new EndpointOptions();
        var op = new Option<string>("--op") { Description = "Operation to load: wrapkey, unwrapkey, info or metadata.", Required = true };
        op.AcceptOnlyFromAmong("wrapkey", "unwrapkey", "info", "metadata");
        var key = new Option<string>("--key") { Description = "Key name (not needed for info)." };
        var alg = new Option<string>("--alg") { Description = "Algorithm for wrapkey/unwrapkey: A256KW, A256KWP, RSA-OAEP-256 or RSA-OAEP." };
        var concurrency = new Option<int>("--concurrency") { Description = "Number of concurrent workers, each with its own kept-alive connection.", DefaultValueFactory = _ => 16 };
        var duration = new Option<string>("--duration") { Description = "Measured time, for example 60s, 500ms, 2m.", DefaultValueFactory = _ => "60s" };
        var warmup = new Option<string>("--warmup") { Description = "Warm-up before the measurement (not counted).", DefaultValueFactory = _ => "5s" };
        var dekSize = new Option<int>("--dek-size") { Description = "Size of the synthetic DEK in bytes for wrapkey/unwrapkey.", DefaultValueFactory = _ => 32 };
        var rate = new Option<double?>("--rate") { Description = "Open loop: target requests per second in total. Latency is measured from each request's scheduled start (corrects coordinated omission). Default: closed loop." };
        var assertP99 = new Option<double?>("--assert-p99-ms") { Description = "Exit with code 1 when the p99 latency is above this many milliseconds." };
        var maxOver = new Option<double?>("--max-over-250-pct") { Description = "Exit with code 1 when more than this percentage of requests took longer than 250 ms." };
        var noErrors = new Option<bool>("--assert-no-errors") { Description = "Exit with code 1 when any request failed (non-2xx or an exception)." };
        var reportFile = new Option<string>("--report") { Description = "Also write the JSON result to this file." };
        var output = new OutputOptionSet();
        var command = new Command("bench", "Load test: N concurrent workers (HTTP/1.1, kept-alive connections) send one operation for a fixed time; reports p50/p90/p99/max latency, throughput, errors per status\n" +
            "and the percentage over 250 ms, with a histogram. Its requests show up in the console like any other traffic.\n\n" +
            "Model: closed loop by default (a worker sends the next request when the last was answered), open loop with --rate. The warm-up is discarded. unwrapkey wraps once first.\n\n" +
            "Examples:\n" +
            "  ekmmock test bench --url https://localhost:8443 --client-cert c.crt --client-key c.key --ca root-ca.pem --op unwrapkey --key aes-key-1 --alg A256KWP --concurrency 16 --duration 60s --assert-p99-ms 10\n" +
            "  ekmmock test bench --url https://localhost:8443 ... --op info --duration 10s --output json\n\n" + ExitCodes.Documentation);
        endpoint.AddTo(command);
        command.Options.Add(op);
        command.Options.Add(key);
        command.Options.Add(alg);
        command.Options.Add(concurrency);
        command.Options.Add(duration);
        command.Options.Add(warmup);
        command.Options.Add(dekSize);
        command.Options.Add(rate);
        command.Options.Add(assertP99);
        command.Options.Add(maxOver);
        command.Options.Add(noErrors);
        command.Options.Add(reportFile);
        output.AddTo(command);
        command.Validators.Add(r =>
        {
            var hasOperation = r.TryGiven(op, out var operation);
            if (hasOperation && operation is "wrapkey" or "unwrapkey" && (!r.IsGiven(key) || !r.IsGiven(alg)))
            {
                r.AddError($"--op {operation} needs --key and --alg.");
            }

            if (hasOperation && operation == "metadata" && !r.IsGiven(key))
            {
                r.AddError("--op metadata needs --key.");
            }

            if (r.TryGiven(concurrency, out var workers) && workers is < 1 or > 1024)
            {
                r.AddError("--concurrency must be between 1 and 1024.");
            }

            if (r.TryGiven(dekSize, out var size) && size is < 1 or > 4096)
            {
                r.AddError("--dek-size must be between 1 and 4096.");
            }

            if (r.TryGiven(rate, out var requestsPerSecond) && requestsPerSecond is <= 0)
            {
                r.AddError("--rate must be greater than 0.");
            }
        });
        CliApp.SetAction(command, env, global, async (result, ct) =>
        {
            if (!Duration.TryParse(result.GetValue(duration), out var measured) || measured <= TimeSpan.Zero)
            {
                throw CliException.Usage($"--duration must look like 60s, 500ms or 2m, not '{result.GetValue(duration)}'.");
            }

            if (!Duration.TryParse(result.GetValue(warmup), out var warm))
            {
                throw CliException.Usage($"--warmup must look like 5s or 500ms, not '{result.GetValue(warmup)}'.");
            }

            var target = endpoint.Target(result);
            using var identity = endpoint.Identity(result, env, required: false);
            var roots = endpoint.Roots(result, env);
            var workers = result.GetValue(concurrency);
            using var client = EkmClient.Create(target, identity, roots, "bench", maxConnections: workers, timeout: TimeSpan.FromSeconds(30));
            var settings = new BenchSettings
            {
                Client = client,
                Operation = Enum.Parse<BenchOperation>(result.GetRequiredValue(op), ignoreCase: true),
                Key = result.GetValue(key) ?? string.Empty,
                Algorithm = result.GetValue(alg),
                Concurrency = workers,
                Duration = measured,
                Warmup = warm,
                DekSize = result.GetValue(dekSize),
                Rate = result.GetValue(rate),
            };

            var started = env.Time.GetUtcNow();
            BenchResult measuredResult;
            try
            {
                if (!output.WantsJson(result))
                {
                    env.Out.WriteLine($"Bench: {settings.Operation.ToString().ToLowerInvariant()} on {target.DisplayUrl}, {workers} workers, {Duration.Format(warm)} warm-up + {Duration.Format(measured)} measured ...");
                }

                measuredResult = await BenchRunner.RunAsync(settings, ct).ConfigureAwait(false);
            }
            catch (HttpRequestException exception)
            {
                throw CliException.Connection($"Cannot reach {target.DisplayUrl}: {exception.GetBaseException().Message.TrimEnd('.')}. Check --ca, --client-cert and --client-key.", exception);
            }
            finally
            {
                if (roots is not null)
                {
                    foreach (var root in roots)
                    {
                        root.Dispose();
                    }
                }
            }

            var outcome = BenchRunner.ToOutcome(settings, measuredResult, target.DisplayUrl, started, result.GetValue(assertP99), result.GetValue(maxOver), result.GetValue(noErrors));
            var json = JsonSerializer.Serialize(outcome, CliOutputJson.Default.BenchOutcome);
            if (result.GetValue(reportFile) is { } file)
            {
                SecureFile.WritePublic(env.ResolvePath(file), json + Environment.NewLine, overwrite: true);
            }

            if (output.WantsJson(result))
            {
                env.Out.WriteLine(json);
            }
            else
            {
                BenchRunner.PrintSummary(env.Out, outcome);
            }

            return outcome.ThresholdFailures.Count == 0 ? ExitCodes.Success : ExitCodes.Failure;
        });
        return command;
    }
}
