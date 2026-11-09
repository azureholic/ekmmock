using System.CommandLine;
using System.Text.Json;
using EkmMock.Cli.Infrastructure;
using EkmMock.Pki;

namespace EkmMock.Cli.Commands;

/// <summary>
/// <c>ekmmock certs ca|server|client|dev</c> (spec 12): test PKI only. Writes PEM files into a folder, private keys readable by the current user only, never prints key material, and prints a loud notice.
/// The logic is <see cref="CertificateAuthority"/> (the same code behind the console's "generate test PKI" action).
/// </summary>
internal static class CertsCommands
{
    public const string Notice = "TEST PKI ONLY: these certificates are for testing EkmMock. Never use them to protect real data or to trust anything outside a test setup.";

    public const string DefaultClientCn = "test.managedhsmclient.local";

    public static Command Create(CliEnvironment env, GlobalOptions global)
    {
        var certs = new Command("certs", "Generate test PKI (root CA, server and client certificates). TEST PKI ONLY.\n\n" +
            "Examples:\n" +
            "  ekmmock certs dev --out ./dev-pki --fqdn localhost\n" +
            "  ekmmock certs ca --out ./pki --name \"My Test Root CA\"\n" +
            "  ekmmock certs server --ca ./pki/root-ca.pem --ca-key ./pki/root-ca.key --fqdn ekm.contoso.test --out ./pki\n" +
            "  ekmmock certs client --ca ./pki/root-ca.pem --ca-key ./pki/root-ca.key --cn test.managedhsmclient.local --out ./pki\n\n" + ExitCodes.Documentation);
        certs.Subcommands.Add(CreateCa(env, global));
        certs.Subcommands.Add(CreateServer(env, global));
        certs.Subcommands.Add(CreateClient(env, global));
        certs.Subcommands.Add(CreateDev(env, global));
        return certs;
    }

    // ---- ekmmock certs ca ----

    private static Command CreateCa(CliEnvironment env, GlobalOptions global)
    {
        var common = new CommonOptions("EkmMock Test Root CA " + Tag(), 3650);
        var command = new Command("ca", "Create a self-signed root CA: <out>/root-ca.pem (certificate) and <out>/root-ca.key (private key, owner-only).\n\n" +
            "Example:\n  ekmmock certs ca --out ./pki --name \"My Test Root CA\"\n\nThe root-ca.pem is what 'az keyvault ekm-connection create --server-ca-certificate' takes.");
        common.AddTo(command);
        CliApp.SetAction(command, env, global, (result, _) =>
        {
            var plan = new FilePlan(env.ResolvePath(result.GetRequiredValue(common.Out)), result.GetValue(common.Force));
            using var ca = CertificateAuthority.CreateRoot(result.GetValue(common.Name)!, common.Algorithm(result), Days(result.GetValue(common.Days)));
            var files = new List<CertFile>();
            plan.Reserve("root-ca.pem", "root-ca.key");
            WriteCa(plan, ca, "root-ca", files);
            return Task.FromResult(Finish(env, common, result, files, new Dictionary<string, string> { ["subject"] = ca.Subject }));
        });
        return command;
    }

    // ---- ekmmock certs server ----

    private static Command CreateServer(CliEnvironment env, GlobalOptions global)
    {
        var common = new CommonOptions("server", 397);
        var ca = new Option<string>("--ca") { Description = "CA certificate (PEM) that issues the server certificate.", Required = true };
        var caKey = new Option<string>("--ca-key") { Description = "The CA's private key (PKCS#8 PEM).", Required = true };
        var fqdn = new Option<string>("--fqdn") { Description = "The public FQDN of the server: becomes the SAN and the subject CN. It must equal the host registered with 'az keyvault ekm-connection create --host'.", Required = true };
        var san = new Option<string[]>("--san") { Description = "Additional SAN (DNS name or IP address); repeat for several.", AllowMultipleArgumentsPerToken = true };
        var command = new Command("server", "Issue a TLS server certificate (serverAuth) signed by your test CA: <out>/<name>.crt (certificate chain) and <out>/<name>.key.\n\n" +
            "Example:\n  ekmmock certs server --ca ./pki/root-ca.pem --ca-key ./pki/root-ca.key --fqdn ekm.contoso.test --san 127.0.0.1 --out ./pki\n\n" +
            "The CA certificate is also copied to <out>/root-ca.pem when it is a root, for --server-ca-certificate.");
        command.Options.Add(ca);
        command.Options.Add(caKey);
        command.Options.Add(fqdn);
        command.Options.Add(san);
        common.AddTo(command, withName: true);
        CliApp.SetAction(command, env, global, (result, _) =>
        {
            var plan = new FilePlan(env.ResolvePath(result.GetRequiredValue(common.Out)), result.GetValue(common.Force));
            var name = result.GetValue(common.Name)!;
            using var issuer = LoadCa(env, result.GetRequiredValue(ca), result.GetRequiredValue(caKey));
            var hosts = HostNames(result.GetRequiredValue(fqdn), result.GetValue(san));
            plan.Reserve(name + ".crt", name + ".key");
            using var server = issuer.IssueServer(hosts, Days(result.GetValue(common.Days)));
            var files = new List<CertFile>();
            plan.WritePublic(name + ".crt", server.ChainPem + "\n", "server certificate (chain)", files);
            plan.WriteSecret(name + ".key", server.PrivateKeyPem, "server private key", files);
            if (!issuer.IntermediatePems.Any() && plan.WritePublicIfMissing("root-ca.pem", issuer.CertificatePem + "\n", "root CA certificate (for --server-ca-certificate)", files) is { } note)
            {
                env.Error.WriteLine("note: " + note);
            }
            return Task.FromResult(Finish(env, common, result, files, new Dictionary<string, string> { ["subject"] = server.Subject, ["san"] = string.Join(", ", hosts) }));
        });
        return command;
    }

    // ---- ekmmock certs client ----

    private static Command CreateClient(CliEnvironment env, GlobalOptions global)
    {
        var common = new CommonOptions("client", 397);
        var ca = new Option<string>("--ca") { Description = "CA certificate (PEM) that issues the client certificate.", Required = true };
        var caKey = new Option<string>("--ca-key") { Description = "The CA's private key (PKCS#8 PEM).", Required = true };
        var cn = new Option<string>("--cn") { Description = $"Subject common name. Managed HSM uses the CN reported by 'az keyvault ekm-connection certificate show'. Default {DefaultClientCn}.", DefaultValueFactory = _ => DefaultClientCn };
        var command = new Command("client", "Issue a client certificate (clientAuth) signed by your test CA, to act as a fake Managed HSM: <out>/<name>.crt and <out>/<name>.key.\n\n" +
            "Example:\n  ekmmock certs client --ca ./pki/client-ca.pem --ca-key ./pki/client-ca.key --cn test.managedhsmclient.local --out ./pki");
        command.Options.Add(ca);
        command.Options.Add(caKey);
        command.Options.Add(cn);
        common.AddTo(command, withName: true);
        CliApp.SetAction(command, env, global, (result, _) =>
        {
            var plan = new FilePlan(env.ResolvePath(result.GetRequiredValue(common.Out)), result.GetValue(common.Force));
            var name = result.GetValue(common.Name)!;
            using var issuer = LoadCa(env, result.GetRequiredValue(ca), result.GetRequiredValue(caKey));
            plan.Reserve(name + ".crt", name + ".key");
            using var client = issuer.IssueClient(result.GetValue(cn)!, Days(result.GetValue(common.Days)));
            var files = new List<CertFile>();
            plan.WritePublic(name + ".crt", client.ChainPem + "\n", "client certificate", files);
            plan.WriteSecret(name + ".key", client.PrivateKeyPem, "client private key", files);
            return Task.FromResult(Finish(env, common, result, files, new Dictionary<string, string> { ["subject"] = client.Subject }));
        });
        return command;
    }

    // ---- ekmmock certs dev ----

    private static Command CreateDev(CliEnvironment env, GlobalOptions global)
    {
        var common = new CommonOptions("dev", 397);
        var fqdn = new Option<string>("--fqdn") { Description = "The server's host name (SAN and CN). localhost, 127.0.0.1 and ::1 are always added to the SAN.", DefaultValueFactory = _ => "localhost" };
        var cn = new Option<string>("--client-cn") { Description = $"CN of the fake Managed HSM client certificate. Default {DefaultClientCn}.", DefaultValueFactory = _ => DefaultClientCn };
        var command = new Command("dev", "Everything a local EkmMock needs, in one go (spec 11.2): a test root CA, a server certificate for --fqdn, a fake Managed HSM client CA with a client certificate\n" +
            "(CN test.managedhsmclient.local), the same CA's wrong-CN client and an untrusted-CA client (for the negative conformance tests), and mhsm-client.json in the format of\n" +
            "'az keyvault ekm-connection certificate show' (import it with 'ekmmock trust import').\n\n" +
            "Example:\n  ekmmock certs dev --out ./dev-pki --fqdn localhost\n");
        command.Options.Add(fqdn);
        command.Options.Add(cn);
        common.AddDevTo(command);
        CliApp.SetAction(command, env, global, (result, _) =>
        {
            var plan = new FilePlan(env.ResolvePath(result.GetRequiredValue(common.Out)), result.GetValue(common.Force));
            plan.Reserve(
                "root-ca.pem", "root-ca.key", "server.crt", "server.key", "mhsm-client-ca.pem", "mhsm-client-ca.key", "client.crt", "client.key",
                "client-wrong-cn.crt", "client-wrong-cn.key", "client-untrusted-ca.crt", "client-untrusted-ca.key", "server-replacement.crt", "server-replacement.key", "mhsm-client.json");
            var days = Days(result.GetValue(common.Days));
            var algorithm = common.Algorithm(result);
            var clientCn = result.GetValue(cn)!;
            var hosts = HostNames(result.GetValue(fqdn)!, ["localhost", "127.0.0.1", "::1"]);
            var tag = Tag();

            using var serverCa = CertificateAuthority.CreateRoot("EkmMock Test Root CA " + tag, algorithm);
            using var server = serverCa.IssueServer(hosts, days);
            using var replacement = serverCa.IssueServer(hosts, days);
            using var clientCa = CertificateAuthority.CreateRoot("EkmMock Fake Managed HSM Client CA " + tag, algorithm);
            using var client = clientCa.IssueClient(clientCn, days);
            using var wrongCn = clientCa.IssueClient("wrong-cn.managedhsmclient.local", days);
            using var rogueCa = CertificateAuthority.CreateRoot("EkmMock Untrusted Rogue CA " + tag, algorithm);
            using var rogue = rogueCa.IssueClient(clientCn, days);

            var files = new List<CertFile>();
            WriteCa(plan, serverCa, "root-ca", files);
            plan.WritePublic("server.crt", server.ChainPem + "\n", "server certificate (chain), SAN " + string.Join(", ", hosts), files);
            plan.WriteSecret("server.key", server.PrivateKeyPem, "server private key", files);
            plan.WritePublic("server-replacement.crt", replacement.ChainPem + "\n", "a second server certificate for the same host (certificate reload test)", files);
            plan.WriteSecret("server-replacement.key", replacement.PrivateKeyPem, "private key of the replacement server certificate", files);
            WriteCa(plan, clientCa, "mhsm-client-ca", files);
            plan.WritePublic("client.crt", client.ChainPem + "\n", $"client certificate, CN {clientCn}", files);
            plan.WriteSecret("client.key", client.PrivateKeyPem, "client private key", files);
            plan.WritePublic("client-wrong-cn.crt", wrongCn.ChainPem + "\n", "client certificate of a trusted CA with another CN (negative test)", files);
            plan.WriteSecret("client-wrong-cn.key", wrongCn.PrivateKeyPem, "private key of the wrong-CN client", files);
            plan.WritePublic("client-untrusted-ca.crt", rogue.ChainPem + "\n", "client certificate of an untrusted CA (negative test)", files);
            plan.WriteSecret("client-untrusted-ca.key", rogue.PrivateKeyPem, "private key of the untrusted-CA client", files);
            plan.WritePublic("mhsm-client.json", MhsmClientJson(clientCa, clientCn), "trust description in the format of 'az keyvault ekm-connection certificate show'", files);

            var details = new Dictionary<string, string>
            {
                ["server_san"] = string.Join(", ", hosts),
                ["client_cn"] = clientCn,
            };
            var code = Finish(env, common, result, files, details);
            if (!common.Output.WantsJson(result))
            {
                PrintDevNextSteps(env, plan.Folder, hosts[0], clientCn);
            }

            return Task.FromResult(code);
        });
        return command;
    }

    private static void PrintDevNextSteps(CliEnvironment env, string folder, string host, string clientCn)
    {
        string P(string file) => Path.Combine(folder, file);
        var o = env.Out;
        o.WriteLine();
        o.WriteLine("Next steps:");
        o.WriteLine("  1. init the data folder and start the server with these certificates (bash; PowerShell: $env:NAME = 'value'):");
        o.WriteLine("       ekmmock init --data ./data");
        o.WriteLine($"       export Tls__CertFile='{P("server.crt")}' Tls__KeyFile='{P("server.key")}' EKMMOCK_MASTER_KEY_FILE='{Path.GetFullPath("./data/master.key")}' Data__Path='{Path.GetFullPath("./data")}'");
        o.WriteLine("       dotnet run --project src/EkmMock.Server");
        o.WriteLine($"  2. trust the fake Managed HSM client:   ekmmock trust import --ns _default --json {P("mhsm-client.json")} --console https://127.0.0.1:8080 --console-ca {P("root-ca.pem")}");
        o.WriteLine($"  3. create sample keys:                  ekmmock key create --ns _default --name aes-key-1 --type aes --console https://127.0.0.1:8080 --console-ca {P("root-ca.pem")}");
        o.WriteLine($"  4. run the conformance suite:           ekmmock test conformance --url https://{host}:8443 --client-cert {P("client.crt")} --client-key {P("client.key")} --ca {P("root-ca.pem")} \\");
        o.WriteLine($"                                            --alt-client-cert {P("client-wrong-cn.crt")} --alt-client-key {P("client-wrong-cn.key")} --rogue-client-cert {P("client-untrusted-ca.crt")} --rogue-client-key {P("client-untrusted-ca.key")} \\");
        o.WriteLine($"                                            --replacement-server-cert {P("server-replacement.crt")} --replacement-server-key {P("server-replacement.key")} \\");
        o.WriteLine($"                                            --console https://127.0.0.1:8080 --console-ca {P("root-ca.pem")}");
        o.WriteLine($"     (the client certificate has CN {clientCn})");
    }

    // ---- helpers ----

    private static string MhsmClientJson(CertificateAuthority clientCa, string commonName)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteStartArray("caCertificates");
            writer.WriteStringValue(clientCa.DerBase64);
            writer.WriteEndArray();
            writer.WriteString("subjectCommonName", commonName);
            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(stream.ToArray()) + "\n";
    }

    private static void WriteCa(FilePlan plan, CertificateAuthority ca, string baseName, List<CertFile> files)
    {
        plan.WritePublic(baseName + ".pem", ca.CertificatePem + "\n", "CA certificate", files);
        plan.WriteSecret(baseName + ".key", ca.PrivateKeyPem, "CA private key (keep it: it issues certificates)", files);
    }

    private static CertificateAuthority LoadCa(CliEnvironment env, string certFile, string keyFile)
    {
        var certPath = env.ResolvePath(certFile);
        var keyPath = env.ResolvePath(keyFile);
        if (!File.Exists(certPath))
        {
            throw CliException.Usage($"The CA certificate does not exist: {certPath}");
        }

        if (!File.Exists(keyPath))
        {
            throw CliException.Usage($"The CA private key does not exist: {keyPath}");
        }

        try
        {
            return CertificateAuthority.Load(File.ReadAllText(certPath), File.ReadAllText(keyPath));
        }
        catch (ArgumentException exception)
        {
            throw CliException.Usage(exception.Message);
        }
    }

    private static string[] HostNames(string fqdn, IEnumerable<string>? extra)
    {
        var names = new List<string> { fqdn.Trim() };
        foreach (var name in extra ?? [])
        {
            if (!string.IsNullOrWhiteSpace(name) && !names.Contains(name.Trim(), StringComparer.OrdinalIgnoreCase))
            {
                names.Add(name.Trim());
            }
        }

        if (names.Any(static n => n.Contains(' ', StringComparison.Ordinal) || n.Contains('/', StringComparison.Ordinal)))
        {
            throw CliException.Usage("A SAN must be a DNS name or an IP address.");
        }

        return [.. names];
    }

    /// <summary>A short random tag in CA names: equal subject names from earlier runs make chain building ambiguous on Windows (the TLS stack caches CA certificates in the user's store, see OPEN-QUESTIONS 25).</summary>
    private static string Tag() => Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();

    private static TimeSpan Days(int days) => TimeSpan.FromDays(days);

    private static int Finish(CliEnvironment env, CommonOptions common, ParseResult result, List<CertFile> files, Dictionary<string, string> details)
    {
        if (common.Output.WantsJson(result))
        {
            env.Out.WriteLine(JsonSerializer.Serialize(new CertsResult(Notice, files, details), CliOutputJson.Default.CertsResult));
            return ExitCodes.Success;
        }

        env.Out.WriteLine("*** " + Notice + " ***");
        env.Out.WriteLine();
        foreach (var detail in details)
        {
            env.Out.WriteLine($"{detail.Key.Replace('_', ' ')}: {detail.Value}");
        }

        env.Out.WriteLine();
        TableWriter.Write(env.Out, ["File", "What", "Access"], files.Select(static f => (IReadOnlyList<string>)[f.Path, f.Role, f.Secret ? "owner only (private key)" : "public"]));
        env.Out.WriteLine();
        env.Out.WriteLine("Private keys are never printed. Register root-ca.pem (the CA, not the server certificate) with: az keyvault ekm-connection create --server-ca-certificate root-ca.pem ...");
        return ExitCodes.Success;
    }

    /// <summary>The options shared by the certs commands.</summary>
    private sealed class CommonOptions
    {
        public Option<string> Out { get; } = new("--out") { Description = "Folder to write the files into (created when missing).", Required = true };

        public Option<string> Name { get; }

        public Option<int> Days { get; }

        public Option<string> AlgorithmOption { get; } = new("--algorithm") { Description = "Key algorithm: 'rsa' (RSA-2048, default) or 'ecdsa' (P-256).", DefaultValueFactory = _ => "rsa" };

        public Option<bool> Force { get; } = new("--force") { Description = "Overwrite existing files. Without it nothing is overwritten and the command stops before writing." };

        public OutputOptionSet Output { get; } = new();

        public CommonOptions(string defaultName, int defaultDays)
        {
            Name = new Option<string>("--name") { Description = $"Certificate common name for a CA, file name stem for server/client. Default '{defaultName}'.", DefaultValueFactory = _ => defaultName };
            Days = new Option<int>("--days") { Description = $"Validity in days. Default {defaultDays}.", DefaultValueFactory = _ => defaultDays };
            Days.Validators.Add(static r =>
            {
                if (r.GetValueOrDefault<int>() is < 1 or > 36500)
                {
                    r.AddError("--days must be between 1 and 36500.");
                }
            });
            AlgorithmOption.AcceptOnlyFromAmong("rsa", "ecdsa");
        }

        public PkiKeyAlgorithm Algorithm(ParseResult result) => result.GetValue(AlgorithmOption) == "ecdsa" ? PkiKeyAlgorithm.EcdsaP256 : PkiKeyAlgorithm.Rsa2048;

        public void AddTo(Command command, bool withName = false)
        {
            command.Options.Add(Out);
            command.Options.Add(Name);
            command.Options.Add(Days);
            command.Options.Add(AlgorithmOption);
            command.Options.Add(Force);
            Output.AddTo(command);
            _ = withName;
        }

        public void AddDevTo(Command command)
        {
            command.Options.Add(Out);
            command.Options.Add(Days);
            command.Options.Add(AlgorithmOption);
            command.Options.Add(Force);
            Output.AddTo(command);
        }
    }

    /// <summary>Collects what a command is going to write, refuses before the first byte when anything exists (unless forced), then writes.</summary>
    private sealed class FilePlan
    {
        private readonly bool _force;

        public FilePlan(string folder, bool force)
        {
            Folder = folder;
            _force = force;
        }

        public string Folder { get; }

        public void Reserve(params string[] names)
        {
            var existing = names.Where(n => File.Exists(Path.Combine(Folder, n))).ToList();
            if (existing.Count > 0 && !_force)
            {
                throw CliException.Failure($"Not overwriting existing files in {Folder}: {string.Join(", ", existing)}. Use --force to replace them, or another --out folder.");
            }
        }

        public void WritePublic(string name, string content, string role, List<CertFile> files)
        {
            var path = Path.Combine(Folder, name);
            SecureFile.WritePublic(path, content, overwrite: true);
            files.Add(new CertFile(role, path, Secret: false));
        }

        /// <summary>Writes a copy of the root CA certificate next to the issued certificate unless a file of that name exists (then returns a note when its content differs).</summary>
        public string? WritePublicIfMissing(string name, string content, string role, List<CertFile> files)
        {
            var path = Path.Combine(Folder, name);
            if (File.Exists(path))
            {
                return File.ReadAllText(path).Trim() == content.Trim() ? null : $"{path} exists and differs from the CA certificate; it was left as it is.";
            }

            SecureFile.WritePublic(path, content);
            files.Add(new CertFile(role, path, Secret: false));
            return null;
        }

        public void WriteSecret(string name, string pem, string role, List<CertFile> files)
        {
            var path = Path.Combine(Folder, name);
            SecureFile.WriteSecret(path, pem.EndsWith('\n') ? pem : pem + "\n", overwrite: true);
            files.Add(new CertFile(role, path, Secret: true));
        }
    }
}
