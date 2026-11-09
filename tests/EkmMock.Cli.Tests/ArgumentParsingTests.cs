using System.CommandLine;

namespace EkmMock.Cli.Tests;

/// <summary>Spec 12: argument parsing and validation of every command, the exit codes, and the help of every command.</summary>
public sealed class ArgumentParsingTests : IDisposable
{
    private readonly CliHarness _cli = new();

    public void Dispose() => _cli.Dispose();

    // ---- help and version ----

    private static List<(string Path, Command Command)> AllCommands()
    {
        var root = CliApp.BuildRoot(new CliEnvironment { Out = TextWriter.Null, Error = TextWriter.Null }, out _);
        var list = new List<(string, Command)>();

        void Walk(Command command, string path)
        {
            list.Add((path, command));
            foreach (var sub in command.Subcommands)
            {
                Walk(sub, (path + " " + sub.Name).Trim());
            }
        }

        Walk(root, string.Empty);
        return list;
    }

    public static TheoryData<string> CommandPaths()
    {
        var data = new TheoryData<string>();
        foreach (var (path, _) in AllCommands())
        {
            data.Add(path);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(CommandPaths))]
    public async Task EveryCommand_HasHelp_WithUsage(string path)
    {
        var args = path.Split(' ', StringSplitOptions.RemoveEmptyEntries).Append("--help").ToArray();

        var run = await _cli.RunAsync(args);

        run.ExitCode.ShouldBe(0, run.ToString());
        run.Out.ShouldContain("Usage:");
        run.Out.ShouldContain("--help");
    }

    [Fact]
    public async Task EveryLeafCommand_HasExamplesInItsHelp()
    {
        var leaves = AllCommands().Where(static c => c.Command.Subcommands.Count == 0 && c.Command.Name != "ekmmock" && c.Path.Length > 0).ToList();

        leaves.Count.ShouldBeGreaterThan(15);
        foreach (var (path, _) in leaves)
        {
            var run = await _cli.RunAsync(path.Split(' ').Append("--help").ToArray());
            run.Out.ShouldContain("Example", customMessage: path);
        }
    }

    [Fact]
    public async Task TheHelpOfTheRoot_DocumentsTheExitCodes()
    {
        var run = await _cli.RunAsync("--help");

        run.Out.ShouldContain("Exit codes");
        run.Out.ShouldContain("3 connection or authentication error");
    }

    [Fact]
    public async Task Version_PrintsTheToolVersion_AndNothingElse()
    {
        var run = await _cli.RunAsync("--version");

        run.ExitCode.ShouldBe(0);
        run.Out.Trim().ShouldBe(CliVersion.Current);
        run.Out.Trim().ShouldMatch(@"^\d+\.\d+\.\d+");
    }

    // ---- usage errors are exit code 2 ----

    [Theory]
    [InlineData("nope")]
    [InlineData("key", "frobnicate")]
    [InlineData("key")]
    [InlineData("certs")]
    [InlineData("test")]
    [InlineData("--no-such-option")]
    public async Task UnknownOrIncompleteCommands_AreUsageErrors_WithAHint_AndNoStackTrace(params string[] args)
    {
        var run = await _cli.RunAsync(args);

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("error:");
        run.Error.ShouldContain("--help");
        run.All.ShouldNotContain("   at ");
    }

    public static TheoryData<string[]> MissingRequiredOptions() => new()
    {
        { ["init"] },
        { ["certs", "ca"] },
        { ["certs", "server", "--out", "x"] },
        { ["certs", "client", "--out", "x"] },
        { ["key", "create", "--name", "k"] },
        { ["key", "create", "--type", "aes"] },
        { ["key", "enable"] },
        { ["key", "disable"] },
        { ["key", "expire", "--name", "k"] },
        { ["key", "destroy", "--name", "k"] },
        { ["key", "destroy", "--confirm", "k"] },
        { ["trust", "import"] },
        { ["ns", "create"] },
        { ["ns", "delete", "--name", "n"] },
        { ["faults", "preset"] },
        { ["faults", "delete"] },
        { ["test", "conformance"] },
        { ["test", "bench", "--url", "https://x.test"] },
        { ["test", "bench", "--op", "info"] },
    };

    [Theory]
    [MemberData(nameof(MissingRequiredOptions))]
    public async Task MissingRequiredOptions_AreUsageErrors(string[] args)
    {
        var run = await _cli.RunAsync(args);

        run.ExitCode.ShouldBe(2, run.ToString());
    }

    [Fact]
    public async Task KeyExpire_NeedsExactlyOneOfAtAndClear()
    {
        (await _cli.RunAsync("key", "expire", "--name", "k")).ExitCode.ShouldBe(2);
        var both = await _cli.RunAsync("key", "expire", "--name", "k", "--at", "2030-01-01T00:00:00Z", "--clear");
        both.ExitCode.ShouldBe(2);
        both.Error.ShouldContain("exactly one of --at");
    }

    [Fact]
    public async Task KeyExpire_WithAnUnparseableTime_IsAUsageError_BeforeAnyRequest()
    {
        var run = await _cli.RunAsync("key", "expire", "--name", "k", "--at", "next tuesday", "--console", "https://127.0.0.1:1");

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("ISO 8601");
    }

    [Theory]
    [InlineData("bad name", "aes", null)]
    [InlineData("under_score", "aes", null)]
    [InlineData("ok", "aes", "512")]
    [InlineData("ok", "rsa", "1024")]
    [InlineData("ok", "rsa", "256")]
    public async Task KeyCreate_ValidatesNameTypeAndSize_BeforeAnyRequest(string name, string type, string? size)
    {
        var args = new List<string> { "key", "create", "--name", name, "--type", type, "--console", "https://127.0.0.1:1" };
        if (size is not null)
        {
            args.AddRange(["--size", size]);
        }

        var run = await _cli.RunAsync([.. args]);

        run.ExitCode.ShouldBe(2, run.ToString());
    }

    [Fact]
    public async Task KeyCreate_WithAnUnknownType_IsAUsageError()
    {
        var run = await _cli.RunAsync("key", "create", "--name", "k", "--type", "des");

        run.ExitCode.ShouldBe(2);
        run.Error.ShouldContain("aes");
    }

    [Fact]
    public async Task KeyDestroy_RequiresTheNameTypedAgain_AndSendsNothingOtherwise()
    {
        var requests = 0;
        _cli.ConsoleHandler = () => new StubHandler(_ =>
        {
            requests++;
            return StubHandler.Json(200, "{}");
        });

        var run = await _cli.RunAsync("key", "destroy", "--ns", "_default", "--name", "aes-key-1", "--confirm", "aes-key-2");

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("--confirm must repeat the key name exactly");
        run.Error.ShouldContain("Nothing was changed");
        requests.ShouldBe(0);
    }

    [Fact]
    public async Task KeyDestroy_ConfirmationIsCaseSensitive()
    {
        var run = await _cli.RunAsync("key", "destroy", "--name", "Aes-Key-1", "--confirm", "aes-key-1");

        run.ExitCode.ShouldBe(2);
    }

    [Fact]
    public async Task NamespaceDelete_RequiresTheNameTypedAgain()
    {
        var run = await _cli.RunAsync("ns", "delete", "--name", "contoso", "--confirm", "contoso-x");

        run.ExitCode.ShouldBe(2);
    }

    [Fact]
    public async Task TrustImport_NeedsExactlyOneInput_AndPemNeedsACn()
    {
        File.WriteAllText(_cli.File("a.json"), "{}");

        (await _cli.RunAsync("trust", "import", "--json", _cli.File("a.json"), "--pem", _cli.File("a.json"))).ExitCode.ShouldBe(2);
        var pem = await _cli.RunAsync("trust", "import", "--pem", _cli.File("a.json"));
        pem.ExitCode.ShouldBe(2);
        pem.Error.ShouldContain("--cn");
    }

    [Fact]
    public async Task TrustImport_WithAMissingFile_IsAUsageError()
    {
        var run = await _cli.RunAsync("trust", "import", "--json", _cli.File("missing.json"));

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("does not exist");
    }

    [Theory]
    [InlineData("--console", "http://127.0.0.1:8080")]
    [InlineData("--console", "not a url")]
    [InlineData("--console", "127.0.0.1:8080")]
    public async Task TheConsoleUrl_MustBeAnAbsoluteHttpsUrl(string option, string value)
    {
        var run = await _cli.RunAsync("key", "list", option, value);

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("https");
    }

    [Fact]
    public async Task TheInsecureConsoleOption_IsRefusedForANonLoopbackHost()
    {
        var run = await _cli.RunAsync("key", "list", "--console", "https://ekm.contoso.test:8080", "--insecure-console-cert");

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("loopback");
    }

    [Fact]
    public async Task AuthEntra_NeedsTenantAndClientId()
    {
        var run = await _cli.RunAsync("key", "list", "--auth", "entra");

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("--tenant");
        run.Error.ShouldContain("--client-id");
    }

    [Fact]
    public async Task AuthEntra_IsSatisfiedByTheEnvironment()
    {
        _cli.Environment = name => name switch
        {
            "EKMMOCK_TENANT_ID" => "44444444-4444-4444-4444-444444444444",
            "EKMMOCK_CLIENT_ID" => "55555555-5555-5555-5555-555555555555",
            _ => null,
        };
        _cli.ConsoleHandler = () => new StubHandler(_ => StubHandler.Json(200, """{"keys":[]}"""));
        _cli.Credential = (_, _) => new FakeCredential("token");

        var run = await _cli.RunAsync("key", "list", "--auth", "entra");

        run.ExitCode.ShouldBe(0, run.ToString());
    }

    // ---- bench and conformance arguments ----

    [Theory]
    [InlineData("--op", "wrapkey")]
    [InlineData("--op", "unwrapkey", "--key", "k")]
    [InlineData("--op", "metadata")]
    [InlineData("--op", "info", "--concurrency", "0")]
    [InlineData("--op", "info", "--concurrency", "5000")]
    [InlineData("--op", "info", "--rate", "0")]
    [InlineData("--op", "info", "--dek-size", "0")]
    [InlineData("--op", "frobnicate")]
    public async Task Bench_ValidatesItsArguments(params string[] extra)
    {
        var run = await _cli.RunAsync(["test", "bench", "--url", "https://localhost:1", .. extra]);

        run.ExitCode.ShouldBe(2, run.ToString());
    }

    [Theory]
    [InlineData("soon")]
    [InlineData("-5s")]
    [InlineData("0s")]
    [InlineData("99999h")]
    public async Task Bench_RejectsAnUnparseableDuration(string duration)
    {
        var run = await _cli.RunAsync("test", "bench", "--url", "https://localhost:1", "--op", "info", "--duration", duration);

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("--duration");
    }

    [Theory]
    [InlineData("http://ekm.contoso.test")]
    [InlineData("ekm.contoso.test")]
    [InlineData("https://ekm.contoso.test/bad_prefix")]
    [InlineData("https://ekm.contoso.test/a?x=1")]
    public async Task Conformance_RejectsAnInvalidUrl(string url)
    {
        File.WriteAllText(_cli.File("c.crt"), "x");
        File.WriteAllText(_cli.File("c.key"), "x");

        var run = await _cli.RunAsync("test", "conformance", "--url", url, "--client-cert", _cli.File("c.crt"), "--client-key", _cli.File("c.key"));

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("--url");
    }

    [Fact]
    public async Task Conformance_NeedsTheClientCertificateAndKeyTogether()
    {
        var withoutCert = await _cli.RunAsync("test", "conformance", "--url", "https://localhost:1");
        File.WriteAllText(_cli.File("c.crt"), "x");
        var withoutKey = await _cli.RunAsync("test", "conformance", "--url", "https://localhost:1", "--client-cert", _cli.File("c.crt"));

        withoutCert.ExitCode.ShouldBe(2);
        withoutKey.ExitCode.ShouldBe(2);
    }

    [Fact]
    public async Task Conformance_RejectsHalfOfAnOptionalCertificatePair()
    {
        var run = await _cli.RunAsync("test", "conformance", "--url", "https://localhost:1", "--client-cert", "a", "--client-key", "b", "--alt-client-cert", "c");

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("--alt-client-cert and --alt-client-key go together");
    }

    [Fact]
    public async Task Conformance_WithUnreadableCertificateFiles_IsAUsageError_NamingTheOption()
    {
        File.WriteAllText(_cli.File("junk.pem"), "not a certificate");

        var run = await _cli.RunAsync("test", "conformance", "--url", "https://localhost:1", "--client-cert", _cli.File("junk.pem"), "--client-key", _cli.File("junk.pem"));

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldNotContain("not a certificate");
    }

    [Fact]
    public async Task Conformance_WithAnUnknownOnlyFilter_IsAUsageError()
    {
        var pki = _cli.File("pki");
        (await _cli.RunAsync("certs", "dev", "--out", pki)).ExitCode.ShouldBe(0);

        var run = await _cli.RunAsync("test", "conformance", "--url", "https://localhost:1", "--client-cert", Path.Combine(pki, "client.crt"), "--client-key", Path.Combine(pki, "client.key"), "--only", "14.99");

        run.ExitCode.ShouldBe(2, run.ToString());
        run.Error.ShouldContain("matches no test");
    }
}
