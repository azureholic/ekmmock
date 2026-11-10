using EkmMock.Pki;
using EkmMock.Cli.Commands;
using EkmMock.Cli.Infrastructure;

namespace EkmMock.Cli.Tests;

/// <summary>Spec 6.2 and 12: <c>ekmmock init</c>. The master key is the one thing in this tool that must never be lost, leaked or silently replaced.</summary>
public sealed class InitCommandTests : IDisposable
{
    private readonly CliHarness _cli = new();

    public void Dispose() => _cli.Dispose();

    private string Data => _cli.File("data");

    [Fact]
    public async Task Init_CreatesTheDataFolders_AndAValidMasterKeyFile()
    {
        var run = await _cli.RunAsync("init", "--data", Data);

        run.ExitCode.ShouldBe(0, run.ToString());
        foreach (var folder in new[] { "", "tls", "inspector", "dataprotection" })
        {
            Directory.Exists(Path.Combine(Data, folder)).ShouldBeTrue(folder);
        }

        var keyFile = Path.Combine(Data, "master.key");
        File.Exists(keyFile).ShouldBeTrue();
        InitCommand.IsValidMasterKeyFile(keyFile).ShouldBeTrue();
        Convert.FromBase64String(File.ReadAllText(keyFile).Trim()).Length.ShouldBe(32);
    }

    [Fact]
    public async Task Init_NeverPrintsTheKey_ButSaysHowToUseTheFile()
    {
        var run = await _cli.RunAsync("init", "--data", Data);

        var key = File.ReadAllText(Path.Combine(Data, "master.key")).Trim();
        run.All.ShouldNotContain(key);
        run.All.ShouldNotContain(Convert.ToHexString(Convert.FromBase64String(key)), Case.Insensitive);
        run.Out.ShouldContain("EKMMOCK_MASTER_KEY_FILE");
        run.Out.ShouldContain(Path.Combine(Data, "master.key"));
        run.Out.ShouldContain("$env:EKMMOCK_MASTER_KEY_FILE");
        run.Out.ShouldContain("export EKMMOCK_MASTER_KEY_FILE");
    }

    [Fact]
    public async Task Init_WithPrint_PrintsTheKeyOnStdout_AndWarnsOnStderr()
    {
        var run = await _cli.RunAsync("init", "--data", Data, "--print");

        var key = File.ReadAllText(Path.Combine(Data, "master.key")).Trim();
        run.Out.ShouldContain(key);
        run.Error.ShouldContain("--print");
        run.Error.ShouldNotContain(key);
    }

    [Fact]
    public async Task Init_RestrictsTheMasterKeyFileToTheCurrentUser()
    {
        await _cli.RunAsync("init", "--data", Data);

        SecureFile.IsOwnerOnly(Path.Combine(Data, "master.key")).ShouldBeTrue();
    }

    [Fact]
    public async Task Init_IsIdempotent_AnExistingMasterKeyIsKept()
    {
        await _cli.RunAsync("init", "--data", Data);
        var before = File.ReadAllText(Path.Combine(Data, "master.key"));

        var again = await _cli.RunAsync("init", "--data", Data);

        again.ExitCode.ShouldBe(0, again.ToString());
        File.ReadAllText(Path.Combine(Data, "master.key")).ShouldBe(before);
        again.Out.ShouldContain("already exists, kept");
        again.Out.ShouldContain("Nothing to do");
    }

    [Fact]
    public async Task Init_WithAnExistingKeyStore_RefusesToReplaceTheMasterKey_EvenWithForce()
    {
        await _cli.RunAsync("init", "--data", Data);
        var before = File.ReadAllText(Path.Combine(Data, "master.key"));
        File.WriteAllText(Path.Combine(Data, "keystore.json"), "{}");

        var run = await _cli.RunAsync("init", "--data", Data, "--force");

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain("a key store exists");
        File.ReadAllText(Path.Combine(Data, "master.key")).ShouldBe(before);
    }

    [Fact]
    public async Task Init_WithAKeyStoreButNoMasterKey_RefusesToCreateOneThatCouldNotOpenTheStore()
    {
        Directory.CreateDirectory(Data);
        File.WriteAllText(Path.Combine(Data, "keystore.json"), "{}");

        var run = await _cli.RunAsync("init", "--data", Data);

        run.ExitCode.ShouldBe(1, run.ToString());
        run.Error.ShouldContain("no master key");
        File.Exists(Path.Combine(Data, "master.key")).ShouldBeFalse();
    }

    [Fact]
    public async Task Init_WithForceAndNoKeyStore_ReplacesTheMasterKey()
    {
        await _cli.RunAsync("init", "--data", Data);
        var before = File.ReadAllText(Path.Combine(Data, "master.key"));

        var run = await _cli.RunAsync("init", "--data", Data, "--force");

        run.ExitCode.ShouldBe(0, run.ToString());
        File.ReadAllText(Path.Combine(Data, "master.key")).ShouldNotBe(before);
        InitCommand.IsValidMasterKeyFile(Path.Combine(Data, "master.key")).ShouldBeTrue();
    }

    [Fact]
    public async Task Init_WithAnInvalidExistingKeyFile_LeavesItAlone()
    {
        Directory.CreateDirectory(Data);
        var keyFile = Path.Combine(Data, "master.key");
        File.WriteAllText(keyFile, "this is not a key");

        var run = await _cli.RunAsync("init", "--data", Data);

        run.ExitCode.ShouldBe(1, run.ToString());
        File.ReadAllText(keyFile).ShouldBe("this is not a key");
        run.Error.ShouldNotContain("this is not a key");
    }

    [Fact]
    public async Task Init_CanPutTheMasterKeyOutsideTheDataFolder()
    {
        var keyFile = _cli.File("secrets/ekmmock.key");

        var run = await _cli.RunAsync("init", "--data", Data, "--master-key-file", keyFile);

        run.ExitCode.ShouldBe(0, run.ToString());
        File.Exists(keyFile).ShouldBeTrue();
        File.Exists(Path.Combine(Data, "master.key")).ShouldBeFalse();
        run.Out.ShouldNotContain("inside the data folder");
    }

    [Fact]
    public async Task Init_WithJsonOutput_IsMachineReadable_AndOnlyContainsTheKeyWithPrint()
    {
        var run = await _cli.RunAsync("init", "--data", Data, "--output", "json");

        using var json = System.Text.Json.JsonDocument.Parse(run.Out);
        json.RootElement.GetProperty("master_key_created").GetBoolean().ShouldBeTrue();
        json.RootElement.GetProperty("environment").GetProperty("EKMMOCK_MASTER_KEY_FILE").GetString().ShouldEndWith("master.key");
        json.RootElement.TryGetProperty("master_key", out _).ShouldBeFalse();
    }

    [Fact]
    public async Task Init_WithoutData_IsAUsageError()
    {
        var run = await _cli.RunAsync("init");

        run.ExitCode.ShouldBe(2);
        run.Error.ShouldContain("--data");
    }

    [Fact]
    public async Task TheCreatedMasterKey_IsReadableByTheServersOwnProvider_Format()
    {
        await _cli.RunAsync("init", "--data", Data);

        var provider = new EkmMock.Crypto.FileMasterKeyProvider(Path.Combine(Data, "master.key"));

        using var key = provider.GetMasterKey();
        key.IsThrowAway.ShouldBeFalse();
    }
}
