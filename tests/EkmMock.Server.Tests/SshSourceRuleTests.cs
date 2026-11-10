using System.Diagnostics;

namespace EkmMock.Server.Tests;

/// <summary>Runs alone (like the benchmark): it starts several Bicep processes at once, which would starve the timing-sensitive tests that run beside it.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class BicepEvaluationCollection
{
    public const string Name = "BicepEvaluation";
}

/// <summary>
/// Security review L6 and L7: the VM template's SSH source rule (one narrow IPv4/IPv6 address or range, nothing else) and its <c>repoRef</c> guard are not mirrored here, they are <b>evaluated by the real template</b>:
/// <c>bicep snapshot</c> of a throw-away <c>.bicepparam</c> runs the ARM template language locally (no Azure, no login), so an unacceptable value fails exactly as it would fail a deployment
/// (<c>substring()</c> asked for more characters than the string has).
/// <para>
/// The tests need the Bicep CLI (<c>bicep</c> on the PATH, or the one <c>az bicep install</c> puts in <c>~/.azure/bin</c>). Without it they are skipped, unless <c>EKMMOCK_REQUIRE_BICEP=true</c> (the Azure job of CI sets it), then they fail.
/// </para>
/// </summary>
[Collection(BicepEvaluationCollection.Name)]
public sealed class SshSourceRuleTests : IDisposable
{
    private const string Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA test@test";
    private const string Master = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private static readonly Lazy<string?> BicepPath = new(FindBicep);
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "ekmmock-bicep-" + Guid.NewGuid().ToString("N"));
    private int _counter;

    public SshSourceRuleTests()
    {
        Directory.CreateDirectory(_folder);
        foreach (var file in new[] { "vm.bicep", "vm-setup.sh", "cloud-init.yaml", "bicepconfig.json" })
        {
            File.Copy(RepositoryFiles.FullPath("deploy/azure/" + file), Path.Combine(_folder, file));
        }
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_folder, recursive: true);
        }
        catch (IOException)
        {
            // A temp folder left behind is harmless.
        }
    }

    private static string? FindBicep()
    {
        var names = OperatingSystem.IsWindows() ? new[] { "bicep.exe" } : new[] { "bicep" };
        var directories = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Append(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".azure", "bin"));
        foreach (var directory in directories)
        {
            foreach (var name in names)
            {
                var candidate = Path.Combine(directory, name);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }

    private static string RequireBicep()
    {
        if (BicepPath.Value is { } path)
        {
            return path;
        }

        if (string.Equals(Environment.GetEnvironmentVariable("EKMMOCK_REQUIRE_BICEP"), "true", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("EKMMOCK_REQUIRE_BICEP=true but the Bicep CLI was not found (PATH or ~/.azure/bin).");
        }

        Assert.Skip("The Bicep CLI is not installed (bicep on the PATH, or az bicep install); the template rules are evaluated with 'bicep snapshot'.");
        return string.Empty;
    }

    /// <summary>True when the template evaluates with these parameters (and then the NSG rule carries exactly the trimmed address); false when evaluation fails, as a deployment would.</summary>
    private async Task<(bool Accepted, string Output)> EvaluateAsync(string bicep, string sshSource, string? repoRef = "v1.0.0", string? imageSource = null)
    {
        var id = "case" + Interlocked.Increment(ref _counter);
        var parameters = $"""
            using './vm.bicep'
            param sshPublicKey = '{Key}'
            param allowedSshSourceAddress = '{sshSource.Replace("'", "\\'", StringComparison.Ordinal)}'
            param masterKey = '{Master}'
            {(repoRef is null ? string.Empty : $"param repoRef = '{repoRef}'")}
            {(imageSource is null ? string.Empty : $"param imageSource = '{imageSource}'")}
            {(imageSource == "pull" ? "param containerImage = 'registry.example.test/ekmmock:1.0.0'" : string.Empty)}
            """;
        var file = Path.Combine(_folder, id + ".bicepparam");
        await File.WriteAllTextAsync(file, parameters, TestContext.Current.CancellationToken);

        var start = new ProcessStartInfo(bicep)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = _folder,
        };
        foreach (var argument in new[] { "snapshot", file, "--mode", "overwrite", "--subscription-id", "00000000-0000-0000-0000-000000000000", "--resource-group", "rg", "--location", "westeurope" })
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var error = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await process.WaitForExitAsync(TestContext.Current.CancellationToken);
        var text = (await output) + (await error);
        if (process.ExitCode != 0)
        {
            return (false, text);
        }

        var snapshot = await File.ReadAllTextAsync(Path.Combine(_folder, id + ".snapshot.json"), TestContext.Current.CancellationToken);
        return (true, snapshot);
    }

    private static readonly (string Value, bool Accepted)[] SshSources =
    [
        // ---- accepted: one IPv4 address, or an IPv4 range no wider than /16 ----
        ("203.0.113.7", true),
        ("1.2.3.4", true),
        ("198.51.100.255", true),
        ("203.0.113.0/28", true),
        ("203.0.0.0/16", true),
        ("10.1.2.3/32", true),
        ("  203.0.113.7  ", true),

        // ---- rejected: open, too wide, malformed ----
        ("0.0.0.0/0", false),
        ("0.0.0.0", false),
        ("10.0.0.0/8", false),
        ("203.0.0.0/15", false),
        ("203.0.113.0/0", false),
        ("203.0.113.0/33", false),
        ("203.0.113.0/", false),
        ("203.0.113.0//28", false),
        ("203.0.113.0/28/1", false),
        ("256.0.0.1", false),
        ("203.0.113", false),
        ("203.0.113.7.1", false),
        ("203.0.113.07", false),
        ("203.0.113.a", false),
        ("203.0.113.7/ab", false),
        ("203.0.113.7/016", false),
        ("203.0.113.7,203.0.113.8", false),
        ("203.0.113.7 203.0.113.8", false),
        ("-1.0.0.1/24", false),

        // ---- rejected: service tags, wildcards, names ----
        ("*", false),
        ("Internet", false),
        ("internet", false),
        ("VirtualNetwork", false),
        ("AzureCloud", false),
        ("Any", false),
        ("any", false),
        ("ekm.example.test", false),
        ("https://203.0.113.7", false),

        // ---- IPv6: one address, or a range no wider than /48 ----
        ("2001:db8::1", true),
        ("2001:db8:abcd::/48", true),
        ("2001:db8:abcd:1234::/64", true),
        ("2001:db8:abcd:1234:5678:9abc:def0:1234/128", true),
        ("::/0", false),
        ("::", false),
        ("2001:db8::/32", false),
        ("2001:db8::/47", false),
        ("2001:db8::/129", false),
        ("2001:db8:::1", false),
        ("2001:db8::1::2", false),
        ("12345::1", false),
        ("2001:db8::g", false),
        ("2001:db8", false),
        ("1:2:3:4:5:6:7:8:9", false),
    ];

    [Fact]
    public async Task TheSshSourceRule_AcceptsOnlyANarrowAddress_AsEvaluatedByTheRealTemplate()
    {
        var bicep = RequireBicep();
        var cases = SshSources;
        var failures = new System.Collections.Concurrent.ConcurrentBag<string>();

        await Parallel.ForEachAsync(cases, new ParallelOptions { MaxDegreeOfParallelism = 6, CancellationToken = TestContext.Current.CancellationToken }, async (item, _) =>
        {
            var (value, expected) = item;
            var (accepted, output) = await EvaluateAsync(bicep, value);
            if (!accepted && !output.Contains("'sshSourceChecked'", StringComparison.Ordinal) && !output.Contains("BCP333", StringComparison.Ordinal))
            {
                failures.Add($"'{value}': rejected, but not by the SSH source rule (and not by the parameter length limits): {output.Trim()}");
            }
            if (accepted != expected)
            {
                failures.Add($"'{value}': expected {(expected ? "accepted" : "rejected")}, the template {(accepted ? "accepted" : "rejected")} it");
            }
            else if (accepted && !output.Contains($"\"sourceAddressPrefix\": \"{value.Trim()}\"", StringComparison.Ordinal))
            {
                failures.Add($"'{value}': accepted, but the NSG rule does not carry the trimmed address");
            }
        });

        failures.ShouldBeEmpty(string.Join(Environment.NewLine, failures.Order(StringComparer.Ordinal)));
    }

    [Fact]
    public async Task TheRepoRefPlaceholder_FailsABuildDeployment_ButNotAPullDeployment_AndATagOrShaPasses()
    {
        var bicep = RequireBicep();

        var byDefault = await EvaluateAsync(bicep, "203.0.113.7", repoRef: null);
        byDefault.Accepted.ShouldBeFalse("the default placeholder must fail a build deployment");
        byDefault.Output.ShouldContain("'repoRefChecked'");
        (await EvaluateAsync(bicep, "203.0.113.7", repoRef: "<REPLACE-WITH-TAG-OR-SHA>")).Accepted.ShouldBeFalse();
        (await EvaluateAsync(bicep, "203.0.113.7", repoRef: null, imageSource: "pull")).Accepted.ShouldBeTrue("the ref is not used when the image is pulled");
        (await EvaluateAsync(bicep, "203.0.113.7", repoRef: "v1.2.3")).Accepted.ShouldBeTrue();
        (await EvaluateAsync(bicep, "203.0.113.7", repoRef: "0123456789abcdef0123456789abcdef01234567")).Accepted.ShouldBeTrue();
    }

}
