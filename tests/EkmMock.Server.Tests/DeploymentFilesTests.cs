using System.Text.RegularExpressions;

namespace EkmMock.Server.Tests;

/// <summary>
/// Static checks of the deployment files (M9): the Dockerfile, the compose files, .dockerignore, the CI workflow and Dependabot. They cannot prove a container behaves (the CI image job and the M9
/// verification do that) but they stop the rules of spec 5.5 and 11 from rotting: pinned base images, a non-root user, no secrets in the files, a loopback-only console publish, pinned actions.
/// </summary>
public sealed partial class DeploymentFilesTests
{
    private static string Root
    {
        get
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "EkmMock.sln")))
            {
                directory = directory.Parent;
            }

            return directory?.FullName ?? throw new InvalidOperationException("EkmMock.sln was not found above the test output.");
        }
    }

    private static string Read(string relative) => File.ReadAllText(Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar)));

    /// <summary>The file without comment lines and blank lines.</summary>
    private static string[] Code(string relative)
        => [.. Read(relative).Split('\n').Select(static l => l.TrimEnd('\r')).Where(static l => l.Trim().Length > 0 && !l.TrimStart().StartsWith('#'))];

    [GeneratedRegex(@"^FROM\s+(?<image>\S+)(\s+AS\s+(?<name>\S+))?\s*$", RegexOptions.IgnoreCase | RegexOptions.Multiline)]
    private static partial Regex FromLine();

    // ---- Dockerfile ----

    [Fact]
    public void TheDockerfile_IsMultiStage_OnTheSpecifiedImages_PinnedByTagAndDigest()
    {
        var froms = FromLine().Matches(Read("deploy/docker/Dockerfile")).Select(static m => m.Groups["image"].Value).ToList();

        froms.Count.ShouldBe(2);
        froms[0].ShouldStartWith("mcr.microsoft.com/dotnet/sdk:10.0");
        froms[1].ShouldStartWith("mcr.microsoft.com/dotnet/aspnet:10.0");
        foreach (var image in froms)
        {
            image.ShouldNotContain(":latest");
            Regex.IsMatch(image, @":10\.0[\w.-]*@sha256:[0-9a-f]{64}$").ShouldBeTrue($"{image} must be pinned by tag and digest");
        }
    }

    [Theory]
    [InlineData("alpine")]
    [InlineData("distroless")]
    [InlineData("chiseled")]
    [InlineData("scratch")]
    public void TheDockerfile_KeepsTheOpenSslBase_NoAlpineDistrolessOrChiseled(string forbidden)
        => FromLine().Matches(Read("deploy/docker/Dockerfile")).Select(static m => m.Groups["image"].Value).ShouldAllBe(image => !image.Contains(forbidden, StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void TheDockerfile_RunsAsTheNonRootAppUid_AndNeverSwitchesBackToRoot()
    {
        var users = Code("deploy/docker/Dockerfile").Where(static l => l.TrimStart().StartsWith("USER ", StringComparison.OrdinalIgnoreCase)).Select(static l => l.Trim()[5..].Trim()).ToList();

        users.ShouldBe(["$APP_UID"], "exactly one USER instruction, the image's non-root APP_UID");
    }

    [Fact]
    public void TheDockerfile_HasTheHealthcheck_TheVolume_ThePorts_AndTheServerAndCli()
    {
        var text = Read("deploy/docker/Dockerfile");

        text.ShouldContain("HEALTHCHECK");
        text.ShouldContain("\"ekmmock\", \"health\"");
        text.ShouldContain("VOLUME [\"/data\"]");
        text.ShouldContain("EXPOSE 8443 8080");
        text.ShouldContain("ENTRYPOINT [\"dotnet\", \"/app/EkmMock.Server.dll\"]");
        text.ShouldContain("/usr/local/bin/ekmmock");
        text.ShouldContain("PublishReadyToRun=true");
        text.ShouldContain("DOTNET_gcServer=1");
        text.ShouldContain("STOPSIGNAL");
        text.ShouldContain("org.opencontainers.image.source");
    }

    [Fact]
    public void TheDockerfile_HasNoSecretBuildArguments_AndNoSecretEnvironment()
    {
        // Comments may talk about secrets; instructions must not carry or name one (ARG and ENV end up in the image history).
        var sensitive = new Regex(@"(SECRET|PASSWORD|PASSWD|TOKEN|MASTER_?KEY|PRIVATE)", RegexOptions.IgnoreCase);

        Code("deploy/docker/Dockerfile").ShouldAllBe(line => !sensitive.IsMatch(line));
    }

    // ---- .dockerignore ----

    [Fact]
    public void TheDockerIgnore_IsAnAllowList_ThatKeepsSecretsAndDataOutOfTheContext()
    {
        var lines = Code(".dockerignore").Select(static l => l.Trim()).ToList();

        lines[0].ShouldBe("*", "everything is excluded first; only what the build reads is allowed back");
        lines.ShouldContain("!src/**");
        lines.ShouldContain("!global.json");
        lines.ShouldContain("!Directory.Packages.props");
        foreach (var pattern in new[] { "**/bin", "**/obj", "**/.env", "**/*.pem", "**/*.key", "**/keystore.json", "**/master.key" })
        {
            lines.ShouldContain(pattern);
        }

        lines.ShouldNotContain("!tests/**");
        lines.ShouldNotContain("!docs/**");
        lines.ShouldNotContain("!.git/**");
    }

    // ---- compose files ----

    [Theory]
    [InlineData("deploy/docker/compose.yaml")]
    [InlineData("deploy/docker/compose.dev.yaml")]
    public void TheComposeFiles_AreHardened_PublishTheConsoleOnLoopbackOnly_AndHaveNoSecretLiterals(string file)
    {
        var text = string.Join('\n', Code(file));

        text.ShouldContain("read_only: true");
        text.ShouldContain("- /tmp");
        text.ShouldContain("cap_drop:");
        text.ShouldContain("- ALL");
        text.ShouldContain("no-new-privileges:true");
        text.ShouldContain(file.EndsWith("dev.yaml", StringComparison.Ordinal) ? "ekmmock-dev-data:/data" : "ekmmock-data:/data");

        // The EKM port maps to 8443; the console is published on the host's loopback only, with a fixed 127.0.0.1 in front (no variable, no empty host address).
        Regex.IsMatch(text, @"-\s*""\$\{EKMMOCK_EKM_PORT:-443\}:8443""").ShouldBeTrue();
        var consoleMappings = text.Split('\n').Where(static l => Regex.IsMatch(l, @"^\s*-\s*""[^""]*:8080""\s*$")).Select(static l => l.Trim()).ToList();
        consoleMappings.Count.ShouldBe(1);
        Regex.IsMatch(consoleMappings[0], @"^-\s*""127\.0\.0\.1:\$\{EKMMOCK_CONSOLE_PORT:-8080\}:8080""$").ShouldBeTrue($"the console must be published on 127.0.0.1 only: {consoleMappings[0]}");
        text.ShouldNotContain("8080:8080");

        // No user override (the image's non-root user is used), no privileged mode, no host networking, no :latest.
        text.ShouldNotMatch(@"(?m)^\s*user:");
        text.ShouldNotContain("privileged");
        text.ShouldNotContain("network_mode");
        text.ShouldNotContain(":latest");

        // The container-publish opt-in is set together with the explicit bind, and nothing sets Console:Auth to something that needs no sign-in beyond LoopbackOnly.
        text.ShouldContain("EKMMOCK_CONSOLE_CONTAINER_PUBLISH: \"true\"");
        text.ShouldContain("Endpoints__Console__Url: https://0.0.0.0:8080");
        text.ShouldNotContain("Console__Auth");

        // No secret literals: the master key comes from a file path, never from a value in the file.
        text.ShouldNotMatch(@"EKMMOCK_MASTER_KEY\s*:");
        text.ShouldNotMatch(@"EKMMOCK_CONSOLE_CLIENT_SECRET\s*:");
        text.ShouldContain("EKMMOCK_MASTER_KEY_FILE:");
        Base64SecretLike().IsMatch(text).ShouldBeFalse("a 32-byte base64 value looks like a key");
    }

    [Fact]
    public void TheProductionCompose_TakesTheMasterKeyFromADockerSecretFile()
    {
        var text = string.Join('\n', Code("deploy/docker/compose.yaml"));

        text.ShouldContain("EKMMOCK_MASTER_KEY_FILE: /run/secrets/ekmmock_master_key");
        text.ShouldContain("file: ./secrets/ekmmock_master_key");
        text.ShouldContain("restart: unless-stopped");
        text.ShouldContain("EKMMOCK_ALLOW_KEY_IMPORT: \"false\"");
    }

    [Fact]
    public void TheDevCompose_IsTheOnlyPlaceWithDevAndTestSwitches()
    {
        var production = string.Join('\n', Code("deploy/docker/compose.yaml"));
        var dev = string.Join('\n', Code("deploy/docker/compose.dev.yaml"));

        production.ShouldNotContain("--dev");
        production.ShouldNotContain("SeedSampleKeys");
        dev.ShouldContain("[\"--dev\"]");
        dev.ShouldContain("Dev__SeedSampleKeys: \"true\"");
        dev.ShouldContain("ekmmock certs dev --out /data/dev-pki");
        dev.ShouldContain("ekmmock trust import --ns _default");
    }

    // ---- CI workflow ----

    [GeneratedRegex(@"[A-Za-z0-9+/]{43}=")]
    private static partial Regex Base64SecretLike();

    [Fact]
    public void TheWorkflow_PinsEveryActionToAFullCommitSha_WithAVersionComment()
    {
        var uses = Read(".github/workflows/ci.yml").Split('\n').Where(static l => l.Contains("uses:", StringComparison.Ordinal) && !l.TrimStart().StartsWith('#')).Select(static l => l.Trim()).ToList();

        uses.ShouldNotBeEmpty();
        foreach (var line in uses)
        {
            Regex.IsMatch(line, @"^- ?uses:\s+[\w.-]+/[\w./-]+@[0-9a-f]{40}\s+#\s+v\d+\.\d+\.\d+$|^uses:\s+[\w.-]+/[\w./-]+@[0-9a-f]{40}\s+#\s+v\d+\.\d+\.\d+$").ShouldBeTrue($"not SHA-pinned with a version comment: {line}");
        }
    }

    [Fact]
    public void TheWorkflow_HasLeastPrivilege_NoPrivilegedTriggers_AndNoSecrets()
    {
        var text = Read(".github/workflows/ci.yml");
        var code = string.Join('\n', Code(".github/workflows/ci.yml"));

        code.ShouldContain("permissions:\n  contents: read");
        code.ShouldNotContain("pull_request_target");
        code.ShouldNotContain("workflow_run");
        code.ShouldNotContain("write-all");
        code.ShouldNotContain("secrets.");
        code.ShouldNotContain("id-token");
        code.ShouldNotContain("self-hosted");

        // Every job: a timeout and its own minimal permissions; every checkout without persisted credentials.
        var jobsSection = text[(text.IndexOf("\njobs:", StringComparison.Ordinal) + 1)..];
        var jobs = Regex.Matches(jobsSection, @"(?m)^  [a-z-]+:\s*$").Count;
        jobs.ShouldBe(4);
        Regex.Matches(text, @"(?m)^    timeout-minutes:").Count.ShouldBe(jobs);
        Regex.Matches(text, @"(?m)^    permissions:\s*\n      contents: read").Count.ShouldBe(jobs);
        var checkouts = Regex.Matches(text, @"uses: actions/checkout@").Count;
        checkouts.ShouldBe(jobs);
        Regex.Matches(text, @"persist-credentials: false").Count.ShouldBe(checkouts);
    }

    [Fact]
    public void TheWorkflow_NeverExpandsAnExpressionInsideAShellScript()
    {
        // The script injection rule: ${{ }} is expanded before the shell runs, so a run: block must read its inputs from env: instead.
        var lines = Read(".github/workflows/ci.yml").Split('\n').Select(static l => l.TrimEnd('\r')).ToList();
        var inScript = false;
        var scriptIndent = 0;
        foreach (var line in lines)
        {
            var indent = line.Length - line.TrimStart().Length;
            if (inScript && line.Trim().Length > 0 && indent <= scriptIndent)
            {
                inScript = false;
            }

            if (inScript)
            {
                line.ShouldNotContain("${{", customMessage: $"expression inside a run script: {line.Trim()}");
            }

            var trimmed = line.TrimStart().TrimStart('-', ' ');
            if (trimmed.StartsWith("run:", StringComparison.Ordinal))
            {
                var rest = trimmed["run:".Length..].Trim();
                rest.ShouldNotContain("${{", customMessage: $"expression inside a run script: {line.Trim()}");
                if (rest is "|" or ">" or "|-" or ">-")
                {
                    inScript = true;
                    scriptIndent = indent;
                }
            }
        }
    }

    [Fact]
    public void TheWorkflow_RunsTheSpecifiedStages()
    {
        var text = Read(".github/workflows/ci.yml");

        text.ShouldContain("dotnet build EkmMock.sln --configuration Release -warnaserror");
        text.ShouldContain("dotnet test --solution EkmMock.sln");
        text.ShouldContain("dotnet list EkmMock.sln package --vulnerable --include-transitive");
        text.ShouldContain("make compose-up");
        text.ShouldContain("make conformance");
        text.ShouldContain("down -v");
        text.ShouldContain("hashFiles('Directory.Packages.props', 'global.json')");
    }

    [Fact]
    public void Dependabot_CoversNuGet_GitHubActions_AndDocker()
    {
        var text = Read(".github/dependabot.yml");

        text.ShouldContain("package-ecosystem: nuget");
        text.ShouldContain("package-ecosystem: github-actions");
        text.ShouldContain("package-ecosystem: docker");
        text.ShouldContain("interval: weekly");
        text.ShouldContain("groups:");
    }
}
