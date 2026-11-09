using System.Text.RegularExpressions;

namespace EkmMock.Server.Tests;

/// <summary>Finds files of the repository from the test output directory.</summary>
internal static class RepositoryFiles
{
    public static string Root
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

    public static string FullPath(string relative) => Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));

    public static string Read(string relative) => File.ReadAllText(FullPath(relative));

    /// <summary>The text of a Bicep/shell/YAML file without full-line comments (so that a comment may name what the code must not contain).</summary>
    public static string WithoutComments(string relative)
        => string.Join('\n', Read(relative).Split('\n').Select(static l => l.TrimEnd('\r')).Where(static l => !l.TrimStart().StartsWith("//", StringComparison.Ordinal) && !l.TrimStart().StartsWith('#')));

    public static IEnumerable<string> Files(string relativeFolder, params string[] patterns)
        => patterns.SelectMany(pattern => Directory.EnumerateFiles(FullPath(relativeFolder), pattern, SearchOption.AllDirectories))
            .Select(file => Path.GetRelativePath(Root, file).Replace('\\', '/'))
            .Order(StringComparer.Ordinal);
}

/// <summary>
/// Static checks of the Azure deployment files (M9 part 2): the Bicep templates, cloud-init, the VM set-up script, the e2e script and the example parameter files. They cannot prove that a deployment works (nothing was
/// deployed; CI only builds and lints the templates) but they stop the rules of spec 5.5 and 11.3 from rotting: only 443 and the operator's SSH are open, the console is never published beyond loopback, secrets are
/// secure parameters and never outputs, no TLS-terminating front end, no committed secrets, no floating image tags.
/// </summary>
public sealed partial class AzureDeploymentFilesTests
{
    private static readonly string[] SecretParameters = ["masterKey", "entraClientSecret", "serverCertificateKeyPem", "registryPassword", "imageRegistryCredentials"];

    private static string Read(string relative) => RepositoryFiles.Read(relative);

    // ---- no secrets, no environment-specific values ----

    [GeneratedRegex(@"-----BEGIN [A-Z ]*PRIVATE KEY-----")]
    private static partial Regex PrivateKeyHeader();

    [GeneratedRegex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")]
    private static partial Regex Guid();

    [GeneratedRegex(@"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")]
    private static partial Regex Base64Of32Bytes();

    [GeneratedRegex(@"[A-Za-z0-9+/]{120,}={0,2}")]
    private static partial Regex LongBase64Blob();

    [GeneratedRegex(@"(?<![A-Za-z0-9$}>])[a-z0-9][a-z0-9-]{2,}\.[a-z0-9]{4,}\.(cloudapp\.azure\.com|azurecontainer\.io)")]
    private static partial Regex LiteralAzureFqdn();

    [GeneratedRegex(@"/subscriptions/[0-9a-fA-F-]{36}")]
    private static partial Regex SubscriptionPath();

    private static IEnumerable<string> ScannedFiles() => RepositoryFiles.Files("deploy/azure", "*.bicep", "*.bicepparam", "*.yaml", "*.sh", "*.md", "*.json")
        .Concat(["README.md", "docs/RUNBOOK.md", "docs/RESULTS.md"]);

    [Fact]
    public void TheAzureFilesAndTheDocs_ContainNoCommittedSecretsOrEnvironmentSpecificValues()
    {
        var files = ScannedFiles().ToList();
        files.ShouldContain("deploy/azure/vm.bicep");
        files.ShouldContain("deploy/azure/e2e.sh");
        // The only GUID-shaped values allowed: the all-zero placeholder and the two request-context examples of the spec (section 4.3).
        string[] allowedGuids = ["00000000-0000-0000-0000-000000000000", "aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85", "6476b291-7c15-4d0b-aef9-03688390cb8e"];

        foreach (var file in files)
        {
            var text = Read(file);
            PrivateKeyHeader().IsMatch(text).ShouldBeFalse($"{file}: a private key header");
            Base64Of32Bytes().IsMatch(text).ShouldBeFalse($"{file}: a 32-byte base64 value looks like a key");
            LongBase64Blob().IsMatch(text).ShouldBeFalse($"{file}: a long base64 blob");
            SubscriptionPath().IsMatch(text).ShouldBeFalse($"{file}: a subscription id");
            LiteralAzureFqdn().IsMatch(text).ShouldBeFalse($"{file}: a literal Azure FQDN (use a placeholder)");
            foreach (Match match in Guid().Matches(text))
            {
                allowedGuids.ShouldContain(match.Value, $"{file}: a real-looking GUID (tenant, subscription, object id?) {match.Value}");
            }
        }
    }

    [Fact]
    public void TheExampleParameterFiles_UseObviousPlaceholders_AndReadSecretsFromTheEnvironment()
    {
        foreach (var file in new[] { "deploy/azure/vm.example.bicepparam", "deploy/azure/aci.example.bicepparam" })
        {
            var code = RepositoryFiles.WithoutComments(file);

            code.ShouldContain("<REPLACE-", customMessage: file);
            code.ShouldContain("readEnvironmentVariable(", customMessage: file);
            foreach (var secret in new[] { "masterKey", "entraClientSecret" })
            {
                foreach (var line in code.Split('\n').Where(l => l.TrimStart().StartsWith($"param {secret} ", StringComparison.Ordinal)))
                {
                    line.ShouldContain("readEnvironmentVariable(", customMessage: $"{file}: {secret} must come from the environment");
                }
            }
        }

        // The committed examples are not git-ignored, local copies are (checked on the patterns, not on git itself).
        var ignore = Read(".gitignore");
        ignore.ShouldContain("/deploy/azure/*.bicepparam");
        ignore.ShouldContain("!/deploy/azure/*.example.bicepparam");
        ignore.ShouldContain("e2e-work/");
        ignore.ShouldContain("mhsm-client.json");
    }

    // ---- secure parameters, no secret outputs ----

    [Theory]
    [InlineData("deploy/azure/vm.bicep")]
    [InlineData("deploy/azure/aci.bicep")]
    public void TheTemplates_DeclareEverySecretAsSecure_AndNeverOutputOne(string file)
    {
        var text = Read(file);
        var lines = text.Split('\n').Select(static l => l.TrimEnd('\r')).ToList();

        foreach (var name in SecretParameters)
        {
            var index = lines.FindIndex(l => l.StartsWith($"param {name} ", StringComparison.Ordinal));
            if (index < 0)
            {
                continue;
            }

            lines[..index].TakeLast(6).ShouldContain("@secure()", $"{file}: {name} must be @secure()");
        }

        var outputs = lines.Where(static l => l.StartsWith("output ", StringComparison.Ordinal)).ToList();
        outputs.ShouldNotBeEmpty();
        foreach (var output in outputs)
        {
            foreach (var secret in SecretParameters.Concat(["listKeys", "customData", "password", "secret", "storageAccountKey"]))
            {
                output.ShouldNotContain(secret, Case.Insensitive, $"{file}: an output that could carry a secret: {output}");
            }
        }
    }

    [Fact]
    public void TheMasterKeyParameter_IsExactly44Characters_SoItIsA32ByteBase64Value()
    {
        foreach (var file in new[] { "deploy/azure/vm.bicep", "deploy/azure/aci.bicep" })
        {
            var text = Read(file).Replace("\r", string.Empty, StringComparison.Ordinal);
            var block = text[..(text.IndexOf("param masterKey ", StringComparison.Ordinal) + 1)];
            var decorators = block[block.LastIndexOf("@description", StringComparison.Ordinal)..];

            decorators.ShouldContain("@secure()", customMessage: file);
            decorators.ShouldContain("@minLength(44)", customMessage: file);
            decorators.ShouldContain("@maxLength(44)", customMessage: file);
        }
    }

    // ---- the rules of spec 11.3 ----

    [Theory]
    [InlineData("deploy/azure/vm.bicep")]
    [InlineData("deploy/azure/aci.bicep")]
    public void TheTemplates_HaveNoTlsTerminatingFrontEnd_AndSayWhy(string file)
    {
        var text = Read(file);

        text.ShouldContain("TLS-terminating front end", customMessage: file);
        var code = RepositoryFiles.WithoutComments(file);
        foreach (var forbidden in new[]
        {
            "Microsoft.Network/applicationGateways", "Microsoft.Cdn/", "Microsoft.Network/frontDoors", "Microsoft.App/", "Microsoft.ContainerService/", "Microsoft.Web/",
            "Microsoft.Network/loadBalancers", "Microsoft.Network/privateLinkServices", "Microsoft.Network/privateEndpoints",
        })
        {
            code.ShouldNotContain(forbidden, customMessage: $"{file}: {forbidden} is not a supported target");
        }
    }

    [Fact]
    public void TheVmNsg_OpensOnly443ToTheInternet_AndSshOnlyToTheOperatorsAddress_AndNeverTheConsolePort()
    {
        var code = RepositoryFiles.WithoutComments("deploy/azure/vm.bicep");
        var ports = Regex.Matches(code, @"destinationPortRange:\s*'([^']+)'").Select(static m => m.Groups[1].Value).ToList();

        ports.ShouldBe(["443", "22", "*"], "the EKM endpoint, SSH, and the explicit deny-all");
        code.ShouldContain("sourceAddressPrefix: 'Internet'");
        code.ShouldContain("sourceAddressPrefix: sshSourceChecked");
        code.ShouldContain("access: 'Deny'");

        // The SSH source has no default, and the open values are rejected by a guard.
        Regex.IsMatch(code, @"(?m)^param allowedSshSourceAddress string$").ShouldBeTrue("allowedSshSourceAddress must have no default value");
        foreach (var open in new[] { "'*'", "'0.0.0.0/0'", "'internet'", "'any'" })
        {
            code.ShouldContain(open);
        }

        code.ShouldContain("disablePasswordAuthentication: true");
    }

    [Fact]
    public void TheVmSetup_RunsTheContainerHardened_WithTheConsoleOnTheVmLoopbackOnly()
    {
        var code = RepositoryFiles.WithoutComments("deploy/azure/vm-setup.sh");

        code.ShouldContain("--publish 443:8443");
        code.ShouldContain("--publish 127.0.0.1:8080:8080");
        code.ShouldNotContain("--publish 8080:8080");
        code.ShouldNotContain("0.0.0.0:8080:");
        code.ShouldNotContain("-p 8080");
        foreach (var flag in new[] { "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges:true", "--restart unless-stopped" })
        {
            code.ShouldContain(flag);
        }

        code.ShouldNotContain("--privileged");
        code.ShouldNotMatch(@"--user(?![a-z])");
        code.ShouldContain("EKMMOCK_CONSOLE_CONTAINER_PUBLISH=true");
        code.ShouldContain("EKMMOCK_MASTER_KEY_FILE=/run/secrets/ekmmock_master_key");
        code.ShouldContain("/run/secrets/ekmmock_master_key:ro");
        code.ShouldNotMatch(@"EKMMOCK_MASTER_KEY=");
        code.ShouldContain("9DC858229FC7DD38854AE2D88D81803C0EBFCD88", Case.Sensitive, "the Docker repository key fingerprint must be verified");
        code.ShouldContain("chmod 0400");
    }

    [Fact]
    public void CloudInit_HasExactlyTheTokensTheTemplateReplaces_AndIsLfOnly()
    {
        var yaml = Read("deploy/azure/cloud-init.yaml");
        var bicep = Read("deploy/azure/vm.bicep");

        yaml.ShouldStartWith("#cloud-config\n");
        yaml.ShouldNotContain("\r");
        var inYaml = Regex.Matches(yaml, @"'(@@[A-Z_]+@@)'").Select(static m => m.Groups[1].Value).Order().ToList();
        var inBicep = Regex.Matches(bicep, @"token: '(@@[A-Z_]+@@)'").Select(static m => m.Groups[1].Value).Order().ToList();

        inYaml.ShouldBe(inBicep);
        inYaml.ShouldContain("@@MASTER_KEY@@");
        // Values travel base64-encoded, never raw: every write_files entry is encoding b64.
        Regex.Matches(yaml, @"(?m)^\s+encoding: b64$").Count.ShouldBe(Regex.Matches(yaml, @"(?m)^  - path:").Count);
        foreach (var token in inBicep)
        {
            Regex.IsMatch(bicep, $@"token: '{token}', value: base64\(").ShouldBeTrue($"{token} must be replaced by a base64 value");
        }

        yaml.ShouldContain("permissions: '0400'");
    }

    [Fact]
    public void TheAciTemplate_ListensOn443InsideTheContainer_UsesEntraId_AndDefaultsToNonRoot()
    {
        var code = RepositoryFiles.WithoutComments("deploy/azure/aci.bicep");

        code.ShouldContain("var ekmPort = 443");
        code.ShouldContain("Endpoints__Ekm__Url");
        code.ShouldContain("'https://0.0.0.0:${ekmPort}'");
        code.ShouldContain("Console__Auth', value: 'EntraId'");
        code.ShouldContain("secureValue: masterKey");
        code.ShouldContain("secureValue: entraClientSecret");
        code.ShouldContain("param runAsRoot bool = false");
        code.ShouldContain("param consolePort int = 8443");
        code.ShouldNotContain("EKMMOCK_CONSOLE_CONTAINER_PUBLISH");
        code.ShouldNotContain("LoopbackOnly");
        Regex.IsMatch(code, @"EKMMOCK_MASTER_KEY', value:").ShouldBeFalse("the master key must be a secureValue, not a plain value");

        // The header must say plainly what is unverified.
        var text = Read("deploy/azure/aci.bicep");
        text.ShouldContain("UNVERIFIED");
        text.ShouldContain("NO read-only root file system");
    }

    [Fact]
    public void NoAzureFileUsesAFloatingImageTag()
    {
        foreach (var file in RepositoryFiles.Files("deploy/azure", "*.bicep", "*.bicepparam", "*.yaml", "*.sh", "*.md"))
        {
            Regex.IsMatch(Read(file), @"[A-Za-z0-9/_.-]+:latest\b").ShouldBeFalse($"{file}: a :latest image tag");
        }
    }

    [Fact]
    public void TheAzureFiles_UseLineFeedsOnly_BecauseTheyRunOnLinuxOrAreCompiledByBicep()
    {
        foreach (var file in RepositoryFiles.Files("deploy/azure", "*"))
        {
            Read(file).ShouldNotContain("\r", customMessage: $"{file} has CR line endings");
        }

        var attributes = Read(".gitattributes");
        attributes.ShouldContain("deploy/azure/** text eol=lf");
        attributes.ShouldContain("*.sh text eol=lf");
    }

    // ---- the e2e script ----

    [Fact]
    public void TheE2eScript_IsStrict_HasHelpAndDryRun_SaysItIsUnverified_AndNeverPrintsTheDek()
    {
        var text = Read("deploy/azure/e2e.sh");
        var code = RepositoryFiles.WithoutComments("deploy/azure/e2e.sh");

        text.ShouldStartWith("#!/usr/bin/env bash\n");
        code.ShouldContain("set -euo pipefail");
        code.ShouldContain("--dry-run)");
        code.ShouldContain("-h | --help)");
        text.ShouldContain("UNVERIFIED AGAINST A REAL MANAGED HSM");
        foreach (var command in new[] { "prereqs", "trust", "connect", "keys", "roundtrip", "baseline", "sweep", "key-disable", "key-destroy", "offline", "observe", "cleanup" })
        {
            code.ShouldContain($"cmd_{command.Replace('-', '_')}", customMessage: command);
        }

        // The az commands of spec 15 (all of which exist in Azure CLI 2.92).
        foreach (var fragment in new[]
        {
            "az keyvault ekm-connection \"$verb\"", "ekm-connection check", "ekm-connection certificate show", "ekm-connection delete", "az keyvault key create", "--external-key-id",
            "az rest --method POST --resource https://managedhsm.azure.net", "api-version=7.5", "az keyvault key delete", "trust import", "az feature show --namespace Microsoft.KeyVault --name MHSM_EKM",
        })
        {
            code.ShouldContain(fragment);
        }

        // The DEK only goes into the request body file and is fingerprinted; it is never echoed.
        foreach (var line in code.Split('\n').Where(static l => l.Contains("say ", StringComparison.Ordinal) || l.Contains("echo ", StringComparison.Ordinal)))
        {
            line.ShouldNotContain("dek_b64u");
            line.ShouldNotContain("dek.bin");
        }

        code.ShouldContain("rm -f \"$WORK_DIR\"/dek.bin");
        code.ShouldNotContain("set -x");
        code.ShouldNotContain("eval ");
    }
}
