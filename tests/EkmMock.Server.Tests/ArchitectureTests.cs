using System.Reflection;
using System.Text.Json;
using EkmMock.Crypto;
using EkmMock.Server.Connections;
using EkmMock.Server.Ekm;
using EkmMock.Server.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>Layering and composition rules of M2 (spec 5.4, 7, 16 and the repository rules).</summary>
public sealed class ArchitectureTests
{
    // Builds the production composition on the in-process test server: constructing the real Kestrel server would (correctly) demand a TLS certificate.
    private static WebApplication BuildApp(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.AddEkmMockServer(args);
        builder.WebHost.UseTestServer();
        return builder.Build();
    }

    [Fact]
    public void Crypto_StillHasNoAspNetCoreOrHostingReference()
    {
        var references = typeof(SoftwareCryptoBackend).Assembly.GetReferencedAssemblies().Select(static a => a.Name!).ToList();

        references.ShouldNotContain(n => n.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal));
        references.ShouldNotContain(n => n.StartsWith("Microsoft.Extensions", StringComparison.Ordinal));
        references.ShouldNotContain(n => n.StartsWith("BouncyCastle", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Server_ConfiguresListenersAndTlsOnlyInTheEkmEndpointSetup()
    {
        // M3: listeners, UseHttps and client certificate mode live in EkmKestrel.cs only; the cipher policy in TlsPolicy.cs/EkmKestrel.cs.
        var listenerTokens = new[] { "ConfigureKestrel(", "UseKestrel(", "UseHttps(", "ListenAnyIP(", "ListenLocalhost(", "ClientCertificateMode" };
        var sources = Directory.EnumerateFiles(RepoPaths.Src("EkmMock.Server"), "*.cs", SearchOption.AllDirectories)
            .Where(static f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .ToList();

        foreach (var file in sources.Where(static f => Path.GetFileName(f) != "EkmKestrel.cs"))
        {
            var text = File.ReadAllText(file);
            foreach (var token in listenerTokens)
            {
                text.Contains(token, StringComparison.Ordinal).ShouldBeFalse($"{Path.GetFileName(file)} contains {token}");
            }
        }

        foreach (var file in sources.Where(static f => Path.GetFileName(f) is not ("EkmKestrel.cs" or "TlsPolicy.cs")))
        {
            File.ReadAllText(file).Contains("CipherSuitesPolicy", StringComparison.Ordinal).ShouldBeFalse(Path.GetFileName(file));
        }
    }

    [Fact]
    public void Server_HasNoPlainHttpEkmPath_AndNoAuthorizationBypassInProductionCode()
    {
        // The only things a test host may replace are the DI seams; the production assembly must not contain an allow-all
        // authorizer, a "disable auth/TLS" option, or a plain-HTTP listener for the EKM endpoint.
        var types = typeof(Program).Assembly.GetTypes();
        types.ShouldNotContain(static t => t.Name.Contains("AllowAll", StringComparison.OrdinalIgnoreCase));
        types.ShouldNotContain(static t => t.Name.Contains("PlainHttp", StringComparison.OrdinalIgnoreCase));

        var optionProperties = types
            .Where(static t => t.Name.EndsWith("Options", StringComparison.Ordinal))
            .SelectMany(static t => t.GetProperties())
            .Select(static p => p.Name)
            .ToList();
        optionProperties.ShouldNotContain(static n => n.Contains("DisableAuth", StringComparison.OrdinalIgnoreCase)
            || n.Contains("AllowAnonymous", StringComparison.OrdinalIgnoreCase)
            || n.Contains("InsecureHttp", StringComparison.OrdinalIgnoreCase)
            || n.Contains("SkipClientCertificate", StringComparison.OrdinalIgnoreCase));

        // The shipped configuration offers https only, and parsing refuses anything else.
        var settings = File.ReadAllText(Path.Combine(RepoPaths.Src("EkmMock.Server"), "appsettings.json"));
        settings.ShouldContain("https://");
        settings.ShouldNotContain("http://");
        Should.Throw<InvalidOperationException>(() => EkmEndpointAddress.Parse("http://0.0.0.0:8443"));
    }

    [Fact]
    public void Production_ComposesTheRealMtlsAuthorizer_AndEkmListenerPorts()
    {
        using var app = BuildApp([]);

        app.Services.GetRequiredService<IEkmCallerAuthorizer>().ShouldBeOfType<MtlsCallerAuthorizer>();
        app.Services.GetRequiredService<IEkmPortPolicy>().ShouldBeOfType<EkmListenerPorts>();
    }

    [Fact]
    public void TestHost_IsTheInProcessServer_NotKestrel()
    {
        using var factory = new EkmFactory();

        factory.Server.GetType().Namespace.ShouldBe("Microsoft.AspNetCore.TestHost");
    }

    [Fact]
    public void Json_IsSourceGeneratedAndSnakeCase()
    {
        EkmJsonContext.Default.Options.PropertyNamingPolicy.ShouldBe(JsonNamingPolicy.SnakeCaseLower);

        JsonSerializer.Serialize(new ProxyError("KeyDisabled", "m"), EkmJsonContext.Default.ProxyError)
            .ShouldBe("""{"code":"KeyDisabled","message":"m"}""");
        JsonSerializer.Serialize(new KeyMetadataResponse("oct", 256, ["wrapKey", "unwrapKey"], null, null), EkmJsonContext.Default.KeyMetadataResponse)
            .ShouldBe("""{"key_type":"oct","key_size":256,"key_ops":["wrapKey","unwrapKey"]}""");
    }

    [Fact]
    public void Server_UsesNoControllersAndNoProblemDetails()
    {
        var types = typeof(Program).Assembly.GetTypes();

        types.ShouldNotContain(t => typeof(Microsoft.AspNetCore.Mvc.ControllerBase).IsAssignableFrom(t));
        typeof(Program).Assembly.GetReferencedAssemblies().Select(static a => a.Name).ShouldNotContain("Microsoft.AspNetCore.Mvc.Core");
    }

    [Fact]
    public void Host_UsesTheJsonConsoleFormatter_AndTheDevFlagSetsDevMode()
    {
        using var app = BuildApp(["--dev"]);

        app.Services.GetRequiredService<IOptions<ConsoleLoggerOptions>>().Value.FormatterName.ShouldBe(ConsoleFormatterNames.Json);
        app.Services.GetRequiredService<IOptions<DevOptions>>().Value.Enabled.ShouldBeTrue();
    }

    [Fact]
    public void Host_WithoutTheDevFlag_IsNotInDevMode()
    {
        using var app = BuildApp([]);

        app.Services.GetRequiredService<IOptions<DevOptions>>().Value.Enabled.ShouldBeFalse();
        app.Services.GetRequiredService<IOptions<DevOptions>>().Value.SeedSampleKeys.ShouldBeFalse();
    }

    [Fact]
    public void MasterKey_IsReadFromTheEnvironment_NeverFromConfiguration()
    {
        using var app = BuildApp([]);

        app.Services.GetRequiredService<IMasterKeyProvider>().ShouldBeOfType<EnvironmentMasterKeyProvider>();

        // The shipped settings file carries no secret, and no option type has a place for one.
        var settings = File.ReadAllText(Path.Combine(RepoPaths.Src("EkmMock.Server"), "appsettings.json"));
        settings.ShouldNotContain("MASTER", Case.Insensitive);
        settings.ShouldNotContain("secret", Case.Insensitive);
        settings.ShouldNotContain("password", Case.Insensitive);
    }

    [Fact]
    public void Server_ExposesOnlyProgramPublicly()
    {
        // Everything else stays internal so M4/M5 can evolve it freely; Program is public for WebApplicationFactory<Program>.
        typeof(Program).Assembly.GetExportedTypes().Select(static t => t.Name).ShouldBe(["Program"]);
    }

    [Fact]
    public void Program_IsLoadableByWebApplicationFactory_AndLeavesTheHostComposable()
    {
        // The host is composed in extension methods, so later milestones add the console endpoint and TLS next to them.
        typeof(EkmServerServiceCollectionExtensions).GetMethod(nameof(EkmServerServiceCollectionExtensions.AddEkmMockServer), BindingFlags.Public | BindingFlags.Static)
            .ShouldNotBeNull();
        typeof(EkmPipeline).GetMethod(nameof(EkmPipeline.UseEkmPipeline), BindingFlags.Public | BindingFlags.Static).ShouldNotBeNull();
    }
}
