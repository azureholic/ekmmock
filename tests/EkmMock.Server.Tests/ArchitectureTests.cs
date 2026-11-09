using System.Reflection;
using System.Text.Json;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using EkmMock.Server.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>Layering and composition rules of M2 (spec 5.4, 7, 16 and the repository rules).</summary>
public sealed class ArchitectureTests
{
    [Fact]
    public void Crypto_StillHasNoAspNetCoreOrHostingReference()
    {
        var references = typeof(SoftwareCryptoBackend).Assembly.GetReferencedAssemblies().Select(static a => a.Name!).ToList();

        references.ShouldNotContain(n => n.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal));
        references.ShouldNotContain(n => n.StartsWith("Microsoft.Extensions", StringComparison.Ordinal));
        references.ShouldNotContain(n => n.StartsWith("BouncyCastle", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Server_HasNoKestrelOrTlsDependencyInM2()
    {
        // TLS 1.3 + mTLS + the real listeners are M3. Nothing in the M2 server code touches them.
        var references = typeof(Program).Assembly.GetReferencedAssemblies().Select(static a => a.Name!).ToList();

        references.ShouldNotContain(n => n.StartsWith("Microsoft.AspNetCore.Server.Kestrel", StringComparison.Ordinal));
        references.ShouldNotContain("System.Net.Security");
        references.ShouldNotContain("System.Security.Cryptography.X509Certificates");
    }

    [Fact]
    public void Server_SourceDoesNotConfigureKestrelOrTls()
    {
        var forbidden = new[] { "ConfigureKestrel(", "UseKestrel(", "UseHttps(", "ListenAnyIP(", "ListenLocalhost(", "SslProtocols", "ClientCertificateMode" };
        var sources = Directory.EnumerateFiles(RepoPaths.Src("EkmMock.Server"), "*.cs", SearchOption.AllDirectories)
            .Where(static f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"));

        foreach (var file in sources)
        {
            var text = File.ReadAllText(file);
            foreach (var token in forbidden)
            {
                text.Contains(token, StringComparison.Ordinal).ShouldBeFalse($"{Path.GetFileName(file)} contains {token}");
            }
        }
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
        var builder = WebApplication.CreateBuilder(["--dev"]);
        builder.AddEkmMockServer(["--dev"]);
        using var app = builder.Build();

        app.Services.GetRequiredService<IOptions<ConsoleLoggerOptions>>().Value.FormatterName.ShouldBe(ConsoleFormatterNames.Json);
        app.Services.GetRequiredService<IOptions<DevOptions>>().Value.Enabled.ShouldBeTrue();
    }

    [Fact]
    public void Host_WithoutTheDevFlag_IsNotInDevMode()
    {
        var builder = WebApplication.CreateBuilder([]);
        builder.AddEkmMockServer([]);
        using var app = builder.Build();

        app.Services.GetRequiredService<IOptions<DevOptions>>().Value.Enabled.ShouldBeFalse();
        app.Services.GetRequiredService<IOptions<DevOptions>>().Value.SeedSampleKeys.ShouldBeFalse();
    }

    [Fact]
    public void MasterKey_IsReadFromTheEnvironment_NeverFromConfiguration()
    {
        var builder = WebApplication.CreateBuilder([]);
        builder.AddEkmMockServer([]);
        using var app = builder.Build();

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
