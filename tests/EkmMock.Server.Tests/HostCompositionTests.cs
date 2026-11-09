using EkmMock.Crypto;
using EkmMock.Server.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>Composition root behaviour: master key, dev mode, seeding, self-test, listener guard, options.</summary>
public sealed class HostCompositionTests
{
    private static ServiceProvider BuildServices(string dataPath, IMasterKeyProvider? provider = null, Dictionary<string, string?>? configuration = null)
    {
        // No web host: the WebApplicationFactory races its own teardown when a host fails to start, which would make the
        // failure-path tests flaky. The composition root is the same code either way.
        var values = new Dictionary<string, string?> { ["Data:Path"] = dataPath };
        foreach (var pair in configuration ?? [])
        {
            values[pair.Key] = pair.Value;
        }

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
        services.AddEkmMockServices();
        if (provider is not null)
        {
            services.AddSingleton(provider);
        }

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task WithoutAMasterKey_TheHostRefusesToStart_AndWritesNothing()
    {
        using var data = new TempDir();
        await using var services = BuildServices(data.Path, new EnvironmentMasterKeyProvider(static _ => null));
        var startup = services.GetServices<IHostedService>().OfType<EkmStartupService>().Single();

        await Should.ThrowAsync<MasterKeyUnavailableException>(() => startup.StartAsync(CancellationToken.None));

        File.Exists(Path.Combine(data.Path, "keystore.json")).ShouldBeFalse();
        services.GetRequiredService<EkmStartupState>().IsReady.ShouldBeFalse();
    }

    [Fact]
    public async Task AValidMasterKey_StartsAndMarksTheEngineReady()
    {
        using var data = new TempDir();
        await using var services = BuildServices(data.Path, new ExplicitMasterKeyProvider(EkmFactory.MasterKeyBytes()));
        var startup = services.GetServices<IHostedService>().OfType<EkmStartupService>().Single();

        await startup.StartAsync(CancellationToken.None);

        services.GetRequiredService<EkmStartupState>().IsReady.ShouldBeTrue();
        services.GetRequiredService<IEngineAvailability>().IsAvailable.ShouldBeTrue();
    }

    [Fact]
    public async Task DevMode_CreatesAThrowAwayMasterKey_AndSaysSo()
    {
        using var factory = new EkmFactory(new EkmFactoryOptions
        {
            MasterKeyProvider = new EnvironmentMasterKeyProvider(static _ => null, devMode: true),
            Configuration = new() { ["Dev:Enabled"] = "true" },
        });
        var ekm = factory.CreateEkmClient();

        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);

        factory.Backend.IsMasterKeyThrowAway.ShouldBeTrue();
        factory.Services.GetRequiredService<IOptions<DevOptions>>().Value.Enabled.ShouldBeTrue();
        factory.Logs.Entries.ShouldContain(e => e.Level == LogLevel.Warning && e.Message.Contains("DEV MODE", StringComparison.Ordinal));
    }

    [Fact]
    public void ANormalStart_DoesNotUseAThrowAwayKey_AndIsNotInDevMode()
    {
        using var factory = new EkmFactory();
        _ = factory.CreateClient();

        factory.Backend.IsMasterKeyThrowAway.ShouldBeFalse();
        factory.Services.GetRequiredService<IOptions<DevOptions>>().Value.Enabled.ShouldBeFalse();
        factory.Logs.Entries.ShouldNotContain(e => e.Message.Contains("DEV MODE", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SampleKeys_AreSeededOnlyWhenExplicitlyEnabled()
    {
        using var off = new EkmFactory();
        var offEkm = off.CreateEkmClient();
        (await offEkm.MetadataAsync("aes-key-1")).ShouldBeProxyError(404, "KeyNotFound");
        (await offEkm.MetadataAsync("rsa-key-1")).ShouldBeProxyError(404, "KeyNotFound");

        using var on = new EkmFactory(new EkmFactoryOptions { SeedSampleKeys = true });
        var onEkm = on.CreateEkmClient();
        using var aes = (await onEkm.MetadataAsync("aes-key-1")).Json();
        using var rsa = (await onEkm.MetadataAsync("rsa-key-1")).Json();
        aes.RootElement.GetProperty("key_type").GetString().ShouldBe("oct");
        rsa.RootElement.GetProperty("key_type").GetString().ShouldBe("RSA");
        rsa.RootElement.GetProperty("key_size").GetInt32().ShouldBe(2048);

        // They really work, and the startup self-test covered them.
        var dek = Fx.Random(32);
        Fx.Same((await onEkm.UnwrapAsync("aes-key-1", "A256KWP", (await onEkm.WrapAsync("aes-key-1", "A256KWP", dek)).Value())).Value(), dek).ShouldBeTrue();
        on.Backend.LastSelfTest.ShouldNotBeNull().Cases.ShouldContain(c => c.Name == "key:_default/aes-key-1");
    }

    [Fact]
    public async Task SampleKeys_AreNotRecreated_OnTheSecondStart()
    {
        using var data = new TempDir();
        byte[] wrapped;
        using (var first = new EkmFactory(new EkmFactoryOptions { DataPath = data.Path, SeedSampleKeys = true }))
        {
            wrapped = (await first.CreateEkmClient().WrapAsync("aes-key-1", "A256KWP", new byte[32])).Value();
        }

        using var second = new EkmFactory(new EkmFactoryOptions { DataPath = data.Path, SeedSampleKeys = true });

        (await second.CreateEkmClient().UnwrapAsync("aes-key-1", "A256KWP", wrapped)).StatusCode.ShouldBe(200);
        second.Keys.List("_default").Count(static k => k.State != KeyState.Destroyed).ShouldBe(2);
    }

    [Fact]
    public async Task TheStartupSelfTest_RunsBeforeTheFirstRequest_AndStrictModeStillStarts()
    {
        using var factory = new EkmFactory(new EkmFactoryOptions { StrictSelfTest = true });
        var ekm = factory.CreateEkmClient();

        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);

        var state = factory.Services.GetRequiredService<EkmStartupState>();
        state.IsReady.ShouldBeTrue();
        state.SelfTest.ShouldNotBeNull().Passed.ShouldBeTrue();
        state.SelfTest.Strict.ShouldBeTrue();
        factory.Backend.LastSelfTest.ShouldBeSameAs(state.SelfTest);
    }

    [Fact]
    public void BeforeStartupHasFinished_TheEngineIsNotAvailable()
    {
        using var data = new TempDir();
        using var backend = new SoftwareCryptoBackend(new SoftwareCryptoBackendOptions
        {
            DataPath = data.Path,
            MasterKeyProvider = new ExplicitMasterKeyProvider(EkmFactory.MasterKeyBytes()),
            CounterFlushInterval = TimeSpan.Zero,
        });
        var state = new EkmStartupState();
        var availability = new DefaultEngineAvailability(backend, state, new EkmMock.Server.Faults.FaultRuleStore(new FixedFaultGate(false), TimeProvider.System, new EkmMock.Server.Faults.SystemFaultRandom()));

        availability.IsAvailable.ShouldBeFalse();
        state.MarkReady(backend.RunSelfTest());
        availability.IsAvailable.ShouldBeTrue();
    }

    [Fact]
    public async Task ADisposedBackend_MakesTheEngineUnavailable()
    {
        using var factory = new EkmFactory();
        var ekm = factory.CreateEkmClient();
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);

        factory.Backend.Dispose();

        (await ekm.InfoAsync()).ShouldBeProxyError(503, "HsmUnavailable");
    }

    [Fact]
    public void EmptyProxyInfoValues_AreRefusedAtStartup()
    {
        using var data = new TempDir();
        using var services = BuildServices(data.Path, configuration: new() { ["ProxyInfo:ProxyName"] = "  " });

        Should.Throw<OptionsValidationException>(() => services.GetRequiredService<IOptions<ProxyInfoOptions>>().Value);
    }

    [Fact]
    public void ProxyInfoDefaults_MatchTheSpecSample()
    {
        using var data = new TempDir();
        using var services = BuildServices(data.Path);

        var info = services.GetRequiredService<IOptions<ProxyInfoOptions>>().Value;

        info.ApiVersion.ShouldBe("0.1-preview");
        info.ProxyVendor.ShouldBe("Remco Test");
        info.ProxyName.ShouldBe("EkmMock v0.2.0");
        info.EkmVendor.ShouldBe("EkmMock");
        info.EkmProduct.ShouldBe("EkmMock Software HSM v0.2.0");
    }
}
