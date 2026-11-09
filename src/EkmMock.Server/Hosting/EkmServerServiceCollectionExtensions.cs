using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Hosting;

/// <summary>
/// The composition root. Everything is registered with <c>TryAdd*</c> so tests (and later milestones) can replace a part,
/// for example the master key provider, without touching production code.
/// </summary>
internal static class EkmServerServiceCollectionExtensions
{
    /// <summary>The command line flag that switches on dev mode.</summary>
    public const string DevFlag = "--dev";

    /// <summary>
    /// Host-level wiring for <see cref="Program"/>: dev flag, JSON console logging, services. Later milestones add the console
    /// Kestrel endpoint and TLS next to this call; nothing here depends on how the host listens.
    /// </summary>
    public static WebApplicationBuilder AddEkmMockServer(this WebApplicationBuilder builder, string[] args)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(args);

        if (args.Contains(DevFlag, StringComparer.Ordinal))
        {
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { [$"{DevOptions.SectionName}:{nameof(DevOptions.Enabled)}"] = "true" });
        }

        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole(options =>
        {
            options.IncludeScopes = false;
            options.UseUtcTimestamp = true;
            options.TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z' ";
        });

        builder.Services.AddEkmMockServices();
        return builder;
    }

    public static IServiceCollection AddEkmMockServices(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<ProxyInfoOptions>()
            .BindConfiguration(ProxyInfoOptions.SectionName)
            .Validate(static o => o.IsValid(), "ProxyInfo values must not be empty")
            .ValidateOnStart();
        services.AddOptions<DataOptions>().BindConfiguration(DataOptions.SectionName);
        services.AddOptions<SelfTestSettings>().BindConfiguration(SelfTestSettings.SectionName);
        services.AddOptions<DevOptions>().BindConfiguration(DevOptions.SectionName);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ExchangeCounter>();

        // Secrets never come from configuration: the provider reads EKMMOCK_MASTER_KEY / EKMMOCK_MASTER_KEY_FILE directly.
        services.TryAddSingleton<IMasterKeyProvider>(static sp
            => new EnvironmentMasterKeyProvider(devMode: sp.GetRequiredService<IOptions<DevOptions>>().Value.Enabled));

        services.TryAddSingleton(static sp =>
        {
            var info = sp.GetRequiredService<IOptions<ProxyInfoOptions>>().Value;
            return new SoftwareCryptoBackendOptions
            {
                DataPath = Path.GetFullPath(sp.GetRequiredService<IOptions<DataOptions>>().Value.Path),
                MasterKeyProvider = sp.GetRequiredService<IMasterKeyProvider>(),
                AllowKeyImport = SoftwareCryptoBackendOptions.IsKeyImportEnabledInEnvironment(),
                TimeProvider = sp.GetRequiredService<TimeProvider>(),
                Info = new BackendInfo(info.EkmVendor, info.EkmProduct),
            };
        });
        services.TryAddSingleton(static sp => new SoftwareCryptoBackend(sp.GetRequiredService<SoftwareCryptoBackendOptions>()));
        services.TryAddSingleton<ICryptoBackend>(static sp => sp.GetRequiredService<SoftwareCryptoBackend>());
        services.TryAddSingleton<IKeyManager>(static sp => sp.GetRequiredService<SoftwareCryptoBackend>());

        services.TryAddSingleton(static sp =>
        {
            var seed = (sp.GetRequiredService<IConfiguration>().GetSection(SeedNamespaceOptions.SectionName).Get<List<SeedNamespaceOptions>>() ?? [])
                .Select(static s => s.ToDefinition());
            return NamespaceStore.Open(Path.GetFullPath(sp.GetRequiredService<IOptions<DataOptions>>().Value.Path), seed);
        });

        services.TryAddSingleton<EkmStartupState>();
        services.TryAddSingleton<IEngineAvailability, DefaultEngineAvailability>();
        services.TryAddSingleton<EkmHandlers>();
        services.TryAddSingleton<EkmDispatcher>();
        services.AddHostedService<EkmStartupService>();
        return services;
    }
}
