using EkmMock.Crypto;
using EkmMock.Server.Connections;
using EkmMock.Server.Ekm;
using EkmMock.Server.Inspector;
using EkmMock.Server.Tls;
using Microsoft.AspNetCore.Server.Kestrel.Core;
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

    /// <summary>
    /// Builds the complete host exactly as <see cref="Program"/> runs it (services, Kestrel endpoint, pipeline). Tests use the
    /// <paramref name="customize"/> hook to point it at temporary folders and ephemeral ports; it is not a way to weaken security
    /// because nothing here has a switch for plain HTTP or disabled authorization.
    /// </summary>
    public static WebApplication BuildEkmMockApp(string[] args, Action<WebApplicationBuilder>? customize = null)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.AddEkmMockServer(args);
        customize?.Invoke(builder);
        var app = builder.Build();
        app.UseEkmPipeline();
        return app;
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
        services.AddOptions<EkmEndpointOptions>().BindConfiguration(EkmEndpointOptions.SectionName);
        services.AddOptions<TlsOptions>().BindConfiguration(TlsOptions.SectionName);
        services.AddOptions<InspectorOptions>().BindConfiguration(InspectorOptions.SectionName).ValidateOnStart();
        services.AddOptions<LimitsOptions>().BindConfiguration(LimitsOptions.SectionName).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<InspectorOptions>, InspectorOptionsValidator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<LimitsOptions>, InspectorOptionsValidator>());

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ExchangeCounter>();

        // ---- EKM endpoint: TLS, trust, authorization and connection capture (M3) ----
        services.TryAddSingleton<TlsPolicy>();
        services.TryAddSingleton(static sp => new ClientTrustProvider(sp.GetRequiredService<NamespaceStore>()));
        services.TryAddSingleton<ClientCertificateValidator>();
        services.TryAddSingleton<ConnectionRegistry>();
        services.TryAddSingleton<ConnectionEventSink>(static sp =>
        {
            var metrics = sp.GetRequiredService<EkmMetrics>();
            return new ConnectionEventSink(onDropped: _ => metrics.RecordInspectorDropped());
        });
        services.TryAddSingleton<IConnectionEventSink>(static sp => sp.GetRequiredService<ConnectionEventSink>());
        services.TryAddSingleton<ConnectionEventStore>();
        services.TryAddSingleton<EkmMetrics>();
        services.TryAddSingleton<EkmListenerPorts>();
        services.TryAddSingleton<IEkmPortPolicy>(static sp => sp.GetRequiredService<EkmListenerPorts>());
        services.TryAddSingleton<ServerCertificateProvider>();
        services.TryAddSingleton<IServerCertificateProvider>(static sp => sp.GetRequiredService<ServerCertificateProvider>());
        services.TryAddSingleton<IEkmCallerAuthorizer, MtlsCallerAuthorizer>();
        services.AddHostedService<ConnectionEventPump>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<KestrelServerOptions>, EkmKestrelSetup>());

        // ---- Traffic inspector (M4, spec 8) ----
        services.TryAddSingleton<IInspectorRevealGate, EnvironmentRevealGate>();
        services.TryAddSingleton<IAuditLog, FileAuditLog>();
        services.TryAddSingleton<CaptureDiagnostics>();
        services.TryAddSingleton<InspectorPipeline>();
        services.TryAddSingleton<ExchangeRecordFactory>();
        services.TryAddSingleton(static sp => new ExchangeRingBuffer(sp.GetRequiredService<IOptions<InspectorOptions>>()));
        services.TryAddSingleton(static sp => new DashboardAggregator(sp.GetRequiredService<IOptions<InspectorOptions>>(), sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<ConnectionStatsStage>();
        services.TryAddSingleton<InspectorFeed>();
        services.TryAddSingleton<IInspectorFeed>(static sp => sp.GetRequiredService<InspectorFeed>());
        services.TryAddSingleton<InspectorJsonlWriter>();
        services.TryAddSingleton<InspectorService>();
        services.TryAddSingleton<IInspector>(static sp => sp.GetRequiredService<InspectorService>());
        services.TryAddSingleton<IInspectorQuery>(static sp => sp.GetRequiredService<InspectorService>());

        // Stages run in this order on the consumer threads: the ring buffer first, so a record is queryable before it is pushed to a console.
        // (Plain AddSingleton: TryAddEnumerable cannot tell factory registrations apart.)
        services.AddSingleton<IInspectorStage>(static sp => sp.GetRequiredService<ExchangeRingBuffer>());
        services.AddSingleton<IInspectorStage>(static sp => sp.GetRequiredService<DashboardAggregator>());
        services.AddSingleton<IInspectorStage>(static sp => sp.GetRequiredService<ConnectionStatsStage>());
        services.AddSingleton<IInspectorStage>(static sp => sp.GetRequiredService<InspectorFeed>());
        services.AddSingleton<IInspectorStage>(static sp => sp.GetRequiredService<InspectorJsonlWriter>());
        services.AddHostedService<InspectorConsumer>();

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
