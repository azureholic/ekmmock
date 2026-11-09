using EkmMock.Server.Hosting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.FluentUI.AspNetCore.Components;

namespace EkmMock.Server.WebConsole;

/// <summary>Registers the console (spec 5.4, 7, 8.5): Blazor Interactive Server with Fluent UI, the console endpoint, certificate, ports and options.</summary>
internal static class ConsoleServiceCollectionExtensions
{
    /// <summary>The services that do not depend on the auth mode. Called by <see cref="EkmServerServiceCollectionExtensions.AddEkmMockServices"/>.</summary>
    public static IServiceCollection AddEkmConsoleServices(this IServiceCollection services)
    {
        services.AddOptions<ConsoleOptions>()
            .BindConfiguration(ConsoleOptions.SectionName)
            .ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<ConsoleOptions>, ConsoleOptionsValidator>());
        services.AddOptions<ConsoleEndpointOptions>().BindConfiguration(ConsoleEndpointOptions.SectionName);

        services.TryAddSingleton<IContainerProbe, SystemContainerProbe>();
        services.TryAddSingleton(static sp => ConsoleExposure.Resolve(
            sp.GetRequiredService<IOptions<ConsoleOptions>>().Value,
            sp.GetRequiredService<IOptions<ConsoleEndpointOptions>>().Value,
            sp.GetRequiredService<IContainerProbe>(),
            sp.GetRequiredService<ILoggerFactory>().CreateLogger("EkmMock.Console")));
        services.TryAddSingleton<ListenerRegistry>();
        services.TryAddSingleton<ConsoleListenerPorts>();
        services.TryAddSingleton<IConsolePortPolicy>(static sp => sp.GetRequiredService<ConsoleListenerPorts>());
        services.TryAddSingleton<ConsoleCertificates>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<KestrelServerOptions>, ConsoleKestrelSetup>());

        services.TryAddSingleton<IFaultStatus, FaultStatus>();
        services.TryAddSingleton<FaultAdminService>();
        services.TryAddSingleton<IConsoleStatusProvider, ConsoleStatusProvider>();

        // M6: the console actions. One set of services shared by the Blazor pages and /api/console/*, so both write the same audit entries.
        services.TryAddSingleton<AuditRecorder>();
        services.TryAddSingleton<ConsoleTestIdentity>();
        // The certificate provider is resolved when the first self-call happens: it throws when no certificate is configured, and the inspector (which holds the replay sender) must still start.
        services.TryAddSingleton(static sp => new EkmSelfClient(
            sp.GetRequiredService<ConsoleTestIdentity>(),
            () => sp.GetRequiredService<Tls.IServerCertificateProvider>().Current.Thumbprint,
            () => sp.GetRequiredService<ListenerRegistry>().EndpointsOf(ListenerRegistry.EkmName)));
        services.TryAddSingleton<KeyAdminService>();
        services.TryAddSingleton<NamespaceAdminService>();
        services.TryAddSingleton<CertificateAdminService>();
        services.TryAddSingleton<PlaygroundService>();
        services.TryAddSingleton<AboutService>();
        services.TryAddSingleton<IAboutService>(static sp => sp.GetRequiredService<AboutService>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<Inspector.IReplaySender, ConsoleReplaySender>());
        services.AddHostedService<ConsoleDevBootstrap>();

        services.AddRazorComponents().AddInteractiveServerComponents();
        services.AddFluentUIComponents();
        services.AddHttpContextAccessor();

        services.AddAntiforgery(antiforgery =>
        {
            antiforgery.HeaderName = ConsoleApi.AntiforgeryHeader;
            antiforgery.Cookie.Name = "__Host-ekmmock-antiforgery";
            antiforgery.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            antiforgery.Cookie.SameSite = SameSiteMode.Strict;
        });
        services.AddEkmConsoleDataProtection();
        return services;
    }

    /// <summary>
    /// The host-level part that needs the final configuration: refuses to start on an unsafe or incomplete console configuration (spec 5.4: LoopbackOnly with a non-loopback
    /// bind, EntraId without tenant/client/secret/allow-list) and registers the authentication of the configured mode. Called by the host builder after the configuration is complete.
    /// </summary>
    public static WebApplicationBuilder AddEkmConsole(this WebApplicationBuilder builder)
    {
        var options = builder.Configuration.GetSection(ConsoleOptions.SectionName).Get<ConsoleOptions>() ?? new ConsoleOptions();
        var endpoint = builder.Configuration.GetSection(ConsoleEndpointOptions.SectionName).Get<ConsoleEndpointOptions>() ?? new ConsoleEndpointOptions();
        var ekmUrl = builder.Configuration.GetSection(EkmEndpointOptions.SectionName).Get<EkmEndpointOptions>()?.Url ?? new EkmEndpointOptions().Url;

        // A test seam: a test registers its own IContainerProbe instance before the host is built (the customize hook of BuildEkmMockApp); production has none and uses the real probe.
        var probe = builder.Services.LastOrDefault(static d => d.ServiceType == typeof(IContainerProbe) && d.ImplementationInstance is not null)?.ImplementationInstance as IContainerProbe;
        ConsoleConfigurationValidator.EnsureValid(options, endpoint, ekmUrl, probe);

        builder.Services.AddConsoleAuthentication(options);
        builder.Services.AddOptions<Microsoft.AspNetCore.Components.Server.CircuitOptions>()
            .Configure(circuit => circuit.DetailedErrors = builder.Environment.IsDevelopment());
        return builder;
    }

    // Antiforgery tokens and the Entra session cookie are protected with Data Protection keys. They are kept on the data volume so that a restart does not invalidate open
    // consoles; when the volume is not writable the keys stay in memory (a warning is the only consequence).
    private static IServiceCollection AddEkmConsoleDataProtection(this IServiceCollection services)
    {
        services.AddDataProtection().SetApplicationName("EkmMock.Console");
        services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(static sp =>
        {
            var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("EkmMock.Console");
            var folder = Path.Combine(Path.GetFullPath(sp.GetRequiredService<IOptions<DataOptions>>().Value.Path), "dataprotection");
            return new ConfigureOptions<KeyManagementOptions>(management =>
            {
                // The keys live on the data volume (open tokens survive a restart). Without a writable volume they stay in memory, deliberately, so the console still works.
                try
                {
                    Directory.CreateDirectory(folder);
                    var directory = new DirectoryInfo(folder);
                    if (DataFolderXmlRepository.IsWritable(directory))
                    {
                        management.XmlRepository = new DataFolderXmlRepository(directory);
                        return;
                    }
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    // fall through to the in-memory keys
                }

                management.XmlRepository = new InMemoryXmlRepository();
                logger.LogWarning("The data protection key folder is not writable; console tokens use in-memory keys and are invalid after a restart.");
            });
        });
        return services;
    }
}
