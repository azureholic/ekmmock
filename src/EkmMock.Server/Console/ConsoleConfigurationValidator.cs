using System.Net;
using EkmMock.Server.Hosting;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.WebConsole;

/// <summary>The host refuses to start: the configuration is unsafe or incomplete. <see cref="Exception.Message"/> says what to change; it never contains a secret.</summary>
internal sealed class StartupConfigurationException : InvalidOperationException
{
    public StartupConfigurationException(IReadOnlyList<string> problems)
        : base("EkmMock refuses to start: " + string.Join(" ", problems))
    {
        Problems = problems;
    }

    public IReadOnlyList<string> Problems { get; }
}

/// <summary>
/// The console start-up checks of spec 5.4, in one place so that the host builder, the options validation and the Kestrel set-up all apply exactly the same rules:
/// <c>LoopbackOnly</c> with a non-loopback bind is refused, <c>EntraId</c> needs tenant, client, secret and an allow-list, a client secret in configuration is refused.
/// </summary>
internal static class ConsoleConfigurationValidator
{
    public static IReadOnlyList<string> Validate(
        ConsoleOptions options,
        ConsoleEndpointOptions endpoint,
        string? ekmUrl = null,
        Func<string, string?>? environment = null,
        Func<string, IReadOnlyList<IPAddress>>? resolve = null,
        IContainerProbe? container = null)
    {
        var problems = new List<string>();

        // The container-publish opt-in (open question 33): only for LoopbackOnly, and only in a container. Anything else is refused outright instead of being silently ignored,
        // so a copied environment variable cannot give a false sense of safety.
        var containerPublish = ConsoleContainerPublish.IsRequested(environment);
        var containerPublishAllowed = containerPublish && options.Auth == ConsoleAuthMode.LoopbackOnly && (container ?? new SystemContainerProbe()).IsRunningInContainer;
        if (containerPublish && options.Auth == ConsoleAuthMode.EntraId)
        {
            problems.Add(
                $"{ConsoleContainerPublish.Variable}=true only applies to Console:Auth=LoopbackOnly. With EntraId the console may bind any address and the sign-in is the access control: unset the variable.");
        }
        else if (containerPublish && !containerPublishAllowed)
        {
            problems.Add(
                $"{ConsoleContainerPublish.Variable}=true is accepted only when the process runs in a Linux container (DOTNET_RUNNING_IN_CONTAINER=true and a container marker such as /.dockerenv). " +
                "Outside a container the console must bind a loopback address; unset the variable.");
        }

        ConsoleEndpointAddress? address = null;
        try
        {
            address = ConsoleEndpointAddress.Parse(endpoint.Url, resolve);
        }
        catch (InvalidOperationException exception)
        {
            problems.Add(exception.Message);
        }

        if (address is not null)
        {
            if (options.Auth == ConsoleAuthMode.LoopbackOnly && address.Kind != ConsoleBindKind.Loopback && !containerPublishAllowed)
            {
                problems.Add(
                    $"Console:Auth=LoopbackOnly requires the console to bind to a loopback address (127.0.0.1, ::1 or localhost), but Endpoints:Console:Url binds '{address.Host}' ({Describe(address.Kind)}). " +
                    "Bind the console to 127.0.0.1, or set Console:Auth=EntraId to expose it on another address.");
            }

            if (ekmUrl is not null && SamePort(address, ekmUrl))
            {
                problems.Add("Endpoints:Console:Url and Endpoints:Ekm:Url must use different ports: the two endpoints are separated by local port (spec 5.4).");
            }
        }

        if (options.Auth == ConsoleAuthMode.EntraId)
        {
            ValidateEntra(options.EntraId, environment, problems);
        }

        if (!string.IsNullOrEmpty(options.EntraId.ClientSecret))
        {
            problems.Add(
                $"Console:EntraId:ClientSecret must not be set in configuration. Provide the client secret through the {ConsoleSecrets.ClientSecretVariable} environment variable " +
                $"or a file named by {ConsoleSecrets.ClientSecretFileVariable}.");
        }

        var hasCert = !string.IsNullOrWhiteSpace(options.Tls.CertFile);
        var hasKey = !string.IsNullOrWhiteSpace(options.Tls.KeyFile);
        if (hasCert != hasKey)
        {
            problems.Add("Console:Tls:CertFile and Console:Tls:KeyFile must be set together.");
        }

        var live = options.LiveTraffic;
        if (live.MaxRows is < 10 or > 100_000 || live.RenderIntervalMs is < 20 or > 900 || live.MaxPending is < 10 or > 1_000_000 || live.InitialRows is < 0 or > 10_000)
        {
            problems.Add("Console:LiveTraffic values are out of range (MaxRows 10..100000, RenderIntervalMs 20..900 so that live updates stay within one second, MaxPending 10..1000000, InitialRows 0..10000).");
        }

        return problems;
    }

    /// <summary>Throws <see cref="StartupConfigurationException"/> when <see cref="Validate"/> finds a problem.</summary>
    public static void EnsureValid(ConsoleOptions options, ConsoleEndpointOptions endpoint, string? ekmUrl = null, IContainerProbe? container = null)
    {
        var problems = Validate(options, endpoint, ekmUrl, container: container);
        if (problems.Count > 0)
        {
            throw new StartupConfigurationException(problems);
        }
    }

    /// <summary>Parses a tenant ID strictly: the 36-character GUID form only (no braces, no missing hyphens, no aliases such as "common").</summary>
    internal static bool TryParseTenantId(string? value, out Guid tenant)
    {
        tenant = Guid.Empty;
        return value is { Length: > 0 } && Guid.TryParseExact(value.Trim(), "D", out tenant) && tenant != Guid.Empty;
    }

    private static void ValidateEntra(EntraIdOptions entra, Func<string, string?>? environment, List<string> problems)
    {
        if (string.IsNullOrWhiteSpace(entra.TenantId))
        {
            problems.Add("Console:Auth=EntraId requires Console:EntraId:TenantId.");
        }
        else if (!TryParseTenantId(entra.TenantId, out _))
        {
            problems.Add(
                "Console:EntraId:TenantId must be the tenant's directory ID as a GUID in the form 00000000-0000-0000-0000-000000000000. The console checks the token's tenant claim (tid) against it on every request, " +
                "which only works with the real tenant ID: 'common', 'organizations', 'consumers' and domain names are refused.");
        }

        if (string.IsNullOrWhiteSpace(entra.ClientId))
        {
            problems.Add("Console:Auth=EntraId requires Console:EntraId:ClientId.");
        }

        if (!ConsoleSecrets.IsConfigured(environment))
        {
            problems.Add(
                $"Console:Auth=EntraId requires the client secret in the {ConsoleSecrets.ClientSecretVariable} environment variable (or a file named by {ConsoleSecrets.ClientSecretFileVariable}).");
        }

        if (!Uri.TryCreate(entra.Instance, UriKind.Absolute, out var instance) || instance.Scheme != Uri.UriSchemeHttps)
        {
            problems.Add("Console:EntraId:Instance must be an https URL such as https://login.microsoftonline.com/.");
        }

        var objectIds = entra.AllowedObjectIds.Where(static id => !string.IsNullOrWhiteSpace(id)).ToList();
        var hasGroup = !string.IsNullOrWhiteSpace(entra.AllowedGroupId);
        if (objectIds.Count == 0 && !hasGroup)
        {
            problems.Add("Console:Auth=EntraId requires Console:EntraId:AllowedObjectIds or Console:EntraId:AllowedGroupId: without an allow-list nobody could sign in, and everybody in the tenant must not.");
        }

        if (objectIds.Any(static id => !Guid.TryParse(id, out _)) || (hasGroup && !Guid.TryParse(entra.AllowedGroupId, out _)))
        {
            problems.Add("Console:EntraId:AllowedObjectIds and AllowedGroupId must be object IDs (GUIDs).");
        }
    }

    private static string Describe(ConsoleBindKind kind) => kind switch
    {
        ConsoleBindKind.AnyAddress => "all network interfaces",
        ConsoleBindKind.OtherAddress => "a non-loopback address",
        ConsoleBindKind.HostName => "a host name that does not resolve to loopback only",
        _ => "loopback",
    };

    private static bool SamePort(ConsoleEndpointAddress console, string ekmUrl)
    {
        try
        {
            var ekm = EkmEndpointAddress.Parse(ekmUrl);
            return console.Port != 0 && console.Port == ekm.Port;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}

/// <summary>Runs the console checks again when the options are first used (<c>ValidateOnStart</c>), for hosts whose configuration was completed after the builder pre-flight.</summary>
internal sealed class ConsoleOptionsValidator : IValidateOptions<ConsoleOptions>
{
    private readonly IOptions<ConsoleEndpointOptions> _endpoint;
    private readonly IOptions<EkmEndpointOptions> _ekm;
    private readonly IContainerProbe _container;

    public ConsoleOptionsValidator(IOptions<ConsoleEndpointOptions> endpoint, IOptions<EkmEndpointOptions> ekm, IContainerProbe container)
    {
        _endpoint = endpoint;
        _ekm = ekm;
        _container = container;
    }

    public ValidateOptionsResult Validate(string? name, ConsoleOptions options)
    {
        var problems = ConsoleConfigurationValidator.Validate(options, _endpoint.Value, _ekm.Value.Url, container: _container);
        return problems.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(problems);
    }
}
