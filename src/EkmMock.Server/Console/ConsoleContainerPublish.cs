using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace EkmMock.Server.WebConsole;

/// <summary>
/// Answers "is this process demonstrably running inside a Linux container?". It is one of the two conditions of the console's container-publish opt-in (<see cref="ConsoleContainerPublish"/>).
/// A test replaces it; production uses <see cref="SystemContainerProbe"/>.
/// </summary>
internal interface IContainerProbe
{
    bool IsRunningInContainer { get; }
}

/// <summary>
/// The real probe. A process counts as "in a container" only when it runs on Linux and <b>both</b> hold: the .NET container images' own marker <c>DOTNET_RUNNING_IN_CONTAINER=true</c> and
/// a runtime marker file that a container engine creates (<c>/.dockerenv</c> for Docker, <c>/run/.containerenv</c> for Podman) or Kubernetes' <c>KUBERNETES_SERVICE_HOST</c>.
/// The environment variable alone is not enough because anybody can export it on a laptop; the marker file alone is not enough because a development machine can contain a stray file.
/// This is a guard against <em>accidental</em> misuse (copying the opt-in onto a host), not against an operator who controls the environment of the process: such an operator can already
/// bind the console to anything with <c>Console:Auth=EntraId</c> or change the configuration. See DECISIONS.md "M9: Container-safe console binding".
/// </summary>
internal sealed class SystemContainerProbe : IContainerProbe
{
    public bool IsRunningInContainer => Detect(OperatingSystem.IsLinux(), static name => Environment.GetEnvironmentVariable(name), static path => File.Exists(path));

    internal static bool Detect(bool isLinux, Func<string, string?> environment, Func<string, bool> fileExists)
    {
        if (!isLinux)
        {
            return false;
        }

        if (!string.Equals(environment("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return fileExists("/.dockerenv") || fileExists("/run/.containerenv") || !string.IsNullOrEmpty(environment("KUBERNETES_SERVICE_HOST"));
    }
}

/// <summary>
/// The container-publish opt-in (resolves open question 33): inside a container a <c>LoopbackOnly</c> console cannot bind <c>127.0.0.1</c>, because traffic that Docker publishes to the
/// container arrives on the bridge address, so spec 5.4 ("refuse LoopbackOnly with a non-loopback bind") and spec 11.2 ("console <c>127.0.0.1:8080:8080</c>") contradict each other.
/// The one narrow exception: <c>EKMMOCK_CONSOLE_CONTAINER_PUBLISH=true</c> allows the non-loopback bind <b>only</b> when <see cref="IContainerProbe"/> says the process is in a container
/// and the auth mode is <c>LoopbackOnly</c>. It is an environment variable (like <c>EKMMOCK_ENABLE_FAULTS</c>), never a configuration value, so it cannot be committed in an appsettings file by accident.
/// While active the console refuses requests from non-private source addresses (<see cref="IsContainerNetworkSource"/>), shows a banner and logs a startup warning.
/// </summary>
internal static class ConsoleContainerPublish
{
    public const string Variable = "EKMMOCK_CONSOLE_CONTAINER_PUBLISH";

    public const string BannerTitle = "Console bound inside a container — host publish must be loopback-only";

    public const string BannerText =
        "The console listens on a non-loopback address inside this container so that Docker can publish it. Publish it to the host on 127.0.0.1 only " +
        "(-p 127.0.0.1:8080:8080). Published on 0.0.0.0 it is an unauthenticated console for everybody on the network segment.";

    /// <summary>True only for the exact value <c>true</c> (any case). Every other value, including <c>1</c> and <c>yes</c>, is "not requested": the opt-in fails closed.</summary>
    public static bool IsRequested(Func<string, string?>? environment = null)
    {
        environment ??= static name => Environment.GetEnvironmentVariable(name);
        return string.Equals(environment(Variable), "true", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Whether a connection from <paramref name="address"/> is plausible container-network traffic: loopback, RFC 1918 (10/8, 172.16/12, 192.168/16), IPv4 link-local (169.254/16),
    /// IPv6 unique local (fc00::/7), IPv6 link-local (fe80::/10), and the IPv4-mapped IPv6 forms of the IPv4 ranges. Everything else (a public address, CGNAT 100.64/10, multicast,
    /// the unspecified address) is not.
    /// </summary>
    public static bool IsContainerNetworkSource(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return bytes[0] == 127
                || bytes[0] == 10
                || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return IPAddress.IPv6Loopback.Equals(address)
                || (bytes[0] & 0xFE) == 0xFC
                || (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80);
        }

        return false;
    }
}

/// <summary>
/// What the running console is exposed as, computed once from the final configuration, the environment and the container probe. <see cref="ContainerPublishActive"/> is true only for a
/// <c>LoopbackOnly</c> console that binds a non-loopback address because the container-publish opt-in allowed it (the start-up validation has already refused every other combination).
/// </summary>
internal sealed class ConsoleExposure
{
    private ConsoleExposure(bool containerPublishActive) => ContainerPublishActive = containerPublishActive;

    /// <summary>The console is not exposed through the container-publish opt-in (the normal case).</summary>
    public static ConsoleExposure None { get; } = new(false);

    /// <summary>The opt-in is in effect. For tests that exercise the request guard directly; the real value comes from <see cref="Resolve"/>.</summary>
    public static ConsoleExposure ContainerPublish { get; } = new(true);

    /// <summary>The nominal evaluation: the opt-in is active only for LoopbackOnly, with the variable set, in a container and with a non-loopback bind. Logs the startup warning when it is.</summary>
    public static ConsoleExposure Resolve(
        ConsoleOptions console,
        ConsoleEndpointOptions endpoint,
        IContainerProbe probe,
        ILogger logger,
        Func<string, string?>? environment = null)
    {
        var active = false;
        if (console.Auth == ConsoleAuthMode.LoopbackOnly && ConsoleContainerPublish.IsRequested(environment) && probe.IsRunningInContainer)
        {
            try
            {
                active = ConsoleEndpointAddress.Parse(endpoint.Url).Kind != ConsoleBindKind.Loopback;
            }
            catch (InvalidOperationException)
            {
                // A malformed URL is refused by the start-up validation; nothing is active.
            }
        }

        if (active)
        {
            logger.LogWarning(
                "{Variable}=true: the LoopbackOnly console is bound to a non-loopback address inside a container. Publish the console port to the host on 127.0.0.1 ONLY (for example -p 127.0.0.1:8080:8080); " +
                "published on 0.0.0.0 it is an unauthenticated console for the whole network segment. Requests from public source addresses are refused as defence in depth.",
                ConsoleContainerPublish.Variable);
        }

        return active ? ContainerPublish : None;
    }

    /// <summary>The non-loopback bind inside a container is allowed by the opt-in: the console shows its banner and checks every source address.</summary>
    public bool ContainerPublishActive { get; }
}

