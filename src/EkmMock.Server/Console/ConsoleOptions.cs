using System.Net;
using System.Net.Sockets;

namespace EkmMock.Server.WebConsole;

/// <summary>How the console authenticates its users (spec 5.4).</summary>
internal enum ConsoleAuthMode
{
    /// <summary>No sign-in. The console binds to loopback only; the app refuses to start with any other bind address.</summary>
    LoopbackOnly,

    /// <summary>OIDC sign-in with Microsoft.Identity.Web; access is limited to configured object IDs or one security group. Required for any non-loopback bind.</summary>
    EntraId,
}

/// <summary>The <c>Console</c> configuration section (spec 5.4, 16). The Entra client secret is NOT part of it: it comes from the environment (see <see cref="ConsoleSecrets"/>).</summary>
internal sealed class ConsoleOptions
{
    public const string SectionName = "Console";

    public ConsoleAuthMode Auth { get; set; } = ConsoleAuthMode.LoopbackOnly;

    public EntraIdOptions EntraId { get; set; } = new();

    /// <summary>
    /// Optional certificate of the console listener (<c>Console:Tls:CertFile</c> / <c>KeyFile</c>, PEM). Without it the console serves the EKM server certificate
    /// (spec 5.4: "may be the same as the EKM server certificate"), or the generated throw-away localhost certificate in <c>--dev</c>.
    /// </summary>
    public ConsoleTlsOptions Tls { get; set; } = new();

    /// <summary>
    /// In <see cref="ConsoleAuthMode.LoopbackOnly"/>: also refuse every request whose connection's remote address is not loopback (defence in depth, default on).
    /// It cannot fire while the bind check passes (a loopback listener only ever sees loopback peers); it protects against a later configuration drift and is
    /// the one switch to turn off for an unusual proxy set-up. See DECISIONS.md "M5: Auth modes".
    /// </summary>
    public bool EnforceLoopbackClient { get; set; } = true;

    /// <summary>In <see cref="ConsoleAuthMode.LoopbackOnly"/>: extra <c>Host</c> header values (without port) accepted besides localhost, 127.0.0.1 and [::1] (DNS-rebinding defence).</summary>
    public List<string> AllowedHosts { get; set; } = [];

    /// <summary>Show the "coming in M6/M7" placeholder entries in the navigation menu. They have no functionality.</summary>
    public bool ShowPlaceholderNavigation { get; set; } = true;

    /// <summary>The live traffic view: UI list cap, render coalescing and paused-buffer behaviour.</summary>
    public LiveTrafficOptions LiveTraffic { get; set; } = new();
}

internal sealed class EntraIdOptions
{
    public string? Instance { get; set; } = "https://login.microsoftonline.com/";

    public string? TenantId { get; set; }

    public string? ClientId { get; set; }

    public string CallbackPath { get; set; } = "/signin-oidc";

    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";

    /// <summary>Entra user object IDs (GUIDs) that may use the console.</summary>
    public List<string> AllowedObjectIds { get; set; } = [];

    /// <summary>Object ID of a security group whose members may use the console (needs the <c>groups</c> claim in the ID token).</summary>
    public string? AllowedGroupId { get; set; }

    /// <summary>Present only so that a configured value can be detected and refused: a client secret must never be configuration (spec 5.5).</summary>
    public string? ClientSecret { get; set; }
}

internal sealed class ConsoleTlsOptions
{
    public string? CertFile { get; set; }

    public string? KeyFile { get; set; }

    public bool HasFiles => !string.IsNullOrWhiteSpace(CertFile) && !string.IsNullOrWhiteSpace(KeyFile);
}

internal sealed class LiveTrafficOptions
{
    /// <summary>Most rows the Live traffic list keeps in the browser session. Older rows fall off the end; the inspector's ring buffer still has them.</summary>
    public int MaxRows { get; set; } = 2000;

    /// <summary>
    /// Renders are coalesced: at most one per interval, so a flood of 1000 requests per second does not melt the circuit, and a new exchange is on screen after at most this
    /// interval plus the render time (spec 14 test 20 requires one second; the default leaves a wide margin).
    /// </summary>
    public int RenderIntervalMs { get; set; } = 150;

    /// <summary>While the view is paused, newer exchanges are kept (counted as pending) up to this many; beyond it the oldest pending ones are dropped and counted.</summary>
    public int MaxPending { get; set; } = 5000;

    /// <summary>Rows loaded from the ring buffer when the page opens.</summary>
    public int InitialRows { get; set; } = 200;
}

/// <summary>The <c>Endpoints:Console:Url</c> configuration section (spec 7, 16).</summary>
internal sealed class ConsoleEndpointOptions
{
    public const string SectionName = "Endpoints:Console";

    public string Url { get; set; } = "https://127.0.0.1:8080";
}

/// <summary>What kind of address the console listener binds to; decides whether <see cref="ConsoleAuthMode.LoopbackOnly"/> is allowed.</summary>
internal enum ConsoleBindKind
{
    /// <summary>127.0.0.0/8, ::1 and <c>localhost</c>.</summary>
    Loopback,

    /// <summary>0.0.0.0, ::, <c>*</c> or <c>+</c>: every interface.</summary>
    AnyAddress,

    /// <summary>A routable IP address.</summary>
    OtherAddress,

    /// <summary>A host name that resolves to something other than loopback only.</summary>
    HostName,
}

/// <summary>Where the console listener binds, parsed from <c>Endpoints:Console:Url</c>. Port 0 asks the OS for a free port (tests).</summary>
internal sealed record ConsoleEndpointAddress(string Host, IPAddress? Address, bool IsLocalhost, bool IsAnyAddress, int Port, ConsoleBindKind Kind)
{
    private const string HttpsPrefix = "https://";

    /// <summary>
    /// Parses and classifies the URL. <paramref name="resolve"/> resolves a host name (defaults to DNS); a name is loopback only when it resolves and <em>every</em> answer is loopback.
    /// </summary>
    /// <exception cref="InvalidOperationException">The URL is not <c>https://host:port</c>.</exception>
    public static ConsoleEndpointAddress Parse(string? url, Func<string, IReadOnlyList<IPAddress>>? resolve = null)
    {
        if (string.IsNullOrWhiteSpace(url) || !url.StartsWith(HttpsPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Endpoints:Console:Url must be an https URL such as https://127.0.0.1:8080. The console is served over HTTPS only.");
        }

        var authority = url[HttpsPrefix.Length..].TrimEnd('/');
        var colon = authority.LastIndexOf(':');
        var closingBracket = authority.LastIndexOf(']');
        if (colon <= 0 || colon < closingBracket || !int.TryParse(authority[(colon + 1)..], out var port) || port is < 0 or > 65535)
        {
            throw new InvalidOperationException("Endpoints:Console:Url must contain a host and a port, for example https://127.0.0.1:8080.");
        }

        var host = authority[..colon].Trim();
        if (host.StartsWith('[') && host.EndsWith(']'))
        {
            host = host[1..^1];
        }

        if (host is "*" or "+")
        {
            return new ConsoleEndpointAddress(host, null, false, true, port, ConsoleBindKind.AnyAddress);
        }

        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return new ConsoleEndpointAddress(host, null, true, false, port, ConsoleBindKind.Loopback);
        }

        if (IPAddress.TryParse(host, out var address))
        {
            var kind = address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
                ? ConsoleBindKind.AnyAddress
                : IsLoopback(address) ? ConsoleBindKind.Loopback : ConsoleBindKind.OtherAddress;
            return new ConsoleEndpointAddress(host, address, false, kind == ConsoleBindKind.AnyAddress, port, kind);
        }

        if (string.IsNullOrWhiteSpace(host) || host.Any(static c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '.')))
        {
            throw new InvalidOperationException("Endpoints:Console:Url host must be an IP address, localhost, * (all addresses) or a host name.");
        }

        // A host name: Kestrel would bind to what it resolves to. It counts as loopback only when it resolves and every answer is loopback.
        IReadOnlyList<IPAddress> resolved;
        try
        {
            resolved = (resolve ?? DefaultResolve)(host);
        }
        catch (Exception exception) when (exception is SocketException or ArgumentException)
        {
            resolved = [];
        }

        var allLoopback = resolved.Count > 0 && resolved.All(IsLoopback);
        return new ConsoleEndpointAddress(host, null, false, false, port, allLoopback ? ConsoleBindKind.Loopback : ConsoleBindKind.HostName);
    }

    /// <summary>True for 127.0.0.0/8, ::1 and their IPv4-mapped forms.</summary>
    public static bool IsLoopback(IPAddress address)
        => IPAddress.IsLoopback(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address);

    private static IReadOnlyList<IPAddress> DefaultResolve(string host) => Dns.GetHostAddresses(host);
}

/// <summary>The environment variables that carry the console's secret (spec 5.5: secrets never come from <c>appsettings.json</c>, are never logged or shown).</summary>
internal static class ConsoleSecrets
{
    public const string ClientSecretVariable = "EKMMOCK_CONSOLE_CLIENT_SECRET";

    public const string ClientSecretFileVariable = "EKMMOCK_CONSOLE_CLIENT_SECRET_FILE";

    /// <summary>Reads the Entra client secret from the environment (or the file it names). Returns null when none is configured or the file is empty.</summary>
    public static string? ReadClientSecret(Func<string, string?>? environment = null)
    {
        environment ??= static name => Environment.GetEnvironmentVariable(name);
        var direct = environment(ClientSecretVariable);
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct.Trim();
        }

        var file = environment(ClientSecretFileVariable);
        if (!string.IsNullOrWhiteSpace(file))
        {
            try
            {
                var text = File.ReadAllText(file).Trim();
                return text.Length == 0 ? null : text;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }

        return null;
    }

    public static bool IsConfigured(Func<string, string?>? environment = null) => ReadClientSecret(environment) is not null;
}
