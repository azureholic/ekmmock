using System.Net.Security;
using System.Security.Authentication;

// CipherSuitesPolicy is unsupported on Windows (and the analyzer cannot see that every use below sits behind the TryCreate probe).
// The capability is detected by catching PlatformNotSupportedException, not by sniffing the OS name; see DECISIONS.md "M3: TLS stack".
#pragma warning disable CA1416

namespace EkmMock.Server.Tls;

/// <summary>How the two permitted TLS 1.3 cipher suites are held to on this operating system.</summary>
internal enum CipherSuiteEnforcement
{
    /// <summary>The TLS stack itself only offers the permitted suites (<c>CipherSuitesPolicy</c>, OpenSSL).</summary>
    EnforcedByTlsStack,

    /// <summary>
    /// <c>CipherSuitesPolicy</c> is not supported here (Windows/SChannel). The TLS stack may negotiate other suites; EkmMock closes
    /// such a connection right after the handshake and records it, but cannot refuse it <em>during</em> the handshake.
    /// </summary>
    NotEnforceableByTlsStack,
}

/// <summary>
/// The effective TLS policy for the "About" page (spec 8.5 item 11): what is required and what this OS can actually enforce.
/// </summary>
internal sealed record EffectiveTlsPolicy(
    string Protocol,
    IReadOnlyList<string> PermittedCipherSuites,
    CipherSuiteEnforcement CipherSuiteEnforcement,
    string CipherSuiteSummary,
    string OperatingSystem);

/// <summary>The cipher suites the API reference allows (spec 3, 5.1) and the capability check for enforcing them.</summary>
internal sealed class TlsPolicy
{
    /// <summary>The only TLS 1.3 suites accepted (RFC 8446 code points 0x1302 and 0x1301).</summary>
    public static readonly IReadOnlyList<TlsCipherSuite> PermittedSuites =
        [TlsCipherSuite.TLS_AES_256_GCM_SHA384, TlsCipherSuite.TLS_AES_128_GCM_SHA256];

    public const SslProtocols RequiredProtocols = SslProtocols.Tls13;

    private readonly Lazy<CipherSuitesPolicy?> _policy = new(TryCreate);

    public TlsPolicy()
    {
        var policy = _policy.Value;
        var names = PermittedSuites.Select(static s => s.ToString()).ToList();
        Effective = new EffectiveTlsPolicy(
            "TLS 1.3 only",
            names,
            policy is null ? CipherSuiteEnforcement.NotEnforceableByTlsStack : CipherSuiteEnforcement.EnforcedByTlsStack,
            policy is null
                ? "not enforceable on this OS (CipherSuitesPolicy is not supported here); a post-handshake check closes connections that negotiated another suite"
                : "enforced by the TLS stack (CipherSuitesPolicy)",
            System.Runtime.InteropServices.RuntimeInformation.OSDescription);
    }

    /// <summary>True when the platform supports <c>CipherSuitesPolicy</c> (Linux/OpenSSL); probed, not assumed from the OS name.</summary>
    public bool CanEnforceCipherSuites => _policy.Value is not null;

    public EffectiveTlsPolicy Effective { get; }

    /// <summary>The policy to put on <c>SslServerAuthenticationOptions.CipherSuitesPolicy</c>, or null when unsupported.</summary>
    public CipherSuitesPolicy? CipherSuitesPolicy => _policy.Value;

    public static bool IsPermitted(TlsCipherSuite suite) => PermittedSuites.Contains(suite);

    private static CipherSuitesPolicy? TryCreate()
    {
        try
        {
            return new CipherSuitesPolicy(PermittedSuites);
        }
        catch (PlatformNotSupportedException)
        {
            return null;
        }
    }
}
