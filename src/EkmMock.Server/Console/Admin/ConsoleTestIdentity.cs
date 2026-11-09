using System.Security.Cryptography.X509Certificates;
using EkmMock.Pki;

namespace EkmMock.Server.WebConsole;

/// <summary>
/// The console's own fake "Managed HSM": a per-process client CA and one client certificate (CN <see cref="CommonName"/>), used by the Playground's "via EKM endpoint"
/// mode and by Replay to make real mutual-TLS requests to the EKM listener (spec 8.5.2 and 8.5.8).
/// <para>
/// Policy (see DECISIONS "M6: Console test client"): the CA and the client key live <b>in memory only</b> and are generated on first use, so no private key is ever
/// written to the data volume and nothing has to be protected at rest. The cost is that a restart creates a new CA; a namespace that trusted the old one then needs the
/// one-click "trust the test CA" again (stale test CAs are replaced, never accumulated), and <c>--dev</c> does that for <c>_default</c> at start-up.
/// The private key is never exposed: nothing here has a member that returns it, and the CA's own key is discarded after the client certificate is issued.
/// </para>
/// </summary>
internal sealed class ConsoleTestIdentity : IDisposable
{
    /// <summary>The subject common name of the test client certificate (spec 11.2 uses the same name for the dev client).</summary>
    public const string CommonName = "test.managedhsmclient.local";

    /// <summary>All test CAs created by this feature start with this common name, so a stale one from an earlier run can be recognised and replaced.</summary>
    public const string CaCommonNamePrefix = "EkmMock Console Test Client CA";

    private readonly Lazy<State> _state = new(Create, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>The client certificate with its private key, for <c>SslClientAuthenticationOptions.ClientCertificates</c>. Not to be exposed outside the self client.</summary>
    internal X509Certificate2 ClientCertificate => _state.Value.Client.Certificate;

    /// <summary>The CA certificate (public) as base64 DER, as stored in a namespace's trust.</summary>
    public string CaDerBase64 => _state.Value.CaDerBase64;

    /// <summary>The CA's subject, for display.</summary>
    public string CaSubject => _state.Value.CaSubject;

    public string CaThumbprintSha256 => _state.Value.CaThumbprint;

    /// <summary>True when <paramref name="subject"/> (a certificate subject) belongs to a console test CA of any run.</summary>
    public static bool IsConsoleTestCaSubject(string? subject)
        => subject is not null && subject.StartsWith("CN=" + CaCommonNamePrefix, StringComparison.Ordinal);

    public void Dispose()
    {
        if (_state.IsValueCreated)
        {
            _state.Value.Client.Dispose();
        }
    }

    private static State Create()
    {
        var suffix = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(4));
        using var ca = CertificateAuthority.CreateRoot($"{CaCommonNamePrefix} {suffix}", PkiKeyAlgorithm.EcdsaP256, TimeSpan.FromDays(400));
        var client = ca.IssueClient(CommonName, TimeSpan.FromDays(365));
        return new State(client, ca.DerBase64, ca.Subject, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(ca.Der)));
    }

    private sealed record State(IssuedCertificate Client, string CaDerBase64, string CaSubject, string CaThumbprint);
}
