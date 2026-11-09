using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EkmMock.Server.Tls;

/// <summary>
/// The public facts about a presented client certificate (spec 8.1 "Client certificate"): safe to log, store and show.
/// Never contains the raw certificate or any key material.
/// </summary>
internal sealed record ClientCertificateSummary(
    string Subject,
    string Issuer,
    string SerialNumber,
    string ThumbprintSha256,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc)
{
    public static ClientCertificateSummary From(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return new ClientCertificateSummary(
            Limit(certificate.Subject),
            Limit(certificate.Issuer),
            certificate.SerialNumber,
            certificate.GetCertHashString(HashAlgorithmName.SHA256),
            new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero),
            new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero));
    }

    // Subject and issuer are client controlled strings; keep them bounded for logs and the inspector.
    private static string Limit(string value) => value.Length <= 512 ? value : value[..512];
}
