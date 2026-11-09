using System.Security.Cryptography.X509Certificates;
using EkmMock.Crypto;
using EkmMock.Server.Connections;
using EkmMock.Server.Tls;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Connections.Features;

namespace EkmMock.Server.Ekm;

/// <summary>Why a caller was not authenticated for a namespace. Internal diagnostics only: the wire answer is always the same 401.</summary>
internal enum AuthFailure
{
    None,

    /// <summary>The request did not arrive over TLS (never true on the EKM listener; a defence in depth).</summary>
    NoTransportSecurity,

    NoClientCertificate,

    /// <summary>The certificate seen on the request is not the one the connection's handshake recorded (defence in depth; should never happen).</summary>
    ClientCertificateChanged,
    /// <summary>The chain does not build to a root CA of <em>this namespace</em>, or a chain element is invalid.</summary>
    ChainNotTrusted,

    CertificateExpired,

    CertificateNotYetValid,

    /// <summary>The certificate is not valid for client authentication (EKU present without clientAuth).</summary>
    UsageNotPermitted,

    /// <summary>No CN, several CNs, or a CN in a multi-valued RDN: ambiguous, never matched.</summary>
    CommonNameMissingOrAmbiguous,

    CommonNameNotAllowed,
}

/// <summary>
/// The outcome of authorizing one exchange, with everything the inspector shows under "Client certificate" (spec 8.1): present?,
/// subject, issuer, serial, thumbprint, validity, chain result, CN allowed?, namespace matched.
/// </summary>
internal sealed record EkmAuthResult
{
    public required bool Succeeded { get; init; }

    public AuthFailure Failure { get; init; }

    public bool CertificatePresent => Certificate is not null;

    public ClientCertificateSummary? Certificate { get; init; }

    /// <summary>The single CN of the subject when there is exactly one; client controlled text, bounded.</summary>
    public string? CommonName { get; init; }

    /// <summary>Result of building the chain against the namespace's own roots (flags, or <c>NoError</c>); null when no certificate.</summary>
    public string? ChainResult { get; init; }

    public bool? CommonNameAllowed { get; init; }

    /// <summary>True when the certificate is authorized for the namespace of the request path.</summary>
    public bool NamespaceMatched => Succeeded;

    public static EkmAuthResult Allowed(string? commonName = null) => new() { Succeeded = true, CommonName = commonName };
}

/// <summary>Decides whether the caller of an exchange may use the namespace of the request. The one seam tests replace (never a production flag).</summary>
internal interface IEkmCallerAuthorizer
{
    EkmAuthResult Authorize(HttpContext context, NamespaceDefinition ns);
}

/// <summary>
/// The production authorizer (spec 5.1): a client certificate must be present, must chain to <em>this namespace's</em> own roots
/// (not the union used at handshake time) and its subject CN must be exactly one of <em>this namespace's</em> allowed names.
/// A certificate that is valid for namespace A is therefore useless on namespace B.
/// <para>
/// Validity: the leaf and every chain element must be inside their validity window now. Key usage: if the certificate carries an EKU
/// it must include clientAuth. Revocation is not checked and nothing is downloaded. CN comparison is ordinal (case-sensitive), exact,
/// with no wildcards and no substring matching, on the parsed CN attribute rather than the formatted subject string.
/// </para>
/// </summary>
internal sealed class MtlsCallerAuthorizer : IEkmCallerAuthorizer
{
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    private const int MaxCommonNameLogLength = 128;

    private readonly ClientTrustProvider _trust;
    private readonly ConnectionRegistry _connections;
    private readonly TimeProvider _time;

    public MtlsCallerAuthorizer(ClientTrustProvider trust, ConnectionRegistry connections, TimeProvider time)
    {
        _trust = trust;
        _connections = connections;
        _time = time;
    }

    public EkmAuthResult Authorize(HttpContext context, NamespaceDefinition ns)
    {
        if (context.Features.Get<ITlsHandshakeFeature>() is null)
        {
            return Failed(AuthFailure.NoTransportSecurity);
        }

        var certificate = context.Connection.ClientCertificate;
        if (certificate is null)
        {
            return Failed(AuthFailure.NoClientCertificate);
        }

        var summary = ClientCertificateSummary.From(certificate);

        // Defence in depth: the certificate the request sees must be the one this connection's handshake recorded (or none at both).
        if (_connections.TryGet(context.Connection.Id) is { HandshakeCompleted: true } connection
            && !string.Equals(connection.ClientCertificate?.ThumbprintSha256, summary.ThumbprintSha256, StringComparison.OrdinalIgnoreCase))
        {
            return Failed(AuthFailure.ClientCertificateChanged, summary);
        }
        var hasName = CommonNameReader.TryGetSingleCommonName(certificate.SubjectName, out var commonName);
        var loggedName = commonName is { Length: > MaxCommonNameLogLength } ? commonName[..MaxCommonNameLogLength] : commonName;

        var trust = _trust.Current;
        if (!trust.ByNamespace.TryGetValue(ns.Name, out var namespaceTrust))
        {
            return Failed(AuthFailure.ChainNotTrusted, summary, loggedName, "NamespaceUnknown");
        }

        var now = _time.GetUtcNow();
        var (chainOk, chainStatus, chainFlags) = BuildChain(certificate, namespaceTrust, now, context.Connection.Id);
        if (!chainOk)
        {
            var failure = ClassifyChainFailure(certificate, chainFlags, now);
            return Failed(failure, summary, loggedName, chainStatus);
        }

        if (!hasName)
        {
            return Failed(AuthFailure.CommonNameMissingOrAmbiguous, summary, loggedName, chainStatus, commonNameAllowed: false);
        }

        if (!namespaceTrust.CommonNames.Contains(commonName!))
        {
            return Failed(AuthFailure.CommonNameNotAllowed, summary, loggedName, chainStatus, commonNameAllowed: false);
        }

        return new EkmAuthResult
        {
            Succeeded = true,
            Certificate = summary,
            CommonName = loggedName,
            ChainResult = chainStatus,
            CommonNameAllowed = true,
        };
    }

    private (bool Ok, string Status, X509ChainStatusFlags Flags) BuildChain(X509Certificate2 certificate, NamespaceTrust trust, DateTimeOffset now, string connectionId)
    {
        using var chain = new X509Chain();
        var policy = chain.ChainPolicy;
        policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        policy.CustomTrustStore.AddRange(trust.Roots);
        policy.RevocationMode = X509RevocationMode.NoCheck;
        policy.DisableCertificateDownloads = true;
        policy.VerificationTime = now.LocalDateTime;
        policy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid(ClientAuthOid));
        foreach (var der in _connections.TryGet(connectionId)?.PresentedIntermediates ?? [])
        {
            policy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(der));
        }

        var ok = chain.Build(certificate);
        var flags = chain.ChainStatus.Aggregate(X509ChainStatusFlags.NoError, static (all, s) => all | s.Status);
        return (ok, ClientCertificateValidator.DescribeStatus(chain), flags);
    }

    private static AuthFailure ClassifyChainFailure(X509Certificate2 certificate, X509ChainStatusFlags flags, DateTimeOffset now)
    {
        if (flags.HasFlag(X509ChainStatusFlags.NotTimeValid))
        {
            var notBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero);
            var notAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            if (now > notAfter)
            {
                return AuthFailure.CertificateExpired;
            }

            if (now < notBefore)
            {
                return AuthFailure.CertificateNotYetValid;
            }
        }

        return flags.HasFlag(X509ChainStatusFlags.NotValidForUsage) ? AuthFailure.UsageNotPermitted : AuthFailure.ChainNotTrusted;
    }

    private static EkmAuthResult Failed(AuthFailure failure, ClientCertificateSummary? certificate = null, string? commonName = null, string? chainResult = null, bool? commonNameAllowed = null)
        => new()
        {
            Succeeded = false,
            Failure = failure,
            Certificate = certificate,
            CommonName = commonName,
            ChainResult = chainResult,
            CommonNameAllowed = commonNameAllowed,
        };
}

/// <summary>The Auth stage of the EKM pipeline (after Route, before Limits): anything but an authorized caller is <c>401 Unauthenticated</c>.</summary>
internal sealed class EkmAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IEkmCallerAuthorizer _authorizer;

    public EkmAuthMiddleware(RequestDelegate next, IEkmCallerAuthorizer authorizer)
    {
        _next = next;
        _authorizer = authorizer;
    }

    public Task InvokeAsync(HttpContext context)
    {
        var exchange = context.GetEkmContext();
        var route = exchange.Route ?? throw new EkmProtocolException(ProxyErrorCode.NotFound);
        var authStarted = System.Diagnostics.Stopwatch.GetTimestamp();
        var result = _authorizer.Authorize(context, route.Namespace);
        exchange.AuthElapsed = System.Diagnostics.Stopwatch.GetElapsedTime(authStarted);
        exchange.Authentication = result;
        if (!result.Succeeded)
        {
            throw new EkmProtocolException(ProxyErrorCode.Unauthenticated);
        }

        return _next(context);
    }
}
