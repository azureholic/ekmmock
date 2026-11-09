using System.Text.Json.Serialization;

namespace EkmMock.Cli.ConsoleApi;

// The console API (/api/console/*) as the CLI sees it. These records duplicate the minimal wire shapes on purpose: the CLI must not reference the ASP.NET Core server project.
// Unknown properties are ignored (forward compatible); every property the server omits (nulls) stays null.

internal sealed record ApiError(string Code, string Message);

internal sealed record KeyView(
    string Namespace,
    string Name,
    string Type,
    int Size,
    string State,
    string Origin,
    DateTimeOffset CreatedAt,
    DateTimeOffset? NotAfter,
    DateTimeOffset? LastUsedAt,
    long WrapCount,
    long UnwrapCount,
    DateTimeOffset? DestroyedAt,
    string? DestroyedBy,
    string? StateNote)
{
    public string Display => Type == "oct" ? "AES-" + Size : "RSA-" + Size;
}

internal sealed record KeyList(List<KeyView> Keys);

internal sealed record PublicKeyView(string Pem, string JwkN, string JwkE, string Jwk);

internal sealed record KeyDetail(KeyView Key, PublicKeyView? PublicKey, string AzCommand, string RoutingNote);

internal sealed record CreateKeyBody(string Namespace, string Name, string Type, int Size, bool AllowReuseOfDestroyedName);

internal sealed record ImportKeyBody(string Namespace, string Name, string Type, string Material, bool AllowReuseOfDestroyedName);

internal sealed record ExpiryBody(DateTimeOffset? NotAfter);

internal sealed record DestroyKeyBody(string ConfirmName);

internal sealed record CaCertificateView(
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string ThumbprintSha256,
    bool IsSelfSigned,
    bool IsCa,
    bool IsExpired,
    bool IsNotYetValid,
    bool IsConsoleTestCa,
    List<string> Warnings,
    string DerBase64);

internal sealed record NamespaceView(
    string Name,
    string Prefix,
    string DisplayPrefix,
    List<string> SubjectCommonNames,
    List<CaCertificateView> CaCertificates,
    int KeyCount,
    int DestroyedKeyCount,
    string AzCommand,
    List<string> Warnings,
    bool TrustsConsoleTestClient);

internal sealed record NamespaceList(List<NamespaceView> Namespaces);

internal sealed record NamespaceBody(string Name, string Prefix, List<string>? SubjectCommonNames, List<string>? CaCertificatesDerBase64);

internal sealed record DeleteNamespaceBody(string ConfirmName, bool DestroyKeys);

internal sealed record NamespaceDeleted(bool Deleted, int DestroyedKeys);

internal sealed record TrustImportBody(string? Format, string Content, List<string>? SubjectCommonNames, string? Mode, bool DryRun);

internal sealed record TrustPreview(
    string Namespace,
    string Format,
    string Mode,
    List<string> SubjectCommonNames,
    List<CaCertificateView> CaCertificates,
    List<string> Warnings,
    List<string> ResultingSubjectCommonNames,
    int ResultingCaCount,
    bool Saved);

internal sealed record FaultRuleView(
    string Id,
    bool Enabled,
    string Kind,
    string? Namespace,
    string? Key,
    string? Op,
    int? DelayMs,
    int? MinMs,
    int? MaxMs,
    double? ErrorPercent,
    int? StatusCode,
    string? Description,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    long Fired,
    string State,
    string Parameters,
    string Scope);

internal sealed record FaultPresetView(string Id, string Title, string Description);

internal sealed record FaultList(bool Enabled, bool HsmOffline, int ActiveRules, int MaxRules, List<FaultRuleView> Rules, List<FaultPresetView> Presets);

internal sealed record FaultRuleBody(string Kind, string? Namespace, string? Key, string? Op, int? DelayMs, int? MinMs, int? MaxMs, double? ErrorPercent, int? StatusCode, string? Description, int? ExpiresAfterSeconds);

internal sealed record FaultCleared(int Removed);

internal sealed record ConsoleStatus(string Version, string AuthMode, bool DevMode, bool DevMasterKey, bool Ready, bool SelfTestPassed, bool FaultsActive, bool RevealAllowed, string SecretDisplay, int LatencyBudgetMs, int LatencyWarningMs, bool FaultsEnabled, bool HsmOfflineFault);

internal sealed record ConfigEntry(string Section, string Name, string Value, bool Redacted);

internal sealed record AboutInfo(string Version, string AuthMode, bool DevMode, bool KeyImportEnabled, bool RevealAllowed, List<ConfigEntry> Configuration);

// ---- inspector (only what the conformance suite checks) ----

internal sealed record ExchangeIdentity(long ExchangeId, string? ConnectionId, DateTimeOffset ReceivedAtUtc);

internal sealed record MaskedField(string Field, string Display, int? Bytes, string? Fingerprint, bool Revealable);

internal sealed record CapturedBody(long SizeBytes, bool Truncated, bool Captured, string? Text, List<MaskedField>? MaskedFields);

internal sealed record ExchangeRequest(string Method, string? Operation, string? Key, string? Namespace, string? ApiVersion, CapturedBody Body);

internal sealed record ExchangeContext(string? RequestId, string? CorrelationId, string? PoolName, string? Algorithm);

internal sealed record ExchangeResponse(int Status, string? Code, CapturedBody Body);

internal sealed record ExchangeTiming(double TotalMs, double CryptoMs, double InjectedDelayMs, string Budget);

internal sealed record ExchangeFault(string Rule, string? Kind, string? Summary);

internal sealed record ExchangeClientCertificate(bool Present, string? CommonName);

internal sealed record ExchangeView(
    ExchangeIdentity Identity,
    ExchangeClientCertificate ClientCertificate,
    ExchangeRequest Request,
    ExchangeContext Context,
    ExchangeResponse Response,
    ExchangeTiming Timing,
    ExchangeFault? Faults);

internal sealed record ExchangePage(List<ExchangeView> Items, bool HasMore);

internal sealed record ConnectionEventView(string ConnectionId, string Kind, DateTimeOffset AtUtc, string? TlsProtocol, string? FailureReason, string? FailureDescription);

internal sealed record ConnectionList(List<ConnectionEventView> Events);

internal sealed record RevealRequest(string Field);

internal sealed record UploadCertificateBody(string CertificatePem, string PrivateKeyPem);

internal sealed record AuditEntryView(DateTimeOffset At, string User, string Action, string Target, string? Detail);

internal sealed record AuditPage(List<AuditEntryView> Entries, int Total, int Skip, int Take);

internal sealed record AntiforgeryTokenBody(string HeaderName, string Token);

/// <summary>Wire JSON of the console API: <c>snake_case</c>, enums as strings, nulls omitted, source generated.</summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    WriteIndented = false)]
[JsonSerializable(typeof(ApiError))]
[JsonSerializable(typeof(KeyView))]
[JsonSerializable(typeof(KeyList))]
[JsonSerializable(typeof(KeyDetail))]
[JsonSerializable(typeof(CreateKeyBody))]
[JsonSerializable(typeof(ImportKeyBody))]
[JsonSerializable(typeof(ExpiryBody))]
[JsonSerializable(typeof(DestroyKeyBody))]
[JsonSerializable(typeof(NamespaceView))]
[JsonSerializable(typeof(NamespaceList))]
[JsonSerializable(typeof(NamespaceBody))]
[JsonSerializable(typeof(DeleteNamespaceBody))]
[JsonSerializable(typeof(NamespaceDeleted))]
[JsonSerializable(typeof(TrustImportBody))]
[JsonSerializable(typeof(TrustPreview))]
[JsonSerializable(typeof(FaultRuleView))]
[JsonSerializable(typeof(FaultList))]
[JsonSerializable(typeof(FaultRuleBody))]
[JsonSerializable(typeof(FaultCleared))]
[JsonSerializable(typeof(ConsoleStatus))]
[JsonSerializable(typeof(AboutInfo))]
[JsonSerializable(typeof(ExchangePage))]
[JsonSerializable(typeof(ExchangeView))]
[JsonSerializable(typeof(ConnectionList))]
[JsonSerializable(typeof(RevealRequest))]
[JsonSerializable(typeof(UploadCertificateBody))]
[JsonSerializable(typeof(AuditPage))]
[JsonSerializable(typeof(AntiforgeryTokenBody))]
internal sealed partial class ConsoleApiJson : JsonSerializerContext
{
}
