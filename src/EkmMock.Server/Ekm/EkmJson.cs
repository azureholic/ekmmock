using System.Text.Json.Serialization;

namespace EkmMock.Server.Ekm;

/// <summary>Response of <c>info</c> (spec 4.6).</summary>
internal sealed record ProxyInfoResponse(
    string ApiVersion,
    string ProxyVendor,
    string ProxyName,
    string EkmVendor,
    string EkmProduct);

/// <summary>Response of <c>metadata</c> (spec 4.7). <c>n</c> and <c>e</c> are only present for RSA keys.</summary>
internal sealed record KeyMetadataResponse(
    string KeyType,
    int KeySize,
    string[] KeyOps,
    string? N,
    string? E);

/// <summary>
/// Source-generated JSON for everything that is not secret. Property names are snake_case (spec 3). Request bodies are
/// parsed by <see cref="EkmRequestBody"/> instead and the <c>value</c> responses are written by hand, because a DEK must
/// never pass through an immutable <see cref="string"/> that cannot be zeroed.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false)]
[JsonSerializable(typeof(ProxyError))]
[JsonSerializable(typeof(ProxyInfoResponse))]
[JsonSerializable(typeof(KeyMetadataResponse))]
internal sealed partial class EkmJsonContext : JsonSerializerContext
{
}
