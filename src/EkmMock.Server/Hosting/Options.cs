using EkmMock.Crypto;

namespace EkmMock.Server.Hosting;

/// <summary>Strongly typed configuration (spec 16 appsettings.json). Secrets such as the master key are NEVER read from configuration.</summary>
internal sealed class ProxyInfoOptions
{
    public const string SectionName = "ProxyInfo";

    /// <summary>Reported by <c>info</c>. Learn's example shows "1.0"; the supported request version is fixed (open question 1).</summary>
    public string ApiVersion { get; set; } = EkmApi.SupportedApiVersion;

    public string ProxyVendor { get; set; } = "Remco Test";

    public string ProxyName { get; set; } = "EkmMock v0.2.0";

    public string EkmVendor { get; set; } = "EkmMock";

    public string EkmProduct { get; set; } = "EkmMock Software HSM v0.2.0";

    public bool IsValid()
        => !string.IsNullOrWhiteSpace(ApiVersion)
        && !string.IsNullOrWhiteSpace(ProxyVendor)
        && !string.IsNullOrWhiteSpace(ProxyName)
        && !string.IsNullOrWhiteSpace(EkmVendor)
        && !string.IsNullOrWhiteSpace(EkmProduct);
}

internal sealed class DataOptions
{
    public const string SectionName = "Data";

    /// <summary>Folder for <c>keystore.json</c> and <c>namespaces.json</c>.</summary>
    public string Path { get; set; } = "/data";
}

internal sealed class SelfTestSettings
{
    public const string SectionName = "SelfTest";

    /// <summary>Refuse to start when a startup self-test fails (spec 6.5).</summary>
    public bool Strict { get; set; }
}

internal sealed class DevOptions
{
    public const string SectionName = "Dev";

    /// <summary>
    /// Dev mode (the <c>--dev</c> command line flag sets it): a missing master key becomes a throw-away one and, without a configured
    /// <c>Tls:CertFile</c>, a throw-away test certificate for <c>localhost</c> is generated. It never relaxes TLS or authorization:
    /// there is no plain-HTTP mode. The console shows a red banner for this later.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>Creates <c>aes-key-1</c> and <c>rsa-key-1</c> in <c>_default</c> when missing (spec 11.2). Off by default.</summary>
    public bool SeedSampleKeys { get; set; }
}

/// <summary>One entry of <c>SeedNamespaces</c>; mapped to <see cref="NamespaceDefinition"/> (used only when namespaces.json does not exist yet).</summary>
internal sealed class SeedNamespaceOptions
{
    public const string SectionName = "SeedNamespaces";

    public string Name { get; set; } = string.Empty;

    public string Prefix { get; set; } = string.Empty;

    public SeedClientTrustOptions ClientTrust { get; set; } = new();

    public NamespaceDefinition ToDefinition() => new()
    {
        Name = Name,
        Prefix = Prefix,
        ClientTrust = new ClientTrust
        {
            SubjectCommonNames = [.. ClientTrust.SubjectCommonNames],
            CaCertificatesDerBase64 = [.. ClientTrust.CaCertificatesDerBase64],
        },
    };
}

internal sealed class SeedClientTrustOptions
{
    public List<string> SubjectCommonNames { get; set; } = [];

    public List<string> CaCertificatesDerBase64 { get; set; } = [];
}

/// <summary>Protocol constants shared by routing and validation.</summary>
internal static class EkmApi
{
    /// <summary>The only <c>api-version</c> accepted on requests (spec 4.2).</summary>
    public const string SupportedApiVersion = "0.1-preview";

    public const string ApiVersionQueryParameter = "api-version";
}
