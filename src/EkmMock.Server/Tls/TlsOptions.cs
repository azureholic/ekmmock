namespace EkmMock.Server.Tls;

/// <summary>
/// The <c>Tls</c> configuration section (spec 5.3, 16). Paths point at a PEM certificate chain (leaf first, then intermediates)
/// and its PKCS#8/PKCS#1/SEC1 PEM private key. The private key is read from the file; it is never a configuration value.
/// </summary>
internal sealed class TlsOptions
{
    public const string SectionName = "Tls";

    /// <summary>The public FQDN the certificate must cover (spec 5.3). Shown in the console; the SAN is what clients actually check.</summary>
    public string? ServerName { get; set; }

    public string? CertFile { get; set; }

    public string? KeyFile { get; set; }

    /// <summary>Fallback poll for changed files (spec 5.3: 60 s). File system events normally trigger a reload much sooner.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Wait after the last file event before reloading, so a cert and key written one after the other are read together.</summary>
    public TimeSpan Debounce { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>The console warns when the server certificate expires within this many days (spec 5.3).</summary>
    public int ExpiryWarningDays { get; set; } = 30;

    /// <summary>How long a client may take to finish the TLS handshake.</summary>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>A replaced certificate is disposed only after this grace, because handshakes that started earlier may still use it.</summary>
    public TimeSpan RetiredCertificateGrace { get; set; } = TimeSpan.FromMinutes(2);

    public bool HasFiles => !string.IsNullOrWhiteSpace(CertFile) && !string.IsNullOrWhiteSpace(KeyFile);

    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(CertFile) != string.IsNullOrWhiteSpace(KeyFile))
        {
            return "Tls:CertFile and Tls:KeyFile must be set together";
        }

        if (PollInterval < TimeSpan.FromMilliseconds(50) || Debounce < TimeSpan.Zero || ExpiryWarningDays < 0 || HandshakeTimeout <= TimeSpan.Zero)
        {
            return "Tls poll interval, debounce, expiry warning days and handshake timeout must be positive";
        }

        return null;
    }
}
