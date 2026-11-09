using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EkmMock.Cli.Infrastructure;

/// <summary>
/// A client certificate with its private key, loaded from PEM files (<c>--client-cert</c>, <c>--client-key</c>). The certificate file may hold the chain (leaf first); the extra certificates are sent
/// to the server as intermediates, never trusted. On Windows the key lives in a key container that SChannel can use and that is deleted when this object is disposed: dispose it.
/// </summary>
internal sealed class ClientIdentity : IDisposable
{
    private readonly X509Certificate2 _leaf;
    private readonly X509Certificate2Collection _extra;

    private ClientIdentity(X509Certificate2 leaf, X509Certificate2Collection extra)
    {
        _leaf = leaf;
        _extra = extra;
    }

    public X509Certificate2 Certificate => _leaf;

    public string Subject => _leaf.Subject;

    public static ClientIdentity Load(string certificateFile, string keyFile, string certOption = "--client-cert", string keyOption = "--client-key")
    {
        if (!File.Exists(certificateFile))
        {
            throw CliException.Usage($"The file given to {certOption} does not exist: {certificateFile}");
        }

        if (!File.Exists(keyFile))
        {
            throw CliException.Usage($"The file given to {keyOption} does not exist: {keyFile}");
        }

        try
        {
            var all = new X509Certificate2Collection();
            all.ImportFromPemFile(certificateFile);
            using var fromPem = X509Certificate2.CreateFromPemFile(certificateFile, keyFile);

            // SChannel needs a key it can use (not an ephemeral PEM import): round trip through PFX bytes, like the test PKI does.
            var pfx = fromPem.Export(X509ContentType.Pfx);
            X509Certificate2 leaf;
            try
            {
                leaf = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.Exportable);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pfx);
            }

            var extra = new X509Certificate2Collection();
            for (var i = 1; i < all.Count; i++)
            {
                extra.Add(all[i]);
            }

            return new ClientIdentity(leaf, extra);
        }
        catch (CryptographicException)
        {
            // The message of a crypto exception can name the file contents; keep it generic.
            throw CliException.Usage($"The certificate ({certificateFile}) and the private key ({keyFile}) could not be loaded: both must be PEM files and the key must belong to the first certificate.");
        }
    }

    public void ApplyTo(SslClientAuthenticationOptions options)
    {
        if (_extra.Count > 0)
        {
            options.ClientCertificateContext = SslStreamCertificateContext.Create(_leaf, _extra, offline: true);
        }
        else
        {
            options.ClientCertificates = [_leaf];
        }
    }

    public void Dispose()
    {
        _leaf.Dispose();
        foreach (var certificate in _extra)
        {
            certificate.Dispose();
        }
    }
}
