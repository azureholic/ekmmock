using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace EkmMock.Server.Tls;

/// <summary>
/// Reads the subject common name of a certificate from its parsed distinguished name (ASN.1), never from the formatted
/// <c>Subject</c> string, so commas, plus signs, quotes and backslashes inside a value cannot change what is compared.
/// </summary>
internal static class CommonNameReader
{
    private const string CommonNameOid = "2.5.4.3";

    /// <summary>
    /// Returns true with the CN when the subject has exactly one <c>CN</c> attribute in a single-valued RDN.
    /// A subject with no CN, several CN attributes, or a CN inside a multi-valued RDN is ambiguous and yields false:
    /// EkmMock never has to guess which of several names the operator meant to allow.
    /// </summary>
    public static bool TryGetSingleCommonName(X500DistinguishedName subject, out string? commonName)
    {
        commonName = null;
        string? found = null;
        try
        {
            foreach (var rdn in subject.EnumerateRelativeDistinguishedNames())
            {
                if (rdn.HasMultipleElements)
                {
                    // Cannot be inspected safely through the public API; a CN in a multi-valued RDN is rejected.
                    return false;
                }

                if (rdn.GetSingleElementType().Value != CommonNameOid)
                {
                    continue;
                }

                if (found is not null)
                {
                    return false;
                }

                found = rdn.GetSingleElementValue();
            }
        }
        catch (CryptographicException)
        {
            return false;
        }

        if (string.IsNullOrEmpty(found))
        {
            return false;
        }

        commonName = found;
        return true;
    }
}
