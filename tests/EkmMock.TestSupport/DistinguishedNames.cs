using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace EkmMock.TestSupport;

/// <summary>Builds distinguished names that the string parsers of the different operating systems would read differently.</summary>
public static class DistinguishedNames
{
    public const string CommonNameOid = "2.5.4.3";
    public const string OrganizationalUnitOid = "2.5.4.11";

    /// <summary>
    /// One RDN holding several attributes (<c>CN=a+OU=b</c> in RFC 4514 text). Encoded as ASN.1 directly, because the managed X.500 text
    /// parser used on Linux does not treat an unquoted plus sign as a multi-valued separator while the Windows one does.
    /// </summary>
    public static X500DistinguishedName MultiValuedRdn(params (string Oid, string Value)[] attributes)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        using (writer.PushSetOf())
        {
            foreach (var (oid, value) in attributes)
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(oid);
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
                }
            }
        }

        return new X500DistinguishedName(writer.Encode());
    }
}
