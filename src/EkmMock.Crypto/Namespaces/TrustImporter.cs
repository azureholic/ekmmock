using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace EkmMock.Crypto;

/// <summary>Public facts about a trusted CA certificate, for the "review before saving" step of the trust import.</summary>
public sealed record CertificateSummary(string Subject, string Issuer, DateTimeOffset NotBefore, DateTimeOffset NotAfter, string ThumbprintSha256);

public sealed record TrustImportResult(ClientTrust Trust, IReadOnlyList<CertificateSummary> Certificates);

/// <summary>
/// Parses client trust input (parsing only, no UI): the JSON printed by <c>az keyvault ekm-connection certificate show</c>
/// (<c>caCertificates</c> as base64 DER and <c>subjectCommonName</c>) or PEM certificate text. Nothing is persisted here.
/// </summary>
public static class TrustImporter
{
    public static TrustImportResult FromAzureCliJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
        }
        catch (JsonException)
        {
            throw Invalid("The trust input is not valid JSON");
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw Invalid("The trust JSON must be an object");
            }

            var commonNames = new List<string>();
            var certificates = new List<byte[]>();

            foreach (var property in document.RootElement.EnumerateObject())
            {
                var name = property.Name.Replace("_", string.Empty, StringComparison.Ordinal);
                if (name.Equals("subjectCommonName", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("subjectCommonNames", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var value in Strings(property.Value))
                    {
                        commonNames.Add(value);
                    }
                }
                else if (name.Equals("caCertificates", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var value in Strings(property.Value))
                    {
                        certificates.AddRange(ParseCertificateText(value));
                    }
                }
            }

            if (certificates.Count == 0)
            {
                throw Invalid("No CA certificates found (expected a 'caCertificates' array of base64 DER)");
            }

            return Build(commonNames, certificates);
        }
    }

    /// <summary>PEM carries no common name, so the caller supplies the allowed subject CNs.</summary>
    public static TrustImportResult FromPem(string pem, IEnumerable<string>? subjectCommonNames = null)
    {
        ArgumentNullException.ThrowIfNull(pem);
        var certificates = ParseCertificateText(pem);
        if (certificates.Count == 0)
        {
            throw Invalid("No PEM certificates found");
        }

        return Build([.. subjectCommonNames ?? []], certificates);
    }

    private static TrustImportResult Build(List<string> commonNames, List<byte[]> certificatesDer)
    {
        var summaries = new List<CertificateSummary>();
        foreach (var der in certificatesDer)
        {
            try
            {
                using var cert = X509CertificateLoader.LoadCertificate(der);
                summaries.Add(new CertificateSummary(
                    cert.Subject,
                    cert.Issuer,
                    new DateTimeOffset(cert.NotBefore.ToUniversalTime(), TimeSpan.Zero),
                    new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero),
                    cert.GetCertHashString(HashAlgorithmName.SHA256)));
            }
            catch (CryptographicException)
            {
                throw Invalid("A CA certificate could not be parsed");
            }
        }

        var trust = new ClientTrust
        {
            SubjectCommonNames = commonNames,
            CaCertificatesDerBase64 = [.. certificatesDer.Select(static der => Convert.ToBase64String(der))],
        };

        // Run the same validation the store applies, so the preview never shows something that cannot be saved.
        var validated = NamespaceStore.Validate(new NamespaceDefinition { Name = EkmNames.DefaultNamespace, ClientTrust = trust }).ClientTrust;
        return new TrustImportResult(validated, summaries);
    }

    // Accepts one base64 DER string, or text containing one or more PEM CERTIFICATE blocks.
    private static List<byte[]> ParseCertificateText(string text)
    {
        var result = new List<byte[]>();
        var span = text.AsSpan();
        var foundPem = false;
        while (PemEncoding.TryFind(span, out var fields))
        {
            foundPem = true;
            if (span[fields.Label].SequenceEqual("CERTIFICATE"))
            {
                try
                {
                    result.Add(Convert.FromBase64String(span[fields.Base64Data].ToString()));
                }
                catch (FormatException)
                {
                    throw Invalid("A PEM certificate is not valid base64");
                }
            }

            span = span[fields.Location.End..];
        }

        if (!foundPem)
        {
            try
            {
                result.Add(Convert.FromBase64String(text.Trim()));
            }
            catch (FormatException)
            {
                throw Invalid("A CA certificate is neither PEM nor base64 DER");
            }
        }

        return result;
    }

    private static IEnumerable<string> Strings(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                yield return element.GetString()!;
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.String)
                    {
                        throw Invalid("Expected a string value in the trust JSON");
                    }

                    yield return item.GetString()!;
                }

                break;
            case JsonValueKind.Null:
                break;
            default:
                throw Invalid("Expected a string or an array of strings in the trust JSON");
        }
    }

    private static NamespaceException Invalid(string message) => new(NamespaceErrorKind.InvalidTrust, message);
}
