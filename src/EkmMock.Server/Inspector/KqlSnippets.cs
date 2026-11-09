using System.Text;

namespace EkmMock.Server.Inspector;

/// <summary>
/// The ready-made KQL for the Exchange detail page (spec 8.5): find the Managed HSM side of an exchange in the diagnostic logs.
/// <para>
/// Schema, from Microsoft Learn ("Logging and monitoring for Managed HSM external key management", "Troubleshoot Managed HSM external key management", read 9 November 2026):
/// table <c>AzureDiagnostics</c>, <c>ResourceProvider == "MICROSOFT.KEYVAULT"</c>, <c>OperationName</c> one of <c>EkmGetProxyInfo</c>, <c>EkmGetKeyMetadata</c>, <c>EkmWrapKey</c>,
/// <c>EkmUnwrapKey</c>; the external key identifier is inside <c>requestUri_s</c>; <c>ResultType</c>, <c>ResultDescription</c> (contains the HTTP status). Learn does <b>not</b> say which
/// column carries the proxy request context's <c>correlation_id</c> (it lists <c>correlationId_g</c> in one article and <c>CorrelationId</c> in another, and recommends matching by
/// external key identifier and a ±1 s timestamp window). The snippet therefore uses <c>column_ifexists</c> for both candidate columns (a missing column is not an error) and also offers
/// the documented fallback. See OPEN-QUESTIONS.md.
/// </para>
/// </summary>
internal static class KqlSnippets
{
    private const string Projection = "| project TimeGenerated, Resource, OperationName, requestUri_s, ResultType, ResultDescription";

    /// <summary>The Managed HSM <c>OperationName</c> of an EKM operation, or null when the operation is unknown.</summary>
    public static string? OperationNameFor(string? operation) => operation switch
    {
        "info" => "EkmGetProxyInfo",
        "metadata" => "EkmGetKeyMetadata",
        "wrapkey" => "EkmWrapKey",
        "unwrapkey" => "EkmUnwrapKey",
        _ => null,
    };

    /// <summary>Matches on the request context's <c>correlation_id</c>. Null when there is no correlation id.</summary>
    public static string? ByCorrelationId(string? correlationId, string? operation = null)
    {
        if (string.IsNullOrWhiteSpace(correlationId))
        {
            return null;
        }

        var literal = Literal(correlationId);
        return string.Join(
            '\n',
            "// Managed HSM audit records for this EKM call (correlation_id from the request context)",
            "AzureDiagnostics",
            "| where ResourceProvider == \"MICROSOFT.KEYVAULT\"",
            OperationFilter(operation),
            $"| where column_ifexists(\"correlationId_g\", \"\") == {literal} or column_ifexists(\"CorrelationId\", \"\") == {literal}",
            Projection,
            "| order by TimeGenerated asc");
    }

    /// <summary>The documented fallback: the external key identifier in <c>requestUri_s</c> within ±1 second of the exchange.</summary>
    public static string? ByKeyAndTime(string? key, string? operation, DateTimeOffset receivedAtUtc)
    {
        if (string.IsNullOrWhiteSpace(key) && OperationNameFor(operation) is null)
        {
            return null;
        }

        var at = receivedAtUtc.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);
        var lines = new List<string>
        {
            "// Fallback: same external key identifier within 1 second of the exchange (Learn: match by key identifier and timestamp, +/- 1 s clock skew)",
            $"let exchangeTime = datetime({at});",
            "AzureDiagnostics",
            "| where ResourceProvider == \"MICROSOFT.KEYVAULT\"",
            OperationFilter(operation),
            "| where TimeGenerated between ((exchangeTime - 1s) .. (exchangeTime + 1s))",
        };
        if (!string.IsNullOrWhiteSpace(key))
        {
            lines.Add($"| where requestUri_s has {Literal(key)}");
        }

        lines.Add(Projection);
        lines.Add("| order by TimeGenerated asc");
        return string.Join('\n', lines);
    }

    /// <summary>Both queries for an exchange; either can be null (no correlation id, no key and unknown operation).</summary>
    public static KqlSnippet For(ExchangeRecord record)
        => new(
            ByCorrelationId(record.Context.CorrelationId, record.Request.Operation),
            ByKeyAndTime(record.Request.Key, record.Request.Operation, record.Identity.ReceivedAtUtc));

    /// <summary>A KQL string literal: quotes and backslashes escaped, control characters dropped. Client supplied text (a correlation id) cannot break out of it.</summary>
    public static string Literal(string value)
    {
        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');
        foreach (var c in value)
        {
            if (c == '\\' || c == '"')
            {
                builder.Append('\\').Append(c);
            }
            else if (!char.IsControl(c))
            {
                builder.Append(c);
            }
        }

        return builder.Append('"').ToString();
    }

    private static string OperationFilter(string? operation)
        => OperationNameFor(operation) is { } name
            ? $"| where OperationName == \"{name}\""
            : "| where OperationName in (\"EkmGetProxyInfo\", \"EkmGetKeyMetadata\", \"EkmWrapKey\", \"EkmUnwrapKey\")";
}

internal sealed record KqlSnippet(string? ByCorrelationId, string? ByKeyAndTime)
{
    /// <summary>The query to show first: by correlation id when there is one.</summary>
    public string? Primary => ByCorrelationId ?? ByKeyAndTime;
}
