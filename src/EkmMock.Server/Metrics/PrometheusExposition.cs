using System.Globalization;
using System.Text;

namespace EkmMock.Server.Metrics;

/// <summary>
/// Renders <see cref="EkmMetrics"/> in the Prometheus text exposition format 0.0.4 (spec 9: <c>/metrics</c> on the console port). It is a plain text writer over the in-process
/// aggregates: no client library, no push, no background work. Series are written in a stable order (name, then labels) so that two scrapes of an idle process are identical.
/// </summary>
internal static class PrometheusExposition
{
    public const string ContentType = "text/plain; version=0.0.4; charset=utf-8";

    public static string Render(EkmMetrics metrics, long inFlight)
    {
        var text = new StringBuilder(4096);

        Header(text, EkmMetrics.RequestsName, "counter", "EKM requests by operation, HTTP status and namespace.");
        foreach (var (op, status, ns, count) in metrics.RequestCounts().OrderBy(static r => r.Op, StringComparer.Ordinal).ThenBy(static r => r.Status, StringComparer.Ordinal).ThenBy(static r => r.Namespace, StringComparer.Ordinal))
        {
            Sample(text, EkmMetrics.RequestsName, [("op", op), ("status", status), ("namespace", ns)], count);
        }

        Header(text, EkmMetrics.RequestDurationName, "histogram", "Server time of EKM requests in seconds.");
        foreach (var (op, histogram) in metrics.RequestDurations().OrderBy(static r => r.Op, StringComparer.Ordinal))
        {
            Histogram(text, EkmMetrics.RequestDurationName, [("op", op)], histogram);
        }

        Header(text, EkmMetrics.CryptoDurationName, "histogram", "Time spent in the crypto engine in seconds, by operation and algorithm.");
        foreach (var (op, alg, histogram) in metrics.CryptoDurations().OrderBy(static r => r.Op, StringComparer.Ordinal).ThenBy(static r => r.Alg, StringComparer.Ordinal))
        {
            Histogram(text, EkmMetrics.CryptoDurationName, [("op", op), ("alg", alg)], histogram);
        }

        Header(text, EkmMetrics.BudgetExceededName, "counter", "Requests that missed the internal deadline.");
        foreach (var (op, count) in metrics.BudgetExceeded().OrderBy(static r => r.Op, StringComparer.Ordinal))
        {
            Sample(text, EkmMetrics.BudgetExceededName, [("op", op)], count);
        }

        Header(text, EkmMetrics.HandshakeFailuresName, "counter", "TLS handshakes on the EKM endpoint that did not complete, by reason.");
        foreach (var (reason, count) in metrics.HandshakeFailureCounts.OrderBy(static r => r.Key, StringComparer.Ordinal))
        {
            Sample(text, EkmMetrics.HandshakeFailuresName, [("reason", reason)], count);
        }

        Header(text, EkmMetrics.InspectorDroppedName, "counter", "Inspector capture records dropped because the bounded capture queue was full.");
        Sample(text, EkmMetrics.InspectorDroppedName, [], metrics.InspectorDroppedTotal);

        Header(text, EkmMetrics.InFlightName, "gauge", "EKM requests currently holding a concurrency slot.");
        Sample(text, EkmMetrics.InFlightName, [], inFlight);

        return text.ToString();
    }

    private static void Header(StringBuilder text, string name, string type, string help)
        => text.Append("# HELP ").Append(name).Append(' ').Append(help).Append('\n').Append("# TYPE ").Append(name).Append(' ').Append(type).Append('\n');

    private static void Histogram(StringBuilder text, string name, (string Name, string Value)[] labels, HistogramSnapshot histogram)
    {
        for (var i = 0; i < histogram.Bounds.Count; i++)
        {
            Sample(text, name + "_bucket", [.. labels, ("le", FormatBound(histogram.Bounds[i]))], histogram.Cumulative[i]);
        }

        Sample(text, name + "_bucket", [.. labels, ("le", "+Inf")], histogram.Cumulative[^1]);
        Sample(text, name + "_sum", labels, histogram.SumSeconds);
        Sample(text, name + "_count", labels, histogram.Count);
    }

    private static void Sample(StringBuilder text, string name, (string Name, string Value)[] labels, long value)
        => Line(text, name, labels, value.ToString(CultureInfo.InvariantCulture));

    private static void Sample(StringBuilder text, string name, (string Name, string Value)[] labels, double value)
        => Line(text, name, labels, value.ToString("0.#########", CultureInfo.InvariantCulture));

    private static void Line(StringBuilder text, string name, (string Name, string Value)[] labels, string value)
    {
        text.Append(name);
        if (labels.Length > 0)
        {
            text.Append('{');
            for (var i = 0; i < labels.Length; i++)
            {
                if (i > 0)
                {
                    text.Append(',');
                }

                text.Append(labels[i].Name).Append("=\"");
                Escape(text, labels[i].Value);
                text.Append('"');
            }

            text.Append('}');
        }

        text.Append(' ').Append(value).Append('\n');
    }

    private static string FormatBound(double bound) => bound.ToString("0.#########", CultureInfo.InvariantCulture);

    // Label values are bounded sets of our own strings (see EkmMetrics), but the format still demands the three escapes.
    private static void Escape(StringBuilder text, string value)
    {
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\':
                    text.Append("\\\\");
                    break;
                case '"':
                    text.Append("\\\"");
                    break;
                case '\n':
                    text.Append("\\n");
                    break;
                default:
                    text.Append(c);
                    break;
            }
        }
    }
}
