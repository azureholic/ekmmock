using System.Globalization;
using EkmMock.Server.Inspector;

namespace EkmMock.Server.WebConsole;

/// <summary>How the pages show values (spec 8.5): short ids, times, status and budget classes with a word as well as a colour (never colour alone).</summary>
internal static class ConsoleDisplay
{
    /// <summary>The number of characters of <c>correlation_id</c> shown in the table (the copy button copies the whole id).</summary>
    public const int ShortIdLength = 8;

    public static string ShortId(string? id)
        => string.IsNullOrEmpty(id) ? "-" : id.Length <= ShortIdLength ? id : id[..ShortIdLength] + "…";

    /// <summary>UTC time of day with milliseconds; the full timestamp is in the tooltip and the detail view.</summary>
    public static string Time(DateTimeOffset at) => at.UtcDateTime.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);

    public static string FullTime(DateTimeOffset at) => at.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture) + " UTC";

    public static string Milliseconds(double ms)
        => ms >= 100 ? ms.ToString("0", CultureInfo.InvariantCulture) + " ms" : ms >= 10 ? ms.ToString("0.0", CultureInfo.InvariantCulture) + " ms" : ms.ToString("0.00", CultureInfo.InvariantCulture) + " ms";

    public static string StatusCss(int status) => status switch
    {
        >= 200 and < 300 => "status-ok",
        >= 400 and < 500 => "status-client",
        >= 500 => "status-server",
        _ => "status-other",
    };

    /// <summary>A word for the status class, so the colour is never the only signal.</summary>
    public static string StatusWord(int status) => status switch
    {
        >= 200 and < 300 => "OK",
        >= 400 and < 500 => "Client error",
        >= 500 => "Server error",
        _ => "Other",
    };

    public static string StatusText(int status, string? code)
        => string.IsNullOrEmpty(code) ? $"{status.ToString(CultureInfo.InvariantCulture)} {StatusWord(status)}" : $"{status.ToString(CultureInfo.InvariantCulture)} {code}";

    public static string BudgetCss(BudgetStatus budget) => budget switch
    {
        BudgetStatus.Red => "budget-red",
        BudgetStatus.Amber => "budget-amber",
        _ => "budget-green",
    };

    public static string BudgetWord(BudgetStatus budget) => budget switch
    {
        BudgetStatus.Red => "over budget",
        BudgetStatus.Amber => "slow",
        _ => "fast",
    };

    public static string Bytes(long size) => size switch
    {
        < 1024 => $"{size.ToString(CultureInfo.InvariantCulture)} B",
        < 1024 * 1024 => $"{(size / 1024d).ToString("0.0", CultureInfo.InvariantCulture)} KiB",
        _ => $"{(size / 1024d / 1024d).ToString("0.0", CultureInfo.InvariantCulture)} MiB",
    };

    public static string Duration(double milliseconds)
    {
        var span = TimeSpan.FromMilliseconds(milliseconds);
        return span.TotalSeconds < 1 ? $"{milliseconds.ToString("0", CultureInfo.InvariantCulture)} ms"
            : span.TotalMinutes < 1 ? $"{span.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture)} s"
            : span.TotalHours < 1 ? $"{span.Minutes}m {span.Seconds}s"
            : $"{(int)span.TotalHours}h {span.Minutes}m";
    }

    public static string Percent(double share) => (share * 100).ToString("0.0", CultureInfo.InvariantCulture) + " %";

    /// <summary>What the connection event row says, in words (spec 8.2).</summary>
    public static string ConnectionSummary(ConnectionEventRecord e) => e.Kind switch
    {
        "opened" => "Connection opened",
        "handshake_succeeded" => $"TLS handshake ok ({e.TlsProtocol ?? "?"}, {e.CipherSuite ?? "?"}){(e.ClientCertificate is { } cert ? $", client {cert.Subject}" : ", no client certificate")}",
        "handshake_failed" => $"TLS handshake failed: {e.FailureDescription ?? e.FailureReason ?? "unknown reason"}",
        "closed" => $"Connection closed after {Duration(e.DurationMs ?? 0)}, {(e.RequestCount ?? 0).ToString(CultureInfo.InvariantCulture)} request(s)",
        _ => e.Kind,
    };

    /// <summary>The ready-made masked-value text of the inspector, kept exactly as captured: <c>32 bytes · fp 3f9a1c07b2e4</c>.</summary>
    public static string MaskedLabel(MaskedField field) => field.Display;
}
