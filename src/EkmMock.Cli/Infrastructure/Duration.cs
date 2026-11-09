using System.Globalization;

namespace EkmMock.Cli.Infrastructure;

/// <summary>Parses durations such as <c>60s</c>, <c>500ms</c>, <c>2m</c>, <c>1h</c> and plain seconds (<c>30</c>).</summary>
internal static class Duration
{
    public static bool TryParse(string? text, out TimeSpan value)
    {
        value = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        var unit = "s";
        var number = trimmed;
        foreach (var suffix in new[] { "ms", "s", "m", "h" })
        {
            if (trimmed.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                unit = suffix;
                number = trimmed[..^suffix.Length];
                break;
            }
        }

        if (!double.TryParse(number, NumberStyles.Float, CultureInfo.InvariantCulture, out var amount) || amount < 0 || double.IsNaN(amount) || double.IsInfinity(amount))
        {
            return false;
        }

        var milliseconds = unit.ToLowerInvariant() switch
        {
            "ms" => amount,
            "m" => amount * 60_000,
            "h" => amount * 3_600_000,
            _ => amount * 1_000,
        };
        if (milliseconds > TimeSpan.FromDays(7).TotalMilliseconds)
        {
            return false;
        }

        value = TimeSpan.FromMilliseconds(milliseconds);
        return true;
    }

    public static string Format(TimeSpan value) => value.TotalSeconds >= 1 ? $"{value.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)}s" : $"{value.TotalMilliseconds.ToString("0.###", CultureInfo.InvariantCulture)}ms";
}
