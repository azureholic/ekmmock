using System.Text;

namespace EkmMock.Cli.Infrastructure;

/// <summary>Plain-text tables for the default (human) output. Columns are padded to the widest cell; nothing is truncated, so a copied value is always complete.</summary>
internal static class TableWriter
{
    public static void Write(TextWriter writer, IReadOnlyList<string> headers, IEnumerable<IReadOnlyList<string>> rows)
    {
        var all = rows.ToList();
        var widths = new int[headers.Count];
        for (var i = 0; i < headers.Count; i++)
        {
            widths[i] = headers[i].Length;
        }

        foreach (var row in all)
        {
            for (var i = 0; i < headers.Count && i < row.Count; i++)
            {
                widths[i] = Math.Max(widths[i], row[i].Length);
            }
        }

        WriteRow(writer, headers, widths);
        WriteRow(writer, widths.Select(static w => new string('-', w)).ToList(), widths);
        foreach (var row in all)
        {
            WriteRow(writer, row, widths);
        }
    }

    private static void WriteRow(TextWriter writer, IReadOnlyList<string> cells, int[] widths)
    {
        var line = new StringBuilder();
        for (var i = 0; i < widths.Length; i++)
        {
            var cell = i < cells.Count ? cells[i] : string.Empty;
            line.Append(i == widths.Length - 1 ? cell : cell.PadRight(widths[i] + 2));
        }

        writer.WriteLine(line.ToString().TrimEnd());
    }

    /// <summary>Key/value block, for the detail of one thing.</summary>
    public static void WriteProperties(TextWriter writer, IEnumerable<(string Name, string? Value)> properties)
    {
        var list = properties.Where(static p => p.Value is not null).ToList();
        var width = list.Count == 0 ? 0 : list.Max(static p => p.Name.Length);
        foreach (var (name, value) in list)
        {
            writer.WriteLine($"{name.PadRight(width)}  {value}");
        }
    }
}
