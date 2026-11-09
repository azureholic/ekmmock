using System.Globalization;

namespace EkmMock.Server.Tests;

/// <summary>One sample line of a Prometheus text exposition.</summary>
internal sealed record PromSample(string Name, IReadOnlyDictionary<string, string> Labels, double Value)
{
    public string Label(string name) => Labels.TryGetValue(name, out var value) ? value : string.Empty;

    public bool Has(params (string Name, string Value)[] labels) => labels.All(l => Labels.TryGetValue(l.Name, out var v) && v == l.Value);
}

/// <summary>A strict parser of the Prometheus text format 0.0.4 (what <c>/metrics</c> serves): it fails the test on any line it does not understand.</summary>
internal sealed class PromText
{
    private PromText(IReadOnlyList<PromSample> samples, IReadOnlyDictionary<string, string> types, IReadOnlyDictionary<string, string> help)
    {
        Samples = samples;
        Types = types;
        Help = help;
    }

    public IReadOnlyList<PromSample> Samples { get; }

    public IReadOnlyDictionary<string, string> Types { get; }

    public IReadOnlyDictionary<string, string> Help { get; }

    public static PromText Parse(string text)
    {
        var samples = new List<PromSample>();
        var types = new Dictionary<string, string>();
        var help = new Dictionary<string, string>();
        text.EndsWith('\n').ShouldBeTrue("the exposition format requires a final newline");
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.StartsWith("# HELP ", StringComparison.Ordinal))
            {
                var rest = line["# HELP ".Length..];
                var space = rest.IndexOf(' ', StringComparison.Ordinal);
                help[rest[..space]] = rest[(space + 1)..];
                continue;
            }

            if (line.StartsWith("# TYPE ", StringComparison.Ordinal))
            {
                var parts = line["# TYPE ".Length..].Split(' ');
                parts.Length.ShouldBe(2, line);
                types[parts[0]] = parts[1];
                continue;
            }

            line.StartsWith('#').ShouldBeFalse($"unexpected comment line: {line}");
            samples.Add(ParseSample(line));
        }

        return new PromText(samples, types, help);
    }

    private static PromSample ParseSample(string line)
    {
        var labels = new Dictionary<string, string>();
        string name;
        string rest;
        var brace = line.IndexOf('{', StringComparison.Ordinal);
        if (brace < 0)
        {
            var space = line.IndexOf(' ', StringComparison.Ordinal);
            name = line[..space];
            rest = line[(space + 1)..];
        }
        else
        {
            name = line[..brace];
            var i = brace + 1;
            while (line[i] != '}')
            {
                var eq = line.IndexOf('=', i);
                var labelName = line[i..eq];
                line[eq + 1].ShouldBe('"', line);
                var value = new System.Text.StringBuilder();
                i = eq + 2;
                while (line[i] != '"')
                {
                    if (line[i] == '\\')
                    {
                        i++;
                        value.Append(line[i] switch { 'n' => '\n', var c => c });
                    }
                    else
                    {
                        value.Append(line[i]);
                    }

                    i++;
                }

                labels[labelName] = value.ToString();
                i++;
                if (line[i] == ',')
                {
                    i++;
                }
            }

            rest = line[(i + 2)..];
        }

        var number = rest.Trim();
        var parsed = number switch
        {
            "+Inf" => double.PositiveInfinity,
            "-Inf" => double.NegativeInfinity,
            "NaN" => double.NaN,
            _ => double.Parse(number, CultureInfo.InvariantCulture),
        };
        return new PromSample(name, labels, parsed);
    }

    public IEnumerable<PromSample> Named(string name) => Samples.Where(s => s.Name == name);

    /// <summary>The value of the one sample with this name and these labels; fails when there is none or more than one.</summary>
    public double Value(string name, params (string Name, string Value)[] labels)
        => Samples.Where(s => s.Name == name && s.Has(labels) && s.Labels.Count == labels.Length).Select(static s => s.Value).DefaultIfEmpty(double.NaN).Single();

    public bool Has(string name, params (string Name, string Value)[] labels) => Samples.Any(s => s.Name == name && s.Has(labels) && s.Labels.Count == labels.Length);

    /// <summary>The upper bounds, in order, of a histogram's finite buckets.</summary>
    public IReadOnlyList<double> Bounds(string histogram, params (string Name, string Value)[] labels)
        => [.. Samples.Where(s => s.Name == histogram + "_bucket" && s.Has(labels) && s.Label("le") != "+Inf").Select(static s => double.Parse(s.Label("le"), CultureInfo.InvariantCulture))];
}
