using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace EkmMock.Server.Tests;

/// <summary>
/// Checks of the documentation that has to stay true: every relative markdown link and heading anchor resolves, the RESULTS verification matrix names only tests that exist, and
/// RESULTS never contains a "measured" Azure value (those cells stay <c>NOT YET MEASURED</c> until someone ran the end-to-end test against a real Managed HSM).
/// </summary>
public sealed partial class DocumentationTests
{
    private static readonly string[] MarkdownFiles =
    [
        "README.md",
        "docs/RUNBOOK.md",
        "docs/RESULTS.md",
        "docs/DECISIONS.md",
        "docs/OPEN-QUESTIONS.md",
        "docs/benchmarks/README.md",
        "deploy/azure/README.md",
    ];

    [GeneratedRegex(@"\[(?<text>[^\]\n]*)\]\((?<target>[^)\s]+)(?:\s+""[^""]*"")?\)")]
    private static partial Regex MarkdownLink();

    [GeneratedRegex(@"^(?<hashes>#{1,6})\s+(?<title>.+?)\s*#*\s*$")]
    private static partial Regex Heading();

    private static string[] LinesOutsideCodeFences(string text)
    {
        var result = new List<string>();
        var inFence = false;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.TrimStart().StartsWith("```", StringComparison.Ordinal))
            {
                inFence = !inFence;
                continue;
            }

            if (!inFence)
            {
                result.Add(line);
            }
        }

        return [.. result];
    }

    /// <summary>The anchor GitHub generates for a heading: lower case, punctuation dropped, spaces to hyphens, duplicates numbered.</summary>
    internal static HashSet<string> Anchors(string markdown)
    {
        var anchors = new HashSet<string>(StringComparer.Ordinal);
        var seen = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var line in LinesOutsideCodeFences(markdown))
        {
            var match = Heading().Match(line);
            if (!match.Success)
            {
                continue;
            }

            var title = Regex.Replace(match.Groups["title"].Value, @"\[([^\]]*)\]\([^)]*\)", "$1").Replace("`", string.Empty, StringComparison.Ordinal).Replace("*", string.Empty, StringComparison.Ordinal);
            var slug = new StringBuilder();
            foreach (var c in title.ToLowerInvariant())
            {
                if (char.IsLetterOrDigit(c) || c is '-' or '_')
                {
                    slug.Append(c);
                }
                else if (c == ' ')
                {
                    slug.Append('-');
                }
            }

            var text = slug.ToString();
            var count = seen.GetValueOrDefault(text);
            seen[text] = count + 1;
            anchors.Add(count == 0 ? text : $"{text}-{count.ToString(CultureInfo.InvariantCulture)}");
        }

        return anchors;
    }

    [Fact]
    public void EveryRelativeMarkdownLink_AndAnchor_InTheDocumentation_Resolves()
    {
        var problems = new List<string>();
        foreach (var file in MarkdownFiles)
        {
            var text = RepositoryFiles.Read(file);
            var directory = Path.GetDirectoryName(RepositoryFiles.FullPath(file))!;
            var ownAnchors = Anchors(text);

            foreach (var line in LinesOutsideCodeFences(text))
            {
                // Inline code may show link syntax; remove it before looking for links.
                var scan = Regex.Replace(line, "`[^`]*`", string.Empty);
                foreach (Match link in MarkdownLink().Matches(scan))
                {
                    var target = link.Groups["target"].Value;
                    if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var hash = target.IndexOf('#', StringComparison.Ordinal);
                    var path = hash >= 0 ? target[..hash] : target;
                    var anchor = hash >= 0 ? target[(hash + 1)..] : string.Empty;

                    if (path.Length == 0)
                    {
                        if (!ownAnchors.Contains(anchor))
                        {
                            problems.Add($"{file}: the anchor #{anchor} does not exist in the same file");
                        }

                        continue;
                    }

                    var full = Path.GetFullPath(Path.Combine(directory, Uri.UnescapeDataString(path).Replace('/', Path.DirectorySeparatorChar)));
                    if (!File.Exists(full) && !Directory.Exists(full))
                    {
                        problems.Add($"{file}: the link target {target} does not exist");
                    }
                    else if (anchor.Length > 0 && full.EndsWith(".md", StringComparison.OrdinalIgnoreCase) && !Anchors(File.ReadAllText(full)).Contains(anchor))
                    {
                        problems.Add($"{file}: the anchor #{anchor} does not exist in {path}");
                    }
                }
            }
        }

        problems.ShouldBeEmpty(string.Join('\n', problems));
    }

    // ---- RESULTS.md ----

    private static string[] Section(string markdown, string headingStart)
    {
        var lines = markdown.Split('\n').Select(static l => l.TrimEnd('\r')).ToList();
        var start = lines.FindIndex(l => l.StartsWith(headingStart, StringComparison.Ordinal));
        start.ShouldBeGreaterThanOrEqualTo(0, $"RESULTS.md has no section starting with '{headingStart}'");
        var end = lines.FindIndex(start + 1, static l => l.StartsWith("## ", StringComparison.Ordinal));
        return [.. lines[start..(end < 0 ? lines.Count : end)]];
    }

    [GeneratedRegex(@"`(?<class>[A-Z]\w*Tests)\.(?<method>\w+)`")]
    private static partial Regex TestReference();

    [Fact]
    public void TheResultsVerificationMatrix_NamesOnlyTestsThatExist()
    {
        var matrix = Section(RepositoryFiles.Read("docs/RESULTS.md"), "## 2. Spec 14 verification matrix");
        var references = matrix.SelectMany(static l => TestReference().Matches(l).Select(static m => (Class: m.Groups["class"].Value, Method: m.Groups["method"].Value))).Distinct().ToList();
        references.Count.ShouldBeGreaterThan(40, "the matrix must reference the proving tests by name");

        var testFiles = Directory.EnumerateFiles(RepositoryFiles.FullPath("tests"), "*.cs", SearchOption.AllDirectories).Where(static f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)).ToList();
        var texts = testFiles.ToDictionary(static f => f, static f => File.ReadAllText(f));
        var missing = new List<string>();
        foreach (var (className, method) in references)
        {
            var declaring = texts.Where(kv => Regex.IsMatch(kv.Value, $@"\bclass {className}\b")).Select(static kv => kv.Value).ToList();
            if (declaring.Count == 0)
            {
                missing.Add($"class {className} (for {className}.{method})");
            }
            else if (!declaring.Any(text => Regex.IsMatch(text, $@"\b{method}\s*\(")))
            {
                missing.Add($"{className}.{method}");
            }
        }

        missing.ShouldBeEmpty($"RESULTS.md names tests that do not exist: {string.Join(", ", missing)}");
    }

    [Fact]
    public void TheResultsVerificationMatrix_HasAllTwentySevenTests_WithAnAllowedStatus()
    {
        var matrix = Section(RepositoryFiles.Read("docs/RESULTS.md"), "## 2. Spec 14 verification matrix");
        string[] statuses = ["automated-passing", "conformance-only", "skipped-explained", "not-verifiable-locally"];
        var rows = matrix.Where(static l => Regex.IsMatch(l, @"^\|\s*\d+\s*\|")).ToList();

        rows.Count.ShouldBe(27);
        rows.Select(static r => int.Parse(r.Split('|')[1].Trim(), CultureInfo.InvariantCulture)).ShouldBe(Enumerable.Range(1, 27));
        foreach (var row in rows)
        {
            var cells = row.Split('|').Select(static c => c.Trim()).ToList();
            statuses.Any(s => cells.Any(c => c.StartsWith($"`{s}`", StringComparison.Ordinal))).ShouldBeTrue($"no allowed status in: {row}");
        }
    }

    [Fact]
    public void TheResultsAzureSection_NeverClaimsAMeasuredValue()
    {
        var azure = Section(RepositoryFiles.Read("docs/RESULTS.md"), "## 3. Azure end-to-end");
        var tables = 0;
        var measuredColumn = -1;
        foreach (var line in azure.Where(static l => l.StartsWith('|')))
        {
            var cells = line.Trim().Trim('|').Split('|').Select(static c => c.Trim()).ToList();
            if (cells.Any(static c => string.Equals(c, "Measured", StringComparison.Ordinal)))
            {
                measuredColumn = cells.FindIndex(static c => string.Equals(c, "Measured", StringComparison.Ordinal));
                tables++;
                continue;
            }

            if (cells.All(static c => c.Length == 0 || c.All(static ch => ch is '-' or ':')))
            {
                continue;
            }

            if (measuredColumn >= 0 && cells.Count > measuredColumn)
            {
                cells[measuredColumn].ShouldBe("NOT YET MEASURED", $"an Azure result must stay NOT YET MEASURED until measured: {line}");
            }
        }

        tables.ShouldBeGreaterThanOrEqualTo(6, "one table per scenario of spec 15");
        string.Join('\n', azure).ShouldContain("pending");
    }
}
