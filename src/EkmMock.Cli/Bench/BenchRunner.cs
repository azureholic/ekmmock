using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using EkmMock.Cli.Commands;
using EkmMock.Cli.Ekm;

namespace EkmMock.Cli.Bench;

internal enum BenchOperation
{
    Info,
    Metadata,
    Wrapkey,
    Unwrapkey,
}

internal sealed class BenchSettings
{
    public required EkmClient Client { get; init; }

    public required BenchOperation Operation { get; init; }

    public string Key { get; init; } = string.Empty;

    public string? Algorithm { get; init; }

    public int Concurrency { get; init; } = 16;

    public TimeSpan Duration { get; init; } = TimeSpan.FromSeconds(60);

    public TimeSpan Warmup { get; init; } = TimeSpan.FromSeconds(5);

    public int DekSize { get; init; } = 32;

    /// <summary>Target request rate. Null is the closed-loop model (every worker sends the next request when the previous one is answered).</summary>
    public double? Rate { get; init; }

    public double BudgetMs { get; init; } = 250;
}

internal sealed record BenchResult(
    long Requests,
    long Errors,
    double MeasuredSeconds,
    LatencyHistogram Latency,
    Dictionary<string, long> StatusCounts,
    long OverBudget,
    List<SlowRequest> Slow);

/// <summary>
/// The load generator of <c>ekmmock test bench</c> (spec 14 test 25).
/// <para><b>Model.</b> <c>Concurrency</c> workers, each with its own kept-alive HTTP/1.1 connection (one TLS handshake per worker, none per request, like Managed HSM which reuses connections). By default
/// the loop is <b>closed</b>: a worker sends its next request as soon as the previous answer arrived, so the offered load adapts to the server. A closed loop under-reports tail latency when the server
/// stalls (coordinated omission: requests that would have been sent during the stall are never made). With <c>--rate</c> the loop is <b>open</b>: requests are scheduled at a fixed rate and the latency of
/// each is measured from its <em>scheduled</em> start, so a stall shows up in the percentiles (it is counted for the requests queued behind it).</para>
/// <para>Timing uses <see cref="Stopwatch.GetTimestamp"/>. The warm-up samples (JIT, connection set-up, the server's pools) are discarded. The DEK is synthetic, generated once, and never logged.</para>
/// </summary>
internal static class BenchRunner
{
    public static async Task<BenchResult> RunAsync(BenchSettings settings, CancellationToken ct)
    {
        var request = await PrepareAsync(settings, ct).ConfigureAwait(false);

        // One request before the load: a TLS or trust problem surfaces here as one clear connection error instead of a run of identical failures. A non-2xx answer is not an error here (a bench may target a 404 on purpose).
        await settings.Client.SendAsync(HttpMethod.Post, request.PathAndQuery, request.Json, correlationId: "bench", cancellationToken: ct).ConfigureAwait(false);
        var workers = Math.Max(1, settings.Concurrency);
        var perWorker = new WorkerState[workers];
        for (var i = 0; i < workers; i++)
        {
            perWorker[i] = new WorkerState();
        }

        var frequency = (double)Stopwatch.Frequency;
        var start = Stopwatch.GetTimestamp();
        var measureStart = start + (long)(settings.Warmup.TotalSeconds * frequency);
        var end = measureStart + (long)(settings.Duration.TotalSeconds * frequency);
        var interval = settings.Rate is > 0 ? workers / settings.Rate.Value : 0;

        var tasks = new Task[workers];
        using (interval > 0 ? FineTimer.Begin() : null)
        {
            for (var i = 0; i < workers; i++)
            {
                var index = i;
                tasks[i] = Task.Run(() => WorkerAsync(settings, request, perWorker[index], index, start, measureStart, end, interval, frequency, ct), CancellationToken.None);
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        var all = new LatencyHistogram();
        var status = new Dictionary<string, long>(StringComparer.Ordinal);
        long errors = 0, over = 0, count = 0;
        var slow = new List<SlowRequest>();
        var lastEnd = measureStart;
        foreach (var worker in perWorker)
        {
            all.Add(worker.Latency);
            slow.AddRange(worker.Slow);
            errors += worker.Errors;
            over += worker.OverBudget;
            count += worker.Requests;
            lastEnd = Math.Max(lastEnd, worker.LastEnd);
            foreach (var pair in worker.Status)
            {
                status[pair.Key] = status.GetValueOrDefault(pair.Key) + pair.Value;
            }
        }

        var seconds = Math.Max((lastEnd - measureStart) / frequency, 0.001);
        slow.Sort(static (a, b) => a.OffsetSeconds.CompareTo(b.OffsetSeconds));
        return new BenchResult(count, errors, seconds, all, status, over, slow);
    }

    /// <summary>Open loop only: asks Windows for a 1 ms timer resolution while the run lasts. At the default 15.6 ms granularity Task.Delay wakes workers late and the lateness would be reported as server latency (the latency is measured from the scheduled start).</summary>
    private sealed class FineTimer : IDisposable
    {
        private FineTimer()
        {
        }

        public static FineTimer? Begin()
        {
            if (!OperatingSystem.IsWindows())
            {
                return null;
            }

            try
            {
                return TimeBeginPeriod(1) == 0 ? new FineTimer() : null;
            }
            catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
            {
                return null;
            }
        }

        public void Dispose() => _ = TimeEndPeriod(1);

        [System.Runtime.InteropServices.DllImport("winmm.dll", EntryPoint = "timeBeginPeriod")]
        private static extern uint TimeBeginPeriod(uint milliseconds);

        [System.Runtime.InteropServices.DllImport("winmm.dll", EntryPoint = "timeEndPeriod")]
        private static extern uint TimeEndPeriod(uint milliseconds);
    }

    private sealed class WorkerState
    {
        public LatencyHistogram Latency { get; } = new();

        /// <summary>The first slow requests (over <see cref="SlowThresholdMs"/>) with the time since the start of the measurement: tells a periodic stall from random noise.</summary>
        public List<SlowRequest> Slow { get; } = [];

        public Dictionary<string, long> Status { get; } = new(StringComparer.Ordinal);

        public long Requests { get; set; }

        public long Errors { get; set; }

        public long OverBudget { get; set; }

        public long LastEnd { get; set; }
    }

    private sealed record PreparedRequest(string PathAndQuery, string Json);

    private static async Task<PreparedRequest> PrepareAsync(BenchSettings settings, CancellationToken ct)
    {
        var client = settings.Client;
        var correlation = $"bench-{Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant()}";
        string json;
        switch (settings.Operation)
        {
            case BenchOperation.Info:
                return new PreparedRequest(client.Path(null, "info"), client.BodyJson(correlation));
            case BenchOperation.Metadata:
                return new PreparedRequest(client.Path(settings.Key, "metadata"), client.BodyJson(correlation));
            case BenchOperation.Wrapkey:
            {
                var dek = RandomNumberGenerator.GetBytes(settings.DekSize);
                json = client.BodyJson(correlation, settings.Algorithm, EkmClient.Base64Url(dek));
                CryptographicOperations.ZeroMemory(dek);
                return new PreparedRequest(client.Path(settings.Key, "wrapkey"), json);
            }

            default:
            {
                // Wrap once: the unwrap benchmark sends a value the server really produced (a valid ciphertext, so the full unwrap path runs).
                var dek = RandomNumberGenerator.GetBytes(settings.DekSize);
                var wrap = await client.WrapAsync(settings.Key, settings.Algorithm!, dek, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(dek);
                if (wrap.Status != 200 || wrap.GetString("value") is not { } wrapped)
                {
                    throw CliException.Failure($"The set-up wrap request for the unwrap benchmark was not answered with 200: {wrap.Status} {(wrap.Status >= 400 ? wrap.Text : string.Empty)}");
                }

                return new PreparedRequest(client.Path(settings.Key, "unwrapkey"), client.BodyJson(correlation, settings.Algorithm, wrapped));
            }
        }
    }

    private static async Task WorkerAsync(BenchSettings settings, PreparedRequest prepared, WorkerState state, int index, long start, long measureStart, long end, double intervalSeconds, double frequency, CancellationToken ct)
    {
        var http = settings.Client;
        var open = intervalSeconds > 0;
        var intervalTicks = (long)(intervalSeconds * frequency);

        // Open loop: worker i starts i/n of an interval after the start so that the workers do not fire in lockstep.
        var scheduled = start + (open ? (long)(intervalTicks * ((double)index / Math.Max(1, settings.Concurrency))) : 0);
        var budgetTicks = (long)(settings.BudgetMs / 1000d * frequency);

        while (!ct.IsCancellationRequested)
        {
            long begin;
            if (open)
            {
                var wait = scheduled - Stopwatch.GetTimestamp();
                if (wait > 0)
                {
                    await Task.Delay(TimeSpan.FromSeconds(wait / frequency), ct).ConfigureAwait(false);

                    // The timer may fire a fraction of a millisecond early: never send before the scheduled start (that would understate the latency).
                    while (Stopwatch.GetTimestamp() < scheduled)
                    {
                        await Task.Yield();
                    }
                }

                begin = scheduled;
                scheduled += intervalTicks;
            }
            else
            {
                begin = Stopwatch.GetTimestamp();
            }

            if (begin >= end)
            {
                break;
            }

            string key;
            try
            {
                var reply = await http.SendAsync(HttpMethod.Post, prepared.PathAndQuery, prepared.Json, correlationId: "bench", cancellationToken: ct).ConfigureAwait(false);
                key = ((int)reply.Status).ToString(System.Globalization.CultureInfo.InvariantCulture);
                Record(state, key, reply.Status is >= 200 and < 300, begin, measureStart, budgetTicks, frequency);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException or TaskCanceledException)
            {
                key = "exception:" + exception.GetType().Name;
                Record(state, key, success: false, begin, measureStart, budgetTicks, frequency);
            }
        }
    }

    public const double SlowThresholdMs = 100;
    private const int MaxSlowPerWorker = 64;

    private static void Record(WorkerState state, string status, bool success, long begin, long measureStart, long budgetTicks, double frequency)
    {
        var finish = Stopwatch.GetTimestamp();
        if (begin < measureStart)
        {
            return; // warm-up
        }

        state.Requests++;
        state.LastEnd = finish;
        state.Status[status] = state.Status.GetValueOrDefault(status) + 1;
        if (!success)
        {
            state.Errors++;
        }

        var ticks = finish - begin;
        if (ticks > budgetTicks)
        {
            state.OverBudget++;
        }

        state.Latency.Record((long)(ticks * 1_000_000d / frequency));
        if (ticks * 1000d / frequency > SlowThresholdMs && state.Slow.Count < MaxSlowPerWorker)
        {
            state.Slow.Add(new SlowRequest(Math.Round((begin - measureStart) / frequency, 3), Math.Round(ticks * 1000d / frequency, 1)));
        }
    }

    // ---- statistics ----

    public static readonly double[] BucketBoundsMs = [1, 2, 5, 10, 25, 50, 100, 150, 200, 250, 500, 1000];

    public static List<HistogramBucket> Histogram(LatencyHistogram latency)
    {
        var counts = latency.CountsPerBound(BucketBoundsMs);
        var buckets = new List<HistogramBucket>();
        for (var i = 0; i < BucketBoundsMs.Length; i++)
        {
            buckets.Add(new HistogramBucket($"<= {BucketBoundsMs[i].ToString("0.###", System.Globalization.CultureInfo.InvariantCulture)} ms", counts[i]));
        }

        buckets.Add(new HistogramBucket("> 1000 ms", counts[^1]));
        return buckets;
    }
    public static BenchOutcome ToOutcome(BenchSettings settings, BenchResult result, string target, DateTimeOffset startedAt, double? maxP99, double? maxOverPct, bool failOnErrors)
    {
        var histogram = result.Latency;
        var latency = new LatencySummary(
            Round(histogram.MinMs),
            Round(histogram.MeanMs),
            Round(histogram.PercentileMs(0.50)),
            Round(histogram.PercentileMs(0.90)),
            Round(histogram.PercentileMs(0.99)),
            Round(histogram.PercentileMs(0.999)),
            Round(histogram.MaxMs));
        var overPercent = result.Requests == 0 ? 0 : 100d * result.OverBudget / result.Requests;
        var failures = new List<string>();
        if (result.Requests == 0)
        {
            failures.Add("no request was completed in the measured period");
        }

        if (maxP99 is { } p99Limit && latency.P99 > p99Limit)
        {
            failures.Add($"p99 {latency.P99:0.###} ms is above --assert-p99-ms {p99Limit:0.###}");
        }

        if (maxOverPct is { } overLimit && overPercent > overLimit)
        {
            failures.Add($"{overPercent:0.###} % of the requests took longer than {settings.BudgetMs:0} ms, above --max-over-250-pct {overLimit:0.###}");
        }

        if (failOnErrors && result.Errors > 0)
        {
            failures.Add($"{result.Errors} request(s) failed (--assert-no-errors)");
        }

        var model = settings.Rate is { } rate
            ? $"open loop at {rate.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture)} requests/s: latency is measured from the scheduled start (corrects coordinated omission)"
            : "closed loop: each worker sends its next request when the previous one is answered (does not correct coordinated omission)";
        return new BenchOutcome(
            "ekmmock test bench",
            CliVersion.Current,
            startedAt,
            target,
            settings.Operation.ToString().ToLowerInvariant(),
            settings.Key,
            settings.Algorithm,
            settings.Concurrency,
            Math.Round(settings.Duration.TotalSeconds, 3),
            Math.Round(settings.Warmup.TotalSeconds, 3),
            settings.Rate,
            model,
            result.Requests,
            result.Errors,
            Math.Round(result.Requests / result.MeasuredSeconds, 1),
            latency,
            new OverBudget(settings.BudgetMs, result.OverBudget, Math.Round(overPercent, 4)),
            result.StatusCounts.OrderBy(static p => p.Key, StringComparer.Ordinal).ToDictionary(static p => p.Key, static p => p.Value),
            Histogram(result.Latency),
            failures,
            result.Slow,
            new BenchEnvironment(RuntimeInformation.OSDescription, RuntimeInformation.OSArchitecture.ToString(), RuntimeInformation.FrameworkDescription, Environment.ProcessorCount));
    }

    private static double Round(double value) => Math.Round(value, 3);

    public static void PrintSummary(TextWriter writer, BenchOutcome outcome)
    {
        writer.WriteLine($"Target:       {outcome.Target}   op {outcome.Operation}{(outcome.Key.Length > 0 ? " key " + outcome.Key : string.Empty)}{(outcome.Algorithm is null ? string.Empty : " alg " + outcome.Algorithm)}");
        writer.WriteLine($"Load:         {outcome.Concurrency} workers, {outcome.DurationSeconds:0.#} s measured after {outcome.WarmupSeconds:0.#} s warm-up");
        writer.WriteLine($"Model:        {outcome.Model}");
        writer.WriteLine($"Requests:     {outcome.Requests} ({outcome.Errors} errors), {outcome.ThroughputRps:0.#} requests/s");
        writer.WriteLine($"Latency (ms): min {outcome.LatencyMs.Min:0.###}  mean {outcome.LatencyMs.Mean:0.###}  p50 {outcome.LatencyMs.P50:0.###}  p90 {outcome.LatencyMs.P90:0.###}  p99 {outcome.LatencyMs.P99:0.###}  p99.9 {outcome.LatencyMs.P999:0.###}  max {outcome.LatencyMs.Max:0.###}");
        writer.WriteLine($"Over {outcome.OverBudget.ThresholdMs:0} ms:  {outcome.OverBudget.Count} requests = {outcome.OverBudget.Percent:0.####} %");
        writer.WriteLine("Status:       " + string.Join(", ", outcome.StatusCounts.Select(static p => $"{p.Key}: {p.Value}")));
        writer.WriteLine();
        writer.WriteLine("Histogram:");
        var max = Math.Max(1, outcome.Histogram.Max(static b => b.Count));
        foreach (var bucket in outcome.Histogram)
        {
            writer.WriteLine($"  {bucket.Le,-12} {bucket.Count,10}  {new string('#', (int)(40d * bucket.Count / max))}");
        }

        if (outcome.SlowRequests.Count > 0)
        {
            writer.WriteLine();
            writer.WriteLine($"Slow requests (over {SlowThresholdMs:0} ms; seconds since the start of the measurement, latency): " + string.Join(", ", outcome.SlowRequests.Take(12).Select(static s => $"{s.OffsetSeconds:0.0}s {s.LatencyMs:0}ms")) + (outcome.SlowRequests.Count > 12 ? $" ... ({outcome.SlowRequests.Count} recorded)" : string.Empty));
        }

        if (outcome.ThresholdFailures.Count > 0)
        {
            writer.WriteLine();
            foreach (var failure in outcome.ThresholdFailures)
            {
                writer.WriteLine("THRESHOLD FAILED: " + failure);
            }
        }
    }
}
