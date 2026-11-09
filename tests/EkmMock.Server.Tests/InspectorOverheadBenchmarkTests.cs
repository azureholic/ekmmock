using System.Buffers.Text;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using EkmMock.Server.Inspector;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>Runs alone: the overhead benchmark measures microseconds and must not share the CPU with other test classes.</summary>
[CollectionDefinition("InspectorBenchmark", DisableParallelization = true)]
public sealed class InspectorBenchmarkCollection;

/// <summary>
/// Spec 8.3 and 14 test 24: the inspector adds less than 1 ms at p99 to a request.
/// <para>
/// <b>Method.</b> The real EKM pipeline (Exchange, Route, Auth, Dispatcher, the real software HSM backend, real AES key wrap) runs on <see cref="DefaultHttpContext"/> objects with
/// in-memory bodies, once with <see cref="InspectorCaptureMiddleware"/> in front and once without, with the real consumer (ring buffer, aggregator, feed, queue) running on its own thread.
/// Two numbers are measured over 20 000 requests after a 10 000 request warm-up (JIT, tiering, pools):
/// </para>
/// <list type="number">
/// <item><b>Capture overhead (asserted):</b> the time the capture itself used per request, measured inside the middleware with <see cref="Stopwatch"/> timestamps around exactly
/// its own work (wrapping the streams, copying 16 KiB-bounded bodies, masking, building the record, the non-blocking enqueue, releasing the buffers; not the time the pipeline took and
/// not the I/O wait for a rejected request's body). This is the cost the capture adds, free of any difference of two noisy distributions.</item>
/// <item><b>End-to-end A/B (asserted as a cross-check):</b> the same requests through both pipelines, interleaved A B / B A so that drift and ordering cancel; the difference of the p99 of both
/// distributions must also stay below 1 ms.</item>
/// </list>
/// Mix: wrap, unwrap, info, metadata (AES-256 key, A256KWP, 32-byte DEKs). RSA is left out on purpose: its millisecond-scale crypto would add noise to the comparison, not to the capture.
/// Run twice: default (masked, nothing raw retained) and with reveal allowed (extra copies of the raw bodies are retained).
/// Numbers are written to the test output and to <c>inspector-benchmark.txt</c> next to the test assembly.
/// </summary>
[Collection("InspectorBenchmark")]
[Trait("Category", "Benchmark")]
public sealed class InspectorOverheadBenchmarkTests
{
    private const int Warmup = 10_000;
    private const int Iterations = 20_000;
    private const double BudgetMicroseconds = 1000;
    private const string Alg = "A256KWP";

    private sealed class TickRecorder : ICaptureOverheadObserver
    {
        private readonly long[] _ticks = new long[Iterations + 16];
        private int _count;
        private bool _recording;

        public void Start() => _recording = true;

        public int Count => _count;

        public void Observe(long overheadTicks)
        {
            if (_recording && _count < _ticks.Length)
            {
                _ticks[_count++] = overheadTicks;
            }
        }

        public double[] Microseconds() => [.. _ticks.Take(_count).Select(static t => t * 1_000_000.0 / Stopwatch.Frequency)];
    }

    private readonly record struct Stats(double P50, double P90, double P99, double Max, double Mean)
    {
        public static Stats Of(double[] microseconds)
        {
            var sorted = microseconds.Order().ToArray();
            return new Stats(
                Percentiles.NearestRank(sorted, 50),
                Percentiles.NearestRank(sorted, 90),
                Percentiles.NearestRank(sorted, 99),
                sorted[^1],
                sorted.Average());
        }

        public override string ToString()
            => string.Create(CultureInfo.InvariantCulture, $"p50={P50:F1} us  p90={P90:F1} us  p99={P99:F1} us  max={Max:F1} us  mean={Mean:F1} us");
    }

    private static RequestDelegate BuildPipeline(IServiceProvider services, bool capture)
    {
        var app = new ApplicationBuilder(services);
        if (capture)
        {
            app.UseMiddleware<InspectorCaptureMiddleware>();
        }

        app.UseMiddleware<EkmExchangeMiddleware>();
        app.UseMiddleware<EkmRouteMiddleware>();
        app.UseMiddleware<EkmAuthMiddleware>();
        app.Run(static context => context.RequestServices.GetRequiredService<EkmDispatcher>().InvokeAsync(context));
        return app.Build();
    }

    private sealed record RequestKind(string Path, byte[] Body);

    private static DefaultHttpContext NewContext(IServiceProvider services, RequestKind kind)
    {
        var context = new DefaultHttpContext { RequestServices = services };
        var request = context.Request;
        request.Method = "POST";
        request.Path = kind.Path;
        request.QueryString = new QueryString("?api-version=0.1-preview");
        request.ContentType = "application/json";
        request.ContentLength = kind.Body.Length;
        request.Body = new MemoryStream(kind.Body, writable: false);
        context.Response.Body = new MemoryStream(256);
        return context;
    }

    private async Task RunAsync(bool reveal, ITestOutputHelper output)
    {
        using var factory = InspectorHarness.CreateFactory(reveal: reveal);
        _ = factory.Server; // starts the host: the real consumer (BackgroundService) is running from here on
        var services = factory.Services;
        var dek = Fx.Random(32);
        var key = new KeyRef("_default", "aes-key-1");
        var wrapped = factory.Backend.Wrap(key, WrapAlgorithm.A256KWP, dek);

        RequestKind[] kinds =
        [
            new("/aes-key-1/wrapkey", Encoding.UTF8.GetBytes(EkmClient.WrapBody(Alg, Base64Url.EncodeToString(dek)))),
            new("/aes-key-1/unwrapkey", Encoding.UTF8.GetBytes(EkmClient.WrapBody(Alg, Base64Url.EncodeToString(wrapped)))),
            new("/info", Encoding.UTF8.GetBytes(EkmClient.Context)),
            new("/aes-key-1/metadata", Encoding.UTF8.GetBytes(EkmClient.Context)),
        ];
        var with = BuildPipeline(services, capture: true);
        var without = BuildPipeline(services, capture: false);
        var recorder = new TickRecorder();
        var diagnostics = services.GetRequiredService<CaptureDiagnostics>();
        diagnostics.Observer = recorder;

        async Task<double> TimedAsync(RequestDelegate pipeline, RequestKind kind)
        {
            var context = NewContext(services, kind);
            var started = Stopwatch.GetTimestamp();
            await pipeline(context);
            var elapsed = Stopwatch.GetTimestamp() - started;
            context.Response.StatusCode.ShouldBe(200);
            return elapsed * 1_000_000.0 / Stopwatch.Frequency;
        }

        // Warm-up: both pipelines, every request kind.
        for (var i = 0; i < Warmup; i++)
        {
            await TimedAsync(with, kinds[i % kinds.Length]);
            await TimedAsync(without, kinds[i % kinds.Length]);
        }

        await Wait.UntilAsync(() => services.GetRequiredService<InspectorService>().Count() > 0);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var droppedBefore = services.GetRequiredService<InspectorService>().Status().DroppedCaptures;
        recorder.Start();

        var withTimes = new double[Iterations];
        var withoutTimes = new double[Iterations];
        for (var i = 0; i < Iterations; i++)
        {
            var kind = kinds[i % kinds.Length];
            if (i % 2 == 0)
            {
                withTimes[i] = await TimedAsync(with, kind);
                withoutTimes[i] = await TimedAsync(without, kind);
            }
            else
            {
                withoutTimes[i] = await TimedAsync(without, kind);
                withTimes[i] = await TimedAsync(with, kind);
            }
        }

        var captureOnly = Stats.Of(recorder.Microseconds());
        var withStats = Stats.Of(withTimes);
        var withoutStats = Stats.Of(withoutTimes);
        var dropped = services.GetRequiredService<InspectorService>().Status().DroppedCaptures - droppedBefore;
        diagnostics.Observer = null;

        var report = new StringBuilder()
            .AppendLine(CultureInfo.InvariantCulture, $"[inspector-benchmark] reveal={reveal}  requests={Iterations} (after {Warmup} warm-up)  runtime={Environment.Version}  cores={Environment.ProcessorCount}  os={Environment.OSVersion.Platform}")
            .AppendLine(CultureInfo.InvariantCulture, $"  capture overhead (inside the middleware): {captureOnly}")
            .AppendLine(CultureInfo.InvariantCulture, $"  pipeline WITH capture    (end to end)    : {withStats}")
            .AppendLine(CultureInfo.InvariantCulture, $"  pipeline WITHOUT capture (end to end)    : {withoutStats}")
            .AppendLine(CultureInfo.InvariantCulture, $"  end-to-end difference: p50 {withStats.P50 - withoutStats.P50:F1} us, p90 {withStats.P90 - withoutStats.P90:F1} us, p99 {withStats.P99 - withoutStats.P99:F1} us, mean {withStats.Mean - withoutStats.Mean:F1} us")
            .AppendLine(CultureInfo.InvariantCulture, $"  captures dropped during the measurement: {dropped}")
            .ToString();
        output.WriteLine(report);
        File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "inspector-benchmark.txt"), report + Environment.NewLine);

        recorder.Count.ShouldBe(Iterations);
        dropped.ShouldBe(0, "the consumer kept up, so every record was queued");
        captureOnly.P99.ShouldBeLessThan(BudgetMicroseconds, $"capture overhead p99 must stay under 1 ms; measured {captureOnly}");
        (withStats.P99 - withoutStats.P99).ShouldBeLessThan(BudgetMicroseconds, $"end-to-end p99 difference must stay under 1 ms; with {withStats}, without {withoutStats}");
        (withStats.P50 - withoutStats.P50).ShouldBeLessThan(BudgetMicroseconds);
    }

    private readonly ITestOutputHelper _output;

    public InspectorOverheadBenchmarkTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public Task CaptureOverhead_IsUnder1msAtP99_InDefaultMaskedMode() => RunAsync(reveal: false, _output);

    [Fact]
    public Task CaptureOverhead_IsUnder1msAtP99_WhenRevealRetainsTheRawBodies() => RunAsync(reveal: true, _output);
}
