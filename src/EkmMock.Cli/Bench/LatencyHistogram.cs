using System.Numerics;

namespace EkmMock.Cli.Bench;

/// <summary>
/// A log-linear latency histogram in microseconds (the idea of HdrHistogram, 128 sub-buckets per power of two: every value is stored with at most 0.8 % error). Recording is one array increment: no per-sample
/// memory, no allocation, so the load generator itself does not create the garbage-collection pauses that would otherwise show up as latency (storing every sample in growing lists did: the arrays landed
/// on the large object heap and caused full collections that stalled all workers for 100 to 300 ms). Minimum, maximum, count and sum are exact; percentiles are the upper edge of the bucket they fall in.
/// One instance per worker, merged at the end; an instance is not thread safe.
/// </summary>
internal sealed class LatencyHistogram
{
    private const int SubBucketBits = 8;
    private const int HalfBuckets = 1 << (SubBucketBits - 1); // 128: the sub-bucket range [128, 256) is reused for every power of two
    private const int Buckets = 1 << SubBucketBits; // 256: exact below 256 microseconds
    private const int MaxExponent = 40;
    private const long MaxValue = (1L << (MaxExponent + SubBucketBits)) - 1;

    private readonly long[] _counts = new long[(MaxExponent + 1) * HalfBuckets + Buckets];
    private long _total;
    private long _sum;
    private long _min = long.MaxValue;
    private long _max;

    public long Count => _total;

    public double MinMs => _total == 0 ? 0 : _min / 1000d;

    public double MaxMs => _max / 1000d;

    public double MeanMs => _total == 0 ? 0 : _sum / (double)_total / 1000d;

    public void Record(long microseconds)
    {
        // Clamp to the representable range (2^47 microseconds, about 4.5 years): nothing a request can take.
        microseconds = Math.Clamp(microseconds, 0, MaxValue);

        _counts[IndexOf(microseconds)]++;
        _total++;
        _sum += microseconds;
        if (microseconds < _min)
        {
            _min = microseconds;
        }

        if (microseconds > _max)
        {
            _max = microseconds;
        }
    }

    public void Add(LatencyHistogram other)
    {
        for (var i = 0; i < _counts.Length; i++)
        {
            _counts[i] += other._counts[i];
        }

        _total += other._total;
        _sum += other._sum;
        _min = Math.Min(_min, other._min);
        _max = Math.Max(_max, other._max);
    }

    /// <summary>The latency (ms) below which <paramref name="fraction"/> of the samples fall: nearest rank, reported as the upper edge of the bucket, never above the exact maximum.</summary>
    public double PercentileMs(double fraction)
    {
        if (_total == 0)
        {
            return 0;
        }

        var rank = Math.Clamp((long)Math.Ceiling(fraction * _total), 1, _total);
        long seen = 0;
        for (var i = 0; i < _counts.Length; i++)
        {
            seen += _counts[i];
            if (seen >= rank)
            {
                return Math.Min(UpperEdge(i), _max) / 1000d;
            }
        }

        return _max / 1000d;
    }

    /// <summary>How many samples were at or below each bound (milliseconds), by the bucket's lower edge, plus the rest.</summary>
    public long[] CountsPerBound(IReadOnlyList<double> boundsMs)
    {
        var result = new long[boundsMs.Count + 1];
        for (var i = 0; i < _counts.Length; i++)
        {
            if (_counts[i] == 0)
            {
                continue;
            }

            var lowerMs = LowerEdge(i) / 1000d;
            var slot = 0;
            while (slot < boundsMs.Count && lowerMs > boundsMs[slot])
            {
                slot++;
            }

            result[slot] += _counts[i];
        }

        return result;
    }

    internal static int IndexOf(long value)
    {
        if (value < Buckets)
        {
            return (int)value;
        }

        var exponent = 63 - BitOperations.LeadingZeroCount((ulong)value) - (SubBucketBits - 1); // shift so that value >> exponent is in [128, 256)
        exponent = Math.Min(exponent, MaxExponent);
        var sub = (int)(value >> exponent);
        return (exponent * HalfBuckets) + sub;
    }

    private static long LowerEdge(int index)
    {
        if (index < Buckets)
        {
            return index;
        }

        var exponent = (index - Buckets) / HalfBuckets + 1;
        var sub = index - (exponent * HalfBuckets);
        return (long)sub << exponent;
    }

    private static long UpperEdge(int index)
    {
        if (index < Buckets)
        {
            return index;
        }

        var exponent = (index - Buckets) / HalfBuckets + 1;
        var sub = index - (exponent * HalfBuckets);
        return (((long)sub + 1) << exponent) - 1;
    }
}
