using System.Security.Cryptography;
using EkmMock.Crypto.KeyStore;
using EkmMock.Crypto.SelfTest;

namespace EkmMock.Crypto;

public sealed partial class SoftwareCryptoBackend
{
    // Bit per WrapAlgorithm; a set bit means the algorithm failed its self-test (-> UnsupportedAlgorithm).
    private int _unavailableAlgorithms;
    private volatile SelfTestResult? _lastSelfTest;

    /// <summary>The most recent self-test, or null if none has run yet.</summary>
    public SelfTestResult? LastSelfTest => _lastSelfTest;

    private bool IsAlgorithmUnavailable(WrapAlgorithm alg) => (Volatile.Read(ref _unavailableAlgorithms) & (1 << (int)alg)) != 0;

    /// <summary>
    /// Startup self-test (spec 6.5): RFC known-answer vectors, RSA-OAEP round trips with an independent second
    /// <c>RSA</c> instance, and one wrap/unwrap round trip per stored key (which also warms the pools).
    /// A failed algorithm becomes unavailable (<c>UnsupportedAlgorithm</c>), a failed key becomes <see cref="KeyState.Unavailable"/>.
    /// Check <see cref="SelfTestResult.RefuseToStart"/> to honour <see cref="SelfTestOptions.Strict"/>.
    /// </summary>
    public SelfTestResult RunSelfTest(SelfTestOptions? options = null) => RunSelfTestCore(options ?? new SelfTestOptions(), forceFailure: null);

    // forceFailure is a test hook (InternalsVisibleTo): it makes the named case fail so the failure path is provable.
    internal SelfTestResult RunSelfTestCore(SelfTestOptions options, Func<string, bool>? forceFailure)
    {
        ThrowIfUnavailable();
        var cases = AlgorithmSelfTests.Run(forceFailure);

        var mask = 0;
        foreach (WrapAlgorithm alg in Enum.GetValues<WrapAlgorithm>())
        {
            var prefix = AlgorithmSelfTests.WrapAlgorithmPrefixFor(alg)!;
            if (cases.Any(c => c.Outcome == SelfTestOutcome.Failed && c.Name.StartsWith(prefix, StringComparison.Ordinal)))
            {
                mask |= 1 << (int)alg;
            }
        }

        Volatile.Write(ref _unavailableAlgorithms, mask);

        foreach (var entry in _keys.Values.OrderBy(static e => e.Key.Namespace, StringComparer.Ordinal).ThenBy(static e => e.Key.Name, StringComparer.Ordinal))
        {
            var name = $"key:{entry.Key}";
            if (entry.Health == KeyHealth.Corrupt)
            {
                cases.Add(new SelfTestCaseResult(name, SelfTestOutcome.Skipped, TimeSpan.Zero, "Key is corrupt"));
                continue;
            }

            var result = AlgorithmSelfTests.RunCase(name, forceFailure, () => KeyRoundTrip(entry));
            entry.Health = result.Outcome == SelfTestOutcome.Passed ? KeyHealth.Ok : KeyHealth.Unavailable;
            cases.Add(result);
        }

        var outcome = new SelfTestResult(cases, _time.GetUtcNow(), options.Strict);
        _lastSelfTest = outcome;
        return outcome;
    }

    // Goes through the same core as production, but skips state checks (disabled/expired keys are still verified) and counters.
    private static void KeyRoundTrip(KeyEntry entry)
    {
        var alg = entry.Type == KeyType.Oct ? WrapAlgorithm.A256KWP : WrapAlgorithm.RsaOaep256;
        var dek = RandomNumberGenerator.GetBytes(32);
        byte[]? unwrapped = null;
        try
        {
            var wrapped = WrapCore(entry, alg, dek);
            unwrapped = UnwrapCore(entry, alg, wrapped);
            if (!CryptographicOperations.FixedTimeEquals(unwrapped, dek))
            {
                throw new InvalidOperationException("Round trip mismatch");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            if (unwrapped is not null)
            {
                CryptographicOperations.ZeroMemory(unwrapped);
            }
        }
    }
}
