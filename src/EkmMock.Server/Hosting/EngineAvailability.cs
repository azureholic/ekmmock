using EkmMock.Crypto;
using EkmMock.Crypto.SelfTest;

namespace EkmMock.Server.Hosting;

/// <summary>
/// The seam for "is the engine usable right now?". <c>info</c> and every key operation answer
/// <c>503 HsmUnavailable</c> when it says no. M7 adds the "HSM offline" fault by decorating or replacing it.
/// A single corrupt key does NOT make the engine unavailable: that key alone answers 503 (spec 6.2, test 19).
/// </summary>
internal interface IEngineAvailability
{
    bool IsAvailable { get; }
}

/// <summary>Set once by <see cref="EkmStartupService"/> after the key store loaded and the startup self-test ran.</summary>
internal sealed class EkmStartupState
{
    private volatile SelfTestResult? _selfTest;
    private volatile bool _ready;

    public bool IsReady => _ready;

    /// <summary>The startup self-test (shown on the console's About page in M6); null until startup finished.</summary>
    public SelfTestResult? SelfTest => _selfTest;

    public void MarkReady(SelfTestResult selfTest)
    {
        _selfTest = selfTest;
        _ready = true;
    }
}

internal sealed class DefaultEngineAvailability : IEngineAvailability
{
    private readonly ICryptoBackend _backend;
    private readonly EkmStartupState _startup;

    public DefaultEngineAvailability(ICryptoBackend backend, EkmStartupState startup)
    {
        _backend = backend;
        _startup = startup;
    }

    public bool IsAvailable => _startup.IsReady && _backend.IsAvailable;
}

/// <summary>Hands out the sequential exchange ids (spec 8.1).</summary>
internal sealed class ExchangeCounter
{
    private long _last;

    public long Next() => Interlocked.Increment(ref _last);
}
