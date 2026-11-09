using System.Security.Cryptography.X509Certificates;
using EkmMock.Crypto;
using EkmMock.Pki;
using EkmMock.Server.Ekm;
using EkmMock.Server.Faults;
using EkmMock.Server.Inspector;
using EkmMock.Server.Metrics;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

[CollectionDefinition(Name)]
public sealed class FaultsHostCollection : ICollectionFixture<FaultsHostFixture>
{
    public const string Name = "faults-host";
}

/// <summary>
/// One real host (real Kestrel, TLS 1.3, mTLS, console listener) with fault injection switched on, shared by the M7 tests that need a real listener (blackhole, close connection,
/// slow request bodies, the Prometheus scrape, the console API). Sharing it keeps the number of generated certificates, and with it the number of leftover Windows key files, small.
/// The settings are chosen for these tests: a concurrency limit of 6, an internal deadline of 400 ms and a blackhole hold cap of 1 s.
/// </summary>
public sealed class FaultsHostFixture : IAsyncLifetime
{
    public const string ClientCn = ConsoleTestHost.ClientCn;
    public const int MaxConcurrency = 6;
    public const int DeadlineMs = 400;
    public const int HoldCapSeconds = 4;

    private ConsoleTestHost _console = null!;
    private IssuedCertificate? _client;

    internal ConsoleTestHost Console => _console;

    internal RealEkmHost Host => _console.Host;

    internal FaultRuleStore Faults => Host.App.Services.GetRequiredService<FaultRuleStore>();

    internal ConcurrencyGate Gate => Host.App.Services.GetRequiredService<ConcurrencyGate>();

    internal EkmMetrics Metrics => Host.App.Services.GetRequiredService<EkmMetrics>();

    internal IInspectorQuery Inspector => Host.App.Services.GetRequiredService<IInspectorQuery>();

    public async ValueTask InitializeAsync()
    {
        _console = await ConsoleTestHost.StartAsync(
            faults: true,
            faultRandom: new ScriptedFaultRandom(0.0),
            configuration: new Dictionary<string, string?>
            {
                ["Limits:MaxConcurrency"] = MaxConcurrency.ToString(),
                ["Limits:InternalDeadlineMs"] = DeadlineMs.ToString(),
                ["Faults:BlackholeMaxHoldSeconds"] = HoldCapSeconds.ToString(),
            });
        _client = _console.Pki.ClientCaA.IssueClient(ClientCn);
        Host.Keys.Create("_default", "pin-key", KeyType.Oct, 256);
    }

    public async ValueTask DisposeAsync()
    {
        _client?.Dispose();
        await _console.DisposeAsync();
    }

    /// <summary>A client of the EKM endpoint with the trusted client certificate and its own timeout; every call starts from a clean slate of rules.</summary>
    internal EkmClient NewClient(TimeSpan? timeout = null)
    {
        var http = Host.CreateHttpClient(_client!.Certificate);
        if (timeout is { } t)
        {
            http.Timeout = t;
        }

        return new EkmClient(http);
    }

    /// <summary>A client without a client certificate (an unauthenticated caller; the handshake allows it, the Auth stage answers 401).</summary>
    internal EkmClient NewAnonymousClient() => new(Host.CreateHttpClient());

    internal AdminApi NewApi() => new(Host.CreateConsoleClient());

    /// <summary>Removes every rule and waits until nothing is in flight: the start of every test.</summary>
    internal async Task ResetAsync()
    {
        Faults.Clear();
        (await Wait.UntilAsync(() => Gate.InFlight == 0, TimeSpan.FromSeconds(10))).ShouldBeTrue("a previous test left requests in flight");
    }

    /// <summary>The highest exchange id stored so far (use it as the mark for <see cref="WaitForExchangeAsync"/>).</summary>
    internal long Mark() => Inspector.Query(paging: new ExchangePaging { Limit = 1 }).Items.FirstOrDefault()?.Id ?? 0;

    /// <summary>Waits for an exchange stored after <paramref name="mark"/> that satisfies <paramref name="match"/> (capture is asynchronous by design).</summary>
    internal async Task<ExchangeRecord> WaitForExchangeAsync(long mark, Func<ExchangeRecord, bool> match, TimeSpan? timeout = null)
    {
        ExchangeRecord? found = null;
        await Wait.UntilAsync(
            () =>
            {
                found = Inspector.Query(paging: new ExchangePaging { Limit = ExchangePaging.MaxLimit }).Items.FirstOrDefault(r => r.Id > mark && match(r));
                return found is not null;
            },
            timeout ?? TimeSpan.FromSeconds(15),
            TimeSpan.FromMilliseconds(20));
        return found ?? throw new ShouldAssertException("no matching exchange was captured");
    }
}
