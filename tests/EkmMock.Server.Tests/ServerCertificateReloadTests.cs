using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using EkmMock.Pki;
using EkmMock.Server.Tls;
using EkmMock.TestSupport;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>Server certificate hot reload on a real listener (spec 5.3, 14 test 15): new connections get the new certificate, nobody else notices.</summary>
public sealed class ServerCertificateReloadTests : IAsyncLifetime
{
    private const string Cn = "reload-client.managedhsmclient.test";

    private TestPki _pki = null!;
    private RealEkmHost _host = null!;
    private IssuedCertificate _initial = null!;

    public async ValueTask InitializeAsync()
    {
        _pki = new TestPki();
        _initial = _pki.IssueServer();
        _host = await RealEkmHost.StartAsync(new RealEkmHostOptions
        {
            Pki = _pki,
            ServerCertificate = _initial,
            Namespaces = [TestNamespace.Default(_pki.ClientCaA, Cn)],
        });
    }

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        _initial.Dispose();
        _pki.Dispose();
    }

    private void Overwrite(IssuedCertificate certificate)
    {
        // Key first, then certificate (the order an operator's tooling usually writes them). A watcher firing in between sees a mismatch
        // and keeps the old certificate, which is exactly the "partial update" case the provider must survive.
        File.WriteAllText(_host.KeyFile, certificate.PrivateKeyPem);
        File.WriteAllText(_host.CertFile, certificate.ChainPem);
    }

    private async Task<bool> WaitForServedAsync(string thumbprint, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(15));
        while (DateTime.UtcNow < deadline)
        {
            if (await _host.ServedThumbprintAsync() == thumbprint)
            {
                return true;
            }

            await Task.Delay(50, TestContext.Current.CancellationToken);
        }

        return false;
    }

    [Fact]
    public async Task TheConfiguredCertificate_IsServedAtStartup_WithItsFacts()
    {
        (await _host.ServedThumbprintAsync()).ShouldBe(_initial.Thumbprint);

        var info = _host.Certificates.Info;
        info.ThumbprintSha256.ShouldBe(_initial.Thumbprint);
        info.SubjectAlternativeNames.ShouldContain("DNS:localhost");
        info.SubjectAlternativeNames.ShouldContain("IP:127.0.0.1");
        info.Issuer.ShouldContain("EkmMock Test Server Root CA");
        info.Source.ShouldBe(ServerCertificateSource.File);
        info.ChainLength.ShouldBe(1);
        info.ExpiresSoon.ShouldBeFalse();
        info.IsExpired.ShouldBeFalse();
        info.IsDevelopmentCertificate.ShouldBeFalse();
        _host.Certificates.LastError.ShouldBeNull();
    }

    [Fact]
    public async Task ReplacingTheFiles_ServesTheNewCertificateToNewConnections_WithinThePollInterval()
    {
        using var replacement = _pki.IssueServer();
        replacement.Thumbprint.ShouldNotBe(_initial.Thumbprint);

        Overwrite(replacement);

        (await WaitForServedAsync(replacement.Thumbprint)).ShouldBeTrue("the new certificate was not served in time");
        _host.Certificates.Info.ThumbprintSha256.ShouldBe(replacement.Thumbprint);
        _host.Certificates.LastError.ShouldBeNull();
    }

    [Fact]
    public async Task ExistingKeepAliveConnections_AndInFlightRequests_NeverFail_WhileTheCertificateIsSwapped()
    {
        using var client = _pki.ClientCaA.IssueClient(Cn);
        using var replacement = _pki.IssueServer();
        using var stop = new CancellationTokenSource();
        var failures = new List<string>();
        var counts = new int[6];

        async Task Worker(int index, bool freshConnections)
        {
            using var http = freshConnections ? null : _host.CreateHttpClient(client.Certificate, singleConnection: true);
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    var current = http is null ? _host.CreateHttpClient(client.Certificate, singleConnection: true) : null;
                    var ekm = new EkmClient(http ?? current!);
                    var reply = await ekm.InfoAsync();
                    if (reply.StatusCode != 200)
                    {
                        lock (failures)
                        {
                            failures.Add($"worker {index}: status {reply.StatusCode}");
                        }
                    }

                    counts[index]++;
                    current?.Dispose();
                }
                catch (Exception ex)
                {
                    lock (failures)
                    {
                        failures.Add($"worker {index}: {ex.GetType().Name}: {ex.Message}");
                    }
                }
            }
        }

        var workers = new[] { Worker(0, false), Worker(1, false), Worker(2, false), Worker(3, false), Worker(4, true), Worker(5, true) };
        await Task.Delay(300, TestContext.Current.CancellationToken);
        Overwrite(replacement);
        (await WaitForServedAsync(replacement.Thumbprint)).ShouldBeTrue();
        var servedAt = counts.Sum();
        await Task.Delay(600, TestContext.Current.CancellationToken);
        await stop.CancelAsync();
        await Task.WhenAll(workers);

        failures.ShouldBeEmpty(string.Join("; ", failures));
        counts.Sum().ShouldBeGreaterThan(servedAt, "requests kept flowing after the swap");
        counts.ShouldAllBe(static c => c > 0);
    }

    [Fact]
    public async Task AnExistingConnection_KeepsItsCertificate_ButItsNextRequestStillWorks()
    {
        using var client = _pki.ClientCaA.IssueClient(Cn);
        using var replacement = _pki.IssueServer();
        using var http = _host.CreateHttpClient(client.Certificate, singleConnection: true);
        var ekm = new EkmClient(http);
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);

        Overwrite(replacement);
        (await WaitForServedAsync(replacement.Thumbprint)).ShouldBeTrue();

        // Same pooled connection, negotiated with the old certificate: unaffected.
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task AnInvalidReplacement_KeepsTheOldCertificate_RecordsTheError_AndRecoversWhenFixed()
    {
        await File.WriteAllTextAsync(_host.CertFile, "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n", TestContext.Current.CancellationToken);

        (await Wait.UntilAsync(() => _host.Certificates.LastError is not null)).ShouldBeTrue("no error was recorded");
        _host.Certificates.LastError!.Value.Message.ShouldContain("keeping the current certificate");
        (await _host.ServedThumbprintAsync()).ShouldBe(_initial.Thumbprint);
        _host.Logs.Entries.ShouldContain(static e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning && e.Message.Contains("Server certificate", StringComparison.Ordinal));
        using var client = _pki.ClientCaA.IssueClient(Cn);
        (await _host.CreateEkmClient(client.Certificate).InfoAsync()).StatusCode.ShouldBe(200);

        using var fixedCertificate = _pki.IssueServer();
        Overwrite(fixedCertificate);

        (await WaitForServedAsync(fixedCertificate.Thumbprint)).ShouldBeTrue();
        (await Wait.UntilAsync(() => _host.Certificates.LastError is null)).ShouldBeTrue("the error was not cleared after the fix");
    }

    [Fact]
    public async Task APartialUpdate_NewCertificateWithTheOldKey_IsRejectedAsAMismatch()
    {
        using var replacement = _pki.IssueServer();
        await File.WriteAllTextAsync(_host.CertFile, replacement.ChainPem, TestContext.Current.CancellationToken); // key file still belongs to the initial certificate

        (await Wait.UntilAsync(() => _host.Certificates.LastError is not null)).ShouldBeTrue();
        (await _host.ServedThumbprintAsync()).ShouldBe(_initial.Thumbprint);

        // Completing the update (writing the matching key) is picked up.
        await File.WriteAllTextAsync(_host.KeyFile, replacement.PrivateKeyPem, TestContext.Current.CancellationToken);
        (await WaitForServedAsync(replacement.Thumbprint)).ShouldBeTrue();
    }

    [Fact]
    public async Task AnExpiredReplacement_IsRejected_AndTheOldCertificateKeepsServing()
    {
        using var expired = _pki.ServerCa.IssueServer(["localhost", "127.0.0.1"], TimeSpan.FromDays(1), DateTimeOffset.UtcNow.AddDays(-3));
        Overwrite(expired);

        // The key is written before the certificate, so a mismatch error may be seen first; wait for the error about expiry itself.
        (await Wait.UntilAsync(() => _host.Certificates.LastError?.Message.Contains("expired", StringComparison.Ordinal) == true)).ShouldBeTrue();
        (await _host.ServedThumbprintAsync()).ShouldBe(_initial.Thumbprint);
    }

    [Fact]
    public async Task AReplacementWithoutServerAuthEku_IsRejected()
    {
        // A client certificate is not a server certificate.
        using var clientOnly = _pki.ServerCa.IssueClient("not-a-server.example");
        Overwrite(clientOnly);

        // The key is written before the certificate, so a mismatch error may be seen first; wait for the error about the EKU itself.
        (await Wait.UntilAsync(() => _host.Certificates.LastError?.Message.Contains("serverAuth", StringComparison.Ordinal) == true)).ShouldBeTrue();
        (await _host.ServedThumbprintAsync()).ShouldBe(_initial.Thumbprint);
    }

    [Fact]
    public async Task ReplaceAsync_TheConsoleUploadSeam_SwapsImmediately_AndPersistsTheFiles()
    {
        using var uploaded = _pki.IssueServer();

        var info = await _host.Certificates.ReplaceAsync(uploaded.ChainPem, uploaded.PrivateKeyPem, TestContext.Current.CancellationToken);

        info.ThumbprintSha256.ShouldBe(uploaded.Thumbprint);
        info.Source.ShouldBe(ServerCertificateSource.Uploaded);
        (await _host.ServedThumbprintAsync()).ShouldBe(uploaded.Thumbprint);
        (await File.ReadAllTextAsync(_host.CertFile, TestContext.Current.CancellationToken)).ShouldBe(uploaded.ChainPem);
        (await File.ReadAllTextAsync(_host.KeyFile, TestContext.Current.CancellationToken)).ShouldBe(uploaded.PrivateKeyPem);

        // The file watcher then sees the same content and changes nothing.
        await Task.Delay(500, TestContext.Current.CancellationToken);
        _host.Certificates.Info.Source.ShouldBe(ServerCertificateSource.Uploaded);
        (await _host.ServedThumbprintAsync()).ShouldBe(uploaded.Thumbprint);
    }

    [Fact]
    public async Task ReplaceAsync_WithAnUnusableCertificate_Throws_AndKeepsTheCurrentOne()
    {
        using var other = _pki.IssueServer();

        await Should.ThrowAsync<ServerCertificateException>(() => _host.Certificates.ReplaceAsync(other.ChainPem, _initial.PrivateKeyPem, TestContext.Current.CancellationToken));
        await Should.ThrowAsync<ServerCertificateException>(() => _host.Certificates.ReplaceAsync("garbage", "garbage", TestContext.Current.CancellationToken));

        _host.Certificates.LastError.ShouldNotBeNull();
        (await _host.ServedThumbprintAsync()).ShouldBe(_initial.Thumbprint);
        (await File.ReadAllTextAsync(_host.CertFile, TestContext.Current.CancellationToken)).ShouldBe(_initial.ChainPem);
    }

    [Fact]
    public async Task AServerCertificateIssuedByAnIntermediate_IsServedWithItsChain()
    {
        using var intermediate = _pki.ServerCa.IssueIntermediate(_pki.Name("EkmMock Test Server Issuing CA"));
        using var leaf = intermediate.IssueServer(["localhost", "127.0.0.1"]);

        Overwrite(leaf);

        // The client trusts only the root and holds no intermediate: it validates only if the server sent the whole chain.
        (await WaitForServedAsync(leaf.Thumbprint)).ShouldBeTrue();
        _host.Certificates.Info.ChainLength.ShouldBe(2);
        using var client = _pki.ClientCaA.IssueClient(Cn);
        (await _host.CreateEkmClient(client.Certificate).InfoAsync()).StatusCode.ShouldBe(200);
    }
}

/// <summary>The 60 s poll fallback (here 300 ms): volume mounts and symlink swaps raise no file events.</summary>
public sealed class ServerCertificatePollFallbackTests
{
    [Fact]
    public async Task WhenNoFileEventTriggersAReload_ThePollFindsTheChange()
    {
        using var pki = new TestPki();
        using var initial = pki.IssueServer();
        await using var host = await RealEkmHost.StartAsync(new RealEkmHostOptions
        {
            Pki = pki,
            ServerCertificate = initial,
            PollInterval = TimeSpan.FromMilliseconds(300),

            // The event-driven reload is parked for an hour, so only the poll can notice the change.
            Debounce = TimeSpan.FromHours(1),
        });
        using var replacement = pki.IssueServer();

        await File.WriteAllTextAsync(host.KeyFile, replacement.PrivateKeyPem, TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(host.CertFile, replacement.ChainPem, TestContext.Current.CancellationToken);

        (await Wait.UntilAsync(() => host.Certificates.Info.ThumbprintSha256 == replacement.Thumbprint, TimeSpan.FromSeconds(10))).ShouldBeTrue();
        (await host.ServedThumbprintAsync()).ShouldBe(replacement.Thumbprint);
    }

    [Fact]
    public void TheDefaultPollIntervalIs60Seconds_AndTheExpiryWarningIs30Days()
    {
        var options = new TlsOptions();

        options.PollInterval.ShouldBe(TimeSpan.FromSeconds(60));
        options.ExpiryWarningDays.ShouldBe(30);
    }
}
