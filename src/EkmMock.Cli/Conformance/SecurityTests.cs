using System.Net;
using System.Security.Authentication;
using System.Text;
using EkmMock.Cli.ConsoleApi;
using EkmMock.Cli.Ekm;

namespace EkmMock.Cli.Conformance;

/// <summary>Section 14, "Security" tests 14 to 19, as far as they can be proven from outside.</summary>
internal static class SecurityTests
{
    public static IEnumerable<ConformanceCase> All()
    {
        yield return new("14.14.a", "14.14", "TLS 1.2 is refused (the handshake fails)", Tls12Refused);
        yield return new("14.14.b", "14.14", "no client certificate is 401 Unauthenticated", NoClientCertificate);
        yield return new("14.14.c", "14.14", "a certificate of a trusted CA with a CN that is not allowed is 401", WrongCn);
        yield return new("14.14.d", "14.14", "a certificate of an untrusted CA fails the handshake", UntrustedCa);
        yield return new("14.14.e", "14.14", "a CN allowed on namespace A is 401 on namespace B", CnOnOtherNamespace);
        yield return new("14.15.a", "14.15", "a replaced server certificate is served within 60 s without failed requests", ServerCertificateReload);
        yield return new("14.16.a", "14.16", "EKM paths on the console port are 404", EkmPathsOnConsolePort);
        yield return new("14.16.b", "14.16", "console paths on the EKM port are 404", ConsolePathsOnEkmPort);
        yield return new("14.17.a", "14.17", "LoopbackOnly with a non-loopback bind refuses to start", LoopbackRefusal);
        yield return new("14.18.a", "14.18", "no key material appears in console API responses or exports after this run", LeakScan);
        yield return new("14.19.a", "14.19", "the key store file holds no raw key bytes; a flipped blob marks the key Corrupt", KeyStoreFile);
    }

    private static async Task Tls12Refused(ConformanceContext ctx, CancellationToken ct)
    {
        using var client = ctx.CreateVariantClient(ctx.Options.Client, SslProtocols.Tls12);
        await ExpectNoHttpAnswerAsync(client, "a TLS 1.2 client", ct).ConfigureAwait(false);
    }

    private static async Task NoClientCertificate(ConformanceContext ctx, CancellationToken ct)
    {
        using var client = ctx.CreateVariantClient(identity: null);
        Expect.ProxyError(await client.InfoAsync(ct).ConfigureAwait(false), 401, "Unauthenticated", "info without a client certificate");
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        Expect.ProxyError(await client.MetadataAsync(key.Name, ct).ConfigureAwait(false), 401, "Unauthenticated", "metadata without a client certificate");
        Expect.ProxyError(await client.WrapAsync(key.Name, "A256KWP", ctx.Random(32), ct).ConfigureAwait(false), 401, "Unauthenticated", "wrapkey without a client certificate");
    }

    private static async Task WrongCn(ConformanceContext ctx, CancellationToken ct)
    {
        if (ctx.Options.AltClient is null)
        {
            throw new SkipTest("needs --alt-client-cert and --alt-client-key: a certificate issued by a trusted CA whose CN is not allowed (ekmmock certs dev writes client-wrong-cn.*)");
        }

        using var client = ctx.CreateVariantClient(ctx.Options.AltClient);
        Expect.ProxyError(await client.InfoAsync(ct).ConfigureAwait(false), 401, "Unauthenticated", "info with a wrong-CN certificate");
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        Expect.ProxyError(await client.WrapAsync(key.Name, "A256KWP", ctx.Random(32), ct).ConfigureAwait(false), 401, "Unauthenticated", "wrapkey with a wrong-CN certificate");
    }

    private static async Task UntrustedCa(ConformanceContext ctx, CancellationToken ct)
    {
        if (ctx.Options.RogueClient is null)
        {
            throw new SkipTest("needs --rogue-client-cert and --rogue-client-key: a client certificate issued by a CA the server does not trust (ekmmock certs dev writes client-untrusted-ca.*)");
        }

        using var client = ctx.CreateVariantClient(ctx.Options.RogueClient);
        await ExpectNoHttpAnswerAsync(client, "a client with a certificate of an untrusted CA", ct).ConfigureAwait(false);
    }

    /// <summary>The handshake must fail: any HTTP answer (even a 401) means the server accepted the connection.</summary>
    private static async Task ExpectNoHttpAnswerAsync(EkmClient client, string who, CancellationToken ct)
    {
        EkmReply reply;
        try
        {
            reply = await client.InfoAsync(ct).ConfigureAwait(false);
        }
        catch (HttpRequestException)
        {
            return; // refused at the TLS layer: what is expected
        }
        catch (IOException)
        {
            return;
        }

        throw new TestFailure($"{who} got an HTTP answer ({Expect.Describe(reply)}) instead of a failed handshake");
    }

    private static async Task CnOnOtherNamespace(ConformanceContext ctx, CancellationToken ct)
    {
        ctx.RequireConsole("to create a namespace that trusts another CN");
        var other = await ctx.OtherNamespaceAsync(sameTrust: false, ct).ConfigureAwait(false);
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        Expect.Status(await ctx.Ekm.MetadataAsync(key.Name, ct).ConfigureAwait(false), 200, "metadata on the namespace the CN is allowed on");
        var reply = await ctx.Ekm.PostAsync(ctx.Ekm.Path(null, "info", prefixOverride: other.Prefix), cancellationToken: ct).ConfigureAwait(false);
        Expect.ProxyError(reply, 401, "Unauthenticated", "info on a namespace that does not allow this client's CN");
    }

    private static async Task ServerCertificateReload(ConformanceContext ctx, CancellationToken ct)
    {
        if (ctx.Options.ReplacementCertFile is not { } certFile || ctx.Options.ReplacementKeyFile is not { } keyFile)
        {
            throw new SkipTest("needs --replacement-server-cert and --replacement-server-key: a second certificate for the same host issued by the CA of --ca (ekmmock certs dev writes server-replacement.*); the check uploads it through the console and the server keeps serving it afterwards");
        }

        var console = ctx.RequireConsole("to upload the replacement certificate");
        var certificatePem = File.ReadAllText(certFile);
        var keyPem = File.ReadAllText(keyFile);
        string wanted;
        using (var replacement = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(certificatePem))
        {
            wanted = replacement.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
        }

        var before = await ServedThumbprintAsync(ctx, ct).ConfigureAwait(false);
        if (string.Equals(before, wanted, StringComparison.OrdinalIgnoreCase))
        {
            throw new SkipTest("the server already serves the replacement certificate (this check was run before against this server): make another one with 'ekmmock certs server' and pass it as --replacement-server-cert");
        }


        // A new TLS handshake per request while the certificate is replaced: every one must succeed, with the old certificate or the new one.
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var failures = new List<string>();
        var requests = 0;
        var load = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    using var fresh = ctx.CreateVariantClient(ctx.Options.Client, maxConnections: 1);
                    var reply = await fresh.InfoAsync(stop.Token).ConfigureAwait(false);
                    Interlocked.Increment(ref requests);
                    if (reply.Status != 200)
                    {
                        lock (failures)
                        {
                            failures.Add($"HTTP {reply.Status}");
                        }
                    }
                }
                catch (OperationCanceledException) when (stop.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception exception) when (exception is HttpRequestException or IOException)
                {
                    lock (failures)
                    {
                        failures.Add(exception.GetBaseException().Message);
                    }
                }

                await Task.Delay(15, CancellationToken.None).ConfigureAwait(false);
            }
        }, CancellationToken.None);

        var served = false;
        try
        {
            await console.UploadCertificateAsync(new(certificatePem, keyPem), ct).ConfigureAwait(false);
            var watch = System.Diagnostics.Stopwatch.StartNew();
            while (watch.Elapsed < TimeSpan.FromSeconds(60))
            {
                if (string.Equals(await ServedThumbprintAsync(ctx, ct).ConfigureAwait(false), wanted, StringComparison.OrdinalIgnoreCase))
                {
                    served = true;
                    break;
                }

                await Task.Delay(250, ct).ConfigureAwait(false);
            }

            // Keep the load running a little longer: connections opened after the switch must work too.
            await Task.Delay(500, ct).ConfigureAwait(false);
        }
        finally
        {
            await stop.CancelAsync().ConfigureAwait(false);
            await load.ConfigureAwait(false);
        }

        Expect.That(served, "the replacement certificate was not served within 60 s of the upload");
        Expect.That(failures.Count == 0, $"{failures.Count} of {requests + failures.Count} requests failed while the certificate was replaced (first: {failures.FirstOrDefault()})");
        Expect.That(requests > 0, "no request completed during the certificate replacement, so nothing was proven");
    }

    /// <summary>The SHA-256 thumbprint of the certificate the endpoint presents right now (a full handshake; the certificate is validated against the roots like any other).</summary>
    private static async Task<string> ServedThumbprintAsync(ConformanceContext ctx, CancellationToken ct)
    {
        string? thumbprint = null;
        var inner = Infrastructure.TlsTrust.CreateCallback(ctx.Options.Roots, pinSha256: null, insecureLoopback: false);
        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync(ctx.Options.Target.Origin.Host, ctx.Options.Target.Origin.Port, ct).ConfigureAwait(false);
        await using var ssl = new System.Net.Security.SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (sender, certificate, chain, errors) =>
        {
            if (certificate is not null)
            {
                using var copy = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                thumbprint = copy.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
            }

            return inner is null ? errors == System.Net.Security.SslPolicyErrors.None : inner(sender, certificate, chain, errors);
        });
        await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions { TargetHost = ctx.Options.Target.ServerName, EnabledSslProtocols = SslProtocols.Tls13 }, ct).ConfigureAwait(false);
        return thumbprint ?? throw new TestFailure("the server presented no certificate");
    }
    private static async Task EkmPathsOnConsolePort(ConformanceContext ctx, CancellationToken ct)
    {
        var console = ctx.RequireConsole("to reach the console port");
        var key = await ctx.AesKeyAsync(ct).ConfigureAwait(false);
        var body = Encoding.UTF8.GetBytes(ctx.Ekm.BodyJson(ctx.Ekm.NewCorrelationId()));
        foreach (var path in new[] { "/info?api-version=0.1-preview", $"/{key.Name}/metadata?api-version=0.1-preview", $"/{key.Name}/wrapkey?api-version=0.1-preview", $"/{key.Name}/unwrapkey?api-version=0.1-preview" })
        {
            var (status, _) = await console.TryAsync(HttpMethod.Post, path, body, ct).ConfigureAwait(false);
            Expect.That(status == HttpStatusCode.NotFound, $"POST {path} on the console port answered {(int)status}, expected 404");
        }

        if (ctx.Options.Target.Prefix.Length > 0)
        {
            var (status, _) = await console.TryAsync(HttpMethod.Post, $"/{ctx.Options.Target.Prefix}/info?api-version=0.1-preview", body, ct).ConfigureAwait(false);
            Expect.That(status == HttpStatusCode.NotFound, $"POST /{ctx.Options.Target.Prefix}/info on the console port answered {(int)status}, expected 404");
        }
    }

    private static async Task ConsolePathsOnEkmPort(ConformanceContext ctx, CancellationToken ct)
    {
        foreach (var (method, path) in new[]
        {
            (HttpMethod.Get, "/api/console/status"),
            (HttpMethod.Get, "/api/console/keys"),
            (HttpMethod.Post, "/api/console/keys"),
            (HttpMethod.Get, "/healthz"),
            (HttpMethod.Get, "/readyz"),
            (HttpMethod.Get, "/metrics"),
            (HttpMethod.Get, "/"),
            (HttpMethod.Get, "/_blazor"),
            (HttpMethod.Get, "/_framework/blazor.web.js"),
        })
        {
            var reply = await ctx.Ekm.SendAsync(method, path, json: method == HttpMethod.Post ? "{}" : null, cancellationToken: ct).ConfigureAwait(false);
            Expect.That(reply.Status == 404, $"{method} {path} on the EKM port answered {reply.Status}, expected 404");
        }
    }

    private static Task LoopbackRefusal(ConformanceContext ctx, CancellationToken ct)
        => throw new SkipTest("needs a server process to be started with a public bind address and a loopback-only console: not observable from outside; covered by the server's own tests (ConsoleStartupValidationTests, real child process)");

    private static async Task KeyStoreFile(ConformanceContext ctx, CancellationToken ct)
    {
        await Task.CompletedTask.ConfigureAwait(false);
        throw new SkipTest("needs read and write access to the server's data volume and a restart (flip a byte of keystore.json, start with a wrong master key); covered by the server's own tests (Crypto key store tests)");
    }

    // ---- 18: leak scan over what the console API serves ----

    private static async Task LeakScan(ConformanceContext ctx, CancellationToken ct)
    {
        var console = ctx.RequireConsole("to read the console API responses that are scanned");
        var texts = new List<(string Source, string Text)>();
        var run = Uri.EscapeDataString("conf-" + ctx.RunId);
        string[] paths =
        [
            "/api/console/keys",
            "/api/console/namespaces",
            "/api/console/about",
            "/api/console/status",
            "/api/console/self-test",
            "/api/console/certificates",
            "/api/console/audit?take=500",
            "/api/console/connections?limit=1000",
            "/api/console/connections/open",
            "/api/console/dashboard",
            "/api/console/faults",
            $"/api/console/exchanges?limit=500&text={run}",
            $"/api/console/export?format=json&text={run}",
            $"/api/console/export?format=jsonl&text={run}",
            "/metrics",
        ];
        foreach (var path in paths)
        {
            var (status, body) = await console.TryAsync(HttpMethod.Get, path, null, ct).ConfigureAwait(false);
            if ((int)status is >= 200 and < 300)
            {
                texts.Add((path.Split('?')[0], Encoding.UTF8.GetString(body)));
            }
        }

        Expect.That(texts.Count >= 6, $"only {texts.Count} console endpoints could be read; the scan would prove little");
        var secrets = ctx.Secrets.Where(static s => s.Length >= 8).ToList();
        Expect.That(secrets.Count > 0, "no secrets were used earlier in this run, so there is nothing to scan for (run the whole suite)");
        var scanned = 0;
        foreach (var (source, text) in texts)
        {
            for (var i = 0; i < secrets.Count; i++)
            {
                foreach (var form in LeakForms(secrets[i]))
                {
                    scanned++;
                    Expect.That(!text.Contains(form.Value, form.Comparison), $"a secret used in this run (#{i}, {form.Name}, {secrets[i].Length} bytes) appears in {source}");
                }
            }
        }

        Expect.That(scanned > 0, "nothing was scanned");
    }

    internal static IEnumerable<(string Name, string Value, StringComparison Comparison)> LeakForms(byte[] secret)
    {
        yield return ("base64", Convert.ToBase64String(secret), StringComparison.Ordinal);
        yield return ("base64url", System.Buffers.Text.Base64Url.EncodeToString(secret), StringComparison.Ordinal);
        yield return ("hex", Convert.ToHexString(secret), StringComparison.OrdinalIgnoreCase);
    }
}
