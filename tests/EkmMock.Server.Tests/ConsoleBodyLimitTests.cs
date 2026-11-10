#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using System.Text;
using System.Text.Json;
using EkmMock.Server.Hosting;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>
/// Security review L10: the whole server limits request bodies to 16 KiB for the EKM endpoint (spec 4.1), but the console takes uploads up to 512 KiB. The console branch raises the limit for its own
/// requests only (<c>IHttpMaxRequestBodySizeFeature</c>); the EKM branch does not. Proven over real Kestrel on both listeners.
/// </summary>
public sealed class ConsoleBodyLimitTests : IAsyncLifetime
{
    private ConsoleTestHost _host = null!;
    private AdminApi _api = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ConsoleTestHost.StartAsync();
        _api = new AdminApi(_host.Host.CreateConsoleClient());
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private sealed class ChunkedContent(byte[] bytes) : HttpContent
    {
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            const int chunk = 8192;
            for (var offset = 0; offset < bytes.Length; offset += chunk)
            {
                await stream.WriteAsync(bytes.AsMemory(offset, Math.Min(chunk, bytes.Length - offset)));
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = -1; // unknown: sent with chunked transfer encoding
            return false;
        }
    }

    [Fact]
    public void KestrelsServerWideLimit_StaysAt16KiB_BecauseOfTheEkmEndpoint()
    {
        var kestrel = _host.Host.App.Services.GetRequiredService<IOptions<KestrelServerOptions>>().Value;

        kestrel.Limits.MaxRequestBodySize.ShouldBe(16 * 1024);
        EkmKestrelSetup.MaxRequestBodyBytes.ShouldBe(16 * 1024);
    }

    [Fact]
    public async Task ACertificateUploadOf100KiB_OnTheConsole_IsHandledByTheEndpoint_NotAGeneric500()
    {
        // A valid chain with 100 KiB of text around the PEM blocks (text outside the blocks is ignored by PEM readers): over Kestrel's 16 KiB server limit, well under the console's 512 KiB.
        using var replacement = _host.Pki.IssueServer();
        var padding = new string('x', 100 * 1024);
        var reply = await _api.PostAsync("/api/console/certificates/upload", new { certificate_pem = replacement.ChainPem + "\n# " + padding + "\n", private_key_pem = replacement.PrivateKeyPem });

        reply.StatusCode.ShouldBeOneOf(200, 400);
        reply.StatusCode.ShouldNotBe(500);
        reply.StatusCode.ShouldNotBe(413);
        if (reply.StatusCode == 400)
        {
            reply.ErrorCode.ShouldBe("InvalidRequest"); // a proper validation error with the endpoint's own words
            reply.ErrorMessage.ShouldNotBeNullOrWhiteSpace();
        }
    }

    [Fact]
    public async Task ATrustImportOf100KiB_OnTheConsole_ReachesTheValidation_AndIsRefusedWithAProperError()
    {
        var content = "{\"subject_common_name\":\"big.test\",\"ca_certificates\":[\"" + new string('A', 100 * 1024) + "\"]}";

        var reply = await _api.PostAsync("/api/console/namespaces/_default/trust/import", new { content, mode = "merge", dry_run = true });

        reply.StatusCode.ShouldBe(400, reply.Text); // the content is not a certificate: a validation error, not a 500 and not Kestrel's 413
        reply.ErrorCode.ShouldBe("InvalidRequest");
        reply.ErrorMessage.ShouldNotContain("too large");
    }

    [Fact]
    public async Task ABodyOver512KiB_IsRefusedByTheEndpoint_WithTheSameWords_WhetherSizedOrChunked()
    {
        var json = JsonSerializer.Serialize(new { content = new string('A', 600 * 1024), mode = "merge", dry_run = true });

        var sized = await _api.PostAsync("/api/console/namespaces/_default/trust/import", json);

        using var chunkedRequest = new HttpRequestMessage(HttpMethod.Post, "/api/console/namespaces/_default/trust/import") { Content = new ChunkedContent(Encoding.UTF8.GetBytes(json)) };
        chunkedRequest.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        chunkedRequest.Headers.Add("X-EkmMock-Client", "tests/1.0");
        sized.StatusCode.ShouldBe(400, sized.Text);
        sized.ErrorMessage.ShouldContain("too large");

        // A chunked body has no announced length, so the server only notices while reading and answers 400 (the same words) as soon as it has seen 512 KiB. A client that keeps on sending
        // after that may see the connection reset before it reads the answer (TCP, see DECISIONS "M3: TLS stack"): that is the only other acceptable outcome, never a 500 or a 413.
        try
        {
            using var chunked = await _api.Http.SendAsync(chunkedRequest);
            var chunkedText = await chunked.Content.ReadAsStringAsync();
            ((int)chunked.StatusCode).ShouldBe(400, chunkedText);
            chunkedText.ShouldContain("too large");
        }
        catch (HttpRequestException)
        {
            // The server refused the body and closed the connection while the client was still writing.
        }
    }

    [Fact]
    public async Task AnEkmRequestOver16KiB_StillGetsTheProxyError400_WhileTheConsoleTakesMore()
    {
        var (ekm, _, owner) = _host.CreateTrustedEkmClient();
        using (owner)
        {
            var big = "{\"request_context\":{\"correlation_id\":\"c\"},\"pad\":\"" + new string('x', 20_000) + "\"}";

            var reply = await ekm.PostAsync(EkmClient.Path(null, null, "info"), big);

            reply.StatusCode.ShouldBe(400);
            var text = Encoding.UTF8.GetString(reply.Body);
            using var document = JsonDocument.Parse(text);
            document.RootElement.GetProperty("code").GetString().ShouldBe("InvalidRequest");
            text.ShouldNotContain("Request Entity Too Large"); // our ProxyError, not Kestrel's 413
        }

        // The console on the same process accepted a body of the same size.
        var console = await _api.PostAsync("/api/console/namespaces/_default/trust/import", new { content = new string('A', 20_000), mode = "merge", dry_run = true });
        console.StatusCode.ShouldBe(400);
        console.ErrorMessage.ShouldNotContain("too large");
    }

    [Fact]
    public void OnlyTheConsoleBranch_RaisesTheLimit()
    {
        var source = RepositoryFiles.Read("src/EkmMock.Server/Console/ConsolePipeline.cs");
        var ekm = RepositoryFiles.Read("src/EkmMock.Server/Ekm/EkmPipeline.cs");

        source.ShouldContain("branch.UseMiddleware<ConsoleBodyLimitMiddleware>();");
        ekm.ShouldNotContain("IHttpMaxRequestBodySizeFeature");
        ekm.ShouldNotContain("ConsoleBodyLimitMiddleware");
    }
}
