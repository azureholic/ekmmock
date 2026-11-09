using System.Net;
using System.Text;
using EkmMock.Crypto;
using EkmMock.Server.Ekm;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>Spec 4.1 transport, 4.3 request body, 4.4 error body and the documented order of validation.</summary>
public sealed class TransportAndValidationTests
{
    private static async Task<(EkmFactory Factory, EkmClient Ekm)> StartAsync(EkmFactoryOptions? options = null)
    {
        var factory = new EkmFactory(options);
        factory.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
        await Task.CompletedTask;
        return (factory, factory.CreateEkmClient());
    }

    private sealed class UnknownLengthContent : HttpContent
    {
        private readonly byte[] _bytes;

        public UnknownLengthContent(byte[] bytes)
        {
            _bytes = bytes;
            Headers.ContentType = new("application/json");
        }

        protected override async Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context)
        {
            // Small writes, so the server sees a body without a Content-Length (the chunked case).
            for (var offset = 0; offset < _bytes.Length; offset += 1000)
            {
                await stream.WriteAsync(_bytes.AsMemory(offset, Math.Min(1000, _bytes.Length - offset)));
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private static byte[] BodyOfExactSize(int size)
    {
        const string prefix = "{\"request_context\":{\"request_id\":\"r\"},\"pad\":\"";
        var padLength = size - prefix.Length - 2; // closing quote and brace
        var json = prefix + new string('x', padLength) + "\"}";
        var bytes = Encoding.UTF8.GetBytes(json);
        bytes.Length.ShouldBe(size);
        return bytes;
    }

    // ---- 4.1: method --------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    [InlineData("OPTIONS")]
    public async Task NonPost_Returns405_WithAProxyErrorBody_AndAnAllowHeader(string method)
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        foreach (var path in new[] { EkmClient.Path(null, null, "info"), EkmClient.Path(null, "aes-key-1", "metadata"), EkmClient.Path(null, "aes-key-1", "wrapkey") })
        {
            var reply = await ekm.SendAsync(new HttpMethod(method), path, EkmClient.JsonBody(EkmClient.Context));

            reply.ShouldBeProxyError(405, "MethodNotAllowed");
            reply.Message.Content.Headers.Allow.ShouldBe(["POST"]);
        }
    }

    [Fact]
    public async Task LowercasePostMethod_IsNotPost()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        (await ekm.SendAsync(new HttpMethod("post"), EkmClient.Path(null, null, "info"), EkmClient.JsonBody(EkmClient.Context))).ShouldBeProxyError(405, "MethodNotAllowed");
    }

    // ---- 4.1: content type ----------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("text/plain")]
    [InlineData("application/xml")]
    [InlineData("application/x-www-form-urlencoded")]
    [InlineData("application/json-patch+json")]
    [InlineData("application/jsonx")]
    [InlineData("application/json; charset=utf-16")]
    public async Task WrongContentType_Returns400InvalidRequest(string contentType)
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        var reply = await ekm.PostAsync(EkmClient.Path(null, null, "info"), EkmClient.Context, contentType);

        reply.ShouldBeProxyError(400, "InvalidRequest");
        reply.Json().RootElement.GetProperty("message").GetString().ShouldBe("The Content-Type must be application/json");
    }

    [Fact]
    public async Task MissingContentType_Returns400InvalidRequest()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        var reply = await ekm.SendAsync(HttpMethod.Post, EkmClient.Path(null, null, "info"), new ByteArrayContent(Encoding.UTF8.GetBytes(EkmClient.Context)));

        reply.ShouldBeProxyError(400, "InvalidRequest");
        reply.Json().RootElement.GetProperty("message").GetString().ShouldBe("The Content-Type must be application/json");
    }

    [Theory]
    [InlineData("application/json")]
    [InlineData("APPLICATION/JSON")]
    [InlineData("application/json; charset=utf-8")]
    [InlineData("application/json;charset=UTF-8")]
    public async Task JsonContentTypeVariants_AreAccepted(string contentType)
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        (await ekm.PostAsync(EkmClient.Path(null, null, "info"), EkmClient.Context, contentType)).StatusCode.ShouldBe(200);
    }

    // ---- 4.1: body size and framing ---------------------------------------------------------------------------------------------

    [Fact]
    public async Task BodyOfExactly16KiB_IsAccepted_AndOneByteMoreIs400()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        var path = EkmClient.Path(null, null, "info");

        var ok = await ekm.SendAsync(HttpMethod.Post, path, new ByteArrayContent(BodyOfExactSize(16384)) { Headers = { { "Content-Type", "application/json" } } });
        var tooBig = await ekm.SendAsync(HttpMethod.Post, path, new ByteArrayContent(BodyOfExactSize(16385)) { Headers = { { "Content-Type", "application/json" } } });

        ok.StatusCode.ShouldBe(200, ok.Text);
        tooBig.ShouldBeProxyError(400, "InvalidRequest");
    }

    [Fact]
    public async Task OversizedBody_WithContentLength_Returns400_ForEveryOperation()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        var huge = new string('A', 20_000);

        foreach (var op in new[] { "info", "metadata", "wrapkey", "unwrapkey" })
        {
            var path = op == "info" ? EkmClient.Path(null, null, op) : EkmClient.Path(null, "aes-key-1", op);
            (await ekm.PostAsync(path, EkmClient.WrapBody("A256KWP", huge))).ShouldBeProxyError(400, "InvalidRequest");
        }
    }

    [Fact]
    public async Task ChunkedBodies_AreReadWithoutAContentLength_AndTheLimitStillApplies()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        var path = EkmClient.Path(null, null, "info");

        var small = new UnknownLengthContent(Encoding.UTF8.GetBytes(EkmClient.Context));
        var exact = new UnknownLengthContent(BodyOfExactSize(16384));
        var big = new UnknownLengthContent(BodyOfExactSize(30000));

        small.Headers.ContentLength.ShouldBeNull();
        (await ekm.SendAsync(HttpMethod.Post, path, small)).StatusCode.ShouldBe(200);
        (await ekm.SendAsync(HttpMethod.Post, path, exact)).StatusCode.ShouldBe(200);
        (await ekm.SendAsync(HttpMethod.Post, path, big)).ShouldBeProxyError(400, "InvalidRequest");
    }

    [Fact]
    public async Task Utf8Bom_IsTolerated()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        var bytes = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Encoding.UTF8.GetBytes(EkmClient.Context)).ToArray();

        var reply = await ekm.SendAsync(HttpMethod.Post, EkmClient.Path(null, null, "info"), new ByteArrayContent(bytes) { Headers = { { "Content-Type", "application/json" } } });

        reply.StatusCode.ShouldBe(200, reply.Text);
    }

    // ---- 4.3: body --------------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("\"text\"")]
    [InlineData("42")]
    [InlineData("null")]
    [InlineData("""{"request_context":{}} trailing""")]
    [InlineData("""{"request_context":{}}{}""")]
    [InlineData("""{"request_context":{},}""")]
    [InlineData("""{"request_context":{} /* c */}""")]
    [InlineData("""{"request_context":{"request_id":"a"}""")]
    [InlineData("""{'request_context':{}}""")]
    public async Task BadJson_Returns400InvalidRequest(string body)
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        foreach (var op in new[] { "info", "metadata", "wrapkey", "unwrapkey" })
        {
            var path = op == "info" ? EkmClient.Path(null, null, op) : EkmClient.Path(null, "aes-key-1", op);
            (await ekm.PostAsync(path, body)).ShouldBeProxyError(400, "InvalidRequest");
        }
    }

    [Fact]
    public async Task InvalidUtf8_Returns400InvalidRequest()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        var bytes = Encoding.UTF8.GetBytes("""{"request_context":{"pool_name":"X"}}""");
        bytes[^10] = 0xFF;

        var reply = await ekm.SendAsync(HttpMethod.Post, EkmClient.Path(null, null, "info"), new ByteArrayContent(bytes) { Headers = { { "Content-Type", "application/json" } } });

        reply.ShouldBeProxyError(400, "InvalidRequest");
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"request_context":null}""")]
    [InlineData("""{"request_context":"x"}""")]
    [InlineData("""{"request_context":[]}""")]
    [InlineData("""{"request_context":42}""")]
    [InlineData("""{"alg":"A256KWP","value":"AAAA"}""")]
    public async Task MissingRequestContext_Returns400InvalidRequest_ForEveryOperation(string body)
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        foreach (var op in new[] { "info", "metadata", "wrapkey", "unwrapkey" })
        {
            var path = op == "info" ? EkmClient.Path(null, null, op) : EkmClient.Path(null, "aes-key-1", op);
            var reply = await ekm.PostAsync(path, body);

            reply.ShouldBeProxyError(400, "InvalidRequest");
            reply.Json().RootElement.GetProperty("message").GetString().ShouldBe("The request_context field is required");
        }
    }

    [Theory]
    [InlineData("""{"request_context":{}}""")]
    [InlineData("""{"request_context":{"request_id":null,"correlation_id":7,"pool_name":{"a":1}}}""")]
    [InlineData("""{"request_context":{"unknown":[1,{"deep":[true]}]},"extra":{"a":"b"},"alg":"ignored","value":1}""")]
    public async Task RequestContextFieldsAreOptional_UnknownFieldsAreIgnored_ForInfoAndMetadata(string body)
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        (await ekm.PostAsync(EkmClient.Path(null, null, "info"), body)).StatusCode.ShouldBe(200);
        (await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "metadata"), body)).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task UnknownFields_AreIgnored_OnWrapAndUnwrap()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        var dek = Fx.Random(32);
        var body = $$"""{"future":{"x":[1,2,3]},"request_context":{"request_id":"r","new_field":true},"alg":"A256KWP","value":"{{System.Buffers.Text.Base64Url.EncodeToString(dek)}}","more":null}""";

        var wrapped = await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), body);
        wrapped.StatusCode.ShouldBe(200, wrapped.Text);

        var unwrapBody = $$"""{"request_context":{},"alg":"A256KWP","value":"{{wrapped.ValueText()}}","z":0}""";
        var unwrapped = await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "unwrapkey"), unwrapBody);
        Fx.Same(unwrapped.Value(), dek).ShouldBeTrue();
    }

    [Fact]
    public async Task RequestContextValues_AreCapturedOnTheExchangeContext_ForTheInspector()
    {
        var filter = new CaptureFilter();
        var (factory, ekm) = await StartAsync(new EkmFactoryOptions { ConfigureServices = s => s.AddSingleton<IStartupFilter>(filter) });
        using var _ = factory;

        var reply = await ekm.WrapAsync("aes-key-1", "A256KWP", Fx.Random(32));
        reply.StatusCode.ShouldBe(200);

        var seen = filter.Seen.Single();
        seen.RequestId.ShouldBe("r");
        seen.CorrelationId.ShouldBe("c");
        seen.PoolName.ShouldBe("p");
        seen.Algorithm.ShouldBe("A256KWP");
        seen.NamespaceName.ShouldBe("_default");
        seen.Operation.ShouldBe(EkmOperation.WrapKey);
        seen.KeyName.ShouldBe("aes-key-1");
        seen.ApiVersion.ShouldBe("0.1-preview");
        seen.StatusCode.ShouldBe(200);
        seen.ExchangeId.ShouldBe(1);
        seen.CryptoElapsed.ShouldBeGreaterThan(TimeSpan.Zero);
    }

    private sealed class CaptureFilter : IStartupFilter
    {
        public List<EkmRequestContext> Seen { get; } = [];

        public Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> Configure(Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> next)
            => app =>
            {
                app.Use(async (context, inner) =>
                {
                    await inner();
                    if (context.Features.Get<EkmRequestContext>() is { } exchange)
                    {
                        lock (Seen)
                        {
                            Seen.Add(exchange);
                        }
                    }
                });
                next(app);
            };
    }

    // ---- 4.2: api-version -------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("api-version=")]
    [InlineData("api-version=9.9")]
    [InlineData("api-version=1.0")]
    [InlineData("api-version=0.1")]
    [InlineData("api-version=0.1-PREVIEW")]
    [InlineData("api-version=0.1-preview%20")]
    [InlineData("api-version=0.1-preview&api-version=0.1-preview")]
    [InlineData("api-version=0.1-preview&api-version=9.9")]
    [InlineData("apiversion=0.1-preview")]
    [InlineData("version=0.1-preview")]
    public async Task MissingOrUnsupportedApiVersion_Returns400UnsupportedApiVersion(string? query)
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        foreach (var (key, op) in new (string?, string)[] { (null, "info"), ("aes-key-1", "metadata"), ("aes-key-1", "wrapkey"), ("aes-key-1", "unwrapkey") })
        {
            (await ekm.PostAsync(EkmClient.Path(null, key, op, query))).ShouldBeProxyError(400, "UnsupportedApiVersion");
        }
    }

    [Fact]
    public async Task ApiVersion_MayBeFollowedByOtherQueryParameters()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        (await ekm.PostAsync(EkmClient.Path(null, null, "info", "x=1&api-version=0.1-preview&y=2"))).StatusCode.ShouldBe(200);
    }

    // ---- 4.2: key names ---------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("a_b")]
    [InlineData("a.b")]
    [InlineData("name.with.dots")]
    [InlineData("a%20b")]
    [InlineData("a:b")]
    [InlineData("%C3%A9")]
    [InlineData("%E3%82%AD%E3%83%BC")]
    [InlineData("a@b")]
    [InlineData("a+b")]
    public async Task InvalidKeyName_Returns400InvalidKeyName_ForEveryKeyOperation(string key)
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        foreach (var op in new[] { "metadata", "wrapkey", "unwrapkey" })
        {
            (await ekm.PostAsync(EkmClient.Path(null, key, op), EkmClient.WrapBody("A256KWP", "AAAA"))).ShouldBeProxyError(400, "InvalidKeyName");
        }
    }

    [Fact]
    public async Task KeyNameOf65Characters_Is400InvalidKeyName_And64Is404KeyNotFound()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        foreach (var op in new[] { "metadata", "wrapkey", "unwrapkey" })
        {
            (await ekm.PostAsync(EkmClient.Path(null, new string('a', 65), op), EkmClient.WrapBody("A256KWP", "AAAA"))).ShouldBeProxyError(400, "InvalidKeyName");
            (await ekm.PostAsync(EkmClient.Path(null, new string('a', 64), op), EkmClient.WrapBody("A256KWP", "AAAA"))).ShouldBeProxyError(404, "KeyNotFound");
        }

        (await ekm.PostAsync(EkmClient.Path(null, "a", "metadata"))).ShouldBeProxyError(404, "KeyNotFound");
        (await ekm.PostAsync(EkmClient.Path(null, "-", "metadata"))).ShouldBeProxyError(404, "KeyNotFound");
    }

    [Fact]
    public async Task KeyNamesAreCaseSensitive()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        (await ekm.MetadataAsync("aes-key-1")).StatusCode.ShouldBe(200);
        (await ekm.MetadataAsync("AES-KEY-1")).ShouldBeProxyError(404, "KeyNotFound");
    }

    // ---- 4.2: routing -----------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/")]
    [InlineData("/nope/info")]
    [InlineData("/nope/aes-key-1/wrapkey")]
    [InlineData("/nope/prod/aes-key-1/metadata")]
    [InlineData("/info/extra")]
    [InlineData("/aes-key-1/wrapkey/extra")]
    [InlineData("/aes-key-1/rewrap")]
    [InlineData("/aes-key-1/info")]
    [InlineData("/aes-key-1/Metadata")]
    [InlineData("/aes-key-1/WRAPKEY")]
    [InlineData("/aes-key-1/UnwrapKey")]
    [InlineData("/INFO")]
    [InlineData("/Info")]
    [InlineData("/aes-key-1")]
    [InlineData("/metadata")]
    [InlineData("//info")]
    [InlineData("/aes-key-1//metadata")]
    [InlineData("/wrapkey/aes-key-1")]
    [InlineData("/health")]
    [InlineData("/favicon.ico")]
    public async Task UnroutablePaths_Return404NotFound_WithAProxyErrorBody(string path)
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        var reply = await ekm.PostAsync(path + "?api-version=0.1-preview");

        reply.ShouldBeProxyError(404, "NotFound");
    }

    [Fact]
    public async Task WithoutADefaultNamespace_APathWithNoMatchingPrefix_Is404NotFound()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        factory.Namespaces.Remove("_default").ShouldBeTrue();

        (await ekm.InfoAsync()).ShouldBeProxyError(404, "NotFound");
        (await ekm.MetadataAsync("aes-key-1")).ShouldBeProxyError(404, "NotFound");
    }

    [Fact]
    public async Task TrailingSlash_IsTolerated()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        factory.Namespaces.Add(new NamespaceDefinition { Name = "contoso", Prefix = "contoso" });
        factory.Keys.Create("contoso", "k1", KeyType.Oct, 256);

        (await ekm.PostAsync("/info/?api-version=0.1-preview")).StatusCode.ShouldBe(200);
        (await ekm.PostAsync("/aes-key-1/metadata/?api-version=0.1-preview")).StatusCode.ShouldBe(200);
        (await ekm.PostAsync("/contoso/info/?api-version=0.1-preview")).StatusCode.ShouldBe(200);
        (await ekm.PostAsync("/contoso/k1/metadata/?api-version=0.1-preview")).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task PrefixAndOperationSegments_AreCaseSensitive()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        factory.Namespaces.Add(new NamespaceDefinition { Name = "contoso", Prefix = "contoso" });
        factory.Keys.Create("contoso", "k1", KeyType.Oct, 256);

        (await ekm.InfoAsync("contoso")).StatusCode.ShouldBe(200);
        (await ekm.InfoAsync("Contoso")).ShouldBeProxyError(404, "NotFound");
        (await ekm.InfoAsync("CONTOSO")).ShouldBeProxyError(404, "NotFound");
        (await ekm.MetadataAsync("k1", "contoso")).StatusCode.ShouldBe(200);
        (await ekm.MetadataAsync("K1", "contoso")).ShouldBeProxyError(404, "KeyNotFound");
    }

    // ---- 4.2: several prefixes ----------------------------------------------------------------------------------------------------

    [Fact]
    public async Task LongestPrefixWins_AndEveryNamespaceHasItsOwnKeys()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        factory.Namespaces.Add(new NamespaceDefinition { Name = "contoso", Prefix = "contoso" });
        factory.Namespaces.Add(new NamespaceDefinition { Name = "contoso-prod", Prefix = "contoso/prod" });
        factory.Namespaces.Add(new NamespaceDefinition { Name = "deep", Prefix = "a/b/c/d" });

        // The same key name in three namespaces, with three different keys.
        foreach (var ns in new[] { "_default", "contoso", "contoso-prod" })
        {
            factory.Keys.Create(ns, "shared-key", KeyType.Oct, 256);
        }

        factory.Keys.Create("contoso-prod", "prod-only", KeyType.Rsa, 2048);
        factory.Keys.Create("deep", "deep-key", KeyType.Oct, 256);

        var dek = Fx.Random(32);
        var wrapped = new Dictionary<string, byte[]>();
        foreach (var prefix in new string?[] { null, "contoso", "contoso/prod" })
        {
            var reply = await ekm.WrapAsync("shared-key", "A256KWP", dek, prefix);
            reply.StatusCode.ShouldBe(200, reply.Text);
            wrapped[prefix ?? "_default"] = reply.Value();
        }

        // Each wrapped value only unwraps in its own namespace.
        foreach (var prefix in new string?[] { null, "contoso", "contoso/prod" })
        {
            foreach (var other in new string?[] { null, "contoso", "contoso/prod" })
            {
                var reply = await ekm.UnwrapAsync("shared-key", "A256KWP", wrapped[prefix ?? "_default"], other);
                if (prefix == other)
                {
                    Fx.Same(reply.Value(), dek).ShouldBeTrue();
                }
                else
                {
                    reply.ShouldBeProxyError(400, "InvalidCiphertext");
                }
            }
        }

        // Longest prefix: /contoso/prod/... is namespace contoso-prod, not contoso (where "prod" would be a key name).
        (await ekm.MetadataAsync("prod-only", "contoso/prod")).StatusCode.ShouldBe(200);
        (await ekm.MetadataAsync("prod-only", "contoso")).ShouldBeProxyError(404, "KeyNotFound");
        (await ekm.MetadataAsync("prod-only")).ShouldBeProxyError(404, "KeyNotFound");
        (await ekm.InfoAsync("contoso/prod")).StatusCode.ShouldBe(200);

        // Multi-segment prefix of 4 segments.
        (await ekm.MetadataAsync("deep-key", "a/b/c/d")).StatusCode.ShouldBe(200);
        (await ekm.MetadataAsync("deep-key", "a/b/c")).ShouldBeProxyError(404, "NotFound");

        // Prefix segments match whole segments only.
        (await ekm.InfoAsync("contosoX")).ShouldBeProxyError(404, "NotFound");
        (await ekm.MetadataAsync("shared-key", "contoso/produce")).ShouldBeProxyError(404, "NotFound");
        (await ekm.InfoAsync("contoso/prod/extra")).ShouldBeProxyError(404, "NotFound");
    }

    [Fact]
    public async Task Namespaces_AddedAtRuntime_AreRoutedImmediately()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;

        (await ekm.InfoAsync("later")).ShouldBeProxyError(404, "NotFound");
        factory.Namespaces.Add(new NamespaceDefinition { Name = "later", Prefix = "later" });
        (await ekm.InfoAsync("later")).StatusCode.ShouldBe(200);
        factory.Namespaces.Remove("later");
        (await ekm.InfoAsync("later")).ShouldBeProxyError(404, "NotFound");
    }

    [Fact]
    public async Task SeedNamespaces_FromConfiguration_AreRoutedOnFirstStart()
    {
        var (factory, ekm) = await StartAsync(new EkmFactoryOptions
        {
            Configuration = new()
            {
                ["SeedNamespaces:1:Name"] = "seeded",
                ["SeedNamespaces:1:Prefix"] = "seeded/one",
                ["SeedNamespaces:1:ClientTrust:SubjectCommonNames:0"] = "contoso.managedhsmclient.azure.net",
            },
        });
        using var _ = factory;

        (await ekm.InfoAsync("seeded/one")).StatusCode.ShouldBe(200);
        factory.Namespaces.Get("seeded")!.ClientTrust.SubjectCommonNames.ShouldBe(["contoso.managedhsmclient.azure.net"]);
        factory.Namespaces.Get("_default").ShouldNotBeNull();
    }

    // ---- the documented validation order -------------------------------------------------------------------------------------------

    [Fact]
    public async Task ValidationOrder_IsRoute_Method_ApiVersion_KeyName_ContentType_Body_RequestContext_Engine()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        const string badKey = "bad_key";
        var wrap = EkmClient.WrapBody("A256KWP", "AAAA");

        // 1. route beats everything: an unknown path is 404 even for GET with a bad version.
        (await ekm.SendAsync(HttpMethod.Get, "/nope/aes-key-1/rewrap?api-version=9.9")).ShouldBeProxyError(404, "NotFound");

        // 2. method beats api-version, key name, content type and body.
        (await ekm.SendAsync(HttpMethod.Get, $"/{badKey}/wrapkey?api-version=9.9", EkmClient.JsonBody("{", "text/plain"))).ShouldBeProxyError(405, "MethodNotAllowed");

        // 3. api-version beats key name, content type and body.
        (await ekm.PostAsync($"/{badKey}/wrapkey?api-version=9.9", "{", "text/plain")).ShouldBeProxyError(400, "UnsupportedApiVersion");

        // 4. key name beats content type and body.
        (await ekm.PostAsync(EkmClient.Path(null, badKey, "wrapkey"), "{", "text/plain")).ShouldBeProxyError(400, "InvalidKeyName");

        // 5. content type beats the body.
        var contentType = await ekm.PostAsync(EkmClient.Path(null, "aes-key-1", "wrapkey"), "{", "text/plain");
        contentType.Json().RootElement.GetProperty("message").GetString().ShouldBe("The Content-Type must be application/json");

        // 6. body (size/JSON) beats a missing key and an unknown alg.
        var badJson = await ekm.PostAsync(EkmClient.Path(null, "missing-key", "wrapkey"), "{");
        badJson.Json().RootElement.GetProperty("message").GetString().ShouldBe("The request body is not a valid JSON object");

        // 7. request_context beats alg, value and the engine.
        (await ekm.PostAsync(EkmClient.Path(null, "missing-key", "wrapkey"), """{"alg":"nope","value":"!"}""")).Json()
            .RootElement.GetProperty("message").GetString().ShouldBe("The request_context field is required");

        // 8. alg syntax and value syntax (400) come before the engine's 404.
        (await ekm.PostAsync(EkmClient.Path(null, "missing-key", "wrapkey"), EkmClient.WrapBody("RSA1_5", "AAAA"))).ShouldBeProxyError(400, "UnsupportedAlgorithm");
        (await ekm.PostAsync(EkmClient.Path(null, "missing-key", "wrapkey"), EkmClient.WrapBody("A256KWP", "a+b/"))).ShouldBeProxyError(400, "InvalidRequest");

        // 9. then the engine: unknown key 404.
        (await ekm.PostAsync(EkmClient.Path(null, "missing-key", "wrapkey"), wrap)).ShouldBeProxyError(404, "KeyNotFound");
    }

    [Fact]
    public async Task EngineAvailability_IsCheckedAfterTheRequestIsValid()
    {
        var availability = new FixedAvailability(available: false);
        var (factory, ekm) = await StartAsync(new EkmFactoryOptions { Availability = availability });
        using var _ = factory;

        (await ekm.PostAsync(EkmClient.Path(null, null, "info", null))).ShouldBeProxyError(400, "UnsupportedApiVersion");
        (await ekm.PostAsync(EkmClient.Path(null, null, "info"), "{")).ShouldBeProxyError(400, "InvalidRequest");
        (await ekm.PostAsync(EkmClient.Path(null, null, "info"))).ShouldBeProxyError(503, "HsmUnavailable");
    }

    // ---- 4.4: every error is a ProxyError --------------------------------------------------------------------------------------------

    [Fact]
    public async Task EveryErrorBody_IsExactlyAProxyError_InSnakeCase_AsApplicationJson()
    {
        var (factory, ekm) = await StartAsync();
        using var _ = factory;
        var key = "aes-key-1";
        var ok = EkmClient.WrapBody("A256KWP", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        var cases = new List<(Task<EkmReply> Reply, int Status, string Code)>
        {
            (ekm.PostAsync("/nope?api-version=0.1-preview"), 404, "NotFound"),
            (ekm.SendAsync(HttpMethod.Get, EkmClient.Path(null, null, "info")), 405, "MethodNotAllowed"),
            (ekm.PostAsync(EkmClient.Path(null, null, "info", null)), 400, "UnsupportedApiVersion"),
            (ekm.PostAsync(EkmClient.Path(null, "bad.key", "metadata")), 400, "InvalidKeyName"),
            (ekm.PostAsync(EkmClient.Path(null, key, "metadata"), "{}", "text/plain"), 400, "InvalidRequest"),
            (ekm.PostAsync(EkmClient.Path(null, key, "metadata"), "{"), 400, "InvalidRequest"),
            (ekm.PostAsync(EkmClient.Path(null, key, "metadata"), "{}"), 400, "InvalidRequest"),
            (ekm.PostAsync(EkmClient.Path(null, "missing", "metadata")), 404, "KeyNotFound"),
            (ekm.PostAsync(EkmClient.Path(null, key, "wrapkey"), EkmClient.WrapBody("RSA-OAEP", "AAAA")), 400, "UnsupportedAlgorithm"),
            (ekm.PostAsync(EkmClient.Path(null, key, "wrapkey"), EkmClient.WrapBody("A256KW", "AAAA")), 400, "InvalidRequest"),
            (ekm.PostAsync(EkmClient.Path(null, key, "unwrapkey"), ok), 400, "InvalidCiphertext"),
        };

        foreach (var (reply, status, code) in cases)
        {
            (await reply).ShouldBeProxyError(status, code);
        }
    }

    [Fact]
    public async Task AnUnexpectedBackendFailure_IsAGenericInternalError_WithoutDetails()
    {
        using var factory = new EkmFactory(new EkmFactoryOptions
        {
            ConfigureServices = services => services.AddSingleton<ICryptoBackend>(new ThrowingBackend()),
        });
        var ekm = factory.CreateEkmClient();

        var reply = await ekm.WrapAsync("k", "A256KWP", Fx.Random(32));
        var meta = await ekm.MetadataAsync("k");

        reply.ShouldBeProxyError(500, "InternalError");
        meta.ShouldBeProxyError(500, "InternalError");
        reply.Json().RootElement.GetProperty("message").GetString().ShouldBe("An internal error occurred");
        reply.Text.ShouldNotContain("SECRET-DETAIL");
        reply.Text.ShouldNotContain("at EkmMock");
        reply.Text.ShouldNotContain(nameof(InvalidOperationException));

        // The log carries the exception type only, never its message or stack.
        var errors = factory.Logs.Entries.Where(static e => e.Level == Microsoft.Extensions.Logging.LogLevel.Error).ToList();
        errors.Count.ShouldBe(2);
        errors[0].Fields["exception_type"].ShouldBe(nameof(InvalidOperationException));
        factory.Logs.AllText.ShouldNotContain("SECRET-DETAIL");
    }

    private sealed class ThrowingBackend : ICryptoBackend
    {
        public BackendInfo Info => new("v", "p");

        public bool IsAvailable => true;

        public KeyMetadata? GetMetadata(KeyRef key) => throw new InvalidOperationException("SECRET-DETAIL-0123 key material");

        public byte[] Wrap(KeyRef key, WrapAlgorithm alg, ReadOnlySpan<byte> dek) => throw new InvalidOperationException("SECRET-DETAIL-0123 key material");

        public byte[] Unwrap(KeyRef key, WrapAlgorithm alg, ReadOnlySpan<byte> wrapped) => throw new InvalidOperationException("SECRET-DETAIL-0123 key material");
    }

    [Fact]
    public async Task EveryRequest_GetsAnExchangeIdThatIncreases()
    {
        var filter = new CaptureFilter();
        var (factory, ekm) = await StartAsync(new EkmFactoryOptions { ConfigureServices = s => s.AddSingleton<IStartupFilter>(filter) });
        using var _ = factory;

        await ekm.InfoAsync();
        await ekm.SendAsync(HttpMethod.Get, "/nope");
        await ekm.MetadataAsync("aes-key-1");

        filter.Seen.Select(static s => s.ExchangeId).ShouldBe([1, 2, 3]);
        filter.Seen.Select(static s => s.StatusCode).ShouldBe([200, 404, 200]);
        filter.Seen[1].Route.ShouldBeNull();
        filter.Seen[1].ErrorCode.ShouldBe("NotFound");
    }
}
