using System.Net;
using System.Text.Json;
using EkmMock.Crypto;
using Microsoft.Extensions.DependencyInjection;

namespace EkmMock.Server.Tests;

/// <summary>Spec 14 test 1 and the 503 behaviour of info (4.6, 14 test 19).</summary>
public sealed class InfoTests
{
    [Fact]
    public async Task Info_Returns200WithTheFiveConfiguredFields()
    {
        using var factory = new EkmFactory();
        var ekm = factory.CreateEkmClient();

        var reply = await ekm.InfoAsync();

        reply.StatusCode.ShouldBe(200, reply.Text);
        reply.ContentType.ShouldNotBeNull().ShouldStartWith("application/json");
        using var doc = reply.Json();
        doc.RootElement.EnumerateObject().Select(static p => p.Name).Order().ShouldBe(
            ["api_version", "ekm_product", "ekm_vendor", "proxy_name", "proxy_vendor"]);
        doc.RootElement.GetProperty("api_version").GetString().ShouldBe("0.1-preview");
        doc.RootElement.GetProperty("proxy_vendor").GetString().ShouldBe("Remco Test");
        doc.RootElement.GetProperty("proxy_name").GetString().ShouldBe("EkmMock v0.2.0");
        doc.RootElement.GetProperty("ekm_vendor").GetString().ShouldBe("EkmMock");
        doc.RootElement.GetProperty("ekm_product").GetString().ShouldBe("EkmMock Software HSM v0.2.0");
    }

    [Fact]
    public async Task Info_ValuesAreConfigurable()
    {
        using var factory = new EkmFactory(new EkmFactoryOptions
        {
            Configuration = new()
            {
                ["ProxyInfo:ApiVersion"] = "1.0",
                ["ProxyInfo:ProxyVendor"] = "Contoso",
                ["ProxyInfo:ProxyName"] = "Contoso Proxy 9",
                ["ProxyInfo:EkmVendor"] = "Fabrikam",
                ["ProxyInfo:EkmProduct"] = "Fabrikam HSM 3",
            },
        });

        var reply = await factory.CreateEkmClient().InfoAsync();

        reply.StatusCode.ShouldBe(200);
        using var doc = reply.Json();
        doc.RootElement.GetProperty("api_version").GetString().ShouldBe("1.0");
        doc.RootElement.GetProperty("proxy_vendor").GetString().ShouldBe("Contoso");
        doc.RootElement.GetProperty("proxy_name").GetString().ShouldBe("Contoso Proxy 9");
        doc.RootElement.GetProperty("ekm_vendor").GetString().ShouldBe("Fabrikam");
        doc.RootElement.GetProperty("ekm_product").GetString().ShouldBe("Fabrikam HSM 3");
    }

    [Fact]
    public async Task Info_Returns503HsmUnavailable_WhenTheEngineIsUnavailable()
    {
        var availability = new FixedAvailability(available: false);
        using var factory = new EkmFactory(new EkmFactoryOptions { Availability = availability });
        var ekm = factory.CreateEkmClient();

        (await ekm.InfoAsync()).ShouldBeProxyError(503, "HsmUnavailable");

        availability.IsAvailable = true;
        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
    }

    [Fact]
    public async Task KeyOperations_Return503_WhenTheEngineIsUnavailable()
    {
        var availability = new FixedAvailability(available: true);
        using var factory = new EkmFactory(new EkmFactoryOptions { Availability = availability });
        factory.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
        var ekm = factory.CreateEkmClient();
        availability.IsAvailable = false;

        (await ekm.MetadataAsync("aes-key-1")).ShouldBeProxyError(503, "HsmUnavailable");
        (await ekm.WrapAsync("aes-key-1", "A256KWP", Fx.Random(32))).ShouldBeProxyError(503, "HsmUnavailable");
        (await ekm.UnwrapAsync("aes-key-1", "A256KWP", Fx.Random(40))).ShouldBeProxyError(503, "HsmUnavailable");
    }

    [Fact]
    public async Task Info_StillWorks_WhenKeysAreCorrupt_ButTheirOperationsAnswer503()
    {
        // Spec 14 test 19: a wrong master key marks every key Corrupt, the app still serves info.
        using var data = new TempDir();
        using (var first = new EkmFactory(new EkmFactoryOptions { DataPath = data.Path, MasterKeyLabel = "right" }))
        {
            first.Keys.Create("_default", "aes-key-1", KeyType.Oct, 256);
            first.Keys.Create("_default", "rsa-key-1", KeyType.Rsa, 2048);
        }

        using var wrong = new EkmFactory(new EkmFactoryOptions { DataPath = data.Path, MasterKeyLabel = "wrong" });
        var ekm = wrong.CreateEkmClient();

        (await ekm.InfoAsync()).StatusCode.ShouldBe(200);
        wrong.Backend.LoadReport.CorruptKeys.ShouldBe(2);
        (await ekm.MetadataAsync("aes-key-1")).ShouldBeProxyError(503, "HsmUnavailable");
        (await ekm.WrapAsync("aes-key-1", "A256KWP", Fx.Random(32))).ShouldBeProxyError(503, "HsmUnavailable");
        (await ekm.UnwrapAsync("rsa-key-1", "RSA-OAEP-256", Fx.Random(256))).ShouldBeProxyError(503, "HsmUnavailable");
    }

    [Fact]
    public async Task Info_WorksWithoutAnyKeys_AndIgnoresUnknownRequestFields()
    {
        using var factory = new EkmFactory();
        var reply = await factory.CreateEkmClient().PostAsync(
            EkmClient.Path(null, null, "info"),
            """{"request_context":{"correlation_id":"x","future":{"a":[1,2]}},"something_new":true}""");

        reply.StatusCode.ShouldBe(200, reply.Text);
    }
}
