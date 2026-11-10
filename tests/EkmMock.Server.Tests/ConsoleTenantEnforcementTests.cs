using System.Net;
using System.Security.Claims;
using EkmMock.Server.WebConsole;

namespace EkmMock.Server.Tests;

/// <summary>
/// Security review L2: in EntraId mode the tenant ID must be a GUID (the console refuses to start otherwise) and the token's tenant claim (<c>tid</c>) is <b>always</b> enforced:
/// a token without it, or with another tenant's, is not let in, whatever the allow-list says.
/// </summary>
public sealed class ConsoleTenantEnforcementTests
{
    private const string Tenant = "44444444-4444-4444-4444-444444444444";
    private const string Oid = "11111111-1111-1111-1111-111111111111";

    private static EntraIdOptions Options(string? tenant = Tenant) => new() { TenantId = tenant, ClientId = "55555555-5555-5555-5555-555555555555", AllowedObjectIds = [Oid] };

    private static ClaimsPrincipal Principal(string? tid, string? longFormTid = null, string oid = Oid)
    {
        var claims = new List<Claim> { new("oid", oid) };
        if (tid is not null)
        {
            claims.Add(new Claim("tid", tid));
        }

        if (longFormTid is not null)
        {
            claims.Add(new Claim("http://schemas.microsoft.com/identity/claims/tenantid", longFormTid));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    // ---- startup validation ----

    private static IReadOnlyList<string> Validate(string? tenant)
    {
        var options = new ConsoleOptions { Auth = ConsoleAuthMode.EntraId, EntraId = Options(tenant) };
        return ConsoleConfigurationValidator.Validate(
            options,
            new ConsoleEndpointOptions { Url = "https://0.0.0.0:8080" },
            "https://0.0.0.0:8443",
            environment: name => name == ConsoleSecrets.ClientSecretVariable ? "present" : null);
    }

    [Theory]
    [InlineData("44444444-4444-4444-4444-444444444444")]
    [InlineData("  44444444-4444-4444-4444-444444444444  ")]
    [InlineData("ABCDEF01-2345-6789-ABCD-EF0123456789")]
    public void AGuidTenantId_IsAccepted(string tenant) => Validate(tenant).ShouldBeEmpty();

    [Theory]
    [InlineData("common")]
    [InlineData("organizations")]
    [InlineData("consumers")]
    [InlineData("contoso.onmicrosoft.com")]
    [InlineData("44444444444444444444444444444444")]
    [InlineData("{44444444-4444-4444-4444-444444444444}")]
    [InlineData("(44444444-4444-4444-4444-444444444444)")]
    [InlineData("44444444-4444-4444-4444")]
    [InlineData("44444444-4444-4444-4444-44444444444g")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("<REPLACE-with-your-tenant-id>")]
    public void ATenantIdThatIsNotAGuid_RefusesToStart_WithAClearMessage(string tenant)
    {
        var problems = Validate(tenant);

        problems.Count.ShouldBe(1);
        problems[0].ShouldContain("Console:EntraId:TenantId must be the tenant");
        problems[0].ShouldContain("GUID");
        problems[0].ShouldContain("'common'");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AMissingTenantId_StillRefusesToStart(string? tenant)
        => Validate(tenant).ShouldContain(static p => p.Contains("requires Console:EntraId:TenantId", StringComparison.Ordinal));

    // ---- the policy ----

    [Fact]
    public void ATokenWithTheConfiguredTenant_IsAllowed_InEitherClaimForm()
    {
        ConsoleAccessPolicy.IsAllowed(Principal(Tenant), Options()).ShouldBeTrue();
        ConsoleAccessPolicy.IsAllowed(Principal(tid: null, longFormTid: Tenant), Options()).ShouldBeTrue();
        ConsoleAccessPolicy.IsAllowed(Principal(Tenant.ToUpperInvariant()), Options()).ShouldBeTrue();
    }

    [Fact]
    public void ATokenWithoutATenantClaim_IsRefused_EvenForAnAllowedObjectId()
        => ConsoleAccessPolicy.IsAllowed(Principal(tid: null), Options()).ShouldBeFalse();

    [Theory]
    [InlineData("99999999-9999-9999-9999-999999999999")]
    [InlineData("")]
    [InlineData("not-a-guid")]
    [InlineData("common")]
    public void ATokenOfAnotherTenantOrAnUnreadableOne_IsRefused(string tid)
        => ConsoleAccessPolicy.IsAllowed(Principal(tid), Options()).ShouldBeFalse();

    [Fact]
    public void ATokenWhoseShortAndLongTenantClaimsDisagree_UsesTheShortOne()
        => ConsoleAccessPolicy.IsAllowed(Principal("99999999-9999-9999-9999-999999999999", longFormTid: Tenant), Options()).ShouldBeFalse();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("common")]
    [InlineData("contoso.onmicrosoft.com")]
    public void AConfiguredTenantThatIsNotAGuid_FailsClosed_NobodyIsAllowed(string? configured)
        => ConsoleAccessPolicy.IsAllowed(Principal(Tenant), Options(configured)).ShouldBeFalse();

    // ---- through the real production authorization policy ----

    [Fact]
    public async Task OnTheRealConsole_ATokenWithoutATenantClaim_Gets403_AndOneWithTheTenant_Gets200()
    {
        await using var host = await ConsoleTestHost.StartAsync(entra: true);
        using var console = host.Host.CreateConsoleClient();

        using var noTenant = await console.SendAsync(HttpMethod.Get, "/api/console/status", request =>
        {
            request.Headers.Add("X-Test-Oid", ConsoleTestHost.AllowedOid);
            request.Headers.Add("X-Test-No-Tid", "1");
        });
        using var withTenant = await console.SendAsync(HttpMethod.Get, "/api/console/status", request => request.Headers.Add("X-Test-Oid", ConsoleTestHost.AllowedOid));
        using var anotherTenant = await console.SendAsync(HttpMethod.Get, "/api/console/status", request =>
        {
            request.Headers.Add("X-Test-Oid", ConsoleTestHost.AllowedOid);
            request.Headers.Add("X-Test-Tid", "99999999-9999-9999-9999-999999999999");
        });

        noTenant.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        anotherTenant.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        withTenant.StatusCode.ShouldBe(HttpStatusCode.OK);
    }
}
