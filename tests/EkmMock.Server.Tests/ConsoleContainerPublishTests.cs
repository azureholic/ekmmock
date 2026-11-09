#pragma warning disable xUnit1051 // The console tests use HttpClients with a bounded timeout; they do not need per-call cancellation tokens.

using System.Net;
using EkmMock.Server.Hosting;
using EkmMock.Server.WebConsole;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>
/// Open question 33 (M9): the container-publish opt-in. A <c>LoopbackOnly</c> console may bind a non-loopback address <b>only</b> when <c>EKMMOCK_CONSOLE_CONTAINER_PUBLISH=true</c>, the process is
/// demonstrably in a container and the auth mode is <c>LoopbackOnly</c>; the spec 14 test 17 refusal is unchanged everywhere else. While active the console checks the source address of every request.
/// </summary>
public sealed class ConsoleContainerPublishTests
{
    private sealed class FakeProbe(bool inContainer) : IContainerProbe
    {
        public bool IsRunningInContainer => inContainer;
    }

    private static Func<string, string?> Env(string? publish) => name => name == ConsoleContainerPublish.Variable ? publish : null;

    private static ConsoleOptions Loopback() => new() { Auth = ConsoleAuthMode.LoopbackOnly };

    private static ConsoleOptions Entra() => new()
    {
        Auth = ConsoleAuthMode.EntraId,
        EntraId =
        {
            TenantId = "44444444-4444-4444-4444-444444444444",
            ClientId = "55555555-5555-5555-5555-555555555555",
            AllowedObjectIds = ["11111111-1111-1111-1111-111111111111"],
        },
    };

    private static IReadOnlyList<string> Validate(ConsoleOptions options, string url, string? publish, bool inContainer)
        => ConsoleConfigurationValidator.Validate(
            options,
            new ConsoleEndpointOptions { Url = url },
            "https://0.0.0.0:8443",
            environment: name => name == ConsoleSecrets.ClientSecretVariable ? "present" : name == ConsoleContainerPublish.Variable ? publish : null,
            container: new FakeProbe(inContainer));

    // ---- the container probe ----

    [Theory]
    [InlineData(true, "true", true, false, null, true)] // Docker: the image's marker plus /.dockerenv
    [InlineData(true, "TRUE", false, true, null, true)] // Podman: /run/.containerenv
    [InlineData(true, "true", false, false, "10.0.0.1", true)] // Kubernetes
    [InlineData(true, "true", false, false, null, false)] // the variable alone is not enough
    [InlineData(true, null, true, true, "10.0.0.1", false)] // marker files without the .NET image marker
    [InlineData(true, "false", true, false, null, false)]
    [InlineData(true, "1", true, false, null, false)]
    [InlineData(false, "true", true, true, "10.0.0.1", false)] // never on a non-Linux OS
    public void TheProbe_RequiresLinux_TheDotNetImageMarker_AndAContainerRuntimeMarker(bool linux, string? dotnetMarker, bool dockerenv, bool containerenv, string? kubernetes, bool expected)
    {
        var detected = SystemContainerProbe.Detect(
            linux,
            name => name switch
            {
                "DOTNET_RUNNING_IN_CONTAINER" => dotnetMarker,
                "KUBERNETES_SERVICE_HOST" => kubernetes,
                _ => null,
            },
            path => path switch
            {
                "/.dockerenv" => dockerenv,
                "/run/.containerenv" => containerenv,
                _ => false,
            });

        detected.ShouldBe(expected);
    }

    [Fact]
    public void TheSystemProbe_IsFalseOnThisTestMachine_UnlessItReallyIsAContainer()
    {
        // The matrix above pins the logic; this pins that a developer machine (Windows) or a CI runner is never mistaken for a container by the real probe.
        if (!File.Exists("/.dockerenv") && !File.Exists("/run/.containerenv"))
        {
            new SystemContainerProbe().IsRunningInContainer.ShouldBeFalse();
        }
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("TRUE", true)]
    [InlineData("True", true)]
    [InlineData("false", false)]
    [InlineData("1", false)]
    [InlineData("yes", false)]
    [InlineData("on", false)]
    [InlineData(" true", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void TheOptIn_IsRequestedOnlyByTheWordTrue_EveryOtherValueFailsClosed(string? value, bool expected)
        => ConsoleContainerPublish.IsRequested(Env(value)).ShouldBe(expected);

    // ---- the validation matrix (container flag on/off, in a container or not, auth mode, bind) ----

    [Theory]
    [InlineData("https://0.0.0.0:8080")]
    [InlineData("https://[::]:8080")]
    [InlineData("https://*:8080")]
    [InlineData("https://10.1.2.3:8080")]
    public void LoopbackOnly_WithANonLoopbackBind_IsAccepted_OnlyWithTheOptIn_InAContainer(string url)
    {
        Validate(Loopback(), url, "true", inContainer: true).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("https://0.0.0.0:8080")]
    [InlineData("https://[::]:8080")]
    [InlineData("https://*:8080")]
    [InlineData("https://10.1.2.3:8080")]
    [InlineData("https://203.0.113.7:8080")]
    public void LoopbackOnly_WithANonLoopbackBind_StaysRefused_WithoutTheOptIn_EvenInAContainer(string url)
    {
        // Spec 14 test 17 is unchanged: the container alone changes nothing.
        var problems = Validate(Loopback(), url, publish: null, inContainer: true);

        problems.Count.ShouldBe(1);
        problems[0].ShouldContain("LoopbackOnly");
        Validate(Loopback(), url, "false", inContainer: true).Count.ShouldBe(1);
        Validate(Loopback(), url, "1", inContainer: true).Count.ShouldBe(1);
        Validate(Loopback(), url, "yes", inContainer: true).Count.ShouldBe(1);
    }

    [Theory]
    [InlineData("https://0.0.0.0:8080")]
    [InlineData("https://[::]:8080")]
    [InlineData("https://203.0.113.7:8080")]
    public void TheOptIn_IsRefused_WhenTheProcessIsNotInAContainer_AndTheBindStaysRefused(string url)
    {
        var problems = Validate(Loopback(), url, "true", inContainer: false);

        problems.ShouldContain(static p => p.Contains(ConsoleContainerPublish.Variable, StringComparison.Ordinal) && p.Contains("container", StringComparison.Ordinal));
        problems.ShouldContain(static p => p.Contains("LoopbackOnly requires the console to bind to a loopback address", StringComparison.Ordinal));
    }

    [Fact]
    public void TheOptIn_WithALoopbackBind_NotInAContainer_IsStillRefused_SoACopiedVariableIsNotSilentlyIgnored()
    {
        var problems = Validate(Loopback(), "https://127.0.0.1:8080", "true", inContainer: false);

        problems.Count.ShouldBe(1);
        problems[0].ShouldContain(ConsoleContainerPublish.Variable);
    }

    [Fact]
    public void TheOptIn_WithALoopbackBind_InAContainer_IsAccepted_ButChangesNothing()
        => Validate(Loopback(), "https://127.0.0.1:8080", "true", inContainer: true).ShouldBeEmpty();

    [Theory]
    [InlineData("https://0.0.0.0:8080", true)]
    [InlineData("https://0.0.0.0:8080", false)]
    [InlineData("https://127.0.0.1:8080", true)]
    [InlineData("https://127.0.0.1:8080", false)]
    public void TheOptIn_IsNeverApplicableToEntraId_InOrOutOfAContainer(string url, bool inContainer)
    {
        var problems = Validate(Entra(), url, "true", inContainer);

        problems.ShouldContain(static p => p.Contains(ConsoleContainerPublish.Variable, StringComparison.Ordinal) && p.Contains("EntraId", StringComparison.Ordinal));
        problems.Count.ShouldBe(1);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void EntraId_WithoutTheOptIn_IsUnchanged_AnyBindIsAccepted(bool inContainer)
        => Validate(Entra(), "https://0.0.0.0:8080", publish: null, inContainer).ShouldBeEmpty();

    [Fact]
    public void TheOptIn_DoesNotRelaxAnyOtherRule()
    {
        // The port rule, the URL rule and the client-secret rule still apply.
        Validate(Loopback(), "https://0.0.0.0:8443", "true", inContainer: true).ShouldContain(static p => p.Contains("different ports", StringComparison.Ordinal));
        Validate(Loopback(), "http://0.0.0.0:8080", "true", inContainer: true).ShouldNotBeEmpty();
        var withSecret = Loopback();
        withSecret.EntraId.ClientSecret = "x";
        Validate(withSecret, "https://0.0.0.0:8080", "true", inContainer: true).ShouldContain(static p => p.Contains("ClientSecret", StringComparison.Ordinal));
    }

    // ---- ConsoleExposure: what is active, and the start-up warning ----

    private static (ConsoleExposure Exposure, CapturingLoggerProvider Logs) Resolve(ConsoleOptions options, string url, string? publish, bool inContainer)
    {
        var logs = new CapturingLoggerProvider();
        var exposure = ConsoleExposure.Resolve(options, new ConsoleEndpointOptions { Url = url }, new FakeProbe(inContainer), logs.CreateLogger("test"), Env(publish));
        return (exposure, logs);
    }

    [Fact]
    public void TheExposure_IsActive_OnlyForLoopbackOnly_WithTheOptIn_InAContainer_OnANonLoopbackBind()
    {
        Resolve(Loopback(), "https://0.0.0.0:8080", "true", true).Exposure.ContainerPublishActive.ShouldBeTrue();
        Resolve(Loopback(), "https://10.0.0.4:8080", "true", true).Exposure.ContainerPublishActive.ShouldBeTrue();

        Resolve(Loopback(), "https://0.0.0.0:8080", null, true).Exposure.ContainerPublishActive.ShouldBeFalse();
        Resolve(Loopback(), "https://0.0.0.0:8080", "true", false).Exposure.ContainerPublishActive.ShouldBeFalse();
        Resolve(Loopback(), "https://127.0.0.1:8080", "true", true).Exposure.ContainerPublishActive.ShouldBeFalse();
        Resolve(Entra(), "https://0.0.0.0:8080", "true", true).Exposure.ContainerPublishActive.ShouldBeFalse();
        Resolve(Loopback(), "not a url", "true", true).Exposure.ContainerPublishActive.ShouldBeFalse();
    }

    [Fact]
    public void WhenActive_AProminentStartupWarning_SaysThatTheHostPublishMustBeLoopbackOnly()
    {
        var (_, logs) = Resolve(Loopback(), "https://0.0.0.0:8080", "true", true);

        var warning = logs.Entries.ShouldHaveSingleItem();
        warning.Level.ShouldBe(LogLevel.Warning);
        warning.Message.ShouldContain("127.0.0.1");
        warning.Message.ShouldContain("ONLY");
        warning.Message.ShouldContain(ConsoleContainerPublish.Variable);

        Resolve(Loopback(), "https://0.0.0.0:8080", null, true).Logs.Entries.ShouldBeEmpty();
    }

    // ---- the source-address check ----

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.9.9.9", true)]
    [InlineData("::1", true)]
    [InlineData("10.0.0.1", true)]
    [InlineData("10.255.255.254", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.17.0.1", true)] // the default Docker bridge gateway
    [InlineData("172.31.255.255", true)]
    [InlineData("192.168.0.10", true)]
    [InlineData("192.168.65.1", true)] // Docker Desktop's host gateway
    [InlineData("169.254.10.10", true)]
    [InlineData("fd00::1", true)] // unique local
    [InlineData("fc00::1", true)]
    [InlineData("fdff:ffff::1", true)]
    [InlineData("fe80::1", true)] // link-local
    [InlineData("febf::1", true)]
    [InlineData("::ffff:172.17.0.1", true)] // IPv4-mapped
    [InlineData("::ffff:10.1.2.3", true)]
    [InlineData("::ffff:127.0.0.1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("1.1.1.1", false)]
    [InlineData("203.0.113.7", false)]
    [InlineData("172.15.255.255", false)] // just outside 172.16/12
    [InlineData("172.32.0.1", false)]
    [InlineData("192.169.0.1", false)]
    [InlineData("11.0.0.1", false)]
    [InlineData("100.64.0.1", false)] // CGNAT is not a container bridge
    [InlineData("169.253.1.1", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("2606:4700::1111", false)]
    [InlineData("fec0::1", false)] // deprecated site-local
    [InlineData("::", false)]
    [InlineData("ff02::1", false)]
    [InlineData("::ffff:8.8.8.8", false)]
    [InlineData("::ffff:100.64.0.1", false)]
    [InlineData("64:ff9b::808:808", false)] // NAT64 of 8.8.8.8
    public void TheSourceAddressCheck_AcceptsLoopbackAndPrivateRanges_AndNothingElse(string address, bool expected)
        => ConsoleContainerPublish.IsContainerNetworkSource(IPAddress.Parse(address)).ShouldBe(expected);

    private static ConsoleRequestGuardMiddleware Guard(ConsoleOptions options, ConsoleExposure exposure)
        => new(static _ => Task.CompletedTask, Options.Create(options), exposure);

    private static DefaultHttpContext Request(IPAddress? remote, string host = "127.0.0.1:8080")
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Path = "/";
        context.Request.Scheme = "https";
        context.Request.Host = new HostString(host);
        context.Connection.RemoteIpAddress = remote;
        return context;
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("172.17.0.1", true)]
    [InlineData("10.0.5.5", true)]
    [InlineData("192.168.65.1", true)]
    [InlineData("fd12::5", true)]
    [InlineData("::ffff:172.17.0.1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("203.0.113.9", false)]
    [InlineData("2001:db8::9", false)]
    [InlineData("::ffff:8.8.8.8", false)]
    public void WhenTheOptInIsActive_TheGuardServesOnlyContainerNetworkSources_With403(string source, bool served)
    {
        var guard = Guard(Loopback(), ConsoleExposure.ContainerPublish);

        var refusal = guard.Check(Request(IPAddress.Parse(source)));

        (refusal is null).ShouldBe(served, refusal);
        if (!served)
        {
            refusal.ShouldNotBeNull().ShouldContain("container network");
        }
    }

    [Fact]
    public async Task WhenTheOptInIsActive_ARefusedSourceGetsA403_AndNeverReachesTheApplication()
    {
        var reached = false;
        var guard = new ConsoleRequestGuardMiddleware(_ => { reached = true; return Task.CompletedTask; }, Options.Create(Loopback()), ConsoleExposure.ContainerPublish);
        var context = Request(IPAddress.Parse("8.8.8.8"));
        context.Response.Body = new MemoryStream();

        await guard.InvokeAsync(context);

        context.Response.StatusCode.ShouldBe(StatusCodes.Status403Forbidden);
        reached.ShouldBeFalse();
    }

    [Fact]
    public void WhenTheOptInIsActive_TheSourceCheckIsNotSwitchedOffByEnforceLoopbackClient()
    {
        var options = Loopback();
        options.EnforceLoopbackClient = false;

        Guard(options, ConsoleExposure.ContainerPublish).Check(Request(IPAddress.Parse("8.8.8.8"))).ShouldNotBeNull();
    }

    [Fact]
    public void WhenTheOptInIsActive_TheHostHeaderAndOriginRulesStillApply()
    {
        var guard = Guard(Loopback(), ConsoleExposure.ContainerPublish);

        guard.Check(Request(IPAddress.Parse("172.17.0.1"), "evil.example:8080")).ShouldNotBeNull("DNS rebinding defence stays");
        guard.Check(Request(IPAddress.Parse("172.17.0.1"), "localhost:8080")).ShouldBeNull();
        guard.Check(Request(null)).ShouldBeNull(); // the in-process test host has no socket
    }

    [Fact]
    public void WithoutTheOptIn_AContainerBridgeSourceIsRefused_AsBefore()
    {
        // 172.17.0.1 is accepted only while the opt-in is active; the normal LoopbackOnly rule is still "loopback peers only".
        Guard(Loopback(), ConsoleExposure.None).Check(Request(IPAddress.Parse("172.17.0.1"))).ShouldNotBeNull();
        Guard(Loopback(), ConsoleExposure.None).Check(Request(IPAddress.Loopback)).ShouldBeNull();
    }

    [Fact]
    public void EntraId_IsNotAffectedByTheExposure_EvenIfSomeoneBuildsItActive()
    {
        // The guard's EntraId branch never looks at the source address (the sign-in is the access control): the opt-in cannot change it either way.
        Guard(Entra(), ConsoleExposure.ContainerPublish).Check(Request(IPAddress.Parse("203.0.113.50"), "console.contoso.example")).ShouldBeNull();
    }

    // ---- the real host (process environment is global, so these run alone) ----

    [Collection(ProcessEnvironmentCollection.Name)]
    public sealed class RealHost
    {
        private static async Task<T> WithOptIn<T>(string? value, Func<Task<T>> body)
        {
            var before = Environment.GetEnvironmentVariable(ConsoleContainerPublish.Variable);
            Environment.SetEnvironmentVariable(ConsoleContainerPublish.Variable, value);
            try
            {
                return await body();
            }
            finally
            {
                Environment.SetEnvironmentVariable(ConsoleContainerPublish.Variable, before);
            }
        }

        private static RealEkmHostOptions Options(TestPki pki, bool inContainer, string consoleUrl = "https://0.0.0.0:0") => new()
        {
            Pki = pki,
            Configuration = { ["Endpoints:Console:Url"] = consoleUrl },
            ConfigureServices = services => services.AddSingleton<IContainerProbe>(new FakeProbe(inContainer)),
        };

        [Fact]
        public async Task InASimulatedContainer_WithTheOptIn_TheConsoleBindsAllInterfaces_ShowsTheBanner_AndWarns()
        {
            using var pki = new TestPki();

            await WithOptIn("true", async () =>
            {
                await using var host = await RealEkmHost.StartAsync(Options(pki, inContainer: true));
                using var console = host.CreateConsoleClient();

                using var health = await console.GetAsync("/healthz");
                health.StatusCode.ShouldBe(HttpStatusCode.OK);

                // The banner itself is a component of the interactive circuit (bUnit test in the console tests); the status the layout reads says the opt-in is active.
                var status = await console.GetStringAsync("/api/console/status");
                status.ShouldContain("\"container_publish\":true");

                host.Logs.Entries.ShouldContain(static e => e.Level == LogLevel.Warning && e.Message.Contains("127.0.0.1", StringComparison.Ordinal) && e.Message.Contains(ConsoleContainerPublish.Variable, StringComparison.Ordinal));
                return 0;
            });
        }

        [Fact]
        public async Task InASimulatedContainer_WithoutTheOptIn_TheHostRefusesToStart_ExactlyAsBefore()
        {
            using var pki = new TestPki();

            await WithOptIn(null, async () =>
            {
                var exception = await Should.ThrowAsync<StartupConfigurationException>(async () => await RealEkmHost.StartAsync(Options(pki, inContainer: true)));
                exception.Message.ShouldContain("LoopbackOnly");
                exception.Problems.Count.ShouldBe(1);
                return 0;
            });
        }

        [Fact]
        public async Task OutsideAContainer_TheOptInIsRefused_AndNothingStarts()
        {
            using var pki = new TestPki();

            await WithOptIn("true", async () =>
            {
                var exception = await Should.ThrowAsync<StartupConfigurationException>(async () => await RealEkmHost.StartAsync(Options(pki, inContainer: false)));
                exception.Message.ShouldContain(ConsoleContainerPublish.Variable);
                return 0;
            });
        }

        [Fact]
        public async Task WithEntraId_TheOptInIsRefused_WhateverTheEnvironment()
        {
            using var pki = new TestPki();
            var before = Environment.GetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable);
            Environment.SetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable, "test-value-no-tenant-behind-it");
            try
            {
                await WithOptIn("true", async () =>
                {
                    var options = Options(pki, inContainer: true);
                    options.Configuration["Console:Auth"] = "EntraId";
                    options.Configuration["Console:EntraId:TenantId"] = "44444444-4444-4444-4444-444444444444";
                    options.Configuration["Console:EntraId:ClientId"] = "55555555-5555-5555-5555-555555555555";
                    options.Configuration["Console:EntraId:AllowedObjectIds:0"] = "11111111-1111-1111-1111-111111111111";

                    var exception = await Should.ThrowAsync<StartupConfigurationException>(async () => await RealEkmHost.StartAsync(options));
                    exception.Message.ShouldContain("EntraId");
                    exception.Message.ShouldContain(ConsoleContainerPublish.Variable);
                    return 0;
                });
            }
            finally
            {
                Environment.SetEnvironmentVariable(ConsoleSecrets.ClientSecretVariable, before);
            }
        }

        [Fact]
        public async Task WithALoopbackBind_TheOptInChangesNothing_NoBanner_NoWarning()
        {
            using var pki = new TestPki();

            await WithOptIn("true", async () =>
            {
                await using var host = await RealEkmHost.StartAsync(Options(pki, inContainer: true, consoleUrl: "https://127.0.0.1:0"));
                using var console = host.CreateConsoleClient();

                (await console.GetStringAsync("/api/console/status")).ShouldContain("\"container_publish\":false");
                host.Logs.Entries.ShouldNotContain(static e => e.Message.Contains(ConsoleContainerPublish.Variable, StringComparison.Ordinal));
                return 0;
            });
        }
    }
}
