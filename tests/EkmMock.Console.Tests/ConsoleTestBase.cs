using EkmMock.Server.Inspector;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.FluentUI.AspNetCore.Components;

namespace EkmMock.Console.Tests;

/// <summary>
/// The component test context of the console: Fluent UI services, loose JavaScript interop (the Fluent web components are JS-backed), the in-memory inspector built from the real M4
/// parts, and a clock. <paramref name="realTime"/> uses the system clock (needed where a component waits with <c>Task.Delay</c>, such as the live feed pump); otherwise the clock and
/// its timers are moved by hand.
/// </summary>
public abstract class ConsoleTestBase : BunitContext
{
    private protected ConsoleTestBase(bool realTime = false, Action<ConsoleOptions>? configure = null)
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        ManualTime = new ManualTimeProvider(Rec.Epoch.AddMinutes(30));
        TimeProvider time = realTime ? TimeProvider.System : ManualTime;

        var options = new ConsoleOptions { LiveTraffic = { RenderIntervalMs = 20 } };
        configure?.Invoke(options);

        InspectorFake = new FakeInspector(time);
        Services.AddSingleton(time);
        Services.AddSingleton<IInspector>(InspectorFake);
        Services.AddSingleton<IInspectorQuery>(InspectorFake);
        Services.AddSingleton<IConsoleStatusProvider>(StatusFake);
        Services.AddSingleton<IFaultStatus>(FaultsFake);
        Services.AddSingleton<IConsoleUser>(UserFake);
        Services.AddSingleton(Options.Create(options));
        Services.AddSingleton(Options.Create(new LimitsOptions()));
        Services.AddFluentUIComponents();
    }

    internal ManualTimeProvider ManualTime { get; }

    internal FakeInspector InspectorFake { get; }

    internal FakeStatus StatusFake { get; } = new();

    internal FakeFaults FaultsFake { get; } = new();

    internal FakeUser UserFake { get; } = new();

    // How long a test waits for something asynchronous to show up. A passing test returns as soon as the condition holds, so a long limit costs nothing; it only gives a slow machine
    // (the first mutual-TLS handshake on a shared Windows CI runner took more than 5 s) room. A test that is really broken still fails, just later.
    internal static TimeSpan Patience { get; } = TimeSpan.FromSeconds(20);
}
