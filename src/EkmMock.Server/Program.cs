using EkmMock.Server.Hosting;
using EkmMock.Server.WebConsole;
using Microsoft.Extensions.Options;

try
{
    var app = EkmServerServiceCollectionExtensions.BuildEkmMockApp(args);
    app.Run();
    return 0;
}
catch (Exception exception) when (exception is StartupConfigurationException or OptionsValidationException)
{
    // Fail fast with a clear, secret-free message and a non-zero exit code (spec 5.4: LoopbackOnly with a non-loopback bind must not start).
    Console.Error.WriteLine(exception is OptionsValidationException options
        ? "EkmMock refuses to start: " + string.Join(" ", options.Failures)
        : exception.Message);
    return 78;
}

/// <summary>Entry point class, public so <c>WebApplicationFactory&lt;Program&gt;</c> can host it in tests.</summary>
public partial class Program;
