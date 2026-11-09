using EkmMock.Server.Hosting;

var app = EkmServerServiceCollectionExtensions.BuildEkmMockApp(args);
app.Run();

/// <summary>Entry point class, public so <c>WebApplicationFactory&lt;Program&gt;</c> can host it in tests.</summary>
public partial class Program;
