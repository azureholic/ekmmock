using EkmMock.Server.Ekm;
using EkmMock.Server.Hosting;

var builder = WebApplication.CreateBuilder(args);
builder.AddEkmMockServer(args);

var app = builder.Build();
app.UseEkmPipeline();
app.Run();

/// <summary>Entry point class, public so <c>WebApplicationFactory&lt;Program&gt;</c> can host it in tests.</summary>
public partial class Program;
