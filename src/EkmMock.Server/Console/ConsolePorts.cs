using System.Collections.Concurrent;

namespace EkmMock.Server.WebConsole;

/// <summary>
/// The ports that carry the console (spec 5.4). Console pages, <c>/_blazor</c>, <c>/api/console/*</c>, health and metrics answer <em>only</em> on these local ports;
/// the EKM port and every other listener get a 404 for them, whatever the Host header says. A port is registered by the console listener's own connection middleware
/// (so ephemeral port-0 listeners work) and a port that carries the EKM endpoint can never be claimed by the console.
/// </summary>
internal interface IConsolePortPolicy
{
    bool IsConsolePort(int localPort);
}

internal sealed class ConsoleListenerPorts : IConsolePortPolicy
{
    private readonly ConcurrentDictionary<int, byte> _ports = new();

    public IReadOnlyCollection<int> Ports => [.. _ports.Keys];

    public void Add(int port)
    {
        if (port > 0)
        {
            _ports[port] = 0;
        }
    }

    public bool IsConsolePort(int localPort) => localPort > 0 && _ports.ContainsKey(localPort);
}
