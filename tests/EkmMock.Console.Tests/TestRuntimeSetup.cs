using System.Runtime.CompilerServices;

namespace EkmMock.Console.Tests;

internal static class TestRuntimeSetup
{
    /// <summary>
    /// The tests in this assembly run real Kestrel servers in the same process as bUnit tests whose WaitForAssertion blocks a thread for up to several seconds.
    /// With the default minimum of one pool thread per core and a slow thread-injection rate that starves the servers (a request then stalls for tens of
    /// seconds on a busy machine). A generous minimum removes the injection delay; it costs nothing when the threads are not needed.
    /// </summary>
    [ModuleInitializer]
    internal static void RaiseThreadPoolMinimum() => ThreadPool.SetMinThreads(workerThreads: 64, completionPortThreads: 64);
}
