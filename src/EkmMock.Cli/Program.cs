namespace EkmMock.Cli;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        using var cancel = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cancel.Cancel();
        };

        return await CliApp.RunAsync(args, CliEnvironment.System(), cancel.Token).ConfigureAwait(false);
    }
}
