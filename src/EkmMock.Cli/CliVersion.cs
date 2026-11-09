using System.Reflection;

namespace EkmMock.Cli;

/// <summary>The tool version as shown by <c>--version</c> and sent in the <c>X-EkmMock-Client</c> header.</summary>
internal static class CliVersion
{
    public static string Current { get; } = typeof(CliVersion).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";
}
