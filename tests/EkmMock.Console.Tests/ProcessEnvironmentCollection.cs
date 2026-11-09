namespace EkmMock.Console.Tests;

/// <summary>
/// Tests that set process-wide environment variables (a fake master key or client secret, the reveal switch) run alone: a host that another test
/// starts at the same moment would read those variables and misbehave (a flake in the mTLS port-separation tests showed exactly that).
/// </summary>
[CollectionDefinition(ProcessEnvironmentCollection.Name, DisableParallelization = true)]
public sealed class ProcessEnvironmentCollection
{
    public const string Name = "ProcessEnvironment";
}