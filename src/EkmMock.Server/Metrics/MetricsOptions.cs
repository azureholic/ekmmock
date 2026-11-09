namespace EkmMock.Server.Metrics;

/// <summary>Options of the <c>/metrics</c> pull endpoint (spec 9). It is served by the console port only; the EKM port answers 404.</summary>
internal sealed class MetricsOptions
{
    public const string SectionName = "Metrics";

    /// <summary>
    /// Serve <c>/metrics</c> without console authentication. Default false: the endpoint follows the console's authentication like every other console route (in
    /// <c>LoopbackOnly</c> that is "local connections only", in <c>EntraId</c> a signed-in, allowed user). Prometheus cannot sign in with Entra ID, so a scraper
    /// against an EntraId console needs this switch (see DECISIONS.md "M7: Metrics endpoint"); the metrics contain counts and timings only, never keys, key names or client names.
    /// </summary>
    public bool AllowAnonymous { get; set; }
}
