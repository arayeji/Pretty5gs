namespace Open5gs.AdminApi.Infrastructure;

/// <summary>
/// Base URLs for each NF metrics/admin HTTP listener (same port as Prometheus).
/// Override in appsettings.json or environment when NFs use non-default ports.
/// </summary>
public class MaintenanceOptions
{
    public const string SectionName = "Maintenance";

    /// <summary>MME metrics/admin port (must match mme.metrics.server in mme.yaml).</summary>
    public string Mme { get; set; } = "http://127.0.0.2:9090";
    public string Sgwc { get; set; } = "http://127.0.0.3:9090";
    public string Smf { get; set; } = "http://127.0.0.4:9090";
}
