namespace Open5gs.AdminApi.Infrastructure;

/// <summary>
/// Base URLs for each NF metrics/admin HTTP listener (same port as Prometheus).
/// Override in appsettings.json or environment when NFs use non-default ports.
/// </summary>
public class MaintenanceOptions
{
    public const string SectionName = "Maintenance";

    public string Mme { get; set; } = "http://127.0.0.1:9090";
    public string Sgwc { get; set; } = "http://127.0.0.1:9090";
    public string Smf { get; set; } = "http://127.0.0.1:9090";
}
