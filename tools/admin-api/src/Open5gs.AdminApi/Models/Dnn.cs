namespace Open5gs.AdminApi.Models;

public sealed class Dnn : ResourceBase
{
    /// <summary>APN / DNN name, case-insensitive per 3GPP.</summary>
    public required string Name { get; set; }

    /// <summary>Primary DNS server (IPv4 or IPv6).</summary>
    public string? Dns1 { get; set; }

    /// <summary>Secondary DNS server.</summary>
    public string? Dns2 { get; set; }

    /// <summary>UE MTU (bytes). Open5GS default is 1400.</summary>
    public int? Mtu { get; set; }

    /// <summary>SST value for 5GS (1..255). Optional for EPC-only.</summary>
    public int? SliceSst { get; set; }

    /// <summary>SD (6 hex digits) for 5GS. Optional.</summary>
    public string? SliceSd { get; set; }
}

public sealed record DnnCreateDto(
    string Name,
    string? Dns1,
    string? Dns2,
    int? Mtu,
    int? SliceSst,
    string? SliceSd,
    string? Label);
