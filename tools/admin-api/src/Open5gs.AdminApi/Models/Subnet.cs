namespace Open5gs.AdminApi.Models;

public sealed class Subnet : ResourceBase
{
    /// <summary>IPv4 or IPv6 CIDR, e.g. "10.45.0.0/16" or "cafe::/64".</summary>
    public required string Cidr { get; set; }

    /// <summary>DNN this pool belongs to. Required.</summary>
    public required string Dnn { get; set; }

    /// <summary>Optional tun/dev device name on the UPF host, e.g. "ogstun".</summary>
    public string? Dev { get; set; }

    /// <summary>Gateway IP on the UPF side (optional).</summary>
    public string? Gateway { get; set; }
}

public sealed record SubnetCreateDto(
    string Cidr,
    string Dnn,
    string? Dev,
    string? Gateway,
    string? Label);
