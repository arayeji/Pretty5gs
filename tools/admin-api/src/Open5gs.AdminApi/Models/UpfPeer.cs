namespace Open5gs.AdminApi.Models;

public sealed class UpfPeer : ResourceBase
{
    /// <summary>PFCP address (IP literal or DNS name).</summary>
    public required string Host { get; set; }

    /// <summary>PFCP port (default 8805).</summary>
    public int Port { get; set; } = 8805;

    /// <summary>DNNs this UPF is authoritative for; empty = any.</summary>
    public string[] Dnns { get; set; } = Array.Empty<string>();
}

public sealed record UpfPeerCreateDto(
    string Host,
    int? Port,
    string[]? Dnns,
    string? Label);
