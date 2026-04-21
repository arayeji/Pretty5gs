namespace Open5gs.AdminApi.Models;

public sealed class Plmn : ResourceBase
{
    public required string Mcc { get; set; }
    public required string Mnc { get; set; }
}

public sealed record PlmnCreateDto(string Mcc, string Mnc, string? Label);
