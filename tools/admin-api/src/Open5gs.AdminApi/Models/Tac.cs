namespace Open5gs.AdminApi.Models;

public sealed class Tac : ResourceBase
{
    public required string Mcc { get; set; }
    public required string Mnc { get; set; }

    /// <summary>TAC (EPS) 0..65535, or TAC-24 if configured (0..16777215).</summary>
    public int TacValue { get; set; }
}

public sealed record TacCreateDto(string Mcc, string Mnc, int Tac, string? Label);
