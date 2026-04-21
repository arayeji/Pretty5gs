namespace Open5gs.AdminApi.Infrastructure;

/// <summary>
/// Mirrors the compile-time caps in Open5GS (lib/proto/types.h and
/// lib/pfcp/context.h). Adding entries beyond these values is rejected at
/// the API layer so an NF cannot overflow a static array on apply.
///
/// KEEP IN SYNC when those headers change. Values are documented here with
/// their source define.
/// </summary>
public static class ConfigLimits
{
    /// <summary>OGS_MAX_NUM_OF_DNN (lib/proto/types.h).</summary>
    public const int MaxDnns = 16;

    /// <summary>OGS_MAX_NUM_OF_PLMN (AMF) (lib/proto/types.h).</summary>
    public const int MaxPlmnsAmf = 12;

    /// <summary>OGS_MAX_NUM_OF_PLMN_PER_MME (lib/proto/types.h).</summary>
    public const int MaxPlmnsMme = 32;

    /// <summary>OGS_MAX_NUM_OF_SERVED_GUMMEI (lib/proto/types.h).</summary>
    public const int MaxGummei = 8;

    /// <summary>OGS_MAX_NUM_OF_SUBNET (lib/pfcp/context.h).</summary>
    public const int MaxSubnets = 16;

    /// <summary>
    /// OGS_MAX_NUM_OF_SUPPORTED_TA (MME served_tai entries). Open5GS defines
    /// this in lib/proto/types.h around 16. Staying conservative.
    /// </summary>
    public const int MaxServedTaiEntries = 16;

    /// <summary>
    /// Per-served-TAI list, the practical per-entry capacity. Open5GS uses
    /// ogs_eps_tai0/1/2 lists; 16 TACs per entry is a safe bound.
    /// </summary>
    public const int MaxTacsPerServedEntry = 16;

    public const int MaxUpfPeers = 16;
}
