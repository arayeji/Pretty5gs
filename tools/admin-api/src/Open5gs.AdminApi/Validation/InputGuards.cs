using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Open5gs.AdminApi.Validation;

/// <summary>
/// Input validators shared between endpoints. All helpers return a
/// user-readable error string on failure, or null on success.
/// </summary>
public static partial class InputGuards
{
    [GeneratedRegex(@"^\d{3}$")]
    private static partial Regex McRe();

    [GeneratedRegex(@"^\d{2,3}$")]
    private static partial Regex MnRe();

    [GeneratedRegex(@"^[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,62}$")]
    private static partial Regex DnnRe();

    [GeneratedRegex(@"^[0-9a-fA-F]{6}$")]
    private static partial Regex SdRe();

    public static string? Mcc(string? v) =>
        v is not null && McRe().IsMatch(v)
            ? null : "mcc must be 3 digits";

    public static string? Mnc(string? v) =>
        v is not null && MnRe().IsMatch(v)
            ? null : "mnc must be 2 or 3 digits";

    public static string? Tac(int v) =>
        v is >= 0 and <= 0xFFFFFF
            ? null : "tac must be between 0 and 16777215";

    public static string? Dnn(string? v) =>
        v is not null && DnnRe().IsMatch(v)
            ? null : "dnn name must match ^[a-zA-Z0-9][a-zA-Z0-9\\-_.]{0,62}$";

    public static string? Sst(int? v) =>
        v is null || v is >= 1 and <= 255
            ? null : "sst must be 1..255";

    public static string? Sd(string? v) =>
        v is null || SdRe().IsMatch(v)
            ? null : "sd must be 6 hex digits";

    public static string? Mtu(int? v) =>
        v is null || v is >= 576 and <= 9216
            ? null : "mtu must be 576..9216";

    public static string? Port(int v) =>
        v is >= 1 and <= 65535
            ? null : "port must be 1..65535";

    public static string? IpAddress(string? v)
    {
        if (v is null) return null;
        return IPAddress.TryParse(v, out _)
            ? null
            : $"'{v}' is not a valid IP address";
    }

    public static string? Cidr(string? v)
    {
        if (string.IsNullOrWhiteSpace(v))
            return "cidr is required";
        var parts = v.Split('/');
        if (parts.Length != 2)
            return "cidr must be in 'network/prefix' form";
        if (!IPAddress.TryParse(parts[0], out var ip))
            return $"'{parts[0]}' is not a valid IP";
        if (!int.TryParse(parts[1], out var prefix))
            return "prefix must be an integer";
        var max = ip.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        if (prefix < 0 || prefix > max)
            return $"prefix must be 0..{max}";
        return null;
    }

    public static string? Host(string? v) =>
        string.IsNullOrWhiteSpace(v)
            ? "host is required"
            : null;

    [GeneratedRegex(@"^[a-z][a-z0-9_]{0,31}$")]
    private static partial Regex SettingsKeyRe();

    /// <summary>Settings (scope, kind) parts: lowercase ASCII identifiers.</summary>
    public static string? SettingsKey(string? v) =>
        v is not null && SettingsKeyRe().IsMatch(v)
            ? null
            : "must match ^[a-z][a-z0-9_]{0,31}$";

    /// <summary>Spool dir must be a non-empty absolute-ish path. We only do
    /// basic shape checks here — the SMF will refuse paths it cannot
    /// create on apply, which surfaces in the NF heartbeat lastError.</summary>
    public static string? SpoolDir(string? v)
    {
        if (string.IsNullOrWhiteSpace(v))
            return "spool_dir is required";
        if (v.Length > 256)
            return "spool_dir is too long (max 256)";
        if (v.IndexOfAny(new[] { '\0', '\n', '\r' }) >= 0)
            return "spool_dir must not contain control characters";
        return null;
    }

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")]
    private static partial Regex NodeIdRe();

    public static string? NodeId(string? v) =>
        v is null || v.Length == 0
            ? "node_id is required"
            : NodeIdRe().IsMatch(v)
                ? null
                : "node_id must match ^[A-Za-z0-9][A-Za-z0-9._\\-]{0,63}$";
}
