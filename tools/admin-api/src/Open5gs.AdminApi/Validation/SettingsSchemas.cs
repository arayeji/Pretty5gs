using System.Text.Json;

namespace Open5gs.AdminApi.Validation;

/// <summary>
/// Per-(scope,kind) settings payload validators.
///
/// Each validator returns:
///   - errors  : field → message (empty dictionary on success);
///   - normalized: a JsonElement representing the *normalized* payload
///                 the API will persist (defaults filled in, unknown
///                 fields stripped, types coerced where safe).
///
/// Adding a new settings kind = adding one entry to <see cref="_table"/>.
/// </summary>
public static class SettingsSchemas
{
    public delegate (Dictionary<string, string> Errors, JsonElement Normalized)
        Validator(JsonElement input);

    private static readonly Dictionary<string, Validator> _table = new()
    {
        ["smf:cdr"]    = SmfCdr.Validate,
        ["smf:radius"] = SmfRadius.Validate,
        ["cgfd:gtpp"]  = CgfdGtpp.Validate,
    };

    public static Validator? For(string scope, string kind)
    {
        var key = scope + ":" + kind;
        return _table.TryGetValue(key, out var v) ? v : null;
    }
}

/* ====================================================================== */
/*   smf:cdr — mirrors the C struct smf_cdr_config_t in src/smf/context.h  */
/* ====================================================================== */

internal static class SmfCdr
{
    /* Trigger flag bit values must match the SMF_CDR_TRIG_* macros in
     * src/smf/context.h. We send the OR'd integer to the NF so a single
     * comparison swaps the bitmask atomically on apply. */
    private const uint TrigStart   = 1u << 0;
    private const uint TrigInterim = 1u << 1;
    private const uint TrigStop    = 1u << 2;

    public static (Dictionary<string, string> Errors, JsonElement Normalized)
        Validate(JsonElement input)
    {
        var errors = new Dictionary<string, string>(StringComparer.Ordinal);

        if (input.ValueKind != JsonValueKind.Object)
        {
            errors["payload"] = "must be a JSON object";
            return (errors, default);
        }

        bool enabled = ReadBool(input, "enabled", true)
                       ?? AddErr(errors, "enabled", "must be a boolean", false);

        string? spoolDir = ReadString(input, "spool_dir");
        string? nodeId   = ReadString(input, "node_id");
        string? localAddr = ReadString(input, "local_address");

        // Only validate path-shaped fields when enabled — when the operator
        // disables the writer they may legitimately PUT {"enabled":false}
        // with everything else missing.
        if (enabled)
        {
            var e = InputGuards.SpoolDir(spoolDir);
            if (e is not null) errors["spool_dir"] = e;

            e = InputGuards.NodeId(nodeId);
            if (e is not null) errors["node_id"] = e;

            if (localAddr is not null)
            {
                e = InputGuards.IpAddress(localAddr);
                if (e is not null) errors["local_address"] = e;
            }
        }

        uint maxRecords = (uint)(ReadInt(input, "max_records", 100) ?? 100);
        uint maxBytes   = (uint)(ReadInt(input, "max_bytes", 65536) ?? 65536);
        uint maxSeconds = (uint)(ReadInt(input, "max_seconds", 30) ?? 30);

        // Hard upper bounds — tracked here, not in the SMF, so a bad PUT
        // is rejected at the API rather than the NF dropping it silently.
        if (maxRecords > 1_000_000) errors["max_records"] = "max 1,000,000";
        if (maxBytes   > 1024L * 1024L * 256L)
            errors["max_bytes"] = "max 256 MiB";
        if (maxSeconds > 24 * 3600) errors["max_seconds"] = "max 86400 (24h)";

        uint triggers = ParseTriggers(input, errors);

        // Build the normalized payload deterministically — SettingsEndpoints
        // serializes this back to canonical JSON so the hash is stable.
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteBoolean("enabled", enabled);
            if (spoolDir is not null)  w.WriteString("spool_dir", spoolDir);
            if (nodeId   is not null)  w.WriteString("node_id", nodeId);
            if (localAddr is not null) w.WriteString("local_address", localAddr);
            w.WriteNumber("max_records", maxRecords);
            w.WriteNumber("max_bytes", maxBytes);
            w.WriteNumber("max_seconds", maxSeconds);
            w.WriteNumber("triggers", triggers);
            w.WriteEndObject();
        }
        var doc = JsonDocument.Parse(ms.ToArray());
        return (errors, doc.RootElement.Clone());
    }

    private static uint ParseTriggers(JsonElement input,
                                      Dictionary<string, string> errors)
    {
        // Accept three forms:
        //   1. integer bitmask (already-encoded)
        //   2. comma string: "start,interim,stop"
        //   3. array of strings
        // Default = all three triggers enabled.
        if (!input.TryGetProperty("triggers", out var t))
            return TrigStart | TrigInterim | TrigStop;

        switch (t.ValueKind)
        {
            case JsonValueKind.Number:
                if (t.TryGetUInt32(out var n))
                {
                    if ((n & ~(TrigStart | TrigInterim | TrigStop)) != 0)
                        errors["triggers"] = "unknown trigger bits set";
                    return n;
                }
                errors["triggers"] = "must fit in uint32";
                return 0;

            case JsonValueKind.String:
                return ParseTriggerNames(
                    t.GetString()!.Split(',', StringSplitOptions.RemoveEmptyEntries
                                              | StringSplitOptions.TrimEntries),
                    errors);

            case JsonValueKind.Array:
                {
                    var names = new List<string>();
                    foreach (var item in t.EnumerateArray())
                    {
                        if (item.ValueKind != JsonValueKind.String)
                        {
                            errors["triggers"] = "array items must be strings";
                            return 0;
                        }
                        names.Add(item.GetString()!);
                    }
                    return ParseTriggerNames(names, errors);
                }

            default:
                errors["triggers"] = "must be int, string, or array";
                return 0;
        }
    }

    private static uint ParseTriggerNames(IEnumerable<string> names,
                                          Dictionary<string, string> errors)
    {
        uint result = 0;
        foreach (var raw in names)
        {
            var n = raw.Trim().ToLowerInvariant();
            switch (n)
            {
                case "start":   result |= TrigStart;   break;
                case "interim": result |= TrigInterim; break;
                case "stop":    result |= TrigStop;    break;
                default:
                    errors["triggers"] =
                        $"unknown trigger '{raw}' (allowed: start, interim, stop)";
                    return 0;
            }
        }
        return result;
    }

    private static bool? ReadBool(JsonElement obj, string name, bool? dflt)
    {
        if (!obj.TryGetProperty(name, out var v)) return dflt;
        return v.ValueKind switch
        {
            JsonValueKind.True  => true,
            JsonValueKind.False => false,
            _ => null,
        };
    }

    private static string? ReadString(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Null) return null;
        return v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    private static int? ReadInt(JsonElement obj, string name, int dflt)
    {
        if (!obj.TryGetProperty(name, out var v)) return dflt;
        return v.ValueKind switch
        {
            JsonValueKind.Number when v.TryGetInt32(out var n) => n,
            JsonValueKind.Null => dflt,
            _ => null, // signals validation error
        };
    }

    private static T AddErr<T>(Dictionary<string, string> errors,
                               string field, string msg, T fallback)
    {
        errors[field] = msg;
        return fallback;
    }
}
