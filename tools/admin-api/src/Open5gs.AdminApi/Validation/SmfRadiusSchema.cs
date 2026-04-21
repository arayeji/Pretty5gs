using System.Text.Json;

namespace Open5gs.AdminApi.Validation;

/// <summary>
/// smf:radius — hot-configurable RADIUS client/PoD settings for the SMF.
///
/// Payload shape (top-level):
/// {
///   "enabled":         bool,
///   "select_mode":     "primary_failover" | "hash_imsi",
///   "nas_identifier":  string?,
///   "nas_ip":          string?,
///   "timeout_ms":      int,
///   "retry":           int,
///   "acct_interim_interval": int,
///   "pod_enabled":     bool,
///   "pod_bind":        string?,
///   "pod_port":        int,
///   "pod_secret":      string?,
///   "pod_teardown_timeout_ms": int,
///   "servers": [
///      {"host": "10.0.0.10", "auth_port":1812, "acct_port":1813,
///       "secret":"s1", "role":"primary"},
///      {"host": "10.0.0.11", "secret":"s2", "role":"secondary"},
///      ...
///   ]
/// }
///
/// The SMF will resolve each `host` on apply; here we only do shape
/// validation so bad IPs are rejected before they land on the NF.
/// </summary>
internal static class SmfRadius
{
    private const int MaxServers = 4;

    public static (Dictionary<string, string> Errors, JsonElement Normalized)
        Validate(JsonElement input)
    {
        var errors = new Dictionary<string, string>(StringComparer.Ordinal);

        if (input.ValueKind != JsonValueKind.Object)
        {
            errors["payload"] = "must be a JSON object";
            return (errors, default);
        }

        bool enabled = TryBool(input, "enabled") ?? true;
        string selectMode = TryString(input, "select_mode") ?? "primary_failover";
        if (selectMode is not "primary_failover" and not "hash_imsi")
            errors["select_mode"] =
                "must be 'primary_failover' or 'hash_imsi'";

        int timeoutMs  = TryInt(input, "timeout_ms", 3000) ?? 3000;
        int retry      = TryInt(input, "retry", 3) ?? 3;
        int interim    = TryInt(input, "acct_interim_interval", 0) ?? 0;
        bool podEnabled = TryBool(input, "pod_enabled") ?? false;
        int podPort    = TryInt(input, "pod_port", 3799) ?? 3799;
        int podTo      = TryInt(input, "pod_teardown_timeout_ms", 5000) ?? 5000;

        if (timeoutMs is < 100 or > 60_000)
            errors["timeout_ms"] = "must be 100..60000";
        if (retry is < 1 or > 20)
            errors["retry"] = "must be 1..20";
        if (interim is < 0 or > 86400)
            errors["acct_interim_interval"] = "must be 0..86400";
        if (podPort is < 1 or > 65535)
            errors["pod_port"] = "must be 1..65535";
        if (podTo < 0 || podTo > 120_000)
            errors["pod_teardown_timeout_ms"] = "must be 0..120000";

        string? nasId = TryString(input, "nas_identifier");
        string? nasIp = TryString(input, "nas_ip");
        if (nasIp is not null && InputGuards.IpAddress(nasIp) is { } ipErr)
            errors["nas_ip"] = ipErr;

        string? podBind = TryString(input, "pod_bind");
        if (podBind is not null && podBind.Length > 64)
            errors["pod_bind"] = "too long";

        string? podSecret = TryString(input, "pod_secret");

        // Per-server validation.
        var servers = new List<Dictionary<string, object?>>();
        bool hasPrimary = false;
        int seenSecondaries = 0;

        if (input.TryGetProperty("servers", out var sArr)
            && sArr.ValueKind == JsonValueKind.Array)
        {
            int idx = -1;
            foreach (var s in sArr.EnumerateArray())
            {
                idx++;
                if (idx >= MaxServers)
                {
                    errors["servers"] = $"max {MaxServers} servers";
                    break;
                }
                if (s.ValueKind != JsonValueKind.Object)
                {
                    errors[$"servers[{idx}]"] = "must be an object";
                    continue;
                }

                string? host = TryString(s, "host");
                if (string.IsNullOrWhiteSpace(host))
                {
                    errors[$"servers[{idx}].host"] = "host is required";
                    continue;
                }
                // Accept either IP or hostname; NF resolves on apply.
                if (host.Length > 255)
                {
                    errors[$"servers[{idx}].host"] = "too long";
                    continue;
                }

                int authPort = TryInt(s, "auth_port", 1812) ?? 1812;
                int acctPort = TryInt(s, "acct_port", 1813) ?? 1813;
                if (authPort is < 1 or > 65535)
                    errors[$"servers[{idx}].auth_port"] = "1..65535";
                if (acctPort is < 1 or > 65535)
                    errors[$"servers[{idx}].acct_port"] = "1..65535";

                string? secret = TryString(s, "secret");
                if (string.IsNullOrEmpty(secret))
                    errors[$"servers[{idx}].secret"] = "secret is required";

                string role = (TryString(s, "role") ?? "primary").ToLowerInvariant();
                if (role is not "primary" and not "secondary")
                    errors[$"servers[{idx}].role"] =
                        "must be 'primary' or 'secondary'";
                if (role == "primary") hasPrimary = true;
                else                   seenSecondaries++;

                int weight = TryInt(s, "weight", 1) ?? 1;
                if (weight is < 1 or > 100)
                    errors[$"servers[{idx}].weight"] = "1..100";

                servers.Add(new Dictionary<string, object?>
                {
                    ["host"]      = host,
                    ["auth_port"] = authPort,
                    ["acct_port"] = acctPort,
                    ["secret"]    = secret,
                    ["role"]      = role,
                    ["weight"]    = weight,
                });
            }
        }

        if (enabled && servers.Count == 0)
            errors["servers"] = "at least one server is required when enabled";
        if (enabled && servers.Count > 0 && !hasPrimary)
            errors["servers"] =
                "at least one server must have role='primary'";

        // Normalize — deterministic field order.
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteBoolean("enabled", enabled);
            w.WriteString("select_mode", selectMode);
            if (nasId is not null) w.WriteString("nas_identifier", nasId);
            if (nasIp is not null) w.WriteString("nas_ip", nasIp);
            w.WriteNumber("timeout_ms", timeoutMs);
            w.WriteNumber("retry", retry);
            w.WriteNumber("acct_interim_interval", interim);
            w.WriteBoolean("pod_enabled", podEnabled);
            if (podBind is not null) w.WriteString("pod_bind", podBind);
            w.WriteNumber("pod_port", podPort);
            if (podSecret is not null) w.WriteString("pod_secret", podSecret);
            w.WriteNumber("pod_teardown_timeout_ms", podTo);

            w.WritePropertyName("servers");
            w.WriteStartArray();
            foreach (var s in servers)
            {
                w.WriteStartObject();
                w.WriteString("host",   (string?)s["host"]);
                w.WriteNumber("auth_port", (int)s["auth_port"]!);
                w.WriteNumber("acct_port", (int)s["acct_port"]!);
                w.WriteString("secret", (string?)s["secret"] ?? "");
                w.WriteString("role",   (string?)s["role"] ?? "primary");
                w.WriteNumber("weight", (int)s["weight"]!);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        var doc = JsonDocument.Parse(ms.ToArray());
        return (errors, doc.RootElement.Clone());
    }

    private static bool? TryBool(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v)
            ? v.ValueKind switch
              {
                  JsonValueKind.True  => true,
                  JsonValueKind.False => false,
                  _ => (bool?)null,
              }
            : null;

    private static int? TryInt(JsonElement o, string name, int dflt)
    {
        if (!o.TryGetProperty(name, out var v)) return dflt;
        return v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n)
               ? n : null;
    }

    private static string? TryString(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;
}

/* ======================================================================= */
/*   cgfd:gtpp — hot-configurable peer list + tunables for open5gs-cgfd    */
/* ======================================================================= */

/// <summary>
/// cgfd:gtpp payload:
/// {
///   "peers": [
///      {"host":"10.0.1.50","port":3386,"role":"primary"},
///      {"host":"10.0.1.51","port":3386,"role":"secondary"}
///   ],
///   "echo_interval_s": 60,
///   "request_rto_ms":  5000,
///   "request_retries": 5,
///   "failover_after_missed_echoes": 3,
///   "max_records_per_packet": 200,
///   "max_bytes_per_packet":   32768
/// }
///
/// The CGF daemon already supports primary/secondary failover; this
/// settings kind lets operators add/replace peers and nudge tunables
/// at runtime without restarting the daemon.
/// </summary>
internal static class CgfdGtpp
{
    private const int MaxPeers = 4;

    public static (Dictionary<string, string> Errors, JsonElement Normalized)
        Validate(JsonElement input)
    {
        var errors = new Dictionary<string, string>(StringComparer.Ordinal);
        if (input.ValueKind != JsonValueKind.Object)
        {
            errors["payload"] = "must be a JSON object";
            return (errors, default);
        }

        int echoS   = TryInt(input, "echo_interval_s", 60) ?? 60;
        int rtoMs   = TryInt(input, "request_rto_ms", 5000) ?? 5000;
        int retries = TryInt(input, "request_retries", 5) ?? 5;
        int fOver   = TryInt(input, "failover_after_missed_echoes", 3) ?? 3;
        int maxRec  = TryInt(input, "max_records_per_packet", 200) ?? 200;
        int maxByt  = TryInt(input, "max_bytes_per_packet", 32768) ?? 32768;

        // Retention for fully-acked spool files. Tri-state on the wire:
        //   - absent (null) -> NF keeps its current setting
        //   - true           -> unlink after ACK
        //   - false          -> keep done/ archive (legacy default)
        // We forward whichever the operator sent so the NF can
        // distinguish "don't touch" from an explicit false.
        bool? purgeOnSuccess = TryBool(input, "purge_on_success");

        if (echoS is < 5 or > 3600)
            errors["echo_interval_s"] = "5..3600";
        if (rtoMs is < 100 or > 60000)
            errors["request_rto_ms"] = "100..60000";
        if (retries is < 0 or > 20)
            errors["request_retries"] = "0..20";
        if (fOver is < 1 or > 100)
            errors["failover_after_missed_echoes"] = "1..100";
        if (maxRec is < 1 or > 10000)
            errors["max_records_per_packet"] = "1..10000";
        if (maxByt is < 512 or > (1 << 20))
            errors["max_bytes_per_packet"] = "512..1048576";

        var peers = new List<Dictionary<string, object?>>();
        bool hasPrimary = false;
        if (input.TryGetProperty("peers", out var arr)
            && arr.ValueKind == JsonValueKind.Array)
        {
            int idx = -1;
            foreach (var p in arr.EnumerateArray())
            {
                idx++;
                if (idx >= MaxPeers)
                {
                    errors["peers"] = $"max {MaxPeers} peers";
                    break;
                }
                if (p.ValueKind != JsonValueKind.Object)
                {
                    errors[$"peers[{idx}]"] = "must be an object";
                    continue;
                }
                string? host = TryString(p, "host");
                if (string.IsNullOrWhiteSpace(host))
                {
                    errors[$"peers[{idx}].host"] = "host is required";
                    continue;
                }
                if (host.Length > 255)
                {
                    errors[$"peers[{idx}].host"] = "too long";
                    continue;
                }

                int port = TryInt(p, "port", 3386) ?? 3386;
                if (port is < 1 or > 65535)
                    errors[$"peers[{idx}].port"] = "1..65535";

                string role = (TryString(p, "role") ?? "primary").ToLowerInvariant();
                if (role is not "primary" and not "secondary")
                    errors[$"peers[{idx}].role"] =
                        "must be 'primary' or 'secondary'";
                if (role == "primary") hasPrimary = true;

                peers.Add(new Dictionary<string, object?>
                {
                    ["host"] = host,
                    ["port"] = port,
                    ["role"] = role,
                });
            }
        }

        if (peers.Count > 0 && !hasPrimary)
            errors["peers"] = "at least one peer must have role='primary'";

        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteNumber("echo_interval_s", echoS);
            w.WriteNumber("request_rto_ms", rtoMs);
            w.WriteNumber("request_retries", retries);
            w.WriteNumber("failover_after_missed_echoes", fOver);
            w.WriteNumber("max_records_per_packet", maxRec);
            w.WriteNumber("max_bytes_per_packet", maxByt);
            if (purgeOnSuccess.HasValue)
                w.WriteBoolean("purge_on_success", purgeOnSuccess.Value);

            w.WritePropertyName("peers");
            w.WriteStartArray();
            foreach (var p in peers)
            {
                w.WriteStartObject();
                w.WriteString("host", (string?)p["host"]);
                w.WriteNumber("port", (int)p["port"]!);
                w.WriteString("role", (string?)p["role"]);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        var doc = JsonDocument.Parse(ms.ToArray());
        return (errors, doc.RootElement.Clone());
    }
    private static bool? TryBool(JsonElement o, string name) =>
       o.TryGetProperty(name, out var v)
           ? v.ValueKind switch
           {
               JsonValueKind.True => true,
               JsonValueKind.False => false,
               _ => (bool?)null,
           }
           : null;
    private static int? TryInt(JsonElement o, string name, int dflt)
    {
        if (!o.TryGetProperty(name, out var v)) return dflt;
        return v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n)
               ? n : null;
    }

    private static string? TryString(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;
}
