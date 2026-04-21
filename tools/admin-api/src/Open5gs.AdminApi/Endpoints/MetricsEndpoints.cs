using System.Globalization;
using System.Text;
using MongoDB.Driver;
using Open5gs.AdminApi.Infrastructure;
using Open5gs.AdminApi.Models;

namespace Open5gs.AdminApi.Endpoints;

/// <summary>
/// Minimal Prometheus exposition (OpenMetrics 0.0.4 text format) built
/// directly from Mongo counts and heartbeat rows. No in-process counters:
/// everything is derived from authoritative state, so the metrics are
/// accurate across process restarts and multi-replica deployments.
///
/// This endpoint is intentionally unauthenticated: most Prometheus
/// deployments scrape via a private network path and embedding bearer
/// tokens in every scrape config is a common foot-gun. If you need
/// auth, front the /metrics route with your reverse proxy.
/// </summary>
public static class MetricsEndpoints
{
    public static RouteGroupBuilder MapMetrics(this RouteGroupBuilder group)
    {
        group.MapGet("/", HandleMetricsAsync)
             .AllowAnonymous()
             .ExcludeFromDescription();
        return group;
    }

    private static async Task<IResult> HandleMetricsAsync(
        AdminContext ctx,
        RevisionService rev,
        CancellationToken ct)
    {
        var sb = new StringBuilder(2048);

        long currentRev = await rev.CurrentAsync(ct);

        long plmns    = await ctx.Plmns.CountDocumentsAsync(FilterDefinition<Plmn>.Empty, cancellationToken: ct);
        long tacs     = await ctx.Tacs.CountDocumentsAsync(FilterDefinition<Tac>.Empty, cancellationToken: ct);
        long dnns     = await ctx.Dnns.CountDocumentsAsync(FilterDefinition<Dnn>.Empty, cancellationToken: ct);
        long upfPeers = await ctx.UpfPeers.CountDocumentsAsync(FilterDefinition<UpfPeer>.Empty, cancellationToken: ct);
        long subnets  = await ctx.Subnets.CountDocumentsAsync(FilterDefinition<Subnet>.Empty, cancellationToken: ct);
        long settings = await ctx.Settings.CountDocumentsAsync(FilterDefinition<SettingsDoc>.Empty, cancellationToken: ct);
        long audit    = await ctx.Audit.CountDocumentsAsync(FilterDefinition<AuditEntry>.Empty, cancellationToken: ct);

        AppendHelp(sb, "open5gs_admin_revision_current",
            "Current global configuration revision.",
            "counter");
        AppendMetric(sb, "open5gs_admin_revision_current", currentRev);

        AppendHelp(sb, "open5gs_admin_resources",
            "Number of configured resources by kind.",
            "gauge");
        AppendMetricLabeled(sb, "open5gs_admin_resources", "kind", "plmn", plmns);
        AppendMetricLabeled(sb, "open5gs_admin_resources", "kind", "tac", tacs);
        AppendMetricLabeled(sb, "open5gs_admin_resources", "kind", "dnn", dnns);
        AppendMetricLabeled(sb, "open5gs_admin_resources", "kind", "upf_peer", upfPeers);
        AppendMetricLabeled(sb, "open5gs_admin_resources", "kind", "subnet", subnets);
        AppendMetricLabeled(sb, "open5gs_admin_resources", "kind", "settings", settings);

        AppendHelp(sb, "open5gs_admin_audit_entries_total",
            "Total number of audit log entries since schema init.",
            "counter");
        AppendMetric(sb, "open5gs_admin_audit_entries_total", audit);

        // Per-NF heartbeat lag (seconds since last heartbeat) and applied
        // revision. Bounded list — this collection has one row per NF id.
        var heartbeats = await ctx.Heartbeats
            .Find(FilterDefinition<NfHeartbeat>.Empty)
            .ToListAsync(ct);

        AppendHelp(sb, "open5gs_admin_nf_applied_revision",
            "Revision last reported as applied by each NF.",
            "gauge");
        AppendHelp(sb, "open5gs_admin_nf_revision_lag",
            "Global revision minus per-NF applied revision (0 = caught up).",
            "gauge");
        AppendHelp(sb, "open5gs_admin_nf_heartbeat_age_seconds",
            "Seconds since the NF last reported a heartbeat.",
            "gauge");

        var now = DateTime.UtcNow;
        foreach (var h in heartbeats)
        {
            // Escape label values for Prometheus text format.
            string nfId = EscapeLabel(h.NfId ?? "unknown");
            string nfType = EscapeLabel(h.NfType ?? "unknown");
            string labels = $"{{nf_id=\"{nfId}\",nf_type=\"{nfType}\"}}";

            AppendMetricRaw(sb, "open5gs_admin_nf_applied_revision", labels,
                h.AppliedRevision);
            AppendMetricRaw(sb, "open5gs_admin_nf_revision_lag", labels,
                Math.Max(0, currentRev - h.AppliedRevision));

            double ageSec = Math.Max(0.0, (now - h.UpdatedAt).TotalSeconds);
            AppendMetricRaw(sb, "open5gs_admin_nf_heartbeat_age_seconds",
                labels, ageSec);
        }

        return Results.Text(
            sb.ToString(),
            contentType: "text/plain; version=0.0.4; charset=utf-8");
    }

    private static void AppendHelp(StringBuilder sb, string name,
                                   string help, string type)
    {
        sb.Append("# HELP ").Append(name).Append(' ').Append(help).Append('\n');
        sb.Append("# TYPE ").Append(name).Append(' ').Append(type).Append('\n');
    }

    private static void AppendMetric(StringBuilder sb, string name, long value)
    {
        sb.Append(name).Append(' ')
          .Append(value.ToString(CultureInfo.InvariantCulture))
          .Append('\n');
    }

    private static void AppendMetricLabeled(StringBuilder sb, string name,
                                            string labelName, string labelValue,
                                            long value)
    {
        sb.Append(name)
          .Append("{").Append(labelName).Append("=\"")
          .Append(EscapeLabel(labelValue)).Append("\"} ")
          .Append(value.ToString(CultureInfo.InvariantCulture))
          .Append('\n');
    }

    private static void AppendMetricRaw(StringBuilder sb, string name,
                                        string labels, double value)
    {
        sb.Append(name).Append(labels).Append(' ')
          .Append(value.ToString("0.######", CultureInfo.InvariantCulture))
          .Append('\n');
    }

    private static string EscapeLabel(string s)
    {
        // Prometheus text format: \ -> \\, " -> \", newline -> \n.
        if (string.IsNullOrEmpty(s)) return string.Empty;
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"':  sb.Append("\\\""); break;
                case '\n': sb.Append("\\n");  break;
                default:   sb.Append(c);      break;
            }
        }
        return sb.ToString();
    }
}
