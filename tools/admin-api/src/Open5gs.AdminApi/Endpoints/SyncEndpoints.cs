using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;
using Open5gs.AdminApi.Auth;
using Open5gs.AdminApi.Infrastructure;
using Open5gs.AdminApi.Models;
using Open5gs.AdminApi.Validation;

namespace Open5gs.AdminApi.Endpoints;

/// <summary>
/// Bi-directional sync between Open5GS YAML config and the Admin API database.
///
/// POST /api/v1/sync/import   — push existing NF config into the DB (file → DB).
///                              Idempotent: duplicate rows are silently skipped.
///
/// GET  /api/v1/sync/export   — return all DB config as a YAML snippet that can
///                              be pasted directly into the relevant NF yaml files
///                              (DB → file).  Format: ?format=yaml (default) or
///                              ?format=json.
///
/// Both directions are additive for TAC/DNN/Subnet (matching the watcher's
/// append-only contract).  Settings documents are upserted so a re-import
/// never creates duplicates.
/// </summary>
public static class SyncEndpoints
{
    public static RouteGroupBuilder MapSync(this RouteGroupBuilder root)
    {
        var g = root.MapGroup("/sync")
            .WithTags("sync")
            .RequireAuthorization(AuthExtensions.PolicyAdmin);

        g.MapPost("/import", Import)
            .WithSummary("Import NF config into the DB (file → DB)")
            .WithDescription(
                "Accepts a JSON snapshot of the current NF configuration " +
                "(TACs, DNNs, subnets, UPF peers, settings) and upserts each " +
                "row into the database.  Existing rows with the same key are " +
                "left untouched.  Returns a summary of what was added vs. skipped.");

        g.MapGet("/export", Export)
            .WithSummary("Export DB config as YAML/JSON snippets (DB → file)")
            .WithDescription(
                "Returns all stored config formatted as ready-to-paste YAML " +
                "blocks (or JSON with ?format=json).  Covers TACs, DNNs, " +
                "subnets, UPF peers and settings documents.");

        return root;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DTOs
    // ─────────────────────────────────────────────────────────────────────────

    public sealed record SyncImportDto(
        List<TacCreateDto>?     Tacs,
        List<DnnCreateDto>?     Dnns,
        List<SubnetCreateDto>?  Subnets,
        List<UpfPeerCreateDto>? UpfPeers,
        // Settings: key = "scope/kind" (e.g. "smf/radius"), value = raw JSON payload
        Dictionary<string, object?>? Settings);

    public sealed record SyncImportResult(
        int TacsAdded,    int TacsSkipped,
        int DnnsAdded,    int DnnsSkipped,
        int SubnetsAdded, int SubnetsSkipped,
        int PeersAdded,   int PeersSkipped,
        int SettingsUpserted,
        List<string> Errors);

    // ─────────────────────────────────────────────────────────────────────────
    // POST /api/v1/sync/import
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<Ok<SyncImportResult>> Import(
        [FromBody] SyncImportDto dto,
        AdminContext ctx,
        RevisionService revs,
        AuditService audit,
        HttpContext http,
        CancellationToken ct)
    {
        var actor  = EndpointHelpers.ActorOf(http.User);
        var errors = new List<string>();

        int tacsAdded = 0, tacsSkipped = 0;
        int dnnsAdded = 0, dnnsSkipped = 0;
        int subsAdded = 0, subsSkipped = 0;
        int peersAdded = 0, peersSkipped = 0;
        int settingsUpserted = 0;

        // ── TACs ──────────────────────────────────────────────────────────────
        foreach (var t in dto.Tacs ?? [])
        {
            var mccErr = InputGuards.Mcc(t.Mcc);
            var mncErr = InputGuards.Mnc(t.Mnc);
            var tacErr = InputGuards.Tac(t.Tac);
            if (mccErr is not null || mncErr is not null || tacErr is not null)
            {
                errors.Add($"tac {t.Mcc}/{t.Mnc}/{t.Tac}: " +
                           string.Join("; ", new[] { mccErr, mncErr, tacErr }
                               .Where(e => e is not null)));
                tacsSkipped++;
                continue;
            }

            var exists = await ctx.Tacs
                .Find(x => x.Mcc == t.Mcc && x.Mnc == t.Mnc && x.TacValue == t.Tac)
                .AnyAsync(ct);
            if (exists) { tacsSkipped++; continue; }

            var rev  = await revs.NextAsync(ct);
            var doc  = new Tac { Mcc = t.Mcc, Mnc = t.Mnc, TacValue = t.Tac,
                                  Label = t.Label, Revision = rev };
            try
            {
                await ctx.Tacs.InsertOneAsync(doc, cancellationToken: ct);
                await audit.RecordAsync("sync-import", "tac", null, doc, rev, actor, ct);
                tacsAdded++;
            }
            catch (MongoWriteException ex)
                when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
            {
                tacsSkipped++;
            }
        }

        // ── DNNs ──────────────────────────────────────────────────────────────
        foreach (var d in dto.Dnns ?? [])
        {
            var nameErr = InputGuards.Dnn(d.Name);
            if (nameErr is not null)
            {
                errors.Add($"dnn {d.Name}: {nameErr}");
                dnnsSkipped++;
                continue;
            }

            var normalized = d.Name.ToLowerInvariant();
            var exists = await ctx.Dnns
                .Find(x => x.Name == normalized).AnyAsync(ct);
            if (exists) { dnnsSkipped++; continue; }

            var rev = await revs.NextAsync(ct);
            var doc = new Dnn
            {
                Name = normalized, Dns1 = d.Dns1, Dns2 = d.Dns2,
                Mtu = d.Mtu, SliceSst = d.SliceSst, SliceSd = d.SliceSd,
                Label = d.Label, Revision = rev,
            };
            try
            {
                await ctx.Dnns.InsertOneAsync(doc, cancellationToken: ct);
                await audit.RecordAsync("sync-import", "dnn", null, doc, rev, actor, ct);
                dnnsAdded++;
            }
            catch (MongoWriteException ex)
                when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
            {
                dnnsSkipped++;
            }
        }

        // ── Subnets ───────────────────────────────────────────────────────────
        foreach (var s in dto.Subnets ?? [])
        {
            var cidrErr = InputGuards.Cidr(s.Cidr);
            var dnnErr  = InputGuards.DnnSubnetSpec(s.Dnn, out var canonicalDnn);
            if (cidrErr is not null || dnnErr is not null)
            {
                errors.Add($"subnet {s.Cidr}/{s.Dnn}: " +
                           string.Join("; ", new[] { cidrErr, dnnErr }
                               .Where(e => e is not null)));
                subsSkipped++;
                continue;
            }

            var exists = await ctx.Subnets
                .Find(x => x.Cidr == s.Cidr && x.Dnn == canonicalDnn).AnyAsync(ct);
            if (exists) { subsSkipped++; continue; }

            var rev = await revs.NextAsync(ct);
            var doc = new Subnet
            {
                Cidr = s.Cidr, Dnn = canonicalDnn,
                Dev = s.Dev, Gateway = s.Gateway,
                Label = s.Label, Revision = rev,
            };
            try
            {
                await ctx.Subnets.InsertOneAsync(doc, cancellationToken: ct);
                await audit.RecordAsync("sync-import", "subnet", null, doc, rev, actor, ct);
                subsAdded++;
            }
            catch (MongoWriteException ex)
                when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
            {
                subsSkipped++;
            }
        }

        // ── UPF peers ─────────────────────────────────────────────────────────
        foreach (var p in dto.UpfPeers ?? [])
        {
            var hostErr = InputGuards.Host(p.Host);
            if (hostErr is not null)
            {
                errors.Add($"upf-peer {p.Host}: {hostErr}");
                peersSkipped++;
                continue;
            }

            var exists = await ctx.UpfPeers
                .Find(x => x.Host == p.Host).AnyAsync(ct);
            if (exists) { peersSkipped++; continue; }

            var rev = await revs.NextAsync(ct);
            var doc = new UpfPeer
            {
                Host = p.Host,
                Port = p.Port ?? 8805,
                Dnns = p.Dnns ?? [],
                Label = p.Label,
                Revision = rev,
            };
            try
            {
                await ctx.UpfPeers.InsertOneAsync(doc, cancellationToken: ct);
                await audit.RecordAsync("sync-import", "upf-peer", null, doc, rev, actor, ct);
                peersAdded++;
            }
            catch (MongoWriteException ex)
                when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
            {
                peersSkipped++;
            }
        }

        // ── Settings (upsert — last-write-wins per the settings contract) ─────
        foreach (var kv in dto.Settings ?? new())
        {
            var parts = kv.Key.Split('/', 2);
            if (parts.Length != 2)
            {
                errors.Add($"settings key '{kv.Key}' must be 'scope/kind'");
                continue;
            }

            var scope   = parts[0].ToLowerInvariant();
            var kind    = parts[1].ToLowerInvariant();
            // Re-serialize the value to get a stable canonical JSON string,
            // then hash it for idempotency (same as the PUT path in SettingsEndpoints).
            var canonical = JsonSerializer.Serialize(kv.Value,
                new JsonSerializerOptions { WriteIndented = false });
            var hash = HashHex(canonical);

            var existing = await ctx.Settings
                .Find(s => s.Scope == scope && s.Kind == kind)
                .FirstOrDefaultAsync(ct);

            // If payload is identical, skip — do NOT bump the revision.
            if (existing is not null && existing.PayloadHash == hash)
            {
                continue;
            }

            var rev = await revs.NextAsync(ct);
            var doc = new SettingsDoc
            {
                Scope       = scope,
                Kind        = kind,
                Payload     = BsonDocument.Parse(canonical),
                PayloadHash = hash,
                Revision    = rev,
                UpdatedAt   = DateTime.UtcNow,
                CreatedAt   = existing?.CreatedAt ?? DateTime.UtcNow,
            };

            await ctx.Settings.ReplaceOneAsync(
                s => s.Scope == scope && s.Kind == kind,
                doc,
                new ReplaceOptions { IsUpsert = true },
                ct);

            await audit.RecordAsync("sync-import", $"settings:{scope}:{kind}",
                existing, doc, rev, actor, ct);
            settingsUpserted++;
        }

        return TypedResults.Ok(new SyncImportResult(
            tacsAdded,    tacsSkipped,
            dnnsAdded,    dnnsSkipped,
            subsAdded,    subsSkipped,
            peersAdded,   peersSkipped,
            settingsUpserted,
            errors));
    }

    private static string HashHex(string s)
    {
        Span<byte> buf = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(s), buf);
        return Convert.ToHexString(buf).ToLowerInvariant();
    }

    private static void AppendSubnetDnnYaml(StringBuilder sb, string dnn)
    {
        if (dnn.Contains(','))
        {
            sb.AppendLine("      dnn:");
            foreach (var p in dnn.Split(',', StringSplitOptions.TrimEntries))
                sb.AppendLine($"        - {p}");
        }
        else
            sb.AppendLine($"      dnn: {dnn}");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/v1/sync/export?format=yaml|json
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<ContentHttpResult> Export(
        string? format,
        AdminContext ctx,
        CancellationToken ct)
    {
        var tacs    = await ctx.Tacs.Find(FilterDefinition<Tac>.Empty)
                          .SortBy(t => t.Mcc).ThenBy(t => t.Mnc).ThenBy(t => t.TacValue)
                          .ToListAsync(ct);
        var dnns    = await ctx.Dnns.Find(FilterDefinition<Dnn>.Empty)
                          .SortBy(d => d.Name).ToListAsync(ct);
        var subnets = await ctx.Subnets.Find(FilterDefinition<Subnet>.Empty)
                          .SortBy(s => s.Dnn).ThenBy(s => s.Cidr).ToListAsync(ct);
        var peers   = await ctx.UpfPeers.Find(FilterDefinition<UpfPeer>.Empty)
                          .SortBy(p => p.Host).ToListAsync(ct);
        var settings = await ctx.Settings.Find(FilterDefinition<SettingsDoc>.Empty)
                           .SortBy(s => s.Scope).ThenBy(s => s.Kind).ToListAsync(ct);

        bool asJson = string.Equals(format, "json",
                                    StringComparison.OrdinalIgnoreCase);

        if (asJson)
        {
            var obj = new
            {
                tacs     = tacs.Select(t => new { t.Mcc, t.Mnc, tac = t.TacValue, t.Label }),
                dnns     = dnns.Select(d => new { name = d.Name, d.Dns1, d.Dns2, d.Mtu,
                                                   d.SliceSst, d.SliceSd, d.Label }),
                subnets  = subnets.Select(s => new { s.Cidr, s.Dnn, s.Dev, s.Gateway, s.Label }),
                upfPeers = peers.Select(p => new { p.Host, p.Port, p.Label }),
                settings = settings.ToDictionary(
                    s => $"{s.Scope}/{s.Kind}",
                    s => (object)s.Payload.ToJson()),
            };
            var json = System.Text.Json.JsonSerializer.Serialize(
                obj, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            return TypedResults.Content(json, "application/json");
        }

        // ── YAML export ───────────────────────────────────────────────────────
        var sb = new StringBuilder();
        sb.AppendLine("# =============================================================");
        sb.AppendLine("# Open5GS Admin API — config export");
        sb.AppendLine($"# Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine("# =============================================================");
        sb.AppendLine();

        // ── mme.yaml snippet ─────────────────────────────────────────────────
        if (tacs.Count > 0)
        {
            sb.AppendLine("# ── mme.yaml ─────────────────────────────────────────────");
            sb.AppendLine("# Paste inside the  mme:  block.");
            sb.AppendLine();
            sb.AppendLine("mme:");

            // Group by PLMN (mcc+mnc) to produce list2 blocks
            var byPlmn = tacs
                .GroupBy(t => (t.Mcc, t.Mnc))
                .OrderBy(g => g.Key.Mcc).ThenBy(g => g.Key.Mnc);

            sb.AppendLine("  served_tai:");
            foreach (var plmnGroup in byPlmn)
            {
                sb.AppendLine("    - plmn_id:");
                sb.AppendLine($"        mcc: '{plmnGroup.Key.Mcc}'");
                sb.AppendLine($"        mnc: '{plmnGroup.Key.Mnc}'");
                sb.AppendLine("      tac:");
                foreach (var t in plmnGroup)
                {
                    if (t.Label is not null)
                        sb.AppendLine($"        - {t.TacValue}  # {t.Label}");
                    else
                        sb.AppendLine($"        - {t.TacValue}");
                }
            }
            sb.AppendLine();
        }

        // ── smf.yaml snippet ─────────────────────────────────────────────────
        if (dnns.Count > 0 || subnets.Count > 0)
        {
            sb.AppendLine("# ── smf.yaml ─────────────────────────────────────────────");
            sb.AppendLine("# Paste inside the  smf:  block.");
            sb.AppendLine();
            sb.AppendLine("smf:");

            if (dnns.Count > 0)
            {
                sb.AppendLine("  # APNs / DNNs");
                foreach (var d in dnns)
                {
                    sb.AppendLine("  - apn: " + d.Name +
                                  (d.Label is not null ? $"  # {d.Label}" : ""));
                    if (d.Dns1 is not null)
                    {
                        sb.AppendLine("    dns:");
                        sb.AppendLine($"      - {d.Dns1}");
                        if (d.Dns2 is not null)
                            sb.AppendLine($"      - {d.Dns2}");
                    }
                    if (d.Mtu.HasValue)
                        sb.AppendLine($"    mtu: {d.Mtu}");
                    if (d.SliceSst.HasValue)
                    {
                        sb.AppendLine("    slice:");
                        sb.AppendLine($"      sst: {d.SliceSst}");
                        if (d.SliceSd is not null)
                            sb.AppendLine($"      sd: {d.SliceSd}");
                    }
                }
                sb.AppendLine();
            }

            if (subnets.Count > 0)
            {
                sb.AppendLine("  # IP pools (subnet assignments)");
                sb.AppendLine("  subnet:");
                foreach (var s in subnets)
                {
                    sb.AppendLine($"    - addr: {s.Cidr}" +
                                  (s.Label is not null ? $"  # {s.Label}" : ""));
                    AppendSubnetDnnYaml(sb, s.Dnn);
                    if (s.Dev is not null)
                        sb.AppendLine($"      dev: {s.Dev}");
                    if (s.Gateway is not null)
                        sb.AppendLine($"      gateway: {s.Gateway}");
                }
                sb.AppendLine();
            }
        }

        // ── upf.yaml snippet ─────────────────────────────────────────────────
        if (peers.Count > 0 || subnets.Count > 0)
        {
            sb.AppendLine("# ── upf.yaml ─────────────────────────────────────────────");
            sb.AppendLine("# Paste inside the  upf:  block.");
            sb.AppendLine();
            sb.AppendLine("upf:");

            if (subnets.Count > 0)
            {
                sb.AppendLine("  subnet:");
                foreach (var s in subnets)
                {
                    sb.AppendLine($"    - addr: {s.Cidr}" +
                                  (s.Label is not null ? $"  # {s.Label}" : ""));
                    AppendSubnetDnnYaml(sb, s.Dnn);
                    if (s.Dev is not null)
                        sb.AppendLine($"      dev: {s.Dev}");
                    if (s.Gateway is not null)
                        sb.AppendLine($"      gateway: {s.Gateway}");
                }
                sb.AppendLine();
            }

            if (peers.Count > 0)
            {
                sb.AppendLine("  # SMF peers that this UPF should advertise to");
                sb.AppendLine("  pfcp:");
                foreach (var p in peers)
                {
                    sb.AppendLine($"    - addr: {p.Host}" +
                                  (p.Label is not null ? $"  # {p.Label}" : ""));
                    if (p.Port != 8805)
                        sb.AppendLine($"      port: {p.Port}");
                }
                sb.AppendLine();
            }
        }

        // ── settings snippets ─────────────────────────────────────────────────
        if (settings.Count > 0)
        {
            sb.AppendLine("# ── Admin API settings (re-import with POST /api/v1/sync/import)");
            sb.AppendLine("# These are stored in the DB and applied at runtime via the");
            sb.AppendLine("# C watcher — they do NOT go into YAML files.");
            sb.AppendLine("#");
            foreach (var s in settings)
            {
                sb.AppendLine($"# settings/{s.Scope}/{s.Kind}:");
                // Indent the raw JSON as a comment block so the YAML file is valid
                var json = s.Payload.ToJson();
                foreach (var line in json.Split('\n'))
                    sb.AppendLine("#   " + line.TrimEnd());
                sb.AppendLine("#");
            }
        }

        return TypedResults.Content(sb.ToString(), "text/plain; charset=utf-8");
    }
}
