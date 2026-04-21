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
/// "Settings" endpoint group. See <see cref="SettingsDoc"/> for the
/// last-write-wins semantics that distinguishes this from list resources.
///
/// Routes:
///   GET    /api/v1/settings                      list all rows
///   GET    /api/v1/settings/{scope}              list one scope
///   GET    /api/v1/settings/{scope}/{kind}       single row (404 if unset)
///   PUT    /api/v1/settings/{scope}/{kind}       upsert (idempotent on payload)
///   DELETE /api/v1/settings/{scope}/{kind}       remove (NF reverts to file/defaults)
/// </summary>
public static class SettingsEndpoints
{
    public static RouteGroupBuilder MapSettings(this RouteGroupBuilder root)
    {
        var g = root.MapGroup("/settings")
            .WithTags("settings")
            .RequireAuthorization(AuthExtensions.PolicyAdmin);

        g.MapGet("/", ListAll);
        g.MapGet("/{scope}", ListScope);
        g.MapGet("/{scope}/{kind}", GetOne);
        g.MapPut("/{scope}/{kind}", Put);
        g.MapDelete("/{scope}/{kind}", Delete);

        return root;
    }

    private static async Task<Ok<List<SettingsDoc>>> ListAll(
        AdminContext ctx, CancellationToken ct)
    {
        var items = await ctx.Settings
            .Find(FilterDefinition<SettingsDoc>.Empty)
            .SortBy(s => s.Scope).ThenBy(s => s.Kind)
            .ToListAsync(ct);
        return TypedResults.Ok(items);
    }

    private static async Task<Ok<List<SettingsDoc>>> ListScope(
        string scope, AdminContext ctx, CancellationToken ct)
    {
        var items = await ctx.Settings
            .Find(s => s.Scope == scope)
            .SortBy(s => s.Kind)
            .ToListAsync(ct);
        return TypedResults.Ok(items);
    }

    private static async Task<Results<Ok<SettingsDoc>, NotFound>> GetOne(
        string scope, string kind, AdminContext ctx, CancellationToken ct)
    {
        var doc = await ctx.Settings
            .Find(s => s.Scope == scope && s.Kind == kind)
            .FirstOrDefaultAsync(ct);
        return doc is null
            ? TypedResults.NotFound()
            : TypedResults.Ok(doc);
    }

    private static async Task<Results<
            Ok<SettingsDoc>,
            BadRequest<Dictionary<string, string>>>>
        Put(
            string scope, string kind,
            [FromBody] JsonElement body,
            AdminContext ctx,
            RevisionService revs,
            AuditService audit,
            HttpContext http,
            CancellationToken ct)
    {
        var keyChecks = new[]
        {
            ("scope", InputGuards.SettingsKey(scope)),
            ("kind",  InputGuards.SettingsKey(kind)),
        };
        if (EndpointHelpers.HasErrors(keyChecks))
            return EndpointHelpers.ValidationError(keyChecks);

        // Per-(scope,kind) typed validator. Unknown combinations are
        // rejected loudly so we never store payloads no NF can consume.
        var validator = SettingsSchemas.For(scope, kind);
        if (validator is null)
            return EndpointHelpers.ValidationError(
                ("kind", $"unknown settings kind '{scope}/{kind}'"));

        var (errors, normalized) = validator(body);
        if (errors.Count > 0)
            return TypedResults.BadRequest(errors);

        // Optional label is read out of the JSON if present (top-level).
        string? label = null;
        if (body.ValueKind == JsonValueKind.Object &&
            body.TryGetProperty("label", out var labelEl) &&
            labelEl.ValueKind == JsonValueKind.String)
        {
            label = labelEl.GetString();
        }

        var canonical = SerializeCanonical(normalized);
        var hash = HashHex(canonical);

        // Idempotency: if there's already a row with the same hash, return
        // it unchanged and do NOT bump the revision.
        var existing = await ctx.Settings
            .Find(s => s.Scope == scope && s.Kind == kind)
            .FirstOrDefaultAsync(ct);
        if (existing is not null && existing.PayloadHash == hash)
            return TypedResults.Ok(existing);

        var rev = await revs.NextAsync(ct);
        var doc = new SettingsDoc
        {
            Scope = scope,
            Kind = kind,
            Payload = BsonDocument.Parse(canonical),
            PayloadHash = hash,
            Revision = rev,
            UpdatedAt = DateTime.UtcNow,
            CreatedAt = existing?.CreatedAt ?? DateTime.UtcNow,
            Label = label,
        };

        var filter = Builders<SettingsDoc>.Filter
            .And(
                Builders<SettingsDoc>.Filter.Eq(s => s.Scope, scope),
                Builders<SettingsDoc>.Filter.Eq(s => s.Kind, kind));

        await ctx.Settings.ReplaceOneAsync(
            filter, doc,
            new ReplaceOptions { IsUpsert = true },
            ct);

        // Re-read so we return the canonical row with its server-side _id.
        doc = await ctx.Settings.Find(filter).FirstAsync(ct);

        await audit.RecordAsync(
            existing is null ? "add" : "update",
            $"settings:{scope}:{kind}",
            existing, doc, rev,
            EndpointHelpers.ActorOf(http.User), ct);

        return TypedResults.Ok(doc);
    }

    private static async Task<Results<NoContent, NotFound>> Delete(
        string scope, string kind,
        AdminContext ctx,
        RevisionService revs,
        AuditService audit,
        HttpContext http,
        CancellationToken ct)
    {
        var existing = await ctx.Settings
            .Find(s => s.Scope == scope && s.Kind == kind)
            .FirstOrDefaultAsync(ct);
        if (existing is null) return TypedResults.NotFound();

        await ctx.Settings.DeleteOneAsync(
            s => s.Scope == scope && s.Kind == kind, cancellationToken: ct);
        var rev = await revs.NextAsync(ct);
        await audit.RecordAsync(
            "delete", $"settings:{scope}:{kind}",
            existing, null, rev,
            EndpointHelpers.ActorOf(http.User), ct);
        return TypedResults.NoContent();
    }

    /* -------------------------------------------------------------- */

    /// <summary>
    /// JSON serialization with a stable property order so the resulting
    /// hash is the same regardless of how the client formatted the body.
    /// </summary>
    private static string SerializeCanonical(JsonElement el)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(
                ms, new JsonWriterOptions { Indented = false }))
        {
            WriteCanonical(w, el);
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static void WriteCanonical(Utf8JsonWriter w, JsonElement el)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                w.WriteStartObject();
                foreach (var p in el.EnumerateObject()
                                    .OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    w.WritePropertyName(p.Name);
                    WriteCanonical(w, p.Value);
                }
                w.WriteEndObject();
                break;
            case JsonValueKind.Array:
                w.WriteStartArray();
                foreach (var item in el.EnumerateArray())
                    WriteCanonical(w, item);
                w.WriteEndArray();
                break;
            default:
                el.WriteTo(w);
                break;
        }
    }

    private static string HashHex(string s)
    {
        Span<byte> buf = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(s), buf);
        return Convert.ToHexString(buf).ToLowerInvariant();
    }
}
