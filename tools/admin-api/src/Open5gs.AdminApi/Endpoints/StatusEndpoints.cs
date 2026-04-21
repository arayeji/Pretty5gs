using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using Open5gs.AdminApi.Auth;
using Open5gs.AdminApi.Infrastructure;
using Open5gs.AdminApi.Models;

namespace Open5gs.AdminApi.Endpoints;

public static class StatusEndpoints
{
    public static RouteGroupBuilder MapStatus(this RouteGroupBuilder root)
    {
        var g = root.MapGroup("/apply-status")
            .WithTags("apply-status")
            .RequireAuthorization(AuthExtensions.PolicyAdmin);

        g.MapGet("/", Get);
        g.MapPost("/heartbeat", Heartbeat);

        return root;
    }

    /// <summary>
    /// Returns current global revision plus per-NF latest applied revision.
    /// UI / scripts can diff to decide which NFs are lagging.
    /// </summary>
    private static async Task<Ok<object>> Get(
        AdminContext ctx,
        RevisionService revs,
        CancellationToken ct)
    {
        var current = await revs.CurrentAsync(ct);
        var heartbeats = await ctx.Heartbeats
            .Find(FilterDefinition<NfHeartbeat>.Empty)
            .SortBy(h => h.NfType).ThenBy(h => h.NfId)
            .ToListAsync(ct);

        return TypedResults.Ok<object>(new
        {
            currentRevision = current,
            nfs = heartbeats.Select(h => new
            {
                h.NfId,
                h.NfType,
                h.AppliedRevision,
                h.UpdatedAt,
                h.LastError,
                h.Version,
                lag = current - h.AppliedRevision,
            }),
        });
    }

    /// <summary>
    /// NF watchers POST here after each successful config reload. Upserts on
    /// (nfId, nfType). Intended to be called by in-tree C clients and also by
    /// admins / dashboards.
    /// </summary>
    private static async Task<Ok<NfHeartbeat>> Heartbeat(
        [FromBody] NfHeartbeatDto dto,
        AdminContext ctx,
        CancellationToken ct)
    {
        var filter = Builders<NfHeartbeat>.Filter.Eq(h => h.NfId, dto.NfId)
            & Builders<NfHeartbeat>.Filter.Eq(h => h.NfType, dto.NfType);
        var update = Builders<NfHeartbeat>.Update
            .SetOnInsert(h => h.NfId, dto.NfId)
            .SetOnInsert(h => h.NfType, dto.NfType)
            .Set(h => h.AppliedRevision, dto.AppliedRevision)
            .Set(h => h.LastError, dto.LastError)
            .Set(h => h.Version, dto.Version)
            .Set(h => h.UpdatedAt, DateTime.UtcNow);
        var opts = new FindOneAndUpdateOptions<NfHeartbeat>
        {
            IsUpsert = true,
            ReturnDocument = ReturnDocument.After,
        };

        var doc = await ctx.Heartbeats
            .FindOneAndUpdateAsync(filter, update, opts, ct);
        return TypedResults.Ok(doc);
    }
}
