using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using Open5gs.AdminApi.Auth;
using Open5gs.AdminApi.Infrastructure;
using Open5gs.AdminApi.Models;
using Open5gs.AdminApi.Validation;

namespace Open5gs.AdminApi.Endpoints;

public static class UpfPeerEndpoints
{
    public static RouteGroupBuilder MapUpfPeers(this RouteGroupBuilder root)
    {
        var g = root.MapGroup("/upf-peers")
            .WithTags("upf-peers")
            .RequireAuthorization(AuthExtensions.PolicyAdmin);

        g.MapGet("/", List);
        g.MapPost("/", Create);
        g.MapDelete("/{host}/{port:int}", Delete);

        return root;
    }

    private static async Task<Ok<List<UpfPeer>>> List(
        AdminContext ctx, CancellationToken ct)
    {
        var items = await ctx.UpfPeers.Find(FilterDefinition<UpfPeer>.Empty)
            .SortBy(u => u.Host).ThenBy(u => u.Port)
            .ToListAsync(ct);
        return TypedResults.Ok(items);
    }

    private static async Task<Results<
            Created<UpfPeer>,
            Ok<UpfPeer>,
            BadRequest<Dictionary<string, string>>,
            Conflict<string>>>
        Create(
            [FromBody] UpfPeerCreateDto dto,
            AdminContext ctx,
            RevisionService revs,
            AuditService audit,
            HttpContext http,
            CancellationToken ct)
    {
        var port = dto.Port ?? 8805;
        var checks = new[]
        {
            ("host", InputGuards.Host(dto.Host)),
            ("port", InputGuards.Port(port)),
        };
        if (EndpointHelpers.HasErrors(checks))
            return EndpointHelpers.ValidationError(checks);

        var count = await ctx.UpfPeers.CountDocumentsAsync(
            FilterDefinition<UpfPeer>.Empty, cancellationToken: ct);
        if (count >= ConfigLimits.MaxUpfPeers)
            return TypedResults.Conflict(
                $"upf peer capacity reached ({ConfigLimits.MaxUpfPeers})");

        var existing = await ctx.UpfPeers
            .Find(u => u.Host == dto.Host && u.Port == port)
            .FirstOrDefaultAsync(ct);
        if (existing is not null)
            return TypedResults.Ok(existing);

        var rev = await revs.NextAsync(ct);
        var u = new UpfPeer
        {
            Host = dto.Host,
            Port = port,
            Dnns = dto.Dnns ?? Array.Empty<string>(),
            Label = dto.Label,
            Revision = rev,
        };

        try
        {
            await ctx.UpfPeers.InsertOneAsync(u, cancellationToken: ct);
        }
        catch (MongoWriteException ex)
            when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            var again = await ctx.UpfPeers
                .Find(x => x.Host == dto.Host && x.Port == port)
                .FirstAsync(ct);
            return TypedResults.Ok(again);
        }

        await audit.RecordAsync(
            "add", "upf_peer", null, u, rev,
            EndpointHelpers.ActorOf(http.User), ct);

        return TypedResults.Created(
            $"/api/v1/upf-peers/{u.Host}/{u.Port}", u);
    }

    private static async Task<Results<NoContent, NotFound>> Delete(
        string host,
        int port,
        AdminContext ctx,
        RevisionService revs,
        AuditService audit,
        HttpContext http,
        CancellationToken ct)
    {
        var existing = await ctx.UpfPeers
            .Find(u => u.Host == host && u.Port == port)
            .FirstOrDefaultAsync(ct);
        if (existing is null)
            return TypedResults.NotFound();

        await ctx.UpfPeers.DeleteOneAsync(
            u => u.Host == host && u.Port == port,
            cancellationToken: ct);
        var rev = await revs.NextAsync(ct);
        await audit.RecordAsync(
            "delete", "upf_peer", existing, null, rev,
            EndpointHelpers.ActorOf(http.User), ct);
        return TypedResults.NoContent();
    }
}
