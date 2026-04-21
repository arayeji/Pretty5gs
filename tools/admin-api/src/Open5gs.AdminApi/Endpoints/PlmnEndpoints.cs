using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using Open5gs.AdminApi.Auth;
using Open5gs.AdminApi.Infrastructure;
using Open5gs.AdminApi.Models;
using Open5gs.AdminApi.Validation;

namespace Open5gs.AdminApi.Endpoints;

public static class PlmnEndpoints
{
    public static RouteGroupBuilder MapPlmns(this RouteGroupBuilder root)
    {
        var g = root.MapGroup("/plmns")
            .WithTags("plmns")
            .RequireAuthorization(AuthExtensions.PolicyAdmin);

        g.MapGet("/", List);
        g.MapPost("/", Create);
        g.MapDelete("/{mcc}/{mnc}", Delete);

        return root;
    }

    private static async Task<Ok<List<Plmn>>> List(
        AdminContext ctx,
        CancellationToken ct)
    {
        var items = await ctx.Plmns
            .Find(FilterDefinition<Plmn>.Empty)
            .SortBy(p => p.Mcc).ThenBy(p => p.Mnc)
            .ToListAsync(ct);
        return TypedResults.Ok(items);
    }

    private static async Task<Results<
            Created<Plmn>,
            Ok<Plmn>,
            BadRequest<Dictionary<string, string>>,
            Conflict<string>>>
        Create(
            [FromBody] PlmnCreateDto dto,
            AdminContext ctx,
            RevisionService revs,
            AuditService audit,
            HttpContext http,
            CancellationToken ct)
    {
        var checks = new[]
        {
            ("mcc", InputGuards.Mcc(dto.Mcc)),
            ("mnc", InputGuards.Mnc(dto.Mnc)),
        };
        if (EndpointHelpers.HasErrors(checks))
            return EndpointHelpers.ValidationError(checks);

        var count = await ctx.Plmns.CountDocumentsAsync(
            FilterDefinition<Plmn>.Empty, cancellationToken: ct);
        if (count >= ConfigLimits.MaxPlmnsMme)
        {
            return TypedResults.Conflict(
                $"plmn capacity reached ({ConfigLimits.MaxPlmnsMme})");
        }

        var existing = await ctx.Plmns
            .Find(p => p.Mcc == dto.Mcc && p.Mnc == dto.Mnc)
            .FirstOrDefaultAsync(ct);
        if (existing is not null)
        {
            // idempotent: same natural key → return existing, no revision bump
            return TypedResults.Ok(existing);
        }

        var rev = await revs.NextAsync(ct);
        var p = new Plmn
        {
            Mcc = dto.Mcc,
            Mnc = dto.Mnc,
            Label = dto.Label,
            Revision = rev,
        };

        try
        {
            await ctx.Plmns.InsertOneAsync(p, cancellationToken: ct);
        }
        catch (MongoWriteException ex)
            when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            // raced: someone else inserted between our check and now
            var again = await ctx.Plmns
                .Find(x => x.Mcc == dto.Mcc && x.Mnc == dto.Mnc)
                .FirstAsync(ct);
            return TypedResults.Ok(again);
        }

        await audit.RecordAsync(
            "add", "plmn", null, p, rev,
            EndpointHelpers.ActorOf(http.User), ct);

        return TypedResults.Created($"/api/v1/plmns/{p.Mcc}/{p.Mnc}", p);
    }

    private static async Task<Results<NoContent, NotFound>> Delete(
        string mcc,
        string mnc,
        AdminContext ctx,
        RevisionService revs,
        AuditService audit,
        HttpContext http,
        CancellationToken ct)
    {
        var existing = await ctx.Plmns
            .Find(p => p.Mcc == mcc && p.Mnc == mnc)
            .FirstOrDefaultAsync(ct);
        if (existing is null)
            return TypedResults.NotFound();

        await ctx.Plmns.DeleteOneAsync(
            p => p.Mcc == mcc && p.Mnc == mnc, cancellationToken: ct);
        var rev = await revs.NextAsync(ct);
        await audit.RecordAsync(
            "delete", "plmn", existing, null, rev,
            EndpointHelpers.ActorOf(http.User), ct);
        return TypedResults.NoContent();
    }
}
