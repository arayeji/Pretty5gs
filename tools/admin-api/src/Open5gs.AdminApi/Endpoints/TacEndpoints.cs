using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using Open5gs.AdminApi.Auth;
using Open5gs.AdminApi.Infrastructure;
using Open5gs.AdminApi.Models;
using Open5gs.AdminApi.Validation;

namespace Open5gs.AdminApi.Endpoints;

public static class TacEndpoints
{
    public static RouteGroupBuilder MapTacs(this RouteGroupBuilder root)
    {
        var g = root.MapGroup("/tacs")
            .WithTags("tacs")
            .RequireAuthorization(AuthExtensions.PolicyAdmin);

        g.MapGet("/", List);
        g.MapPost("/", Create);
        g.MapDelete("/{mcc}/{mnc}/{tac:int}", Delete);

        return root;
    }

    private static async Task<Ok<List<Tac>>> List(
        string? mcc,
        string? mnc,
        AdminContext ctx,
        CancellationToken ct)
    {
        var fb = Builders<Tac>.Filter;
        var filter = FilterDefinition<Tac>.Empty;
        if (!string.IsNullOrEmpty(mcc))
            filter &= fb.Eq(t => t.Mcc, mcc);
        if (!string.IsNullOrEmpty(mnc))
            filter &= fb.Eq(t => t.Mnc, mnc);

        var items = await ctx.Tacs.Find(filter)
            .SortBy(t => t.Mcc).ThenBy(t => t.Mnc).ThenBy(t => t.TacValue)
            .ToListAsync(ct);
        return TypedResults.Ok(items);
    }

    private static async Task<Results<
            Created<Tac>,
            Ok<Tac>,
            BadRequest<Dictionary<string, string>>,
            Conflict<string>>>
        Create(
            [FromBody] TacCreateDto dto,
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
            ("tac", InputGuards.Tac(dto.Tac)),
        };
        if (EndpointHelpers.HasErrors(checks))
            return EndpointHelpers.ValidationError(checks);

        // Capacity check — aggregate across all PLMNs is what the MME's
        // served_tai array bounds care about on apply.
        var total = await ctx.Tacs.CountDocumentsAsync(
            FilterDefinition<Tac>.Empty, cancellationToken: ct);
        // Each served_tai entry can hold up to MaxTacsPerServedEntry TACs, and
        // we allow up to MaxServedTaiEntries entries. Be conservative.
        var cap = ConfigLimits.MaxServedTaiEntries *
                  ConfigLimits.MaxTacsPerServedEntry;
        if (total >= cap)
            return TypedResults.Conflict($"tac capacity reached ({cap})");

        var existing = await ctx.Tacs
            .Find(t => t.Mcc == dto.Mcc
                    && t.Mnc == dto.Mnc
                    && t.TacValue == dto.Tac)
            .FirstOrDefaultAsync(ct);
        if (existing is not null)
            return TypedResults.Ok(existing);

        var rev = await revs.NextAsync(ct);
        var t = new Tac
        {
            Mcc = dto.Mcc,
            Mnc = dto.Mnc,
            TacValue = dto.Tac,
            Label = dto.Label,
            Revision = rev,
        };

        try
        {
            await ctx.Tacs.InsertOneAsync(t, cancellationToken: ct);
        }
        catch (MongoWriteException ex)
            when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            var again = await ctx.Tacs
                .Find(x => x.Mcc == dto.Mcc
                        && x.Mnc == dto.Mnc
                        && x.TacValue == dto.Tac)
                .FirstAsync(ct);
            return TypedResults.Ok(again);
        }

        await audit.RecordAsync(
            "add", "tac", null, t, rev,
            EndpointHelpers.ActorOf(http.User), ct);

        return TypedResults.Created(
            $"/api/v1/tacs/{t.Mcc}/{t.Mnc}/{t.TacValue}", t);
    }

    private static async Task<Results<NoContent, NotFound>> Delete(
        string mcc,
        string mnc,
        int tac,
        AdminContext ctx,
        RevisionService revs,
        AuditService audit,
        HttpContext http,
        CancellationToken ct)
    {
        var existing = await ctx.Tacs
            .Find(t => t.Mcc == mcc && t.Mnc == mnc && t.TacValue == tac)
            .FirstOrDefaultAsync(ct);
        if (existing is null)
            return TypedResults.NotFound();

        await ctx.Tacs.DeleteOneAsync(
            t => t.Mcc == mcc && t.Mnc == mnc && t.TacValue == tac,
            cancellationToken: ct);
        var rev = await revs.NextAsync(ct);
        await audit.RecordAsync(
            "delete", "tac", existing, null, rev,
            EndpointHelpers.ActorOf(http.User), ct);
        return TypedResults.NoContent();
    }
}
