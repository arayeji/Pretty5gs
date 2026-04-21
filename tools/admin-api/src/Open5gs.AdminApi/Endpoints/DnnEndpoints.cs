using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using Open5gs.AdminApi.Auth;
using Open5gs.AdminApi.Infrastructure;
using Open5gs.AdminApi.Models;
using Open5gs.AdminApi.Validation;

namespace Open5gs.AdminApi.Endpoints;

public static class DnnEndpoints
{
    public static RouteGroupBuilder MapDnns(this RouteGroupBuilder root)
    {
        var g = root.MapGroup("/dnns")
            .WithTags("dnns")
            .RequireAuthorization(AuthExtensions.PolicyAdmin);

        g.MapGet("/", List);
        g.MapPost("/", Create);
        g.MapDelete("/{name}", Delete);

        return root;
    }

    private static async Task<Ok<List<Dnn>>> List(
        AdminContext ctx, CancellationToken ct)
    {
        var items = await ctx.Dnns.Find(FilterDefinition<Dnn>.Empty)
            .SortBy(d => d.Name).ToListAsync(ct);
        return TypedResults.Ok(items);
    }

    private static async Task<Results<
            Created<Dnn>,
            Ok<Dnn>,
            BadRequest<Dictionary<string, string>>,
            Conflict<string>>>
        Create(
            [FromBody] DnnCreateDto dto,
            AdminContext ctx,
            RevisionService revs,
            AuditService audit,
            HttpContext http,
            CancellationToken ct)
    {
        var checks = new[]
        {
            ("name", InputGuards.Dnn(dto.Name)),
            ("dns1", InputGuards.IpAddress(dto.Dns1)),
            ("dns2", InputGuards.IpAddress(dto.Dns2)),
            ("mtu",  InputGuards.Mtu(dto.Mtu)),
            ("sliceSst", InputGuards.Sst(dto.SliceSst)),
            ("sliceSd",  InputGuards.Sd(dto.SliceSd)),
        };
        if (EndpointHelpers.HasErrors(checks))
            return EndpointHelpers.ValidationError(checks);

        var count = await ctx.Dnns.CountDocumentsAsync(
            FilterDefinition<Dnn>.Empty, cancellationToken: ct);
        if (count >= ConfigLimits.MaxDnns)
            return TypedResults.Conflict(
                $"dnn capacity reached ({ConfigLimits.MaxDnns})");

        var normalized = dto.Name.ToLowerInvariant();
        var existing = await ctx.Dnns
            .Find(d => d.Name == normalized)
            .FirstOrDefaultAsync(ct);
        if (existing is not null)
            return TypedResults.Ok(existing);

        var rev = await revs.NextAsync(ct);
        var d = new Dnn
        {
            Name = normalized,
            Dns1 = dto.Dns1,
            Dns2 = dto.Dns2,
            Mtu = dto.Mtu,
            SliceSst = dto.SliceSst,
            SliceSd = dto.SliceSd,
            Label = dto.Label,
            Revision = rev,
        };

        try
        {
            await ctx.Dnns.InsertOneAsync(d, cancellationToken: ct);
        }
        catch (MongoWriteException ex)
            when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            var again = await ctx.Dnns
                .Find(x => x.Name == normalized).FirstAsync(ct);
            return TypedResults.Ok(again);
        }

        await audit.RecordAsync(
            "add", "dnn", null, d, rev,
            EndpointHelpers.ActorOf(http.User), ct);

        return TypedResults.Created($"/api/v1/dnns/{d.Name}", d);
    }

    private static async Task<Results<NoContent, NotFound>> Delete(
        string name,
        AdminContext ctx,
        RevisionService revs,
        AuditService audit,
        HttpContext http,
        CancellationToken ct)
    {
        var normalized = name.ToLowerInvariant();
        var existing = await ctx.Dnns.Find(d => d.Name == normalized)
            .FirstOrDefaultAsync(ct);
        if (existing is null)
            return TypedResults.NotFound();

        await ctx.Dnns.DeleteOneAsync(
            d => d.Name == normalized, cancellationToken: ct);
        var rev = await revs.NextAsync(ct);
        await audit.RecordAsync(
            "delete", "dnn", existing, null, rev,
            EndpointHelpers.ActorOf(http.User), ct);
        return TypedResults.NoContent();
    }
}
