using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;
using Open5gs.AdminApi.Auth;
using Open5gs.AdminApi.Infrastructure;
using Open5gs.AdminApi.Models;
using Open5gs.AdminApi.Validation;
using System.Text.RegularExpressions;

namespace Open5gs.AdminApi.Endpoints;

public static class SubnetEndpoints
{
    public static RouteGroupBuilder MapSubnets(this RouteGroupBuilder root)
    {
        var g = root.MapGroup("/subnets")
            .WithTags("subnets")
            .RequireAuthorization(AuthExtensions.PolicyAdmin);

        g.MapGet("/", List);
        g.MapPost("/", Create);
        // CIDR contains a '/' which breaks path routing; take id from query.
        g.MapDelete("/", Delete);

        return root;
    }

    private static async Task<Ok<List<Subnet>>> List(
        string? dnn, AdminContext ctx, CancellationToken ct)
    {
        var filter = FilterDefinition<Subnet>.Empty;
        if (!string.IsNullOrEmpty(dnn))
        {
            var q = dnn.ToLowerInvariant();
            var esc = Regex.Escape(q);
            filter &= Builders<Subnet>.Filter.Regex(
                s => s.Dnn,
                new BsonRegularExpression($@"(^|,){esc}(,|$)"));
        }

        var items = await ctx.Subnets.Find(filter)
            .SortBy(s => s.Dnn).ThenBy(s => s.Cidr)
            .ToListAsync(ct);
        return TypedResults.Ok(items);
    }

    private static async Task<Results<
            Created<Subnet>,
            Ok<Subnet>,
            BadRequest<Dictionary<string, string>>,
            Conflict<string>>>
        Create(
            [FromBody] SubnetCreateDto dto,
            AdminContext ctx,
            RevisionService revs,
            AuditService audit,
            HttpContext http,
            CancellationToken ct)
    {
        var dnnSpecErr = InputGuards.DnnSubnetSpec(dto.Dnn, out var canonicalDnn);
        var checks = new[]
        {
            ("cidr",    InputGuards.Cidr(dto.Cidr)),
            ("dnn",     dnnSpecErr),
            ("gateway", InputGuards.IpAddress(dto.Gateway)),
        };
        if (EndpointHelpers.HasErrors(checks))
            return EndpointHelpers.ValidationError(checks);

        var count = await ctx.Subnets.CountDocumentsAsync(
            FilterDefinition<Subnet>.Empty, cancellationToken: ct);
        if (count >= ConfigLimits.MaxSubnets)
            return TypedResults.Conflict(
                $"subnet capacity reached ({ConfigLimits.MaxSubnets})");

        var existing = await ctx.Subnets
            .Find(s => s.Cidr == dto.Cidr && s.Dnn == canonicalDnn)
            .FirstOrDefaultAsync(ct);
        if (existing is not null)
            return TypedResults.Ok(existing);

        var rev = await revs.NextAsync(ct);
        var s = new Subnet
        {
            Cidr = dto.Cidr,
            Dnn = canonicalDnn,
            Dev = dto.Dev,
            Gateway = dto.Gateway,
            Label = dto.Label,
            Revision = rev,
        };

        try
        {
            await ctx.Subnets.InsertOneAsync(s, cancellationToken: ct);
        }
        catch (MongoWriteException ex)
            when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            var again = await ctx.Subnets
                .Find(x => x.Cidr == dto.Cidr && x.Dnn == canonicalDnn)
                .FirstAsync(ct);
            return TypedResults.Ok(again);
        }

        await audit.RecordAsync(
            "add", "subnet", null, s, rev,
            EndpointHelpers.ActorOf(http.User), ct);

        return TypedResults.Created(
            $"/api/v1/subnets?cidr={Uri.EscapeDataString(s.Cidr)}" +
            $"&dnn={Uri.EscapeDataString(s.Dnn)}", s);
    }

    private static async Task<Results<NoContent, NotFound, BadRequest<string>>>
        Delete(
            string? cidr,
            string? dnn,
            AdminContext ctx,
            RevisionService revs,
            AuditService audit,
            HttpContext http,
            CancellationToken ct)
    {
        if (string.IsNullOrEmpty(cidr) || string.IsNullOrEmpty(dnn))
            return TypedResults.BadRequest(
                "both 'cidr' and 'dnn' query parameters are required");

        if (InputGuards.DnnSubnetSpec(dnn, out var canonicalDelete) is { } delErr)
            return TypedResults.BadRequest(delErr);

        var existing = await ctx.Subnets
            .Find(s => s.Cidr == cidr && s.Dnn == canonicalDelete)
            .FirstOrDefaultAsync(ct);
        if (existing is null)
            return TypedResults.NotFound();

        await ctx.Subnets.DeleteOneAsync(
            s => s.Cidr == cidr && s.Dnn == canonicalDelete,
            cancellationToken: ct);
        var rev = await revs.NextAsync(ct);
        await audit.RecordAsync(
            "delete", "subnet", existing, null, rev,
            EndpointHelpers.ActorOf(http.User), ct);
        return TypedResults.NoContent();
    }
}
