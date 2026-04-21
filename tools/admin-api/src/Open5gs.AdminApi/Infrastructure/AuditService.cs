using System.Text.Json;
using MongoDB.Bson;
using Open5gs.AdminApi.Models;

namespace Open5gs.AdminApi.Infrastructure;

/// <summary>
/// Append-only audit log. Never update, never delete (TTL handled by ops).
/// Failures to write audit are logged but do not fail the surrounding op.
/// </summary>
public sealed class AuditService
{
    private readonly AdminContext _ctx;
    private readonly ILogger<AuditService> _log;

    public AuditService(AdminContext ctx, ILogger<AuditService> log)
    {
        _ctx = ctx;
        _log = log;
    }

    public async Task RecordAsync(
        string op,
        string kind,
        object? before,
        object? after,
        long revision,
        string? actor,
        CancellationToken ct = default)
    {
        var entry = new AuditEntry
        {
            Id = ObjectId.GenerateNewId(),
            At = DateTime.UtcNow,
            Actor = actor,
            Op = op,
            Kind = kind,
            Revision = revision,
            Before = before is null ? null : JsonSerializer.SerializeToDocument(before),
            After = after is null ? null : JsonSerializer.SerializeToDocument(after),
        };

        try
        {
            await _ctx.Audit.InsertOneAsync(entry, cancellationToken: ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "audit: failed to write entry kind={Kind} op={Op}",
                kind, op);
        }
    }
}
