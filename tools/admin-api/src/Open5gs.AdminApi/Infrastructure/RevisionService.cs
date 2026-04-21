using MongoDB.Bson;
using MongoDB.Driver;

namespace Open5gs.AdminApi.Infrastructure;

/// <summary>
/// Monotonic global revision counter. Every successful write bumps it by one.
/// NFs read the counter to decide when they have caught up; admins use it as
/// an If-Match / ETag primitive.
/// </summary>
public sealed class RevisionService
{
    private const string CounterKey = "global";

    private readonly AdminContext _ctx;

    public RevisionService(AdminContext ctx)
    {
        _ctx = ctx;
    }

    public async Task<long> NextAsync(CancellationToken ct = default)
    {
        var filter = Builders<BsonDocument>.Filter.Eq("_id", CounterKey);
        var update = Builders<BsonDocument>.Update.Inc("value", 1L);
        var opts = new FindOneAndUpdateOptions<BsonDocument>
        {
            IsUpsert = true,
            ReturnDocument = ReturnDocument.After,
        };

        var doc = await _ctx.RevisionRaw
            .FindOneAndUpdateAsync(filter, update, opts, ct);
        return doc["value"].ToInt64();
    }

    public async Task<long> CurrentAsync(CancellationToken ct = default)
    {
        var filter = Builders<BsonDocument>.Filter.Eq("_id", CounterKey);
        var doc = await _ctx.RevisionRaw
            .Find(filter)
            .FirstOrDefaultAsync(ct);
        return doc is null ? 0L : doc["value"].ToInt64();
    }
}
