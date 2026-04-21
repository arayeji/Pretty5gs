using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Open5gs.AdminApi.Models;

/// <summary>
/// Common base for append-only admin resources. The primary key is a natural
/// composite (enforced by a Mongo unique index) rather than the ObjectId —
/// that makes <c>POST</c> idempotent without client-supplied UUIDs.
/// </summary>
public abstract class ResourceBase
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public ObjectId Id { get; set; }

    /// <summary>Global revision at which this document was last written.</summary>
    public long Revision { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Free-form operator label (e.g. "site-a", "cluster-1"). Not interpreted.
    /// </summary>
    public string? Label { get; set; }
}
