using System.Text.Json;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Open5gs.AdminApi.Models;

public sealed class AuditEntry
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public ObjectId Id { get; set; }

    public DateTime At { get; set; }

    public string? Actor { get; set; }

    /// <summary>One of "add", "delete".</summary>
    public required string Op { get; set; }

    /// <summary>Resource kind: "plmn", "tac", "dnn", "upf_peer", "subnet".</summary>
    public required string Kind { get; set; }

    public long Revision { get; set; }

    public JsonDocument? Before { get; set; }

    public JsonDocument? After { get; set; }
}
