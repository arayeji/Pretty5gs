using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Open5gs.AdminApi.Models;

/// <summary>
/// Posted by each NF's config watcher to report "I have applied revision N".
/// Keyed by (nfType, nfId) so e.g. three SMF replicas each have their own row.
/// </summary>
public sealed class NfHeartbeat
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public ObjectId Id { get; set; }

    public required string NfId { get; set; }

    /// <summary>"mme", "smf", "upf", etc.</summary>
    public required string NfType { get; set; }

    public long AppliedRevision { get; set; }

    public DateTime UpdatedAt { get; set; }

    /// <summary>Optional last error reported by the NF on its latest apply.</summary>
    public string? LastError { get; set; }

    /// <summary>Optional NF version / build info.</summary>
    public string? Version { get; set; }
}

public sealed record NfHeartbeatDto(
    string NfId,
    string NfType,
    long AppliedRevision,
    string? LastError,
    string? Version);
