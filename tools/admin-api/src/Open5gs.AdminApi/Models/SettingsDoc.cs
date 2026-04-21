using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Open5gs.AdminApi.Models;

/// <summary>
/// "Settings" resources are last-write-wins singletons keyed by the natural
/// pair (<see cref="Scope"/>, <see cref="Kind"/>) — e.g. ("smf", "cdr").
///
/// They are deliberately separate from the append-only list resources
/// (PLMN/TAC/DNN/UPF-peer/Subnet) because their semantics differ:
///   • Lists never change in place; new rows are appended and old ones
///     deleted/forgotten.
///   • Settings are mutated in place by PUT. Each PUT bumps the global
///     revision so watchers can detect the change. PUTting an identical
///     payload is a no-op (the revision is NOT bumped) for idempotency.
/// </summary>
public sealed class SettingsDoc
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public ObjectId Id { get; set; }

    /// <summary>NF family the setting belongs to: "smf", "upf", "mme", ...</summary>
    public required string Scope { get; set; }

    /// <summary>Kind within the scope, e.g. "cdr", "radius", "logging".</summary>
    public required string Kind { get; set; }

    /// <summary>
    /// Opaque JSON document containing the setting payload. Validated against
    /// a per-(scope, kind) schema in the endpoint layer; stored as raw BSON
    /// so adding new kinds does not require schema migration.
    /// </summary>
    public BsonDocument Payload { get; set; } = new BsonDocument();

    /// <summary>
    /// Stable hash (sha-256, hex, lower-case) of the payload's canonical
    /// JSON form. Used to keep PUT idempotent without round-tripping the
    /// full document on every comparison.
    /// </summary>
    public string PayloadHash { get; set; } = string.Empty;

    /// <summary>Global revision at which the document was last modified.</summary>
    public long Revision { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Free-form operator label (e.g. "site-a"). Not interpreted.</summary>
    public string? Label { get; set; }
}
