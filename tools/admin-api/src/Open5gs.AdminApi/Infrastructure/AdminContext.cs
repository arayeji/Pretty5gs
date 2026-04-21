using MongoDB.Bson;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Driver;
using Open5gs.AdminApi.Models;

namespace Open5gs.AdminApi.Infrastructure;

/// <summary>
/// Thin wrapper over <see cref="IMongoDatabase"/> exposing the typed
/// collections used by this service. All collection names are stable and
/// versioned; breaking changes go to a new collection name (e.g. "plmns_v2").
/// </summary>
public sealed class AdminContext
{
    public const string PlmnsCollection = "plmns";
    public const string TacsCollection = "tacs";
    public const string DnnsCollection = "dnns";
    public const string UpfPeersCollection = "upf_peers";
    public const string SubnetsCollection = "subnets";
    public const string AuditCollection = "audit_log";
    public const string RevisionCollection = "revision";
    public const string HeartbeatCollection = "nf_heartbeats";
    public const string SettingsCollection = "settings";

    private static int s_conventionsRegistered;

    public AdminContext(IConfiguration config)
    {
        if (Interlocked.Exchange(ref s_conventionsRegistered, 1) == 0)
        {
            var pack = new ConventionPack
            {
                new CamelCaseElementNameConvention(),
                new IgnoreExtraElementsConvention(true),
                new EnumRepresentationConvention(BsonType.String),
            };
            ConventionRegistry.Register("open5gs-admin", pack, _ => true);
        }

        var cs = config["Mongo:ConnectionString"]
            ?? throw new InvalidOperationException(
                "Mongo:ConnectionString is not configured.");
        var dbName = config["Mongo:Database"]
            ?? throw new InvalidOperationException(
                "Mongo:Database is not configured.");

        var settings = MongoClientSettings.FromConnectionString(cs);
        settings.ServerSelectionTimeout = TimeSpan.FromSeconds(5);
        Client = new MongoClient(settings);
        Database = Client.GetDatabase(dbName);
    }

    public IMongoClient Client { get; }
    public IMongoDatabase Database { get; }

    public IMongoCollection<Plmn> Plmns =>
        Database.GetCollection<Plmn>(PlmnsCollection);
    public IMongoCollection<Tac> Tacs =>
        Database.GetCollection<Tac>(TacsCollection);
    public IMongoCollection<Dnn> Dnns =>
        Database.GetCollection<Dnn>(DnnsCollection);
    public IMongoCollection<UpfPeer> UpfPeers =>
        Database.GetCollection<UpfPeer>(UpfPeersCollection);
    public IMongoCollection<Subnet> Subnets =>
        Database.GetCollection<Subnet>(SubnetsCollection);
    public IMongoCollection<AuditEntry> Audit =>
        Database.GetCollection<AuditEntry>(AuditCollection);
    public IMongoCollection<NfHeartbeat> Heartbeats =>
        Database.GetCollection<NfHeartbeat>(HeartbeatCollection);
    public IMongoCollection<SettingsDoc> Settings =>
        Database.GetCollection<SettingsDoc>(SettingsCollection);
    public IMongoCollection<BsonDocument> RevisionRaw =>
        Database.GetCollection<BsonDocument>(RevisionCollection);

    /// <summary>
    /// Create the natural-key unique indexes that enforce idempotency at
    /// the storage layer. Called once at startup.
    /// </summary>
    public async Task EnsureIndexesAsync(CancellationToken ct = default)
    {
        await Plmns.Indexes.CreateOneAsync(
            new CreateIndexModel<Plmn>(
                Builders<Plmn>.IndexKeys
                    .Ascending(p => p.Mcc)
                    .Ascending(p => p.Mnc),
                new CreateIndexOptions { Unique = true, Name = "uq_plmn" }),
            cancellationToken: ct);

        await Tacs.Indexes.CreateOneAsync(
            new CreateIndexModel<Tac>(
                Builders<Tac>.IndexKeys
                    .Ascending(t => t.Mcc)
                    .Ascending(t => t.Mnc)
                    .Ascending(t => t.TacValue),
                new CreateIndexOptions { Unique = true, Name = "uq_tac" }),
            cancellationToken: ct);

        await Dnns.Indexes.CreateOneAsync(
            new CreateIndexModel<Dnn>(
                Builders<Dnn>.IndexKeys.Ascending(d => d.Name),
                new CreateIndexOptions { Unique = true, Name = "uq_dnn" }),
            cancellationToken: ct);

        await UpfPeers.Indexes.CreateOneAsync(
            new CreateIndexModel<UpfPeer>(
                Builders<UpfPeer>.IndexKeys
                    .Ascending(u => u.Host)
                    .Ascending(u => u.Port),
                new CreateIndexOptions { Unique = true, Name = "uq_upf_peer" }),
            cancellationToken: ct);

        await Subnets.Indexes.CreateOneAsync(
            new CreateIndexModel<Subnet>(
                Builders<Subnet>.IndexKeys
                    .Ascending(s => s.Cidr)
                    .Ascending(s => s.Dnn),
                new CreateIndexOptions { Unique = true, Name = "uq_subnet" }),
            cancellationToken: ct);

        await Audit.Indexes.CreateOneAsync(
            new CreateIndexModel<AuditEntry>(
                Builders<AuditEntry>.IndexKeys.Descending(a => a.At),
                new CreateIndexOptions { Name = "ix_audit_at" }),
            cancellationToken: ct);

        await Heartbeats.Indexes.CreateOneAsync(
            new CreateIndexModel<NfHeartbeat>(
                Builders<NfHeartbeat>.IndexKeys.Ascending(h => h.NfId),
                new CreateIndexOptions { Unique = true, Name = "uq_nf" }),
            cancellationToken: ct);

        await Settings.Indexes.CreateOneAsync(
            new CreateIndexModel<SettingsDoc>(
                Builders<SettingsDoc>.IndexKeys
                    .Ascending(s => s.Scope)
                    .Ascending(s => s.Kind),
                new CreateIndexOptions { Unique = true, Name = "uq_settings" }),
            cancellationToken: ct);
    }
}
