using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.OpenApi.Models;
using MongoDB.Bson;
using MongoDB.Driver;
using Open5gs.AdminApi.Auth;
using Open5gs.AdminApi.Endpoints;
using Open5gs.AdminApi.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<AdminContext>();
builder.Services.AddSingleton<RevisionService>();
builder.Services.AddSingleton<AuditService>();

builder.Services.AddAdminAuth(builder.Configuration);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Open5GS Admin API",
        Version = "v1",
        Description =
            "Append-only admin API for dynamic MME/SMF/UPF configuration. " +
            "Adds are hot-applied by NF watchers on the next revision tick. " +
            "Deletes remove the config entry only and never touch live UEs.",
    });

    var bearerScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "token",
    };
    c.AddSecurityDefinition("bearer", bearerScheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        [new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "bearer",
                },
            }
        ] = Array.Empty<string>(),
    });
});

builder.Services.AddHealthChecks()
    .AddCheck<MongoHealthCheck>("mongo");

builder.Logging.AddSimpleConsole(c =>
{
    c.SingleLine = true;
    c.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ ";
    c.UseUtcTimestamp = true;
});

var app = builder.Build();

// Ensure indexes exist before serving traffic.
using (var scope = app.Services.CreateScope())
{
    var ctx = scope.ServiceProvider.GetRequiredService<AdminContext>();
    try
    {
        await ctx.EnsureIndexesAsync();
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex,
            "admin-api: failed to ensure Mongo indexes; continuing anyway");
    }
}

if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(
        builder.Configuration["Auth:TokenEnvVar"] ?? "OPEN5GS_ADMIN_TOKEN")))
{
    app.Logger.LogWarning(
        "admin-api: no admin token configured (env var unset) — " +
        "all requests will be accepted. Do NOT run this way on untrusted networks.");
}

app.UseAuthentication();
app.UseAuthorization();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Open5GS Admin API v1");
    c.RoutePrefix = "swagger";
});

app.MapHealthChecks("/healthz", new HealthCheckOptions
{
    AllowCachingResponses = false,
});

var v1 = app.MapGroup("/api/v1");
v1.MapPlmns();
v1.MapTacs();
v1.MapDnns();
v1.MapUpfPeers();
v1.MapSubnets();
v1.MapSettings();
v1.MapSync();
v1.MapStatus();

// Prometheus scrape endpoint at /metrics (unauthenticated by design —
// protect via network ACL / reverse proxy if needed).
app.MapGroup("/metrics").MapMetrics();

app.MapGet("/", () => Results.Redirect("/swagger"))
    .ExcludeFromDescription();

app.Run();

/// <summary>Lightweight ping-based Mongo health check.</summary>
internal sealed class MongoHealthCheck : IHealthCheck
{
    private readonly AdminContext _ctx;

    public MongoHealthCheck(AdminContext ctx) { _ctx = ctx; }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var cts = CancellationTokenSource
                .CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            await _ctx.Database.RunCommandAsync<BsonDocument>(
                new BsonDocument("ping", 1), cancellationToken: cts.Token);
            return HealthCheckResult.Healthy();
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy(ex.Message);
        }
    }
}
