using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Open5gs.AdminApi.Auth;
using Open5gs.AdminApi.Infrastructure;

namespace Open5gs.AdminApi.Endpoints;

public static class MaintenanceEndpoints
{
    private static readonly string[] SupportedNfs = ["mme", "sgwc", "smf"];

    public static RouteGroupBuilder MapMaintenance(this RouteGroupBuilder root)
    {
        var g = root.MapGroup("/maintenance")
            .WithTags("maintenance")
            .RequireAuthorization(AuthExtensions.PolicyAdmin);

        g.MapGet("/{nf}/status", GetStatus);
        g.MapPost("/{nf}/enable", Enable);
        g.MapPost("/{nf}/disable", Disable);
        g.MapPost("/{nf}/drain", Drain);
        g.MapPost("/drain-all", DrainAll);

        return root;
    }

    private static bool TryGetBaseUrl(MaintenanceOptions opts, string nf, out string baseUrl)
    {
        baseUrl = nf switch
        {
            "mme" => opts.Mme,
            "sgwc" => opts.Sgwc,
            "smf" => opts.Smf,
            _ => "",
        };
        return SupportedNfs.Contains(nf, StringComparer.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(baseUrl);
    }

    private static IResult? BadNf(string nf)
    {
        if (SupportedNfs.Contains(nf, StringComparer.OrdinalIgnoreCase))
            return null;
        return Results.BadRequest(new
        {
            error = $"unsupported nf '{nf}' (use mme, sgwc, or smf)",
        });
    }

    private static async Task<IResult> GetStatus(
        string nf,
        IHttpClientFactory httpFactory,
        IOptions<MaintenanceOptions> opts,
        CancellationToken ct)
    {
        var bad = BadNf(nf);
        if (bad != null) return bad;

        nf = nf.ToLowerInvariant();
        if (!TryGetBaseUrl(opts.Value, nf, out var baseUrl))
            return Results.Problem($"Maintenance URL not configured for {nf}");

        return await ProxyGetAsync(httpFactory, baseUrl, "/admin/maintenance/status", ct);
    }

    private static Task<IResult> Enable(
        string nf,
        IHttpClientFactory httpFactory,
        IOptions<MaintenanceOptions> opts,
        CancellationToken ct) =>
        ProxyPostAsync(httpFactory, opts.Value, nf, "/admin/maintenance/enable", false, ct);

    private static Task<IResult> Disable(
        string nf,
        IHttpClientFactory httpFactory,
        IOptions<MaintenanceOptions> opts,
        CancellationToken ct) =>
        ProxyPostAsync(httpFactory, opts.Value, nf, "/admin/maintenance/disable", false, ct);

    private static Task<IResult> Drain(
        string nf,
        [FromQuery] bool force,
        IHttpClientFactory httpFactory,
        IOptions<MaintenanceOptions> opts,
        CancellationToken ct) =>
        ProxyPostAsync(httpFactory, opts.Value, nf, "/admin/maintenance/drain", force, ct);

    /// <summary>
    /// Operator workflow: MME first (detach UEs), then SGWC, then SMF.
    /// </summary>
    private static async Task<IResult> DrainAll(
        [FromQuery] bool force,
        IHttpClientFactory httpFactory,
        IOptions<MaintenanceOptions> opts,
        CancellationToken ct)
    {
        var results = new List<object>();
        foreach (var nf in SupportedNfs)
        {
            var (status, body) = await SendPostAsync(
                httpFactory, opts.Value, nf, "/admin/maintenance/drain", force, ct);
            results.Add(new { nf, status, body });
            if (status >= 400)
            {
                return Results.Json(new
                {
                    error = $"drain failed on {nf}",
                    completed = results,
                }, statusCode: status);
            }
        }

        return Results.Ok(new { drained = results });
    }

    private static async Task<IResult> ProxyPostAsync(
        IHttpClientFactory httpFactory,
        MaintenanceOptions opts,
        string nf,
        string path,
        bool force,
        CancellationToken ct)
    {
        var bad = BadNf(nf);
        if (bad != null) return bad;

        nf = nf.ToLowerInvariant();
        if (!TryGetBaseUrl(opts, nf, out var baseUrl))
            return Results.Problem($"Maintenance URL not configured for {nf}");

        var (status, body) = await SendPostAsync(
            httpFactory, opts, nf, path, force, ct);
        return Results.Content(body, "application/json", statusCode: status);
    }

    private static async Task<(int status, string body)> SendPostAsync(
        IHttpClientFactory httpFactory,
        MaintenanceOptions opts,
        string nf,
        string path,
        bool force,
        CancellationToken ct)
    {
        if (!TryGetBaseUrl(opts, nf.ToLowerInvariant(), out var baseUrl))
            return (500, "{\"error\":\"maintenance url not configured\"}");

        var url = path + (force ? "?force=1" : "");
        var client = httpFactory.CreateClient("maintenance");
        using var req = new HttpRequestMessage(HttpMethod.Post, CombineUrl(baseUrl, url));
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var resp = await client.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        return ((int)resp.StatusCode, body);
    }

    private static async Task<IResult> ProxyGetAsync(
        IHttpClientFactory httpFactory,
        string baseUrl,
        string path,
        CancellationToken ct)
    {
        var client = httpFactory.CreateClient("maintenance");
        using var resp = await client.GetAsync(CombineUrl(baseUrl, path), ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        return Results.Content(body, "application/json", statusCode: (int)resp.StatusCode);
    }

    private static string CombineUrl(string baseUrl, string path)
    {
        baseUrl = baseUrl.TrimEnd('/');
        if (!path.StartsWith('/'))
            path = "/" + path;
        return baseUrl + path;
    }
}
