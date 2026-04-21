using System.Security.Claims;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Open5gs.AdminApi.Endpoints;

public static class EndpointHelpers
{
    public static string? ActorOf(ClaimsPrincipal user) =>
        user.Identity?.Name ?? "anonymous";

    public static BadRequest<Dictionary<string, string>> ValidationError(
        params (string Field, string? Error)[] checks)
    {
        var errors = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (field, err) in checks)
            if (err is not null)
                errors[field] = err;
        return TypedResults.BadRequest(errors);
    }

    public static bool HasErrors(
        params (string Field, string? Error)[] checks) =>
        checks.Any(c => c.Error is not null);
}
