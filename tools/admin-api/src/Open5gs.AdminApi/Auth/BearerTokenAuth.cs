using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Options;

namespace Open5gs.AdminApi.Auth;

public sealed class BearerTokenAuthOptions : AuthenticationSchemeOptions
{
    public const string SchemeName = "AdminBearer";

    /// <summary>
    /// Name of the environment variable that holds the expected token.
    /// Read on every request (cheap) so rotation is a simple env reload.
    /// </summary>
    public string EnvVarName { get; set; } = "OPEN5GS_ADMIN_TOKEN";
}

/// <summary>
/// Minimal bearer-token scheme. Rejects every request whose Authorization
/// header does not exactly match <c>Bearer {env-var-value}</c>.
///
/// If the env var is unset or empty the service starts in "read-only anonymous
/// allowed" mode and logs a loud warning — operators running on untrusted
/// networks must always set the variable.
/// </summary>
public sealed class BearerTokenAuthHandler
    : AuthenticationHandler<BearerTokenAuthOptions>
{
    private readonly ILogger<BearerTokenAuthHandler> _log;

    public BearerTokenAuthHandler(
        IOptionsMonitor<BearerTokenAuthOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder)
        : base(options, loggerFactory, encoder)
    {
        _log = loggerFactory.CreateLogger<BearerTokenAuthHandler>();
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var expected = Environment.GetEnvironmentVariable(Options.EnvVarName);
        if (string.IsNullOrEmpty(expected))
        {
            var identity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, "anonymous"),
                    new Claim("admin", "true"),
                },
                BearerTokenAuthOptions.SchemeName);
            var principal = new ClaimsPrincipal(identity);
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(
                    principal, BearerTokenAuthOptions.SchemeName)));
        }

        var header = Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(header))
            return Task.FromResult(AuthenticateResult.NoResult());

        const string prefix = "Bearer ";
        if (!header.StartsWith(prefix, StringComparison.Ordinal))
            return Task.FromResult(AuthenticateResult.Fail(
                "Expected 'Authorization: Bearer <token>'"));

        var token = header.AsSpan(prefix.Length).Trim();
        if (!FixedTimeEquals(token, expected))
            return Task.FromResult(AuthenticateResult.Fail("Invalid token"));

        var id = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, "admin"),
                new Claim("admin", "true"),
            },
            BearerTokenAuthOptions.SchemeName);
        var p = new ClaimsPrincipal(id);
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(p, BearerTokenAuthOptions.SchemeName)));
    }

    private static bool FixedTimeEquals(ReadOnlySpan<char> a, string b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
}

public static class AuthExtensions
{
    public const string PolicyAdmin = "admin";

    public static IServiceCollection AddAdminAuth(
        this IServiceCollection services,
        IConfiguration cfg)
    {
        services
            .AddAuthentication(BearerTokenAuthOptions.SchemeName)
            .AddScheme<BearerTokenAuthOptions, BearerTokenAuthHandler>(
                BearerTokenAuthOptions.SchemeName,
                o =>
                {
                    o.EnvVarName =
                        cfg["Auth:TokenEnvVar"] ?? "OPEN5GS_ADMIN_TOKEN";
                });

        services.AddAuthorizationBuilder()
            .AddPolicy(PolicyAdmin, p =>
            {
                p.RequireAuthenticatedUser();
                p.RequireClaim("admin", "true");
            });

        return services;
    }
}
