using System.Security.Claims;
using System.Security.Cryptography;
using AAuth.Core.Signatures;
using AAuth.Server;
using Microsoft.IdentityModel.Tokens;

namespace HelloAAuth;

/// <summary>
/// Resource server — verifies agent identity and applies allowlist-based access control.
/// </summary>
public static class ResourceServer
{
    public static WebApplication CreateApp(string[] allowedAgents, int port)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls($"https://localhost:{port}");
        builder.Logging.ClearProviders();

        // Generate a throwaway key for server signing material
        var serverEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var serverSigningKey = serverEcdsa;
        var serverPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
            new ECDsaSecurityKey(serverEcdsa));

        builder.Services.AddAuthentication("AAuth")
            .AddAAuth(opts =>
            {
                opts.ServerIdentifier = $"https://localhost:{port}";
                opts.GetKeyMaterial = async () => new KeyMaterial
                {
                    SigningKey = serverSigningKey,
                    SignatureKey = new SignatureKeyValue.JwksUri($"https://localhost:{port}/jwks"),
                };
                opts.SupportedModes = AccessMode.IdentityBased;
            });

        builder.Services.AddAuthorization();

        var app = builder.Build();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/api/hello", (HttpContext ctx) =>
        {
            var agentId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (agentId is null)
            {
                return Results.Json(new { error = "unauthorized" }, statusCode: 401);
            }

            if (!allowedAgents.Contains(agentId))
            {
                Console.WriteLine($"  \u2717 Agent \"{agentId}\" not in allowlist");
                return Results.Json(new
                {
                    error = "access_denied",
                    detail = $"Agent \"{agentId}\" is not authorized"
                }, statusCode: 403);
            }

            var issuer = ctx.User.FindFirstValue("aauth_issuer") ?? "self-issued";
            Console.WriteLine($"  \u2713 Access granted to \"{agentId}\"");
            return Results.Json(new
            {
                message = "Hello from the resource!",
                agent = agentId,
                issuer
            });
        }).RequireAuthorization();

        return app;
    }
}
