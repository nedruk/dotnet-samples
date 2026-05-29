using Microsoft.IdentityModel.Tokens;

namespace FirstCallRegistration;

public static class AgentProviderServer
{
    public static WebApplication CreateApp(JsonWebKey rootPublicKey, int port)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.UseUrls($"https://localhost:{port}");
        builder.Logging.ClearProviders();

        var app = builder.Build();
        var baseUrl = $"https://localhost:{port}";

        app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new
        {
            issuer = baseUrl,
            jwks_uri = $"{baseUrl}/jwks"
        }));

        app.MapGet("/jwks", () => Results.Json(new
        {
            keys = new[] { rootPublicKey }
        }));

        return app;
    }
}
