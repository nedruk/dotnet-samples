using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace PSAssertedAccess;

/// <summary>
/// Self-hosted Agent Provider — serves well-known metadata and JWKS.
/// </summary>
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

        var metadata = JsonSerializer.Serialize(new
        {
            issuer = baseUrl,
            jwks_uri = $"{baseUrl}/jwks"
        });
        var jwks = JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                JsonSerializer.Deserialize<JsonElement>(JsonExtensions.SerializeJwk(rootPublicKey))
            }
        });

        app.MapGet("/.well-known/aauth-agent.json", () => Results.Content(metadata, "application/json"));
        app.MapGet("/jwks", () => Results.Content(jwks, "application/json"));

        return app;
    }
}

internal static class JsonExtensions
{
    public static string SerializeJwk(JsonWebKey jwk)
    {
        var dict = new Dictionary<string, string>();
        if (jwk.Kty is not null) dict["kty"] = jwk.Kty;
        if (jwk.Crv is not null) dict["crv"] = jwk.Crv;
        if (jwk.X is not null) dict["x"] = jwk.X;
        if (jwk.Y is not null) dict["y"] = jwk.Y;
        if (jwk.Kid is not null) dict["kid"] = jwk.Kid;
        if (jwk.Use is not null) dict["use"] = jwk.Use;
        if (jwk.Alg is not null) dict["alg"] = jwk.Alg;
        return JsonSerializer.Serialize(dict);
    }
}
