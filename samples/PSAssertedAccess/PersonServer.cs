using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace PSAssertedAccess;

/// <summary>
/// Person Server — verifies agent + resource tokens and issues auth tokens for the three-party flow.
/// </summary>
public static class PersonServer
{
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    public static WebApplication CreateApp(ECDsa signingKey, JsonWebKey signingPublicJwk, int port)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.UseUrls($"https://localhost:{port}");
        builder.Logging.ClearProviders();

        var app = builder.Build();
        var psUrl = $"https://localhost:{port}";

        // ── Metadata ─────────────────────────────────────────────────────────
        var metadata = JsonSerializer.Serialize(new
        {
            issuer = psUrl,
            token_endpoint = $"{psUrl}/token",
            jwks_uri = $"{psUrl}/jwks",
        });

        var jwks = JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                JsonSerializer.Deserialize<JsonElement>(JsonExtensions.SerializeJwk(signingPublicJwk))
            }
        });

        app.MapGet("/.well-known/aauth-person.json", () => Results.Content(metadata, "application/json"));
        app.MapGet("/jwks", () => Results.Content(jwks, "application/json"));

        // ── POST /token — exchange resource token for auth token ─────────────
        app.MapPost("/token", async (HttpContext context) =>
        {
            try
            {
                var request = ConvertToRequestMessage(context);
                var verifyResult = HttpMessageSigner.Verify(request);

                if (!verifyResult.IsValid)
                {
                    Console.WriteLine($"  ✗ Signature verification failed: {verifyResult.Error}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = verifyResult.Error });
                    return;
                }

                Console.WriteLine("  ✓ HTTP signature verified");

                var signatureKeyHeader = context.Request.Headers["Signature-Key"].ToString();
                var agentJwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeader);
                if (agentJwt is null)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                    return;
                }

                var tokenHandler = new JsonWebTokenHandler();
                var rawAgentToken = tokenHandler.ReadJsonWebToken(agentJwt);
                if (rawAgentToken.Typ != "aa-agent+jwt")
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_token_type", detail = "Expected aa-agent+jwt in Signature-Key" });
                    return;
                }

                await JwtValidationHelpers.ValidateJwtSignatureFromIssuerAsync(agentJwt, rawAgentToken.Issuer, rawAgentToken.GetClaim("dwk").Value, "aa-agent+jwt", ClockSkew);
                // Production code must verify the JWT signature against the issuer's JWKS before calling Decode().
                var agentToken = AgentToken.Decode(agentJwt);
                if (agentToken.ExpiresAt + ClockSkew < DateTimeOffset.UtcNow)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "token_expired" });
                    return;
                }

                if (agentToken.IssuedAt - ClockSkew > DateTimeOffset.UtcNow)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "token_not_yet_valid" });
                    return;
                }

                var sigThumbprint = JsonWebKeyThumbprint.Compute(agentToken.ConfirmationKey);
                if (sigThumbprint != verifyResult.Thumbprint)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "cnf_binding_mismatch" });
                    return;
                }

                Console.WriteLine($"  ✓ Agent token verified — identity: {agentToken.Subject}");

                var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                if (!body.TryGetProperty("resource_token", out var rtProp) || rtProp.GetString() is not { } resourceTokenJwt)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                    return;
                }

                var rawResourceToken = tokenHandler.ReadJsonWebToken(resourceTokenJwt);
                await JwtValidationHelpers.ValidateJwtSignatureFromIssuerAsync(resourceTokenJwt, rawResourceToken.Issuer, rawResourceToken.GetClaim("dwk").Value, "aa-resource+jwt", ClockSkew);
                var resourceToken = ResourceToken.Decode(resourceTokenJwt);
                Console.WriteLine($"  ✓ Resource token decoded — issuer: {resourceToken.Issuer}");

                if (resourceToken.IssuedAt > DateTimeOffset.UtcNow + ClockSkew)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token" });
                    return;
                }

                Console.WriteLine("  ✓ Resource token signature verified");

                if (resourceToken.Audience != psUrl)
                {
                    Console.WriteLine($"  ✗ Resource token audience mismatch: {resourceToken.Audience} != {psUrl}");
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token" });
                    return;
                }

                if (resourceToken.Agent != agentToken.Subject)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token" });
                    return;
                }

                if (resourceToken.AgentJkt != sigThumbprint)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token" });
                    return;
                }

                Console.WriteLine("  ✓ All resource token claims verified");
                Console.WriteLine("  ✓ Auto-approved (demo mode)");

                var resourceAud = resourceToken.Issuer;
                var now = DateTimeOffset.UtcNow;

                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(resourceAud));
                var sub = "user-" + Convert.ToHexString(hash).ToLowerInvariant()[..12];

                var authTokenClaims = new Dictionary<string, object>
                {
                    ["iss"] = psUrl,
                    ["dwk"] = "aauth-person.json",
                    ["aud"] = resourceAud,
                    ["jti"] = Guid.NewGuid().ToString(),
                    ["agent"] = agentToken.Subject,
                    ["cnf"] = new Dictionary<string, object>
                    {
                        ["jwk"] = JsonSerializer.Deserialize<Dictionary<string, object>>(
                            JsonExtensions.SerializeJwk(agentToken.ConfirmationKey))!
                    },
                    ["act"] = new Dictionary<string, object> { ["sub"] = agentToken.Subject },
                    ["sub"] = sub,
                    ["iat"] = now.ToUnixTimeSeconds(),
                    ["exp"] = now.AddHours(1).ToUnixTimeSeconds(),
                };

                if (resourceToken.Scope is not null)
                    authTokenClaims["scope"] = resourceToken.Scope;

                var authTokenJwt = tokenHandler.CreateToken(new SecurityTokenDescriptor
                {
                    Claims = authTokenClaims,
                    SigningCredentials = CreateSigningCredentials(signingKey, signingPublicJwk.Kid),
                    TokenType = "aa-auth+jwt",
                });

                Console.WriteLine($"  ✓ Auth token issued — sub: {sub}, aud: {resourceAud}");

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { auth_token = authTokenJwt, expires_in = 3600 });
            }
            catch (AAuthTokenException ex)
            {
                Console.WriteLine($"  ✗ Token validation failed: {ex}");
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = ex.Code });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ✗ Error: {ex}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        return app;
    }

    private static SigningCredentials CreateSigningCredentials(ECDsa signingKey, string? keyId)
    {
        var securityKey = new ECDsaSecurityKey(signingKey) { KeyId = keyId };
        return new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);
    }

    private static HttpRequestMessage ConvertToRequestMessage(HttpContext context)
    {
        var request = new HttpRequestMessage(
            new HttpMethod(context.Request.Method),
            new Uri($"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}"));

        foreach (var header in context.Request.Headers)
            request.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());

        return request;
    }
}
