using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FederatedAccess;

/// <summary>
/// Resource 2 — downstream resource accessed via call chaining.
/// Issues resource tokens with aud=AS and verifies AS-issued auth tokens.
/// </summary>
public static class Resource2Server
{
    public static WebApplication CreateApp(
        ECDsa signingKey, JsonWebKey signingPublicJwk,
        int port, string asUrl)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.UseUrls($"https://localhost:{port}");
        builder.Logging.ClearProviders();

        var app = builder.Build();
        var resourceUrl = $"https://localhost:{port}";

        // ── Metadata ─────────────────────────────────────────────────────────
        var metadata = JsonSerializer.Serialize(new
        {
            issuer = resourceUrl,
            authorization_endpoint = $"{resourceUrl}/authorize",
            jwks_uri = $"{resourceUrl}/jwks",
        });

        var jwks = JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                JsonSerializer.Deserialize<JsonElement>(JsonExtensions.SerializeJwk(signingPublicJwk))
            }
        });

        app.MapGet("/.well-known/aauth-resource.json", () => Results.Content(metadata, "application/json"));
        app.MapGet("/jwks", () => Results.Content(jwks, "application/json"));

        // ── POST /authorize — issue resource token ───────────────────────────
        app.MapPost("/authorize", async (HttpContext context) =>
        {
            try
            {
                var request = ConvertToRequestMessage(context);
                var verifyResult = HttpMessageSigner.Verify(request);

                if (!verifyResult.IsValid)
                {
                    Console.WriteLine($"  [R2] ✗ Signature verification failed: {verifyResult.Error}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = verifyResult.Error });
                    return;
                }

                Console.WriteLine("  [R2] ✓ HTTP signature verified");

                var signatureKeyHeaderValue = context.Request.Headers["Signature-Key"].ToString();
                var jwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeaderValue);
                if (jwt is null)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                    return;
                }

                var handler = new JsonWebTokenHandler();
                var token = handler.ReadJsonWebToken(jwt);
                if (token.Typ != "aa-agent+jwt")
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_token_type", detail = "Expected aa-agent+jwt" });
                    return;
                }

                var agentValidation = await ValidateJwtAgainstIssuerAsync(
                    jwt,
                    tokenType: "aa-agent+jwt",
                    allowedMetadataDocuments: ["aauth-agent.json"]);
                if (!agentValidation.IsValid)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_agent_token", detail = agentValidation.Error });
                    return;
                }

                var agentToken = AgentToken.Decode(jwt);
                var thumbprint = JsonWebKeyThumbprint.Compute(agentToken.ConfirmationKey);

                if (thumbprint != verifyResult.Thumbprint)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "cnf_binding_mismatch" });
                    return;
                }

                Console.WriteLine($"  [R2] ✓ Agent token verified — identity: {agentToken.Subject}");

                // Read optional scope from request body
                var scope = "flights.read";
                try
                {
                    var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                    if (body.TryGetProperty("scope", out var scopeProp) && scopeProp.GetString() is { } s)
                        scope = s;
                }
                catch
                {
                    // No body or invalid JSON — use default scope
                }

                // Issue resource token with aud = AS URL (four-party flow)
                var resourceTokenJwt = ResourceToken.Create(new ResourceTokenOptions
                {
                    Resource = resourceUrl,
                    AuthServer = asUrl,
                    Agent = agentToken.Subject,
                    AgentJkt = thumbprint,
                    Scope = scope,
                }, new SigningCredentials(new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256));

                Console.WriteLine($"  [R2] ✓ Resource token issued → AS: {asUrl}");

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { resource_token = resourceTokenJwt });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [R2] ✗ Error: {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        // ── GET /api/data — protected resource ──────────────────────────────
        app.MapGet("/api/data", async (HttpContext context) =>
        {
            try
            {
                var request = ConvertToRequestMessage(context);
                var verifyResult = HttpMessageSigner.Verify(request);

                if (!verifyResult.IsValid)
                {
                    Console.WriteLine($"  [R2] ✗ Signature verification failed: {verifyResult.Error}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = verifyResult.Error });
                    return;
                }

                Console.WriteLine("  [R2] ✓ HTTP signature verified");

                var signatureKeyHeaderValue = context.Request.Headers["Signature-Key"].ToString();
                var jwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeaderValue);
                if (jwt is null)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                    return;
                }

                var handler = new JsonWebTokenHandler();
                var token = handler.ReadJsonWebToken(jwt);

                if (token.Typ == "aa-agent+jwt")
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "auth_token_required", detail = "An aa-auth+jwt token is required" });
                    return;
                }

                if (token.Typ != "aa-auth+jwt")
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_token_type", detail = $"Expected aa-auth+jwt, got {token.Typ}" });
                    return;
                }

                var authValidation = await ValidateJwtAgainstIssuerAsync(
                    jwt,
                    tokenType: "aa-auth+jwt",
                    allowedMetadataDocuments: ["aauth-access.json"],
                    validAudience: resourceUrl,
                    expectedIssuer: asUrl);
                if (!authValidation.IsValid)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_auth_token", detail = authValidation.Error });
                    return;
                }

                var authToken = AuthToken.Decode(jwt);

                // Verify audience
                if (authToken.Audience != resourceUrl)
                {
                    Console.WriteLine($"  [R2] ✗ Audience mismatch: {authToken.Audience} != {resourceUrl}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token" });
                    return;
                }

                // Verify issuer is the AS
                if (authToken.Issuer != asUrl)
                {
                    Console.WriteLine($"  [R2] ✗ Issuer mismatch: {authToken.Issuer} != {asUrl}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_issuer" });
                    return;
                }

                // Verify dwk
                if (authToken.Dwk != "aauth-access.json")
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_dwk", detail = $"Expected aauth-access.json, got {authToken.Dwk}" });
                    return;
                }

                // Verify cnf binding
                var cnfThumbprint = JsonWebKeyThumbprint.Compute(authToken.ConfirmationKey);
                if (cnfThumbprint != verifyResult.Thumbprint)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "cnf_binding_mismatch" });
                    return;
                }

                Console.WriteLine($"  [R2] ✓ Auth token verified — sub: {authToken.Subject}, agent: {authToken.Agent}");

                // Extract delegation chain from nested act claims
                var delegationChain = ExtractDelegationChain(authToken.Actor);

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new
                {
                    message = "Here is your flight data!",
                    flights = new[]
                    {
                        new { flight = "AA 100", from = "JFK", to = "LAX", status = "on_time" },
                        new { flight = "UA 200", from = "SFO", to = "ORD", status = "delayed" },
                    },
                    access = new
                    {
                        user = authToken.Subject,
                        agent = authToken.Agent,
                        scope = authToken.Scope,
                        issuer = authToken.Issuer,
                        delegation_chain = delegationChain,
                    },
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [R2] ✗ Error: {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        return app;
    }

    private static List<string> ExtractDelegationChain(ActorClaim? actor)
    {
        var chain = new List<string>();
        var current = actor;
        while (current is not null)
        {
            chain.Add(current.Subject);
            current = current.Nested;
        }
        return chain;
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

    private static async Task<(bool IsValid, string Error)> ValidateJwtAgainstIssuerAsync(
        string jwt,
        string tokenType,
        string[] allowedMetadataDocuments,
        string? validAudience = null,
        string? expectedIssuer = null)
    {
        try
        {
            var tokenHandler = new JsonWebTokenHandler();
            var jsonWebToken = tokenHandler.ReadJsonWebToken(jwt);

            if (!string.Equals(jsonWebToken.Typ, tokenType, StringComparison.Ordinal))
                return (false, $"Expected {tokenType}");

            var issuer = jsonWebToken.Issuer;
            if (string.IsNullOrWhiteSpace(issuer))
                return (false, "Missing issuer");

            if (expectedIssuer is not null && !string.Equals(issuer, expectedIssuer, StringComparison.Ordinal))
                return (false, "Issuer mismatch");

            if (!jsonWebToken.TryGetClaim("dwk", out var dwkClaim))
                return (false, "Missing dwk claim");

            var metadataDocument = dwkClaim.Value;
            if (!allowedMetadataDocuments.Contains(metadataDocument, StringComparer.Ordinal))
                return (false, "Unexpected metadata document");

            using var httpClient = new HttpClient();
            var metadata = await httpClient.GetFromJsonAsync<JsonElement>($"{issuer}/.well-known/{metadataDocument}");
            if (!metadata.TryGetProperty("jwks_uri", out var jwksUriProp))
                return (false, "Missing jwks_uri");

            var jwksUri = jwksUriProp.GetString();
            if (string.IsNullOrWhiteSpace(jwksUri))
                return (false, "Missing jwks_uri");

            var jwks = await httpClient.GetFromJsonAsync<JsonElement>(jwksUri);
            if (!jwks.TryGetProperty("keys", out var keysArray) || keysArray.ValueKind != JsonValueKind.Array)
                return (false, "Invalid JWKS");

            foreach (var jwk in GetCandidateKeys(keysArray, jsonWebToken.Kid))
            {
                var validationParams = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = issuer,
                    ValidateAudience = validAudience is not null,
                    ValidAudience = validAudience,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    IssuerSigningKey = jwk,
                    ValidTypes = [tokenType],
                };

                var result = await tokenHandler.ValidateTokenAsync(jwt, validationParams);
                if (result.IsValid)
                    return (true, string.Empty);
            }

            return (false, "Signature or claim validation failed");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [R2] ✗ JWT validation error: {ex.Message}");
            return (false, "Token validation failed");
        }
    }

    private static List<JsonWebKey> GetCandidateKeys(JsonElement keysArray, string? kid)
    {
        var keys = keysArray
            .EnumerateArray()
            .Select(keyElement => new JsonWebKey(keyElement.GetRawText()))
            .ToList();

        if (string.IsNullOrWhiteSpace(kid))
            return keys;

        return keys.Where(jwk => string.Equals(jwk.Kid, kid, StringComparison.Ordinal)).ToList();
    }
}
