using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FederatedAccess;

/// <summary>
/// Person Server — verifies agent + resource tokens and issues auth tokens.
/// Supports both three-party (direct issuance) and four-party (AS federation) flows.
/// </summary>
public static class PersonServer
{
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
                // 1. Verify HTTP message signature
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

                // 2. Extract and verify agent token from Signature-Key
                var signatureKeyHeader = context.Request.Headers["Signature-Key"].ToString();
                var agentJwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeader);
                if (agentJwt is null)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                    return;
                }

                var tokenHandler = new JsonWebTokenHandler();
                var rawToken = tokenHandler.ReadJsonWebToken(agentJwt);
                if (rawToken.Typ != "aa-agent+jwt")
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_token_type", detail = "Expected aa-agent+jwt in Signature-Key" });
                    return;
                }

                var agentValidation = await ValidateJwtAgainstIssuerAsync(
                    agentJwt,
                    tokenType: "aa-agent+jwt",
                    allowedMetadataDocuments: ["aauth-agent.json"]);
                if (!agentValidation.IsValid)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_agent_token", detail = agentValidation.Error });
                    return;
                }

                var agentToken = AgentToken.Decode(agentJwt);
                var sigThumbprint = JsonWebKeyThumbprint.Compute(agentToken.ConfirmationKey);

                if (sigThumbprint != verifyResult.Thumbprint)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "cnf_binding_mismatch" });
                    return;
                }

                Console.WriteLine($"  ✓ Agent token verified — identity: {agentToken.Subject}");

                // 3. Read resource_token from body
                var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                if (!body.TryGetProperty("resource_token", out var rtProp) || rtProp.GetString() is not { } resourceTokenJwt)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request", detail = "Missing resource_token" });
                    return;
                }

                // 4. Verify resource token signature via resource's JWKS
                var resourceValidation = await ValidateJwtAgainstIssuerAsync(
                    resourceTokenJwt,
                    tokenType: "aa-resource+jwt",
                    allowedMetadataDocuments: ["aauth-resource.json"]);
                if (!resourceValidation.IsValid)
                {
                    Console.WriteLine("  ✗ Resource token signature verification failed");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token", detail = resourceValidation.Error });
                    return;
                }

                Console.WriteLine("  ✓ Resource token signature verified");

                var resourceToken = ResourceToken.Decode(resourceTokenJwt);
                Console.WriteLine($"  ✓ Resource token decoded — issuer: {resourceToken.Issuer}");

                // 6. Verify agent identity matches
                if (resourceToken.Agent != agentToken.Subject)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token" });
                    return;
                }

                // 7. Verify agent_jkt matches
                if (resourceToken.AgentJkt != sigThumbprint)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token" });
                    return;
                }

                Console.WriteLine("  ✓ All resource token claims verified");

                // Read optional upstream_token for delegation chaining
                string? upstreamTokenJwt = null;
                AuthToken? upstreamToken = null;
                if (body.TryGetProperty("upstream_token", out var utProp) && utProp.GetString() is { } ut)
                {
                    upstreamTokenJwt = ut;
                    var upstreamValidation = await ValidateUpstreamTokenAsync(upstreamTokenJwt, agentToken.Issuer);
                    if (upstreamValidation.Token is null)
                    {
                        Console.WriteLine($"  ✗ Invalid upstream token: {upstreamValidation.Error}");
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { error = "invalid_request", detail = upstreamValidation.Error });
                        return;
                    }

                    upstreamToken = upstreamValidation.Token;
                    Console.WriteLine($"  ✓ Upstream token verified — aud={upstreamToken.Audience}, iss={upstreamToken.Issuer}");
                }

                // 8. Check audience to determine three-party vs four-party flow
                if (resourceToken.Audience == psUrl)
                {
                    // ── Three-party: issue auth token directly ────────────────
                    Console.WriteLine("  → Three-party flow: issuing auth token directly");
                    var authTokenJwt = IssueAuthToken(
                        psUrl, "aauth-person.json", resourceToken, agentToken, upstreamToken,
                        signingKey, tokenHandler);
                    Console.WriteLine("  ✓ Auth token issued (three-party)");

                    context.Response.StatusCode = 200;
                    await context.Response.WriteAsJsonAsync(new { auth_token = authTokenJwt, expires_in = 3600 });
                }
                else
                {
                    // ── Four-party: federate to Access Server ─────────────────
                    Console.WriteLine($"  → Four-party flow: aud={resourceToken.Audience} ≠ PS — federating to AS");

                    var asUrl = resourceToken.Audience;
                    using var httpClient = new HttpClient();

                    // Discover AS metadata
                    var asMetaResponse = await httpClient.GetFromJsonAsync<JsonElement>(
                        $"{asUrl}/.well-known/aauth-access.json");
                    var asTokenEndpoint = asMetaResponse.GetProperty("token_endpoint").GetString()!;
                    Console.WriteLine($"  ✓ AS discovered — token endpoint: {asTokenEndpoint}");

                    // Build request body for AS
                    var asRequestBody = new Dictionary<string, string>
                    {
                        ["resource_token"] = resourceTokenJwt,
                        ["agent_token"] = agentJwt,
                    };
                    if (upstreamTokenJwt is not null)
                        asRequestBody["upstream_token"] = upstreamTokenJwt;

                    // Sign request to AS with PS key (JWKS URI scheme)
                    var asRequest = new HttpRequestMessage(HttpMethod.Post, asTokenEndpoint);
                    asRequest.Content = JsonContent.Create(asRequestBody);
                    var psSignatureKey = new SignatureKeyValue.JwksUri($"{psUrl}/jwks");
                    HttpMessageSigner.Sign(asRequest, signingKey, psSignatureKey);

                    Console.WriteLine($"  → Forwarding to AS: POST {asTokenEndpoint}");

                    var asResponse = await httpClient.SendAsync(asRequest);
                    var asBody = await asResponse.Content.ReadAsStringAsync();

                    if ((int)asResponse.StatusCode == 202)
                    {
                        Console.WriteLine("  ↺ AS returned 202 Accepted — relaying deferred response");
                        context.Response.StatusCode = 202;

                        if (asResponse.Headers.Location is not null)
                            context.Response.Headers.Location = asResponse.Headers.Location.ToString();

                        if (asResponse.Headers.TryGetValues("Retry-After", out var retryAfterValues))
                            context.Response.Headers.Append("Retry-After", retryAfterValues.ToArray());

                        context.Response.ContentType = asResponse.Content.Headers.ContentType?.ToString() ?? "application/json";
                        await context.Response.WriteAsync(asBody);
                        return;
                    }

                    if (!asResponse.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"  ✗ AS returned {(int)asResponse.StatusCode}: {asBody}");
                        context.Response.StatusCode = 500;
                        await context.Response.WriteAsJsonAsync(new { error = "server_error", detail = $"AS returned {(int)asResponse.StatusCode}" });
                        return;
                    }

                    Console.WriteLine("  ✓ AS issued auth token — returning to caller");

                    // Return AS response directly
                    var asJson = JsonSerializer.Deserialize<JsonElement>(asBody);
                    context.Response.StatusCode = 200;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        auth_token = asJson.GetProperty("auth_token").GetString(),
                        expires_in = asJson.TryGetProperty("expires_in", out var expProp) ? expProp.GetInt32() : 3600,
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ✗ Error: {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        return app;
    }

    private static string IssueAuthToken(
        string issuer, string dwk,
        ResourceToken resourceToken, AgentToken agentToken, AuthToken? upstreamToken,
        ECDsa signingKey, JsonWebTokenHandler tokenHandler)
    {
        var resourceAud = resourceToken.Issuer;
        var now = DateTimeOffset.UtcNow;

        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(resourceAud));
        var sub = "user-" + Convert.ToHexString(hash).ToLowerInvariant()[..12];

        // Build act claim
        Dictionary<string, object> actClaim;
        if (upstreamToken is not null)
        {
            actClaim = new Dictionary<string, object>
            {
                ["sub"] = agentToken.Subject,
                ["act"] = SerializeActorClaim(upstreamToken.Actor),
            };
        }
        else
        {
            actClaim = new Dictionary<string, object> { ["sub"] = agentToken.Subject };
        }

        var authTokenClaims = new Dictionary<string, object>
        {
            ["iss"] = issuer,
            ["dwk"] = dwk,
            ["aud"] = resourceAud,
            ["jti"] = Guid.NewGuid().ToString(),
            ["agent"] = agentToken.Subject,
            ["cnf"] = new Dictionary<string, object>
            {
                ["jwk"] = JsonSerializer.Deserialize<Dictionary<string, object>>(
                    JsonExtensions.SerializeJwk(agentToken.ConfirmationKey))!
            },
            ["act"] = actClaim,
            ["sub"] = sub,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddHours(1).ToUnixTimeSeconds(),
        };

        if (resourceToken.Scope is not null)
            authTokenClaims["scope"] = resourceToken.Scope;

        return tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Claims = authTokenClaims,
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256),
            TokenType = "aa-auth+jwt",
        });
    }

    private static Dictionary<string, object> SerializeActorClaim(ActorClaim actor)
    {
        var dict = new Dictionary<string, object> { ["sub"] = actor.Subject };
        if (actor.Nested is not null)
            dict["act"] = SerializeActorClaim(actor.Nested);
        return dict;
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
            Console.WriteLine($"  ✗ JWT validation error: {ex.Message}");
            return (false, "Token validation failed");
        }
    }

    private static async Task<(AuthToken? Token, string? Error)> ValidateUpstreamTokenAsync(string upstreamTokenJwt, string expectedAudience)
    {
        try
        {
            var validation = await ValidateJwtAgainstIssuerAsync(
                upstreamTokenJwt,
                "aa-auth+jwt",
                ["aauth-person.json", "aauth-access.json"],
                validAudience: expectedAudience);
            if (!validation.IsValid)
                return (null, validation.Error);

            var upstreamToken = AuthToken.Decode(upstreamTokenJwt);
            if (upstreamToken.ExpiresAt <= DateTimeOffset.UtcNow)
                return (null, "upstream_token expired");

            if (upstreamToken.Audience != expectedAudience)
                return (null, $"upstream_token audience {upstreamToken.Audience} does not match intermediary resource {expectedAudience}");

            return (upstreamToken, null);
        }
        catch (Exception ex)
        {
            return (null, $"invalid upstream_token: {ex.Message}");
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

        return keys
            .Where(jwk => string.Equals(jwk.Kid, kid, StringComparison.Ordinal))
            .ToList();
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
