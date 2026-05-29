using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FederatedAccess;

/// <summary>
/// Access Server — issues auth tokens for resources that delegate token authority to this AS.
/// Implements the AS role in the four-party AAuth flow.
/// </summary>
public static class AccessServer
{
    public static WebApplication CreateApp(ECDsa signingKey, JsonWebKey signingPublicJwk, int port)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.UseUrls($"https://localhost:{port}");
        builder.Logging.ClearProviders();

        var app = builder.Build();
        var asUrl = $"https://localhost:{port}";

        // ── Metadata ─────────────────────────────────────────────────────────
        var metadata = JsonSerializer.Serialize(new
        {
            issuer = asUrl,
            token_endpoint = $"{asUrl}/token",
            jwks_uri = $"{asUrl}/jwks",
        });

        var jwks = JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                JsonSerializer.Deserialize<JsonElement>(JsonExtensions.SerializeJwk(signingPublicJwk))
            }
        });

        app.MapGet("/.well-known/aauth-access.json", () => Results.Content(metadata, "application/json"));
        app.MapGet("/jwks", () => Results.Content(jwks, "application/json"));

        // ── POST /token — validate resource+agent tokens and issue auth token ─
        app.MapPost("/token", async (HttpContext context) =>
        {
            try
            {
                // 1. Verify HTTP message signature (PS signs with its own key via JWKS URI)
                var request = ConvertToRequestMessage(context);
                var signatureKeyHeader = context.Request.Headers["Signature-Key"].ToString();
                var parsedSigKey = SignatureKeyHeader.Parse(signatureKeyHeader);

                if (parsedSigKey is not SignatureKeyValue.JwksUri jwksUriKey)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = "Expected PS Signature-Key to use jwks_uri" });
                    return;
                }

                var verifyResult = await VerifyHttpSignatureWithJwksAsync(request, jwksUriKey.Uri);
                if (!verifyResult.IsValid)
                {
                    Console.WriteLine($"  ✗ PS signature verification failed: {verifyResult.Error}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = verifyResult.Error });
                    return;
                }

                Console.WriteLine("  ✓ PS HTTP signature verified");

                // 2. Read body
                var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                if (!body.TryGetProperty("resource_token", out var rtProp) || rtProp.GetString() is not { } resourceTokenJwt)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request", detail = "Missing resource_token" });
                    return;
                }

                if (!body.TryGetProperty("agent_token", out var atProp) || atProp.GetString() is not { } agentTokenJwt)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request", detail = "Missing agent_token" });
                    return;
                }

                // 3. Decode and validate resource token
                var resourceToken = ResourceToken.Decode(resourceTokenJwt);
                Console.WriteLine($"  ✓ Resource token decoded — issuer: {resourceToken.Issuer}");

                // 4. Verify resource token audience matches this AS
                if (resourceToken.Audience != asUrl)
                {
                    Console.WriteLine($"  ✗ Resource token audience mismatch: {resourceToken.Audience} != {asUrl}");
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token", detail = "Audience does not match this Access Server" });
                    return;
                }

                if (!await ValidateJwtAgainstIssuerAsync(resourceTokenJwt, resourceToken.Issuer, resourceToken.Dwk, "aa-resource+jwt", asUrl))
                {
                    Console.WriteLine("  ✗ Resource token signature verification failed");
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token", detail = "Signature verification failed" });
                    return;
                }

                Console.WriteLine("  ✓ Resource token signature verified");

                // 5. Decode agent token and verify it matches the resource token binding
                var agentToken = AgentToken.Decode(agentTokenJwt);
                Console.WriteLine($"  ✓ Agent token decoded — sub: {agentToken.Subject}");

                if (agentToken.Subject != resourceToken.Agent)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request", error_description = "agent_token does not match resource_token" });
                    return;
                }

                var agentThumbprint = JsonWebKeyThumbprint.Compute(agentToken.ConfirmationKey);
                if (agentThumbprint != resourceToken.AgentJkt)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request", error_description = "agent_token confirmation key does not match resource_token" });
                    return;
                }

                // 6. Build act claim (handle delegation chain from upstream_token)
                Dictionary<string, object> actClaim;
                if (body.TryGetProperty("upstream_token", out var utProp) && utProp.GetString() is { } upstreamTokenJwt)
                {
                    var upstreamValidation = await ValidateUpstreamTokenAsync(upstreamTokenJwt, agentToken.Issuer);
                    if (upstreamValidation.Token is null)
                    {
                        Console.WriteLine($"  ✗ Invalid upstream token: {upstreamValidation.Error}");
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { error = "invalid_request", detail = upstreamValidation.Error });
                        return;
                    }

                    var upstreamToken = upstreamValidation.Token;
                    actClaim = new Dictionary<string, object>
                    {
                        ["sub"] = agentToken.Subject,
                        ["act"] = SerializeActorClaim(upstreamToken.Actor),
                    };
                    Console.WriteLine($"  ✓ Upstream token verified — building nested act: {agentToken.Subject} → {upstreamToken.Actor.Subject}");
                }
                else
                {
                    actClaim = new Dictionary<string, object> { ["sub"] = agentToken.Subject };
                }

                // 7. Issue auth token
                var resourceAud = resourceToken.Issuer;
                var now = DateTimeOffset.UtcNow;

                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(resourceAud));
                var sub = "user-" + Convert.ToHexString(hash).ToLowerInvariant()[..12];

                var tokenHandler = new JsonWebTokenHandler();
                var authTokenClaims = new Dictionary<string, object>
                {
                    ["iss"] = asUrl,
                    ["dwk"] = "aauth-access.json",
                    ["aud"] = resourceAud,
                    ["jti"] = Guid.NewGuid().ToString(),
                    ["agent"] = resourceToken.Agent,
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

                var authTokenJwtResult = tokenHandler.CreateToken(new SecurityTokenDescriptor
                {
                    Claims = authTokenClaims,
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256),
                    TokenType = "aa-auth+jwt",
                });

                Console.WriteLine($"  ✓ Auth token issued — sub: {sub}, aud: {resourceAud}, iss: {asUrl}");

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { auth_token = authTokenJwtResult, expires_in = 3600 });
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

    private static Dictionary<string, object> SerializeActorClaim(ActorClaim actor)
    {
        var dict = new Dictionary<string, object> { ["sub"] = actor.Subject };
        if (actor.Nested is not null)
            dict["act"] = SerializeActorClaim(actor.Nested);
        return dict;
    }

    private static async Task<SignatureVerificationResult> VerifyHttpSignatureWithJwksAsync(HttpRequestMessage request, string jwksUri)
    {
        using var httpClient = new HttpClient();
        var jwksResponse = await httpClient.GetFromJsonAsync<JsonElement>(jwksUri);
        var keysArray = jwksResponse.GetProperty("keys");

        SignatureVerificationResult? lastFailure = null;
        foreach (var jwk in GetCandidateKeys(keysArray, kid: null))
        {
            var result = HttpMessageSigner.Verify(request, jwk);
            if (result.IsValid)
                return result;

            lastFailure = result;
        }

        return lastFailure ?? new SignatureVerificationResult(false, null, null, "No signing keys found in JWKS");
    }

    private static async Task<bool> ValidateJwtAgainstIssuerAsync(
        string jwt,
        string issuer,
        string metadataDocument,
        string tokenType,
        string? validAudience = null)
    {
        using var httpClient = new HttpClient();
        var metadata = await httpClient.GetFromJsonAsync<JsonElement>($"{issuer}/.well-known/{metadataDocument}");
        var jwksUri = metadata.GetProperty("jwks_uri").GetString();
        if (string.IsNullOrWhiteSpace(jwksUri))
            return false;

        var jwks = await httpClient.GetFromJsonAsync<JsonElement>(jwksUri);
        var keysArray = jwks.GetProperty("keys");

        var tokenHandler = new JsonWebTokenHandler();
        var jsonWebToken = tokenHandler.ReadJsonWebToken(jwt);

        foreach (var jwk in GetCandidateKeys(keysArray, jsonWebToken.Kid))
        {
            var validationParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = validAudience is not null,
                ValidAudience = validAudience,
                ValidateLifetime = true,
                IssuerSigningKey = jwk,
                ValidTypes = new[] { tokenType },
            };

            var result = await tokenHandler.ValidateTokenAsync(jwt, validationParams);
            if (result.IsValid)
                return true;
        }

        return false;
    }

    private static async Task<(AuthToken? Token, string? Error)> ValidateUpstreamTokenAsync(string upstreamTokenJwt, string expectedAudience)
    {
        try
        {
            var upstreamToken = AuthToken.Decode(upstreamTokenJwt);
            if (upstreamToken.ExpiresAt <= DateTimeOffset.UtcNow)
                return (null, "upstream_token expired");

            if (upstreamToken.Audience != expectedAudience)
                return (null, $"upstream_token audience {upstreamToken.Audience} does not match intermediary resource {expectedAudience}");

            var isValid = await ValidateJwtAgainstIssuerAsync(
                upstreamTokenJwt,
                upstreamToken.Issuer,
                upstreamToken.Dwk,
                "aa-auth+jwt",
                expectedAudience);

            if (!isValid)
                return (null, "upstream_token signature verification failed");

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
