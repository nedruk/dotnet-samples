using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FederatedAccess;

/// <summary>
/// Resource 1 — dual role server acting as both resource and agent.
/// As a resource: issues resource tokens and verifies auth tokens.
/// As an agent: signs outbound requests to Resource 2 for call chaining.
/// </summary>
public static class ResourceServer
{
    public static WebApplication CreateApp(
        ECDsa resourceSigningKey, JsonWebKey resourcePublicJwk,
        ECDsa agentEphemeralKey, string agentTokenJwt, JsonWebKey agentRootPublicJwk,
        int port, string asUrl, string psUrl, int resource2Port)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.UseUrls($"https://localhost:{port}");
        builder.Logging.ClearProviders();

        var app = builder.Build();
        var resourceUrl = $"https://localhost:{port}";
        var resource2Url = $"https://localhost:{resource2Port}";

        // ── Resource Metadata ────────────────────────────────────────────────
        var resourceMetadata = JsonSerializer.Serialize(new
        {
            issuer = resourceUrl,
            authorization_endpoint = $"{resourceUrl}/authorize",
            jwks_uri = $"{resourceUrl}/jwks",
        });

        var resourceJwks = JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                JsonSerializer.Deserialize<JsonElement>(JsonExtensions.SerializeJwk(resourcePublicJwk))
            }
        });

        // ── Agent Metadata (for call chaining) ──────────────────────────────
        var agentMetadata = JsonSerializer.Serialize(new
        {
            issuer = resourceUrl,
            jwks_uri = $"{resourceUrl}/agent-jwks",
        });

        var agentJwks = JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                JsonSerializer.Deserialize<JsonElement>(JsonExtensions.SerializeJwk(agentRootPublicJwk))
            }
        });

        app.MapGet("/.well-known/aauth-resource.json", () => Results.Content(resourceMetadata, "application/json"));
        app.MapGet("/.well-known/aauth-agent.json", () => Results.Content(agentMetadata, "application/json"));
        app.MapGet("/jwks", () => Results.Content(resourceJwks, "application/json"));
        app.MapGet("/agent-jwks", () => Results.Content(agentJwks, "application/json"));

        // ── POST /authorize — issue resource token (aud = AS) ────────────────
        app.MapPost("/authorize", async (HttpContext context) =>
        {
            try
            {
                var request = ConvertToRequestMessage(context);
                var verifyResult = HttpMessageSigner.Verify(request);

                if (!verifyResult.IsValid)
                {
                    Console.WriteLine($"  [R1] ✗ Signature verification failed: {verifyResult.Error}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = verifyResult.Error });
                    return;
                }

                Console.WriteLine("  [R1] ✓ HTTP signature verified");

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

                Console.WriteLine($"  [R1] ✓ Agent token verified — identity: {agentToken.Subject}");

                var scope = "weather.read";
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
                }, new SigningCredentials(new ECDsaSecurityKey(resourceSigningKey), SecurityAlgorithms.EcdsaSha256));

                Console.WriteLine($"  [R1] ✓ Resource token issued → AS: {asUrl}");

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { resource_token = resourceTokenJwt });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [R1] ✗ Error: {ex}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        // ── GET /api/data — protected resource (weather data) ────────────────
        app.MapGet("/api/data", async (HttpContext context) =>
        {
            try
            {
                var authToken = await VerifyIncomingAuthToken(context, resourceUrl, asUrl);
                if (authToken is null) return; // Response already written

                Console.WriteLine($"  [R1] ✓ Auth token verified — sub: {authToken.Subject}, agent: {authToken.Agent}");

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new
                {
                    message = "Here is your weather data!",
                    weather = new[]
                    {
                        new { city = "New York", temp = "72°F", condition = "Sunny" },
                        new { city = "London", temp = "59°F", condition = "Cloudy" },
                    },
                    access = new
                    {
                        user = authToken.Subject,
                        agent = authToken.Agent,
                        scope = authToken.Scope,
                        issuer = authToken.Issuer,
                    },
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [R1] ✗ Error: {ex}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        // ── GET /api/enriched — call chaining to Resource 2 ──────────────────
        app.MapGet("/api/enriched", async (HttpContext context) =>
        {
            try
            {
                // 1. Verify incoming auth token (same as /api/data)
                var authToken = await VerifyIncomingAuthToken(context, resourceUrl, asUrl);
                if (authToken is null) return;

                Console.WriteLine($"  [R1] ✓ Incoming auth token verified for enriched request");
                var upstreamTokenJwt = authToken.RawJwt;

                var httpClient = new HttpClient();
                var r1SignatureKey = new SignatureKeyValue.Jwt(agentTokenJwt);

                // 2. Call Resource 2 /authorize as agent
                Console.WriteLine($"  [R1] → Calling Resource 2 /authorize as agent");
                var authorizeRequest = new HttpRequestMessage(HttpMethod.Post, $"{resource2Url}/authorize");
                authorizeRequest.Content = JsonContent.Create(new { scope = "flights.read" });
                HttpMessageSigner.Sign(authorizeRequest, agentEphemeralKey, r1SignatureKey);

                var authorizeResponse = await httpClient.SendAsync(authorizeRequest);
                var authorizeBody = await authorizeResponse.Content.ReadAsStringAsync();

                if (!authorizeResponse.IsSuccessStatusCode)
                {
                    Console.WriteLine($"  [R1] ✗ Resource 2 /authorize failed: {authorizeBody}");
                    context.Response.StatusCode = 502;
                    await context.Response.WriteAsJsonAsync(new { error = "downstream_authorize_failed", detail = authorizeBody });
                    return;
                }

                var authorizeJson = JsonSerializer.Deserialize<JsonElement>(authorizeBody);
                var r2ResourceTokenJwt = authorizeJson.GetProperty("resource_token").GetString()!;
                Console.WriteLine($"  [R1] ✓ Got Resource 2 resource token");

                // 3. Exchange at PS with upstream_token for delegation
                Console.WriteLine($"  [R1] → Exchanging at PS with upstream_token");
                var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/token");
                tokenRequest.Content = JsonContent.Create(new
                {
                    resource_token = r2ResourceTokenJwt,
                    upstream_token = upstreamTokenJwt,
                });
                HttpMessageSigner.Sign(tokenRequest, agentEphemeralKey, r1SignatureKey);

                var tokenResponse = await httpClient.SendAsync(tokenRequest);
                var tokenBody = await tokenResponse.Content.ReadAsStringAsync();

                if (!tokenResponse.IsSuccessStatusCode)
                {
                    Console.WriteLine($"  [R1] ✗ PS token exchange failed: {tokenBody}");
                    context.Response.StatusCode = 502;
                    await context.Response.WriteAsJsonAsync(new { error = "downstream_exchange_failed", detail = tokenBody });
                    return;
                }

                var tokenJson = JsonSerializer.Deserialize<JsonElement>(tokenBody);
                var r2AuthTokenJwt = tokenJson.GetProperty("auth_token").GetString()!;
                Console.WriteLine($"  [R1] ✓ Got auth token for Resource 2");

                // 4. Access Resource 2 /api/data with downstream auth token
                Console.WriteLine($"  [R1] → Calling Resource 2 /api/data");
                var r2SignatureKey = new SignatureKeyValue.Jwt(r2AuthTokenJwt);
                var dataRequest = new HttpRequestMessage(HttpMethod.Get, $"{resource2Url}/api/data");
                HttpMessageSigner.Sign(dataRequest, agentEphemeralKey, r2SignatureKey);

                var dataResponse = await httpClient.SendAsync(dataRequest);
                var dataBody = await dataResponse.Content.ReadAsStringAsync();

                if (!dataResponse.IsSuccessStatusCode)
                {
                    Console.WriteLine($"  [R1] ✗ Resource 2 /api/data failed: {dataBody}");
                    context.Response.StatusCode = 502;
                    await context.Response.WriteAsJsonAsync(new { error = "downstream_access_failed", detail = dataBody });
                    return;
                }

                Console.WriteLine($"  [R1] ✓ Got Resource 2 data — combining results");

                var r2Data = JsonSerializer.Deserialize<JsonElement>(dataBody);

                // 5. Combine weather + flight data
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new
                {
                    message = "Here is your enriched data (weather + flights)!",
                    weather = new[]
                    {
                        new { city = "New York", temp = "72°F", condition = "Sunny" },
                        new { city = "London", temp = "59°F", condition = "Cloudy" },
                    },
                    flights = r2Data.TryGetProperty("flights", out var flights)
                        ? flights
                        : JsonSerializer.Deserialize<JsonElement>("[]"),
                    access = new
                    {
                        user = authToken.Subject,
                        agent = authToken.Agent,
                        scope = authToken.Scope,
                        issuer = authToken.Issuer,
                    },
                    call_chain = new
                    {
                        upstream_agent = authToken.Agent,
                        downstream_agent = new JsonWebTokenHandler().ReadJsonWebToken(agentTokenJwt).Subject,
                        delegation = r2Data.TryGetProperty("access", out var r2Access)
                            && r2Access.TryGetProperty("delegation_chain", out var chain)
                            ? chain : JsonSerializer.Deserialize<JsonElement>("[]"),
                    },
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [R1] ✗ Error: {ex}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        return app;

        // ── Helper: verify incoming auth token ──────────────────────────────
        async Task<AuthToken?> VerifyIncomingAuthToken(HttpContext context, string expectedAud, string expectedIss)
        {
            var request = ConvertToRequestMessage(context);
            var verifyResult = HttpMessageSigner.Verify(request);

            if (!verifyResult.IsValid)
            {
                Console.WriteLine($"  [R1] ✗ Signature verification failed: {verifyResult.Error}");
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = verifyResult.Error });
                return null;
            }

            Console.WriteLine("  [R1] ✓ HTTP signature verified");

            var signatureKeyHeaderValue = context.Request.Headers["Signature-Key"].ToString();
            var jwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeaderValue);
            if (jwt is null)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                return null;
            }

            var handler = new JsonWebTokenHandler();
            var token = handler.ReadJsonWebToken(jwt);

            if (token.Typ == "aa-agent+jwt")
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "auth_token_required", detail = "An aa-auth+jwt token is required" });
                return null;
            }

            if (token.Typ != "aa-auth+jwt")
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_token_type", detail = $"Expected aa-auth+jwt, got {token.Typ}" });
                return null;
            }

            var authValidation = await ValidateJwtAgainstIssuerAsync(
                jwt,
                tokenType: "aa-auth+jwt",
                allowedMetadataDocuments: ["aauth-access.json"],
                validAudience: expectedAud,
                expectedIssuer: expectedIss);
            if (!authValidation.IsValid)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_auth_token", detail = authValidation.Error });
                return null;
            }

            var authToken = AuthToken.Decode(jwt);

            if (authToken.Audience != expectedAud)
            {
                Console.WriteLine($"  [R1] ✗ Audience mismatch: {authToken.Audience} != {expectedAud}");
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token" });
                return null;
            }

            if (authToken.Issuer != expectedIss)
            {
                Console.WriteLine($"  [R1] ✗ Issuer mismatch: {authToken.Issuer} != {expectedIss}");
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_issuer" });
                return null;
            }

            if (authToken.Dwk != "aauth-access.json")
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_dwk", detail = $"Expected aauth-access.json, got {authToken.Dwk}" });
                return null;
            }

            var cnfThumbprint = JsonWebKeyThumbprint.Compute(authToken.ConfirmationKey);
            if (cnfThumbprint != verifyResult.Thumbprint)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "cnf_binding_mismatch" });
                return null;
            }

            return authToken;
        }
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
            Console.WriteLine($"  [R1] ✗ JWT validation error: {ex.Message}");
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
