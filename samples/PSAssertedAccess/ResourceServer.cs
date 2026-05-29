using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Core.Headers;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace PSAssertedAccess;

/// <summary>
/// Resource Server — verifies signatures/tokens and issues resource tokens for the three-party flow.
/// </summary>
public static class ResourceServer
{
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);
    private const string DocumentsScope = "data.read";

    public static WebApplication CreateApp(ECDsa signingKey, JsonWebKey signingPublicJwk, int port)
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
                    Console.WriteLine($"  ✗ Signature verification failed: {verifyResult.Error}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_signature", detail = verifyResult.Error });
                    return;
                }

                Console.WriteLine("  ✓ HTTP signature verified");

                var signatureKeyHeader = context.Request.Headers["Signature-Key"].ToString();
                var jwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeader);
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

                await JwtValidationHelpers.ValidateJwtSignatureFromIssuerAsync(jwt, token.Issuer, token.GetClaim("dwk").Value, "aa-agent+jwt", ClockSkew);
                // Production code must verify the JWT signature against the issuer's JWKS before calling Decode().
                var agentToken = AgentToken.Decode(jwt);
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

                var thumbprint = JsonWebKeyThumbprint.Compute(agentToken.ConfirmationKey);
                if (thumbprint != verifyResult.Thumbprint)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "cnf_binding_mismatch" });
                    return;
                }

                Console.WriteLine($"  ✓ Agent token verified — identity: {agentToken.Subject}");

                if (agentToken.PersonServerUrl is null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "missing_ps_claim", detail = "Agent token must contain ps claim for three-party flow" });
                    return;
                }

                var scope = DocumentsScope;
                try
                {
                    var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                    if (body.TryGetProperty("scope", out var scopeProp) && scopeProp.GetString() is { } s)
                        scope = s;
                }
                catch
                {
                    // No body or invalid JSON — use default scope.
                }

                var resourceTokenJwt = CreateResourceTokenJwt(signingKey, signingPublicJwk.Kid, resourceUrl, agentToken, thumbprint, scope);
                Console.WriteLine($"  ✓ Resource token issued → PS: {agentToken.PersonServerUrl}");

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { resource_token = resourceTokenJwt });
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

        // ── GET /api/documents — protected resource ──────────────────────────
        app.MapGet("/api/documents", async (HttpContext context) =>
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
                var jwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeader);
                if (jwt is null)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                    return;
                }

                var handler = new JsonWebTokenHandler();
                var token = handler.ReadJsonWebToken(jwt);
                var typ = token.Typ;

                if (typ == "aa-agent+jwt")
                {
                    await JwtValidationHelpers.ValidateJwtSignatureFromIssuerAsync(jwt, token.Issuer, token.GetClaim("dwk").Value, "aa-agent+jwt", ClockSkew);
                    // Production code must verify the JWT signature against the issuer's JWKS before calling Decode().
                    var agentToken = AgentToken.Decode(jwt);
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

                    if (agentToken.PersonServerUrl is null)
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { error = "missing_ps_claim", detail = "Agent token must contain ps claim for three-party flow" });
                        return;
                    }

                    var thumbprint = JsonWebKeyThumbprint.Compute(agentToken.ConfirmationKey);
                    if (thumbprint != verifyResult.Thumbprint)
                    {
                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsJsonAsync(new { error = "cnf_binding_mismatch" });
                        return;
                    }

                    var resourceTokenJwt = CreateResourceTokenJwt(signingKey, signingPublicJwk.Kid, resourceUrl, agentToken, thumbprint, DocumentsScope);
                    context.Response.StatusCode = 401;
                    context.Response.Headers["AAuth-Requirement"] = AAuthRequirement.BuildAuthToken(resourceTokenJwt);
                    await context.Response.WriteAsJsonAsync(new { error = "auth_token_required" });
                    return;
                }

                if (typ != "aa-auth+jwt")
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_token_type", detail = $"Expected aa-auth+jwt, got {typ}" });
                    return;
                }

                await JwtValidationHelpers.ValidateJwtSignatureFromIssuerAsync(jwt, token.Issuer, token.GetClaim("dwk").Value, "aa-auth+jwt", ClockSkew);
                // Production code must verify the JWT signature against the issuer's JWKS before calling Decode().
                var authToken = AuthToken.Decode(jwt);
                if (authToken.ExpiresAt + ClockSkew < DateTimeOffset.UtcNow)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "token_expired" });
                    return;
                }

                if (authToken.IssuedAt - ClockSkew > DateTimeOffset.UtcNow)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "token_not_yet_valid" });
                    return;
                }

                if (authToken.Audience != resourceUrl)
                {
                    Console.WriteLine($"  ✗ Auth token audience mismatch: {authToken.Audience} != {resourceUrl}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token" });
                    return;
                }

                var cnfThumbprint = JsonWebKeyThumbprint.Compute(authToken.ConfirmationKey);
                if (cnfThumbprint != verifyResult.Thumbprint)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "cnf_binding_mismatch" });
                    return;
                }

                Console.WriteLine($"  ✓ Auth token verified — sub: {authToken.Subject}, agent: {authToken.Agent}");

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new
                {
                    message = "Here are your documents!",
                    documents = new[]
                    {
                        new { id = "doc-1", title = "Project Roadmap", status = "draft" },
                        new { id = "doc-2", title = "Architecture Guide", status = "published" },
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

    private static string CreateResourceTokenJwt(
        ECDsa signingKey,
        string? keyId,
        string resourceUrl,
        AgentToken agentToken,
        string agentThumbprint,
        string scope)
    {
        if (agentToken.PersonServerUrl is null)
            throw new InvalidOperationException("Agent token must contain ps claim for three-party flow");

        return ResourceToken.Create(new ResourceTokenOptions
        {
            Resource = resourceUrl,
            AuthServer = agentToken.PersonServerUrl,
            Agent = agentToken.Subject,
            AgentJkt = agentThumbprint,
            Scope = scope,
        }, CreateSigningCredentials(signingKey, keyId));
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
