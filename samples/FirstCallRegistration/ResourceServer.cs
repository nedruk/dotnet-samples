using System.Text.Json;
using AAuth.Core.Discovery;
using AAuth.Core.Headers;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FirstCallRegistration;

public static class ResourceServer
{
    public static WebApplication CreateApp(JsonWebKey signingPublicJwk, int port)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseKestrelHttpsConfiguration();
        builder.WebHost.UseUrls($"https://localhost:{port}");
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton(new IssuerKeyResolver(new HttpClient()));

        var app = builder.Build();
        var baseUrl = $"https://localhost:{port}";

        app.MapGet("/.well-known/aauth-resource.json", () => Results.Json(new
        {
            issuer = baseUrl,
            jwks_uri = $"{baseUrl}/jwks"
        }));

        app.MapGet("/jwks", () => Results.Json(new
        {
            keys = new[] { signingPublicJwk }
        }));

        app.MapGet("/api/data", async (HttpContext context) =>
        {
            try
            {
                var keyResolver = context.RequestServices.GetRequiredService<IssuerKeyResolver>();
                var (agentToken, thumbprint) = await VerifySignedAgentRequestAsync(context, keyResolver, context.RequestAborted);
                Console.WriteLine($"  ✓ Agent token verified — identity: {agentToken.Subject}");

                var authHeader = context.Request.Headers.Authorization.ToString();
                if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("AAuth ", StringComparison.Ordinal))
                {
                    var accessToken = authHeader["AAuth ".Length..];
                    if (PendingStore.ValidateAccessToken(accessToken, thumbprint))
                    {
                        Console.WriteLine("  ✓ Access token valid — granting access");
                        context.Response.StatusCode = 200;
                        await context.Response.WriteAsJsonAsync(new
                        {
                            message = "Hello from the resource!",
                            agent = agentToken.Subject,
                            access = "granted via AAuth-Access token",
                        });
                        return;
                    }

                    Console.WriteLine("  ✗ Invalid access token");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_access_token" });
                    return;
                }

                Console.WriteLine("  → No access token — initiating interaction flow");
                var pending = PendingStore.CreatePending(agentToken.Subject, thumbprint);

                context.Response.StatusCode = 202;
                context.Response.Headers["Location"] = $"{baseUrl}/pending/{pending.Id}";
                context.Response.Headers["Retry-After"] = "2";
                context.Response.Headers["Cache-Control"] = "no-store";
                context.Response.Headers["AAuth-Requirement"] = AAuthRequirement.BuildInteraction(
                    $"{baseUrl}/interact", pending.Code);
                await context.Response.WriteAsJsonAsync(new { status = "pending" });

                Console.WriteLine($"  → Pending ID: {pending.Id}");
                Console.WriteLine($"  → Interaction URL: {baseUrl}/interact?code={pending.Code}");
            }
            catch (AAuthTokenException ex)
            {
                Console.WriteLine($"  ✗ Token validation failed: {ex.Message}");
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = ex.Code, detail = ex.Message });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ✗ Error: {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error", detail = ex.Message });
            }
        });

        app.MapGet("/pending/{id}", async (string id, HttpContext context) =>
        {
            var pending = PendingStore.GetPendingById(id);
            if (pending is null || pending.IsConsumed || pending.Status == "consumed")
            {
                context.Response.StatusCode = 410;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_code" });
                return;
            }

            if (pending.IsExpired)
            {
                PendingStore.ExpirePending(id);
                context.Response.StatusCode = 408;
                await context.Response.WriteAsJsonAsync(new { error = "expired" });
                return;
            }

            try
            {
                var keyResolver = context.RequestServices.GetRequiredService<IssuerKeyResolver>();
                var (agentToken, thumbprint) = await VerifySignedAgentRequestAsync(context, keyResolver, context.RequestAborted);
                if (!string.Equals(agentToken.Subject, pending.AgentId, StringComparison.Ordinal) ||
                    !string.Equals(thumbprint, pending.AgentJkt, StringComparison.Ordinal))
                {
                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsJsonAsync(new { error = "denied" });
                    return;
                }
            }
            catch (AAuthTokenException ex)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = ex.Code, detail = ex.Message });
                return;
            }

            if (pending.Status == "approved")
            {
                var consumed = PendingStore.ConsumeApprovedPending(id);
                if (consumed is null)
                {
                    context.Response.StatusCode = 410;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_code" });
                    return;
                }

                Console.WriteLine($"  ✓ Pending {pending.Id} approved — returning access token");
                context.Response.StatusCode = 200;
                context.Response.Headers["AAuth-Access"] = consumed.AccessToken!;
                await context.Response.WriteAsJsonAsync(new { status = "authorized" });
                return;
            }

            if (pending.Status == "denied")
            {
                Console.WriteLine($"  ✗ Pending {pending.Id} denied");
                context.Response.StatusCode = 403;
                await context.Response.WriteAsJsonAsync(new { status = "denied" });
                return;
            }

            context.Response.StatusCode = 202;
            context.Response.Headers["Retry-After"] = "2";
            context.Response.Headers["Cache-Control"] = "no-store";
            await context.Response.WriteAsJsonAsync(new { status = pending.Status });
        });

        app.MapGet("/interact", (HttpContext context) =>
        {
            var code = context.Request.Query["code"].ToString();
            if (string.IsNullOrEmpty(code))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "text/html";
                return context.Response.WriteAsync(InteractionPage.RenderErrorPage("Missing interaction code."));
            }

            var pending = PendingStore.GetPendingByCode(code);
            if (pending is null)
            {
                context.Response.StatusCode = 404;
                context.Response.ContentType = "text/html";
                return context.Response.WriteAsync(InteractionPage.RenderErrorPage("Invalid or expired interaction code."));
            }

            if (pending.IsExpired)
            {
                PendingStore.ExpirePending(pending.Id);
                context.Response.StatusCode = 410;
                context.Response.ContentType = "text/html";
                return context.Response.WriteAsync(InteractionPage.RenderErrorPage("This interaction has expired."));
            }

            if (pending.Status != "pending" && pending.Status != "interacting")
            {
                context.Response.StatusCode = 410;
                context.Response.ContentType = "text/html";
                return context.Response.WriteAsync(InteractionPage.RenderErrorPage("This interaction has already been completed."));
            }

            pending.Status = "interacting";
            context.Response.ContentType = "text/html";
            return context.Response.WriteAsync(InteractionPage.RenderConsentPage(pending.AgentId, pending.Code));
        });

        app.MapPost("/interact/approve", async (HttpContext context) =>
        {
            string? code;
            try
            {
                code = await ReadInteractionCodeAsync(context.Request, context.RequestAborted);
            }
            catch (JsonException)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                return;
            }

            if (string.IsNullOrEmpty(code))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                return;
            }

            var pending = PendingStore.GetPendingByCode(code);
            if (pending is null)
            {
                context.Response.StatusCode = 410;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_code" });
                return;
            }

            if (pending.IsExpired)
            {
                PendingStore.ExpirePending(pending.Id);
                context.Response.StatusCode = 408;
                await context.Response.WriteAsJsonAsync(new { error = "expired" });
                return;
            }

            PendingStore.ApprovePending(pending.Id);
            Console.WriteLine($"  ✓ User approved agent \"{pending.AgentId}\" (code: {code})");
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(InteractionPage.RenderResultPage(true));
        });

        app.MapPost("/interact/deny", async (HttpContext context) =>
        {
            string? code;
            try
            {
                code = await ReadInteractionCodeAsync(context.Request, context.RequestAborted);
            }
            catch (JsonException)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                return;
            }

            if (string.IsNullOrEmpty(code))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                return;
            }

            var pending = PendingStore.GetPendingByCode(code);
            if (pending is null)
            {
                context.Response.StatusCode = 410;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_code" });
                return;
            }

            if (pending.IsExpired)
            {
                PendingStore.ExpirePending(pending.Id);
                context.Response.StatusCode = 408;
                await context.Response.WriteAsJsonAsync(new { error = "expired" });
                return;
            }

            PendingStore.DenyPending(pending.Id);
            Console.WriteLine($"  ✗ User denied agent \"{pending.AgentId}\" (code: {code})");
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(InteractionPage.RenderResultPage(false));
        });

        return app;
    }

    private static async Task<(AgentToken AgentToken, string Thumbprint)> VerifySignedAgentRequestAsync(
        HttpContext context,
        IssuerKeyResolver keyResolver,
        CancellationToken cancellationToken)
    {
        var request = ConvertToRequestMessage(context);
        var verifyResult = HttpMessageSigner.Verify(request);
        if (!verifyResult.IsValid)
            throw new AAuthTokenException("invalid_signature", verifyResult.Error ?? "HTTP message signature verification failed");

        Console.WriteLine("  ✓ HTTP signature verified");

        var signatureKeyHeader = context.Request.Headers["Signature-Key"].ToString();
        var jwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeader);
        if (jwt is null)
            throw new AAuthTokenException("invalid_request", "Signature-Key does not contain an agent token JWT");

        var agentToken = await ValidateAgentTokenAsync(jwt, keyResolver, cancellationToken);
        var thumbprint = JsonWebKeyThumbprint.Compute(agentToken.ConfirmationKey);
        if (thumbprint != verifyResult.Thumbprint)
            throw new AAuthTokenException("cnf_binding_mismatch", "HTTP signature key does not match the token confirmation key");

        return (agentToken, thumbprint);
    }

    private static async Task<AgentToken> ValidateAgentTokenAsync(
        string rawJwt,
        IssuerKeyResolver keyResolver,
        CancellationToken cancellationToken)
    {
        try
        {
            var agentToken = AgentToken.Decode(rawJwt);
            var keys = await keyResolver.ResolveKeysAsync(agentToken.Issuer, agentToken.Dwk, cancellationToken);
            var handler = new JsonWebTokenHandler();
            var result = await handler.ValidateTokenAsync(rawJwt, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = keys.Keys,
                ValidateIssuer = true,
                ValidIssuer = agentToken.Issuer,
                ValidateAudience = false,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.FromMinutes(1),
            });

            if (!result.IsValid)
                throw new AAuthTokenException("invalid_agent_token", result.Exception?.Message ?? "Agent token signature validation failed");

            return agentToken;
        }
        catch (AAuthTokenException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AAuthTokenException("invalid_agent_token", ex.Message, ex);
        }
    }

    private static async Task<string?> ReadInteractionCodeAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        var body = await JsonSerializer.DeserializeAsync<JsonElement>(request.Body, cancellationToken: cancellationToken);
        return body.TryGetProperty("code", out var codeProp) ? codeProp.GetString() : null;
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
