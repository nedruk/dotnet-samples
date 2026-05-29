using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AAuth.Core.Headers;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using CoreMission = AAuth.Core.Tokens.Mission;

namespace MissionControl;

/// <summary>
/// Person Server — extends Sample 03's token exchange with governance endpoints
/// (missions, permissions, auditing, interactions) and a dashboard API.
/// </summary>
public static class PersonServer
{
    public static WebApplication CreateApp(ECDsa signingKey, JsonWebKey signingPublicJwk, int port, GovernanceStore store, bool autoApprove = false)
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
            mission_endpoint = $"{psUrl}/mission",
            permission_endpoint = $"{psUrl}/permission",
            audit_endpoint = $"{psUrl}/audit",
            interaction_endpoint = $"{psUrl}/interaction",
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
                var (sigResult, agentToken, thumbprint) = await VerifyRequest(context);
                if (sigResult is null)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "unauthorized" });
                    return;
                }

                var tokenHandler = new JsonWebTokenHandler();
                var agentTokenValue = agentToken!;
                var sigThumbprint = thumbprint!;

                var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                if (!body.TryGetProperty("resource_token", out var rtProp) || rtProp.GetString() is not { } resourceTokenJwt)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                    return;
                }

                var resourceValidation = await ValidateJwtAgainstIssuerAsync(
                    resourceTokenJwt,
                    tokenType: "aa-resource+jwt",
                    allowedMetadataDocuments: ["aauth-resource.json"],
                    validAudience: psUrl);
                if (!resourceValidation.IsValid)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token", detail = resourceValidation.Error });
                    return;
                }

                Console.WriteLine("  ✓ Resource token signature verified");

                var resourceToken = ResourceToken.Decode(resourceTokenJwt);
                Console.WriteLine($"  ✓ Resource token decoded — issuer: {resourceToken.Issuer}");

                if (resourceToken.Audience != psUrl)
                {
                    Console.WriteLine($"  ✗ Resource token audience mismatch: {resourceToken.Audience} != {psUrl}");
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_resource_token" });
                    return;
                }

                if (resourceToken.Agent != agentTokenValue.Subject)
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

                // Validate mission claim if present in resource token
                CoreMission? missionClaim = null;
                if (resourceToken.Mission is not null)
                {
                    Console.WriteLine($"  → Validating mission claim s256={resourceToken.Mission.S256}");
                    var mission = store.FindMissionByS256(resourceToken.Mission.S256);
                    if (mission is null || !string.Equals(mission.Approver, resourceToken.Mission.Approver, StringComparison.Ordinal))
                    {
                        context.Response.StatusCode = 403;
                        await context.Response.WriteAsJsonAsync(new { error = "mission_not_found" });
                        return;
                    }
                    if (mission.Status != "active")
                    {
                        await WriteMissionTerminatedAsync(context, mission.Status);
                        return;
                    }
                    Console.WriteLine($"  ✓ Mission validated: {mission.Id} (active)");
                    store.AddMissionLogEntry(mission.Id, new MissionLogEntry
                    {
                        Timestamp = DateTimeOffset.UtcNow,
                        Type = "token_request",
                        Summary = $"Token requested for resource {resourceToken.Issuer}"
                    });
                    missionClaim = resourceToken.Mission;
                }

                Console.WriteLine("  ✓ Auto-approved (demo mode)");

                // Create auth token
                var resourceAud = resourceToken.Issuer;
                var now = DateTimeOffset.UtcNow;

                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(resourceAud));
                var sub = "user-" + Convert.ToHexString(hash).ToLowerInvariant()[..12];

                var authTokenClaims = new Dictionary<string, object>
                {
                    ["iss"] = psUrl,
                    ["dwk"] = "aauth-person.json",
                    ["aud"] = resourceAud,
                    ["jti"] = Guid.NewGuid().ToString(),
                    ["agent"] = agentTokenValue.Subject,
                    ["cnf"] = new Dictionary<string, object>
                    {
                        ["jwk"] = JsonSerializer.Deserialize<Dictionary<string, object>>(
                            JsonExtensions.SerializeJwk(agentTokenValue.ConfirmationKey))!
                    },
                    ["act"] = new Dictionary<string, object> { ["sub"] = agentTokenValue.Subject },
                    ["sub"] = sub,
                    ["iat"] = now.ToUnixTimeSeconds(),
                    ["exp"] = now.AddHours(1).ToUnixTimeSeconds(),
                };

                if (resourceToken.Scope is not null)
                    authTokenClaims["scope"] = resourceToken.Scope;

                if (missionClaim is not null)
                {
                    authTokenClaims["mission"] = new Dictionary<string, object>
                    {
                        ["approver"] = missionClaim.Approver,
                        ["s256"] = missionClaim.S256,
                    };
                }

                var authTokenJwt = tokenHandler.CreateToken(new SecurityTokenDescriptor
                {
                    Claims = authTokenClaims,
                    SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256),
                    TokenType = "aa-auth+jwt",
                });

                Console.WriteLine($"  ✓ Auth token issued — sub: {sub}, aud: {resourceAud}");

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { auth_token = authTokenJwt, expires_in = 3600 });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ✗ Error: {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        // ── POST /mission — create mission proposal ─────────────────────────
        app.MapPost("/mission", async (HttpContext context) =>
        {
            try
            {
                var (sigResult, agentToken, thumbprint) = await VerifyRequest(context);
                if (sigResult is null)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "unauthorized" });
                    return;
                }

                var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                var description = body.GetProperty("description").GetString()!;

                List<ToolInfo>? tools = null;
                if (body.TryGetProperty("tools", out var toolsArr))
                {
                    tools = new List<ToolInfo>();
                    foreach (var t in toolsArr.EnumerateArray())
                    {
                        var name = t.GetProperty("name").GetString()!;
                        var desc = t.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";
                        tools.Add(new ToolInfo { Name = name, Description = desc });
                    }
                }

                var proposal = new MissionProposal { Description = description, Tools = tools };
                var pending = store.CreateMission(proposal, agentToken!.Subject, psUrl);

                if (autoApprove)
                {
                    var approved = store.ApproveMission(pending.Id);
                    Console.WriteLine($"  ✓ Mission auto-approved: {approved.Id}");
                    var missionHeader = AAuthMissionHeader.Build(new CoreMission(approved.Approver, approved.S256!));
                    context.Response.Headers["AAuth-Mission"] = missionHeader;
                    context.Response.StatusCode = 200;
                    await WriteMissionResponseAsync(context, approved);
                    return;
                }

                Console.WriteLine($"  → Mission pending approval: {pending.Id}");
                context.Response.StatusCode = 202;
                context.Response.Headers["Location"] = $"{psUrl}/pending/mission/{pending.Id}";
                await context.Response.WriteAsJsonAsync(new { id = pending.Id, status = "pending" });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ✗ Error: {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        // ── GET /pending/mission/{id} — poll mission status ──────────────────
        app.MapGet("/pending/mission/{id}", async (HttpContext context, string id) =>
        {
            var mission = store.GetMission(id);
            if (mission is null)
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsJsonAsync(new { error = "not_found" });
                return;
            }

            if (mission.Status == "active")
            {
                var missionHeader = AAuthMissionHeader.Build(new CoreMission(mission.Approver, mission.S256!));
                context.Response.Headers["AAuth-Mission"] = missionHeader;
                context.Response.StatusCode = 200;
                await WriteMissionResponseAsync(context, mission);
            }
            else if (mission.Status == "terminated")
            {
                context.Response.StatusCode = 410;
                await context.Response.WriteAsJsonAsync(new { status = "terminated" });
            }
            else
            {
                context.Response.StatusCode = 202;
                await context.Response.WriteAsJsonAsync(new { id, status = mission.Status });
            }
        });

        // ── POST /permission — request permission ────────────────────────────
        app.MapPost("/permission", async (HttpContext context) =>
        {
            try
            {
                var (sigResult, agentToken, thumbprint) = await VerifyRequest(context);
                if (sigResult is null)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "unauthorized" });
                    return;
                }

                var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                var action = body.GetProperty("action").GetString()!;
                var description = body.TryGetProperty("description", out var descProp) ? descProp.GetString() : null;
                JsonElement? parameters = body.TryGetProperty("parameters", out var paramsProp) ? paramsProp : null;

                var (canProceed, missionData) = await ResolveMissionContextAsync(context, store, body, required: false);
                if (!canProceed)
                    return;

                var missionId = missionData?.Id;

                if (missionData is not null)
                {
                    var isApprovedTool = missionData.ApprovedTools.Any(t => t.Name == action);
                    if (isApprovedTool)
                    {
                        store.AddMissionLogEntry(missionData.Id, new MissionLogEntry
                        {
                            Timestamp = DateTimeOffset.UtcNow,
                            Type = "permission_response",
                            Summary = $"Permission auto-granted (approved tool): {action}"
                        });
                        context.Response.StatusCode = 200;
                        await context.Response.WriteAsJsonAsync(new { permission = "granted" });
                        return;
                    }
                }

                var pending = store.CreatePermission(action, missionId, description, parameters);

                if (autoApprove)
                {
                    var resolved = store.ResolvePermission(pending.Id, granted: true);
                    Console.WriteLine($"  ✓ Permission auto-granted: {action}");
                    if (missionId is not null)
                    {
                        store.AddMissionLogEntry(missionId, new MissionLogEntry
                        {
                            Timestamp = DateTimeOffset.UtcNow,
                            Type = "permission_response",
                            Summary = $"Permission auto-granted: {action}"
                        });
                    }
                    context.Response.StatusCode = 200;
                    await context.Response.WriteAsJsonAsync(new { permission = "granted" });
                    return;
                }

                Console.WriteLine($"  → Permission pending: {pending.Id}");
                if (missionId is not null)
                {
                    store.AddMissionLogEntry(missionId, new MissionLogEntry
                    {
                        Timestamp = DateTimeOffset.UtcNow,
                        Type = "permission_request",
                        Summary = $"Permission requested: {action}"
                    });
                }
                context.Response.StatusCode = 202;
                context.Response.Headers["Location"] = $"{psUrl}/pending/permission/{pending.Id}";
                await context.Response.WriteAsJsonAsync(new { id = pending.Id, status = "pending" });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ✗ Error: {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        // ── GET /pending/permission/{id} — poll permission status ────────────
        app.MapGet("/pending/permission/{id}", async (HttpContext context, string id) =>
        {
            var permission = store.GetPermission(id);
            if (permission is null)
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsJsonAsync(new { error = "not_found" });
                return;
            }

            if (permission.Status == "granted")
            {
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { permission = "granted" });
            }
            else if (permission.Status == "denied")
            {
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { permission = "denied", reason = permission.Reason });
            }
            else
            {
                context.Response.StatusCode = 202;
                await context.Response.WriteAsJsonAsync(new { id, status = permission.Status });
            }
        });

        // ── POST /audit — log audit record ───────────────────────────────────
        app.MapPost("/audit", async (HttpContext context) =>
        {
            try
            {
                var (sigResult, agentToken, thumbprint) = await VerifyRequest(context);
                if (sigResult is null)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "unauthorized" });
                    return;
                }

                var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                var action = body.GetProperty("action").GetString()!;
                var description = body.TryGetProperty("description", out var descProp) ? descProp.GetString() : null;
                JsonElement? parameters = body.TryGetProperty("parameters", out var paramsProp) ? paramsProp : null;
                JsonElement? result = body.TryGetProperty("result", out var resultProp) ? resultProp : null;

                var (canProceed, missionData) = await ResolveMissionContextAsync(context, store, body, required: true);
                if (!canProceed || missionData is null)
                    return;

                var audit = store.CreateAudit(missionData.Id, action, description, parameters, result);

                Console.WriteLine($"  ✓ Audit record created: {audit.Id}");
                context.Response.StatusCode = 201;
                await context.Response.WriteAsJsonAsync(new { id = audit.Id });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ✗ Error: {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        // ── POST /interaction — create interaction ───────────────────────────
        app.MapPost("/interaction", async (HttpContext context) =>
        {
            try
            {
                var (sigResult, agentToken, thumbprint) = await VerifyRequest(context);
                if (sigResult is null)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsJsonAsync(new { error = "unauthorized" });
                    return;
                }

                var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                var type = body.GetProperty("type").GetString()!;
                var description = body.TryGetProperty("description", out var descProp) ? descProp.GetString() : null;
                var summary = body.TryGetProperty("summary", out var sumProp) ? sumProp.GetString() : null;
                var question = body.TryGetProperty("question", out var qProp) ? qProp.GetString() : null;

                var (canProceed, missionData) = await ResolveMissionContextAsync(context, store, body, required: false);
                if (!canProceed)
                    return;

                var missionId = missionData?.Id;

                var interactionData = new InteractionData
                {
                    Description = description,
                    Summary = summary,
                    Question = question,
                };
                var pending = store.CreateInteraction(type, missionId, interactionData);

                if (autoApprove)
                {
                    if (type == "completion")
                    {
                        store.ResolveInteraction(pending.Id);
                        if (missionId is not null)
                        {
                            store.TerminateMission(missionId);
                            store.AddMissionLogEntry(missionId, new MissionLogEntry
                            {
                                Timestamp = DateTimeOffset.UtcNow,
                                Type = "interaction_response",
                                Summary = "Completion accepted, mission terminated"
                            });
                        }
                        Console.WriteLine($"  ✓ Completion auto-accepted: {pending.Id}");
                        context.Response.StatusCode = 200;
                        await context.Response.WriteAsJsonAsync(new { status = "accepted" });
                        return;
                    }

                    if (type == "question")
                    {
                        store.ResolveInteraction(pending.Id, answer: "Auto-approved");
                        Console.WriteLine($"  ✓ Question auto-answered: {pending.Id}");
                        if (missionId is not null)
                        {
                            store.AddMissionLogEntry(missionId, new MissionLogEntry
                            {
                                Timestamp = DateTimeOffset.UtcNow,
                                Type = "interaction_response",
                                Summary = "Question auto-answered"
                            });
                        }
                        context.Response.StatusCode = 200;
                        await context.Response.WriteAsJsonAsync(new { status = "answered", answer = "Auto-approved" });
                        return;
                    }
                }

                Console.WriteLine($"  → Interaction pending: {pending.Id}");
                if (missionId is not null)
                {
                    store.AddMissionLogEntry(missionId, new MissionLogEntry
                    {
                        Timestamp = DateTimeOffset.UtcNow,
                        Type = "interaction_request",
                        Summary = $"Interaction requested: {type}"
                    });
                }
                context.Response.StatusCode = 202;
                context.Response.Headers["Location"] = $"{psUrl}/pending/interaction/{pending.Id}";
                await context.Response.WriteAsJsonAsync(new { id = pending.Id, status = "pending" });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ✗ Error: {ex.Message}");
                context.Response.StatusCode = 500;
                await context.Response.WriteAsJsonAsync(new { error = "server_error" });
            }
        });

        // ── GET /pending/interaction/{id} — poll interaction status ──────────
        app.MapGet("/pending/interaction/{id}", async (HttpContext context, string id) =>
        {
            var interaction = store.GetInteraction(id);
            if (interaction is null)
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsJsonAsync(new { error = "not_found" });
                return;
            }

            if (interaction.Status == "completed")
            {
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { status = interaction.Status, answer = interaction.Answer });
            }
            else
            {
                context.Response.StatusCode = 202;
                await context.Response.WriteAsJsonAsync(new { id, status = interaction.Status });
            }
        });

        // ── Dashboard APIs ────────────────────────────────────────────────────
        app.MapGet("/api/dashboard", async (HttpContext context) =>
        {
            if (!await EnsureLocalDashboardAccessAsync(context))
                return;

            var state = store.GetDashboardState();
            await context.Response.WriteAsJsonAsync(state);
        });

        app.MapPost("/api/missions/{id}/approve", async (HttpContext context, string id) =>
        {
            if (!await EnsureLocalDashboardAccessAsync(context))
                return;

            try
            {
                var approved = store.ApproveMission(id);
                await context.Response.WriteAsJsonAsync(new { status = "active", id = approved.Id });
            }
            catch (KeyNotFoundException)
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsJsonAsync(new { error = "not_found_or_not_pending" });
            }
        });

        app.MapPost("/api/missions/{id}/deny", async (HttpContext context, string id) =>
        {
            if (!await EnsureLocalDashboardAccessAsync(context))
                return;

            try
            {
                store.TerminateMission(id);
                await context.Response.WriteAsJsonAsync(new { status = "terminated" });
            }
            catch (KeyNotFoundException)
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsJsonAsync(new { error = "not_found" });
            }
        });

        app.MapPost("/api/permissions/{id}/grant", async (HttpContext context, string id) =>
        {
            if (!await EnsureLocalDashboardAccessAsync(context))
                return;

            try
            {
                store.ResolvePermission(id, granted: true);
                await context.Response.WriteAsJsonAsync(new { status = "granted" });
            }
            catch (KeyNotFoundException)
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsJsonAsync(new { error = "not_found" });
            }
        });

        app.MapPost("/api/permissions/{id}/deny", async (HttpContext context, string id) =>
        {
            if (!await EnsureLocalDashboardAccessAsync(context))
                return;

            string? reason = null;
            try
            {
                var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                if (body.TryGetProperty("reason", out var reasonProp))
                    reason = reasonProp.GetString();
            }
            catch { }

            try
            {
                store.ResolvePermission(id, granted: false, reason);
                await context.Response.WriteAsJsonAsync(new { status = "denied" });
            }
            catch (KeyNotFoundException)
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsJsonAsync(new { error = "not_found" });
            }
        });

        app.MapPost("/api/interactions/{id}/answer", async (HttpContext context, string id) =>
        {
            if (!await EnsureLocalDashboardAccessAsync(context))
                return;

            string? answer = null;
            try
            {
                var body = await JsonSerializer.DeserializeAsync<JsonElement>(context.Request.Body);
                if (body.TryGetProperty("answer", out var answerProp))
                    answer = answerProp.GetString();
            }
            catch { }

            try
            {
                store.ResolveInteraction(id, answer);
                await context.Response.WriteAsJsonAsync(new { status = "answered", answer });
            }
            catch (KeyNotFoundException)
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsJsonAsync(new { error = "not_found" });
            }
        });

        app.MapPost("/api/interactions/{id}/accept", async (HttpContext context, string id) =>
        {
            if (!await EnsureLocalDashboardAccessAsync(context))
                return;

            var interaction = store.GetInteraction(id);
            if (interaction is null)
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsJsonAsync(new { error = "not_found" });
                return;
            }

            try
            {
                store.ResolveInteraction(id);
            }
            catch (KeyNotFoundException)
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsJsonAsync(new { error = "not_found" });
                return;
            }

            if (interaction.MissionId is not null)
            {
                store.TerminateMission(interaction.MissionId);
                store.AddMissionLogEntry(interaction.MissionId, new MissionLogEntry
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Type = "interaction_response",
                    Summary = "Completion accepted, mission terminated"
                });
            }

            await context.Response.WriteAsJsonAsync(new { status = "accepted" });
        });

        return app;
    }

    /// <summary>
    /// Verifies the HTTP message signature and agent token on an incoming request.
    /// </summary>
    private static async Task<(SignatureVerificationResult? sigResult, AgentToken? agentToken, string? thumbprint)> VerifyRequest(HttpContext context)
    {
        var request = ConvertToRequestMessage(context);
        var verifyResult = HttpMessageSigner.Verify(request);
        if (!verifyResult.IsValid)
        {
            Console.WriteLine($"  ✗ Signature verification failed: {verifyResult.Error}");
            return (null, null, null);
        }
        Console.WriteLine("  ✓ HTTP signature verified");

        var signatureKeyHeader = context.Request.Headers["Signature-Key"].ToString();
        var jwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeader);
        if (jwt is null)
        {
            Console.WriteLine("  ✗ No agent token in signature");
            return (null, null, null);
        }

        var handler = new JsonWebTokenHandler();
        var rawToken = handler.ReadJsonWebToken(jwt);
        if (rawToken.Typ != "aa-agent+jwt")
        {
            Console.WriteLine("  ✗ Expected agent token");
            return (null, null, null);
        }

        var agentValidation = await ValidateJwtAgainstIssuerAsync(
            jwt,
            tokenType: "aa-agent+jwt",
            allowedMetadataDocuments: ["aauth-agent.json"]);
        if (!agentValidation.IsValid)
        {
            Console.WriteLine($"  ✗ Agent token validation failed: {agentValidation.Error}");
            return (null, null, null);
        }

        var agentToken = AgentToken.Decode(jwt);
        var thumbprint = JsonWebKeyThumbprint.Compute(agentToken.ConfirmationKey);
        if (thumbprint != verifyResult.Thumbprint)
        {
            Console.WriteLine("  ✗ CNF binding mismatch");
            return (null, null, null);
        }

        Console.WriteLine($"  ✓ Agent token verified — identity: {agentToken.Subject}");
        return (verifyResult, agentToken, thumbprint);
    }

    private static async Task<(bool canProceed, Mission? mission)> ResolveMissionContextAsync(
        HttpContext context,
        GovernanceStore store,
        JsonElement body,
        bool required)
    {
        if (!TryReadMissionReference(context, body, out var missionReference))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "invalid_mission" });
            return (false, null);
        }

        if (missionReference is null)
        {
            if (!required)
                return (true, null);

            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "missing_mission" });
            return (false, null);
        }

        var mission = store.FindMissionByS256(missionReference.S256);
        if (mission is null || !string.Equals(mission.Approver, missionReference.Approver, StringComparison.Ordinal))
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsJsonAsync(new { error = "mission_not_found" });
            return (false, null);
        }

        if (mission.Status != "active")
        {
            await WriteMissionTerminatedAsync(context, mission.Status);
            return (false, null);
        }

        return (true, mission);
    }

    private static bool TryReadMissionReference(HttpContext context, JsonElement body, out CoreMission? mission)
    {
        mission = null;

        if (body.TryGetProperty("mission", out var missionProp))
        {
            var approver = missionProp.GetProperty("approver").GetString();
            var s256 = missionProp.GetProperty("s256").GetString();
            if (string.IsNullOrEmpty(approver) || string.IsNullOrEmpty(s256))
                return false;

            mission = new CoreMission(approver, s256);
            return true;
        }

        var missionHeader = context.Request.Headers["AAuth-Mission"].ToString();
        if (string.IsNullOrWhiteSpace(missionHeader))
            return true;

        try
        {
            mission = AAuthMissionHeader.Parse(missionHeader);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static async Task WriteMissionResponseAsync(HttpContext context, Mission mission)
    {
        context.Response.ContentType = "application/json; charset=utf-8";
        await context.Response.Body.WriteAsync(mission.BlobBytes!);
    }

    private static async Task WriteMissionTerminatedAsync(HttpContext context, string missionStatus)
    {
        context.Response.StatusCode = 403;
        await context.Response.WriteAsJsonAsync(new { error = "mission_terminated", mission_status = missionStatus });
    }

    private static async Task<bool> EnsureLocalDashboardAccessAsync(HttpContext context)
    {
        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp?.IsIPv4MappedToIPv6 == true)
            remoteIp = remoteIp.MapToIPv4();

        if (remoteIp is not null && IPAddress.IsLoopback(remoteIp))
            return true;

        context.Response.StatusCode = 403;
        await context.Response.WriteAsJsonAsync(new { error = "forbidden", detail = "Dashboard APIs require localhost access." });
        return false;
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
            Console.WriteLine($"  ✗ JWT validation error: {ex.Message}");
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
