using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AAuth.Core.Headers;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using MissionControl;

const int ResourcePort = 3012;
const int PsPort = 3013;
const int ApPort = 3011;
const string AgentId = "aauth:demo-agent@localhost";

Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║  Sample 4: Mission Control — Agent Governance Dashboard    ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
Console.ResetColor();
Console.WriteLine();

// 1. Generate ECDSA P-256 key pairs
Console.WriteLine("1. Generating ECDSA P-256 key pairs...");
var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var ephemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var resourceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var psKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

var rootPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(rootKey) { KeyId = "root-1" });
rootPublicJwk.Kid = "root-1";

var ephemeralPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ephemeralKey));
var ephemeralThumbprint = JsonWebKeyThumbprint.Compute(ephemeralPublicJwk);

var resourcePublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(resourceKey) { KeyId = "resource-1" });
resourcePublicJwk.Kid = "resource-1";

var psPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(psKey) { KeyId = "ps-1" });
psPublicJwk.Kid = "ps-1";

Console.WriteLine($"   Root key kid: root-1");
Console.WriteLine($"   Ephemeral key thumbprint: {ephemeralThumbprint}");
Console.WriteLine($"   Resource key kid: resource-1");
Console.WriteLine($"   Person Server key kid: ps-1");
Console.WriteLine();

// 2. Create agent token (with ps claim)
var apUrl = $"https://localhost:{ApPort}";
var psUrl = $"https://localhost:{PsPort}";
var resourceUrl = $"https://localhost:{ResourcePort}";
Console.WriteLine("2. Creating agent token (with ps claim)...");
var agentTokenJwt = AgentToken.Create(new AgentTokenOptions
{
    Issuer = apUrl,
    Subject = AgentId,
    PublicKey = ephemeralPublicJwk,
    PersonServerUrl = psUrl,
}, new SigningCredentials(new ECDsaSecurityKey(rootKey), SecurityAlgorithms.EcdsaSha256));

Console.WriteLine($"   Agent ID: {AgentId}");
Console.WriteLine($"   Issuer (AP): {apUrl}");
Console.WriteLine($"   Person Server: {psUrl}");
Console.WriteLine();

// 3. Start Agent Provider
Console.WriteLine($"3. Starting Agent Provider on port {ApPort}...");
var apApp = AgentProviderServer.CreateApp(rootPublicJwk, ApPort);
await apApp.StartAsync();
Console.WriteLine($"   Metadata: {apUrl}/.well-known/aauth-agent.json");
Console.WriteLine();

// 4. Start Resource Server
Console.WriteLine($"4. Starting Resource Server on port {ResourcePort}...");
var resourceApp = ResourceServer.CreateApp(resourceKey, resourcePublicJwk, ResourcePort);
await resourceApp.StartAsync();
Console.WriteLine($"   API:       {resourceUrl}/api/data");
Console.WriteLine($"   Authorize: {resourceUrl}/authorize");
Console.WriteLine();

// 5. Start Person Server with governance
var interactive = args.Contains("interactive") || args.Contains("--interactive");
Console.WriteLine($"5. Starting Person Server on port {PsPort}...");
var store = new GovernanceStore();
var psApp = PersonServer.CreateApp(psKey, psPublicJwk, PsPort, store, autoApprove: !interactive);

// Serve dashboard HTML
psApp.MapGet("/dashboard", () => Results.Content(Dashboard.GetHtml(psUrl), "text/html"));

await psApp.StartAsync();
Console.WriteLine($"   Token:       {psUrl}/token");
Console.WriteLine($"   Mission:     {psUrl}/mission");
Console.WriteLine($"   Permission:  {psUrl}/permission");
Console.WriteLine($"   Audit:       {psUrl}/audit");
Console.WriteLine($"   Interaction: {psUrl}/interaction");
Console.WriteLine($"   Dashboard:   {psUrl}/dashboard");
Console.WriteLine();

try
{
    if (interactive)
        await RunInteractive();
    else
        await RunAutomated();
}
finally
{
    await apApp.StopAsync();
    await resourceApp.StopAsync();
    await psApp.StopAsync();
}

return;

// ─── Automated mode ──────────────────────────────────────────────────────────

async Task RunAutomated()
{
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  AUTOMATED MODE — Full mission lifecycle");
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine();

    var plainClient = new HttpClient();
    var signatureKey = new SignatureKeyValue.Jwt(agentTokenJwt);

    // Step 1: Propose mission
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 1: Propose mission ──────────────────────────────────");
    Console.ResetColor();
    Console.WriteLine($"→ POST {psUrl}/mission");

    var missionRequest = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/mission");
    missionRequest.Content = JsonContent.Create(new
    {
        description = "# Research Weather Data\n\nSearch for current weather data for Tokyo and summarize the findings.",
        tools = new[]
        {
            new { name = "WebSearch", description = "Search the web for information" },
            new { name = "ReadPage", description = "Read a web page" },
        },
    });
    SignRequest(missionRequest, ephemeralKey, signatureKey);

    var missionResponse = await plainClient.SendAsync(missionRequest);
    Console.WriteLine($"← {(int)missionResponse.StatusCode}");

    var approvedMission = await ReadApprovedMissionAsync(missionResponse);
    var missionHeader = approvedMission.Header;
    var missionBodyBytes = approvedMission.BodyBytes;
    var missionBody = Encoding.UTF8.GetString(missionBodyBytes);
    Console.WriteLine("  ✓ Mission approved");
    Console.WriteLine($"  AAuth-Mission: {missionHeader}");
    Console.WriteLine($"  Verified SHA-256 over {missionBodyBytes.Length} response bytes");
    Console.WriteLine($"  Blob: {missionBody[..Math.Min(120, missionBody.Length)]}...");
    Console.WriteLine();

    var mission = approvedMission.Mission;

    // Step 2: Request permission for WebSearch
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 2: Request permission — WebSearch ───────────────────");
    Console.ResetColor();
    Console.WriteLine($"→ POST {psUrl}/permission");

    var permRequest = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/permission");
    permRequest.Content = JsonContent.Create(new
    {
        action = "WebSearch",
        description = "Search for Tokyo weather data",
        parameters = new { query = "Tokyo weather today" },
        mission = new { approver = mission.Approver, s256 = mission.S256 },
    });
    SignRequest(permRequest, ephemeralKey, signatureKey);

    var permResponse = await plainClient.SendAsync(permRequest);
    var permBody = await permResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)permResponse.StatusCode}");
    Console.WriteLine($"  {permBody}");
    Console.WriteLine();

    // Step 3: Log audit record
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 3: Log audit record ─────────────────────────────────");
    Console.ResetColor();
    Console.WriteLine($"→ POST {psUrl}/audit");

    var auditRequest = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/audit");
    auditRequest.Content = JsonContent.Create(new
    {
        mission = new { approver = mission.Approver, s256 = mission.S256 },
        action = "WebSearch",
        description = "Searched for Tokyo weather data",
        parameters = new { query = "Tokyo weather today" },
        result = new { status = "completed", summary = "Found current weather: 22°C, partly cloudy" },
    });
    SignRequest(auditRequest, ephemeralKey, signatureKey);

    var auditResponse = await plainClient.SendAsync(auditRequest);
    Console.WriteLine($"← {(int)auditResponse.StatusCode}");
    Console.WriteLine();

    // Step 4: Authorize at resource with AAuth-Mission
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 4: POST /authorize with AAuth-Mission ───────────────");
    Console.ResetColor();
    Console.WriteLine($"→ POST {resourceUrl}/authorize");

    var authorizeRequest = new HttpRequestMessage(HttpMethod.Post, $"{resourceUrl}/authorize");
    authorizeRequest.Content = JsonContent.Create(new { scope = "data.read" });
    authorizeRequest.Headers.TryAddWithoutValidation("AAuth-Mission", missionHeader);
    SignRequest(authorizeRequest, ephemeralKey, signatureKey);

    var authorizeResponse = await plainClient.SendAsync(authorizeRequest);
    Console.WriteLine($"← {(int)authorizeResponse.StatusCode}");

    var authorizeBody = await authorizeResponse.Content.ReadAsStringAsync();
    var authorizeJson = JsonSerializer.Deserialize<JsonElement>(authorizeBody);
    if (!authorizeJson.TryGetProperty("resource_token", out var rtProp))
    {
        Console.WriteLine($"  ✗ No resource_token: {authorizeBody}");
        return;
    }

    var resourceTokenJwt = rtProp.GetString()!;
    var decodedRt = ResourceToken.Decode(resourceTokenJwt);
    Console.WriteLine("  ✓ Resource token issued");
    Console.WriteLine($"  aud={decodedRt.Audience} scope={decodedRt.Scope}");
    if (decodedRt.Mission is not null)
        Console.WriteLine($"  mission: approver={decodedRt.Mission.Approver}, s256={decodedRt.Mission.S256[..16]}...");
    Console.WriteLine();

    // Step 5: Exchange at PS for auth token
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 5: POST PS /token → auth token ─────────────────────");
    Console.ResetColor();
    Console.WriteLine($"→ POST {psUrl}/token");

    var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/token");
    tokenRequest.Content = JsonContent.Create(new { resource_token = resourceTokenJwt });
    SignRequest(tokenRequest, ephemeralKey, signatureKey);

    var tokenResponse = await plainClient.SendAsync(tokenRequest);
    var tokenBody = await tokenResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)tokenResponse.StatusCode}");

    var tokenJson = JsonSerializer.Deserialize<JsonElement>(tokenBody);
    if (!tokenJson.TryGetProperty("auth_token", out var atProp))
    {
        Console.WriteLine($"  ✗ No auth_token: {tokenBody}");
        return;
    }

    var authTokenJwt = atProp.GetString()!;
    var decodedAt = AuthToken.Decode(authTokenJwt);
    Console.WriteLine("  ✓ Auth token issued");
    Console.WriteLine($"  sub={decodedAt.Subject} scope={decodedAt.Scope} aud={decodedAt.Audience}");
    if (decodedAt.Mission is not null)
        Console.WriteLine($"  mission: approver={decodedAt.Mission.Approver}, s256={decodedAt.Mission.S256[..16]}...");
    Console.WriteLine();

    // Step 6: Access resource with auth token
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 6: GET /api/data with auth token ────────────────────");
    Console.ResetColor();
    Console.WriteLine($"→ GET {resourceUrl}/api/data");

    var authSignatureKey = new SignatureKeyValue.Jwt(authTokenJwt);
    var accessRequest = new HttpRequestMessage(HttpMethod.Get, $"{resourceUrl}/api/data");
    SignRequest(accessRequest, ephemeralKey, authSignatureKey);

    var accessResponse = await plainClient.SendAsync(accessRequest);
    var accessBody = await accessResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)accessResponse.StatusCode}");
    Console.WriteLine($"  {accessBody}");
    Console.WriteLine();

    // Step 7: Propose mission completion
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 7: Propose mission completion ───────────────────────");
    Console.ResetColor();
    Console.WriteLine($"→ POST {psUrl}/interaction");

    var completeRequest = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/interaction");
    completeRequest.Content = JsonContent.Create(new
    {
        type = "completion",
        summary = "# Weather Research Complete\n\nRetrieved current weather data for Tokyo: 22°C, partly cloudy with warm temperatures and occasional rain forecast.",
        mission = new { approver = mission.Approver, s256 = mission.S256 },
    });
    SignRequest(completeRequest, ephemeralKey, signatureKey);

    var completeResponse = await plainClient.SendAsync(completeRequest);
    var completeBody = await completeResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)completeResponse.StatusCode}");
    Console.WriteLine($"  {completeBody}");
    Console.WriteLine();

    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  ✓ Full mission lifecycle complete!");
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine();
    Console.WriteLine("Demo complete. Shutting down servers...");
}

// ─── Interactive mode ────────────────────────────────────────────────────────

async Task RunInteractive()
{
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  INTERACTIVE MODE — Dashboard-driven governance");
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine();
    Console.WriteLine($"  📊 Open dashboard: {psUrl}/dashboard");
    Console.WriteLine();
    Console.WriteLine("The agent proposes actions. You approve/deny via the dashboard.");
    Console.WriteLine("Tokens are stored automatically — no copy-paste needed.");
    Console.WriteLine();
    PrintHelp();
    Console.WriteLine();

    var plainClient = new HttpClient();
    var signatureKey = new SignatureKeyValue.Jwt(agentTokenJwt);
    string? currentMissionHeader = null;
    byte[]? currentMissionBodyBytes = null;
    string? lastResourceToken = null;
    string? lastAuthToken = null;

    while (true)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("aauth> ");
        Console.ResetColor();

        var input = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(input)) continue;

        var parts = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var cmd = parts[0].ToLowerInvariant();

        if (cmd is "quit" or "exit" or "q")
        {
            Console.WriteLine("Shutting down servers...");
            break;
        }

        if (cmd == "help")
        {
            PrintHelp();
            Console.WriteLine();
            continue;
        }

        if (cmd == "token")
        {
            Console.WriteLine(agentTokenJwt);
            Console.WriteLine();
            Console.WriteLine("  Copy-paste for shell:");
            Console.WriteLine($"  export AGENT_JWT='{agentTokenJwt}'");
            Console.WriteLine();
            continue;
        }

        if (cmd == "keys")
        {
            Console.WriteLine($"  Root key kid: {rootPublicJwk.Kid}");
            Console.WriteLine($"  Ephemeral thumbprint: {ephemeralThumbprint}");
            Console.WriteLine($"  Resource key kid: {resourcePublicJwk.Kid}");
            Console.WriteLine($"  PS key kid: {psPublicJwk.Kid}");
            Console.WriteLine();
            continue;
        }

        if (cmd == "signing-key")
        {
            var jwk = SerializePrivateJwk(ephemeralKey);
            Console.WriteLine(jwk);
            Console.WriteLine();
            Console.WriteLine("  Copy-paste for shell:");
            Console.WriteLine($"  export SIGNING_KEY='{jwk}'");
            Console.WriteLine();
            continue;
        }

        if (cmd == "status")
        {
            if (currentMissionHeader is not null)
            {
                var m = AAuthMissionHeader.Parse(currentMissionHeader);
                Console.WriteLine($"  Mission: approver={m.Approver} s256={m.S256[..Math.Min(20, m.S256.Length)]}...");
                if (currentMissionBodyBytes is not null)
                    Console.WriteLine($"  Stored mission bytes: {currentMissionBodyBytes.Length}");
            }
            else
            {
                Console.WriteLine("  Mission: (none — run \"mission\" first)");
            }
            Console.WriteLine(lastResourceToken is not null
                ? $"  Resource token: {lastResourceToken[..40]}..."
                : "  Resource token: (none)");
            Console.WriteLine(lastAuthToken is not null
                ? $"  Auth token: {lastAuthToken[..40]}..."
                : "  Auth token: (none)");
            Console.WriteLine();
            continue;
        }

        try
        {
            if (cmd == "mission")
            {
                var desc = parts.Length > 1
                    ? string.Join(' ', parts[1..])
                    : "# Research Weather Data\n\nSearch for current weather data for Tokyo and summarize the findings.";

                Console.WriteLine($"→ POST {psUrl}/mission");
                var request = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/mission");
                request.Content = JsonContent.Create(new
                {
                    description = desc,
                    tools = new[]
                    {
                        new { name = "WebSearch", description = "Search the web" },
                        new { name = "ReadPage", description = "Read web pages" },
                    },
                });
                SignRequest(request, ephemeralKey, signatureKey);
                var response = await plainClient.SendAsync(request);
                Console.WriteLine($"← {(int)response.StatusCode}");

                if ((int)response.StatusCode == 200)
                {
                    var approvedMission = await ReadApprovedMissionAsync(response);
                    currentMissionHeader = approvedMission.Header;
                    currentMissionBodyBytes = approvedMission.BodyBytes;
                    Console.WriteLine("  ✓ Mission approved immediately");
                    Console.WriteLine($"  AAuth-Mission: {currentMissionHeader}");
                    Console.WriteLine($"  Stored {currentMissionBodyBytes.Length} verified mission bytes");
                }
                else if ((int)response.StatusCode == 202)
                {
                    Console.WriteLine("  ⏳ Mission pending — open dashboard to approve");
                    var location = response.Headers.Location?.ToString();
                    if (location is not null)
                    {
                        var pollUrl = location.StartsWith("http") ? location : $"{psUrl}{location}";
                        Console.WriteLine($"  Polling {pollUrl}...");
                        for (var i = 0; i < 60; i++)
                        {
                            await Task.Delay(2000);
                            var pollRes = await plainClient.GetAsync(pollUrl);
                            if ((int)pollRes.StatusCode == 200)
                            {
                                var approvedMission = await ReadApprovedMissionAsync(pollRes);
                                currentMissionHeader = approvedMission.Header;
                                currentMissionBodyBytes = approvedMission.BodyBytes;
                                Console.WriteLine("  ✓ Mission approved!");
                                Console.WriteLine($"  AAuth-Mission: {currentMissionHeader}");
                                Console.WriteLine($"  Stored {currentMissionBodyBytes.Length} verified mission bytes");
                                break;
                            }
                            if (i % 5 == 4) Console.WriteLine($"  ... still waiting ({(i + 1) * 2}s)");
                        }
                    }
                }
                else
                {
                    var body = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"  {body}");
                }
            }
            else if (cmd == "permission")
            {
                var action = parts.Length > 1 ? parts[1] : "WebSearch";
                var desc = parts.Length > 2 ? string.Join(' ', parts[2..]) : (string?)null;
                object? missionObj = null;
                if (currentMissionHeader is not null)
                {
                    var m = AAuthMissionHeader.Parse(currentMissionHeader);
                    missionObj = new { approver = m.Approver, s256 = m.S256 };
                }

                Console.WriteLine($"→ POST {psUrl}/permission");
                var request = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/permission");
                request.Content = JsonContent.Create(new { action, description = desc, mission = missionObj });
                SignRequest(request, ephemeralKey, signatureKey);
                var response = await plainClient.SendAsync(request);

                if ((int)response.StatusCode == 200)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"← {(int)response.StatusCode}");
                    Console.WriteLine($"  {body}");
                }
                else if ((int)response.StatusCode == 202)
                {
                    Console.WriteLine("← 202");
                    Console.WriteLine("  ⏳ Permission pending — approve via dashboard");
                    var location = response.Headers.Location?.ToString();
                    if (location is not null)
                    {
                        var pollUrl = location.StartsWith("http") ? location : $"{psUrl}{location}";
                        for (var i = 0; i < 30; i++)
                        {
                            await Task.Delay(2000);
                            var pollRes = await plainClient.GetAsync(pollUrl);
                            if ((int)pollRes.StatusCode == 200)
                            {
                                var body = await pollRes.Content.ReadAsStringAsync();
                                Console.WriteLine($"  ✓ {body}");
                                break;
                            }
                            if (i % 5 == 4) Console.WriteLine("  ... still waiting");
                        }
                    }
                }
                else
                {
                    var body = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"← {(int)response.StatusCode} {body}");
                }
            }
            else if (cmd == "audit")
            {
                if (currentMissionHeader is null)
                {
                    Console.WriteLine("  No active mission — run \"mission\" first");
                    Console.WriteLine();
                    continue;
                }

                var action = parts.Length > 1 ? parts[1] : "WebSearch";
                var desc = parts.Length > 2 ? string.Join(' ', parts[2..]) : "Performed action";
                var m = AAuthMissionHeader.Parse(currentMissionHeader);

                Console.WriteLine($"→ POST {psUrl}/audit");
                var request = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/audit");
                request.Content = JsonContent.Create(new
                {
                    mission = new { approver = m.Approver, s256 = m.S256 },
                    action,
                    description = desc,
                    result = new { status = "completed" },
                });
                SignRequest(request, ephemeralKey, signatureKey);
                var response = await plainClient.SendAsync(request);
                Console.WriteLine($"← {(int)response.StatusCode}");
            }
            else if (cmd == "authorize")
            {
                var scope = parts.Length > 1 ? string.Join(' ', parts[1..]) : "data.read";
                var request = new HttpRequestMessage(HttpMethod.Post, $"{resourceUrl}/authorize");
                request.Content = JsonContent.Create(new { scope });
                if (currentMissionHeader is not null)
                    request.Headers.TryAddWithoutValidation("AAuth-Mission", currentMissionHeader);

                Console.WriteLine($"→ POST {resourceUrl}/authorize (scope: {scope}){(currentMissionHeader is not null ? " + AAuth-Mission" : "")}");
                SignRequest(request, ephemeralKey, signatureKey);
                var response = await plainClient.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"← {(int)response.StatusCode}");

                var json = JsonSerializer.Deserialize<JsonElement>(body);
                if (json.TryGetProperty("resource_token", out var rt))
                {
                    lastResourceToken = rt.GetString()!;
                    var decoded = ResourceToken.Decode(lastResourceToken);
                    Console.WriteLine("  ✓ Resource token stored");
                    Console.WriteLine($"  aud={decoded.Audience} scope={decoded.Scope}");
                    if (decoded.Mission is not null)
                        Console.WriteLine($"  mission: approver={decoded.Mission.Approver}, s256={decoded.Mission.S256[..16]}...");
                    Console.WriteLine("  → Next: \"exchange\"");
                }
                else
                {
                    Console.WriteLine($"  {body}");
                }
            }
            else if (cmd == "exchange")
            {
                if (lastResourceToken is null)
                {
                    Console.WriteLine("  No resource token — run \"authorize\" first");
                    Console.WriteLine();
                    continue;
                }

                Console.WriteLine($"→ POST {psUrl}/token");
                var request = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/token");
                request.Content = JsonContent.Create(new { resource_token = lastResourceToken });
                SignRequest(request, ephemeralKey, signatureKey);
                var response = await plainClient.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"← {(int)response.StatusCode}");

                var json = JsonSerializer.Deserialize<JsonElement>(body);
                if (json.TryGetProperty("auth_token", out var at))
                {
                    lastAuthToken = at.GetString()!;
                    var decoded = AuthToken.Decode(lastAuthToken);
                    Console.WriteLine("  ✓ Auth token stored");
                    Console.WriteLine($"  sub={decoded.Subject} scope={decoded.Scope} aud={decoded.Audience}");
                    if (decoded.Mission is not null)
                        Console.WriteLine($"  mission: approver={decoded.Mission.Approver}, s256={decoded.Mission.S256[..16]}...");
                    Console.WriteLine("  → Next: \"access\"");
                }
                else
                {
                    Console.WriteLine($"  {body}");
                }
            }
            else if (cmd == "access")
            {
                if (lastAuthToken is null)
                {
                    Console.WriteLine("  No auth token — run \"authorize\" then \"exchange\" first");
                    Console.WriteLine();
                    continue;
                }

                Console.WriteLine($"→ GET {resourceUrl}/api/data (with auth token)");
                var authSigKey = new SignatureKeyValue.Jwt(lastAuthToken);
                var request = new HttpRequestMessage(HttpMethod.Get, $"{resourceUrl}/api/data");
                SignRequest(request, ephemeralKey, authSigKey);
                var response = await plainClient.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"← {(int)response.StatusCode}");
                Console.WriteLine($"  {body}");
            }
            else if (cmd == "complete")
            {
                if (currentMissionHeader is null)
                {
                    Console.WriteLine("  No active mission — run \"mission\" first");
                    Console.WriteLine();
                    continue;
                }

                var summary = parts.Length > 1
                    ? string.Join(' ', parts[1..])
                    : "# Research Complete\n\nWeather data retrieved and summarized successfully.";
                var m = AAuthMissionHeader.Parse(currentMissionHeader);

                Console.WriteLine($"→ POST {psUrl}/interaction (type=completion)");
                var request = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/interaction");
                request.Content = JsonContent.Create(new
                {
                    type = "completion",
                    summary,
                    mission = new { approver = m.Approver, s256 = m.S256 },
                });
                SignRequest(request, ephemeralKey, signatureKey);
                var response = await plainClient.SendAsync(request);

                if ((int)response.StatusCode == 200)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    Console.WriteLine("← 200");
                    Console.WriteLine($"  ✓ Mission completed: {body}");
                    currentMissionHeader = null;
                    currentMissionBodyBytes = null;
                }
                else if ((int)response.StatusCode == 202)
                {
                    Console.WriteLine("← 202");
                    Console.WriteLine("  ⏳ Completion pending — accept via dashboard");
                    var location = response.Headers.Location?.ToString();
                    if (location is not null)
                    {
                        var pollUrl = location.StartsWith("http") ? location : $"{psUrl}{location}";
                        for (var i = 0; i < 30; i++)
                        {
                            await Task.Delay(2000);
                            var pollRes = await plainClient.GetAsync(pollUrl);
                            if ((int)pollRes.StatusCode == 200)
                            {
                                Console.WriteLine("  ✓ Mission completed!");
                                currentMissionHeader = null;
                                currentMissionBodyBytes = null;
                                break;
                            }
                            if (i % 5 == 4) Console.WriteLine("  ... still waiting");
                        }
                    }
                }
                else
                {
                    var body = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"← {(int)response.StatusCode} {body}");
                }
            }
            else if (cmd == "flow")
            {
                if (currentMissionHeader is null)
                    Console.WriteLine("  No active mission — run \"mission\" first for full governance flow");

                var scope = parts.Length > 1 ? string.Join(' ', parts[1..]) : "data.read";
                Console.WriteLine("Running authorize → exchange → access...");
                Console.WriteLine();

                // Step 1: Authorize
                var authzReq = new HttpRequestMessage(HttpMethod.Post, $"{resourceUrl}/authorize");
                authzReq.Content = JsonContent.Create(new { scope });
                if (currentMissionHeader is not null)
                    authzReq.Headers.TryAddWithoutValidation("AAuth-Mission", currentMissionHeader);
                Console.WriteLine($"1. POST /authorize (scope: \"{scope}\")");
                SignRequest(authzReq, ephemeralKey, signatureKey);
                var authzRes = await plainClient.SendAsync(authzReq);
                var authzBody = await authzRes.Content.ReadAsStringAsync();
                var authzJson = JsonSerializer.Deserialize<JsonElement>(authzBody);
                if (!authzJson.TryGetProperty("resource_token", out var rt2))
                {
                    Console.WriteLine($"   ✗ No resource token: {authzBody}");
                    Console.WriteLine();
                    continue;
                }
                lastResourceToken = rt2.GetString()!;
                Console.WriteLine("   ✓ Got resource token");

                // Step 2: Exchange
                Console.WriteLine("2. POST PS /token");
                var tokReq = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/token");
                tokReq.Content = JsonContent.Create(new { resource_token = lastResourceToken });
                SignRequest(tokReq, ephemeralKey, signatureKey);
                var tokRes = await plainClient.SendAsync(tokReq);
                var tokBody = await tokRes.Content.ReadAsStringAsync();
                var tokJson = JsonSerializer.Deserialize<JsonElement>(tokBody);
                if (!tokJson.TryGetProperty("auth_token", out var at2))
                {
                    Console.WriteLine($"   ✗ No auth token: {tokBody}");
                    Console.WriteLine();
                    continue;
                }
                lastAuthToken = at2.GetString()!;
                var atClaims = AuthToken.Decode(lastAuthToken);
                Console.WriteLine($"   ✓ Got auth token (sub={atClaims.Subject}, scope={atClaims.Scope})");

                // Step 3: Access
                Console.WriteLine("3. GET /api/data");
                var authFetchKey = new SignatureKeyValue.Jwt(lastAuthToken);
                var dataReq = new HttpRequestMessage(HttpMethod.Get, $"{resourceUrl}/api/data");
                SignRequest(dataReq, ephemeralKey, authFetchKey);
                var dataRes = await plainClient.SendAsync(dataReq);
                var dataBody = await dataRes.Content.ReadAsStringAsync();
                Console.WriteLine($"   ← {(int)dataRes.StatusCode}");
                Console.WriteLine($"   {dataBody}");
            }
            else
            {
                Console.WriteLine("Unknown command. Type \"help\" for options.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }

        Console.WriteLine();
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

void PrintHelp()
{
    Console.WriteLine("Commands:");
    Console.WriteLine("  mission [desc]     Propose a mission (default: weather research)");
    Console.WriteLine("  permission <act>   Request permission for an action");
    Console.WriteLine("  audit <act> [desc] Log an audit record (requires active mission)");
    Console.WriteLine("  authorize [scope]  POST /authorize → resource token (default: data.read)");
    Console.WriteLine("  exchange           Exchange resource token at PS → auth token");
    Console.WriteLine("  access             GET /api/data with auth token");
    Console.WriteLine("  complete [summary] Propose mission completion");
    Console.WriteLine("  flow [scope]       Full flow: authorize → exchange → access");
    Console.WriteLine("  token              Print the full agent token (JWT)");
    Console.WriteLine("  signing-key        Print the ephemeral private key (JWK, for SignTool)");
    Console.WriteLine("  keys               Print all public key identifiers");
    Console.WriteLine("  status             Show current mission and token state");
    Console.WriteLine("  help               Show commands");
    Console.WriteLine("  quit               Shut down");
}

string SerializePrivateJwk(ECDsa key)
{
    var parameters = key.ExportParameters(true);
    var dict = new Dictionary<string, string>
    {
        ["kty"] = "EC",
        ["crv"] = "P-256",
        ["x"] = Base64UrlEncoder.Encode(parameters.Q.X!),
        ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y!),
        ["d"] = Base64UrlEncoder.Encode(parameters.D!)
    };
    return System.Text.Json.JsonSerializer.Serialize(dict);
}

void SignRequest(HttpRequestMessage request, AsymmetricAlgorithm signingKey, SignatureKeyValue signatureKey)
{
    var additionalComponents = request.Headers.Contains("AAuth-Mission")
        ? new[] { "aauth-mission" }
        : null;

    HttpMessageSigner.Sign(request, signingKey, signatureKey, additionalComponents);
}

async Task<(string Header, AAuth.Core.Tokens.Mission Mission, byte[] BodyBytes)> ReadApprovedMissionAsync(HttpResponseMessage response)
{
    var missionHeader = response.Headers.TryGetValues("AAuth-Mission", out var values)
        ? values.FirstOrDefault()
        : null;

    if (missionHeader is null)
        throw new InvalidOperationException("No AAuth-Mission header — mission not approved");

    var bodyBytes = await response.Content.ReadAsByteArrayAsync();
    var mission = AAuthMissionHeader.Parse(missionHeader);
    var computedS256 = Base64UrlEncoder.Encode(SHA256.HashData(bodyBytes));

    if (!string.Equals(computedS256, mission.S256, StringComparison.Ordinal))
        throw new InvalidOperationException($"Mission hash mismatch: header={mission.S256} body={computedS256}");

    return (missionHeader, mission, bodyBytes);
}
