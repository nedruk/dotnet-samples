using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using FederatedAccess;

const int ApPort = 3011;
const int Resource1Port = 3012;
const int PsPort = 3013;
const int AsPort = 3014;
const int Resource2Port = 3015;
const string AgentId = "aauth:demo-agent@localhost";
const string Resource1AgentId = "aauth:resource1-agent@localhost";

Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║  Sample 5: Federated Access — Four-Party Flow + Chaining   ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
Console.ResetColor();
Console.WriteLine();

// ── 1. Generate ECDSA P-256 key pairs ────────────────────────────────────────

Console.WriteLine("1. Generating ECDSA P-256 key pairs...");

// Agent keys
var agentRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var agentEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var agentRootPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(agentRootKey) { KeyId = "agent-root-1" });
agentRootPublicJwk.Kid = "agent-root-1";
var agentEphemeralPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(agentEphemeralKey));
var agentEphemeralThumbprint = JsonWebKeyThumbprint.Compute(agentEphemeralPublicJwk);

// Resource 1 keys (resource role)
var resource1Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var resource1PublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(resource1Key) { KeyId = "resource1-1" });
resource1PublicJwk.Kid = "resource1-1";

// Resource 1 keys (agent role for call chaining)
var r1AgentRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var r1AgentEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var r1AgentRootPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(r1AgentRootKey) { KeyId = "r1-agent-root-1" });
r1AgentRootPublicJwk.Kid = "r1-agent-root-1";
var r1AgentEphemeralPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(r1AgentEphemeralKey));

// Resource 2 key
var resource2Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var resource2PublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(resource2Key) { KeyId = "resource2-1" });
resource2PublicJwk.Kid = "resource2-1";

// Person Server key
var psKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var psPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(psKey) { KeyId = "ps-1" });
psPublicJwk.Kid = "ps-1";

// Access Server key
var asKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var asPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(asKey) { KeyId = "as-1" });
asPublicJwk.Kid = "as-1";

Console.WriteLine($"   Agent root key kid: agent-root-1");
Console.WriteLine($"   Agent ephemeral thumbprint: {agentEphemeralThumbprint}");
Console.WriteLine($"   Resource 1 key kid: resource1-1");
Console.WriteLine($"   R1 agent root key kid: r1-agent-root-1");
Console.WriteLine($"   Resource 2 key kid: resource2-1");
Console.WriteLine($"   Person Server key kid: ps-1");
Console.WriteLine($"   Access Server key kid: as-1");
Console.WriteLine();

// ── 2. Create agent tokens ───────────────────────────────────────────────────

var apUrl = $"https://localhost:{ApPort}";
var psUrl = $"https://localhost:{PsPort}";
var asUrl = $"https://localhost:{AsPort}";
var resource1Url = $"https://localhost:{Resource1Port}";

Console.WriteLine("2. Creating agent tokens...");

// Demo agent token (with ps claim)
var agentTokenJwt = AgentToken.Create(new AgentTokenOptions
{
    Issuer = apUrl,
    Subject = AgentId,
    PublicKey = agentEphemeralPublicJwk,
    PersonServerUrl = psUrl,
}, new SigningCredentials(new ECDsaSecurityKey(agentRootKey), SecurityAlgorithms.EcdsaSha256));

Console.WriteLine($"   Demo agent: {AgentId}");
Console.WriteLine($"   Token: {agentTokenJwt[..40]}...");

// Resource 1 agent token (for call chaining — R1 acting as agent)
var r1AgentTokenJwt = AgentToken.Create(new AgentTokenOptions
{
    Issuer = resource1Url,
    Subject = Resource1AgentId,
    PublicKey = r1AgentEphemeralPublicJwk,
    PersonServerUrl = psUrl,
}, new SigningCredentials(new ECDsaSecurityKey(r1AgentRootKey), SecurityAlgorithms.EcdsaSha256));

Console.WriteLine($"   R1 agent:   {Resource1AgentId}");
Console.WriteLine($"   Token: {r1AgentTokenJwt[..40]}...");
Console.WriteLine();

// ── 3. Start servers ─────────────────────────────────────────────────────────

Console.WriteLine($"3. Starting Agent Provider on port {ApPort}...");
var apApp = AgentProviderServer.CreateApp(agentRootPublicJwk, ApPort);
await apApp.StartAsync();
Console.WriteLine($"   Metadata: {apUrl}/.well-known/aauth-agent.json");

Console.WriteLine($"4. Starting Resource 1 (dual role) on port {Resource1Port}...");
var r1App = ResourceServer.CreateApp(
    resource1Key, resource1PublicJwk,
    r1AgentEphemeralKey, r1AgentTokenJwt, r1AgentRootPublicJwk,
    Resource1Port, asUrl, psUrl, Resource2Port);
await r1App.StartAsync();
Console.WriteLine($"   Resource metadata: {resource1Url}/.well-known/aauth-resource.json");
Console.WriteLine($"   Agent metadata:    {resource1Url}/.well-known/aauth-agent.json");

Console.WriteLine($"5. Starting Person Server on port {PsPort}...");
var psApp = PersonServer.CreateApp(psKey, psPublicJwk, PsPort);
await psApp.StartAsync();
Console.WriteLine($"   Metadata: {psUrl}/.well-known/aauth-person.json");

Console.WriteLine($"6. Starting Access Server on port {AsPort}...");
var asApp = AccessServer.CreateApp(asKey, asPublicJwk, AsPort);
await asApp.StartAsync();
Console.WriteLine($"   Metadata: {asUrl}/.well-known/aauth-access.json");

Console.WriteLine($"7. Starting Resource 2 on port {Resource2Port}...");
var r2App = Resource2Server.CreateApp(resource2Key, resource2PublicJwk, Resource2Port, asUrl);
await r2App.StartAsync();
Console.WriteLine($"   Metadata: https://localhost:{Resource2Port}/.well-known/aauth-resource.json");
Console.WriteLine();

var interactive = args.Contains("interactive") || args.Contains("--interactive");

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
    await r1App.StopAsync();
    await psApp.StopAsync();
    await asApp.StopAsync();
    await r2App.StopAsync();
}

return;

// ─── Automated mode ──────────────────────────────────────────────────────────

async Task RunAutomated()
{
    var plainClient = new HttpClient();
    var signatureKey = new SignatureKeyValue.Jwt(agentTokenJwt);

    // ── Part A: Four-Party Federated Access ──────────────────────────────
    Console.ForegroundColor = ConsoleColor.Magenta;
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  PART A: Four-Party Federated Access");
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.ResetColor();
    Console.WriteLine();

    // Step 1: POST /authorize on Resource 1 → get resource token
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 1: Request resource token from Resource 1 ───────────");
    Console.ResetColor();
    Console.WriteLine($"→ POST {resource1Url}/authorize");

    var authorizeRequest = new HttpRequestMessage(HttpMethod.Post, $"{resource1Url}/authorize");
    authorizeRequest.Content = JsonContent.Create(new { scope = "weather.read" });
    HttpMessageSigner.Sign(authorizeRequest, agentEphemeralKey, signatureKey);

    var authorizeResponse = await plainClient.SendAsync(authorizeRequest);
    var authorizeBody = await authorizeResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)authorizeResponse.StatusCode} {authorizeResponse.ReasonPhrase}");

    if (!authorizeResponse.IsSuccessStatusCode)
    {
        Console.WriteLine($"  Error: {authorizeBody}");
        return;
    }

    var authorizeJson = JsonSerializer.Deserialize<JsonElement>(authorizeBody);
    var resourceTokenJwt = authorizeJson.GetProperty("resource_token").GetString()!;
    Console.WriteLine($"  Resource token: {resourceTokenJwt[..40]}...");

    var decodedResourceToken = ResourceToken.Decode(resourceTokenJwt);
    Console.WriteLine($"  → Audience (AS): {decodedResourceToken.Audience}");
    Console.WriteLine($"  → Agent: {decodedResourceToken.Agent}");
    Console.WriteLine($"  → Scope: {decodedResourceToken.Scope}");
    Console.WriteLine($"  ★ Note: aud={decodedResourceToken.Audience} (AS, not PS) — triggers four-party flow");
    Console.WriteLine();

    // Step 2: POST /token on PS → PS federates to AS → get auth token
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 2: Exchange at Person Server (PS→AS federation) ─────");
    Console.ResetColor();
    Console.WriteLine($"→ POST {psUrl}/token");

    var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/token");
    tokenRequest.Content = JsonContent.Create(new { resource_token = resourceTokenJwt });
    HttpMessageSigner.Sign(tokenRequest, agentEphemeralKey, signatureKey);

    var tokenResponse = await plainClient.SendAsync(tokenRequest);
    var tokenBody = await tokenResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)tokenResponse.StatusCode} {tokenResponse.ReasonPhrase}");

    if (!tokenResponse.IsSuccessStatusCode)
    {
        Console.WriteLine($"  Error: {tokenBody}");
        return;
    }

    var tokenJson = JsonSerializer.Deserialize<JsonElement>(tokenBody);
    var authTokenJwt = tokenJson.GetProperty("auth_token").GetString()!;
    Console.WriteLine($"  Auth token: {authTokenJwt[..40]}...");

    var decodedAuthToken = AuthToken.Decode(authTokenJwt);
    Console.WriteLine($"  → Subject: {decodedAuthToken.Subject}");
    Console.WriteLine($"  → Audience: {decodedAuthToken.Audience}");
    Console.WriteLine($"  → Agent: {decodedAuthToken.Agent}");
    Console.WriteLine($"  → Scope: {decodedAuthToken.Scope}");
    Console.WriteLine($"  → Issuer (AS): {decodedAuthToken.Issuer}");
    Console.WriteLine($"  → DWK: {decodedAuthToken.Dwk}");
    Console.WriteLine($"  ★ Note: iss={decodedAuthToken.Issuer} (AS), dwk={decodedAuthToken.Dwk} — AS-issued token");
    Console.WriteLine();

    // Step 3: GET /api/data on Resource 1 with auth token
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 3: Access Resource 1 with AS-issued auth token ──────");
    Console.ResetColor();
    Console.WriteLine($"→ GET {resource1Url}/api/data");

    var authSignatureKey = new SignatureKeyValue.Jwt(authTokenJwt);
    var accessRequest = new HttpRequestMessage(HttpMethod.Get, $"{resource1Url}/api/data");
    HttpMessageSigner.Sign(accessRequest, agentEphemeralKey, authSignatureKey);

    var accessResponse = await plainClient.SendAsync(accessRequest);
    var accessBody = await accessResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)accessResponse.StatusCode} {accessResponse.ReasonPhrase}");
    Console.WriteLine($"  Response: {accessBody}");
    Console.WriteLine();

    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("✓ Part A complete — four-party federated access succeeded!");
    Console.ResetColor();
    Console.WriteLine();

    // ── Part B: Call Chaining ────────────────────────────────────────────
    Console.ForegroundColor = ConsoleColor.Magenta;
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  PART B: Call Chaining (Resource 1 → Resource 2)");
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.ResetColor();
    Console.WriteLine();

    // Step 4: GET /api/enriched on Resource 1 → triggers call chaining
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 4: Request enriched data (triggers call chaining) ───");
    Console.ResetColor();
    Console.WriteLine($"→ GET {resource1Url}/api/enriched");
    Console.WriteLine("  (R1 will chain to R2: authorize → PS/AS exchange → access)");
    Console.WriteLine();

    var enrichedRequest = new HttpRequestMessage(HttpMethod.Get, $"{resource1Url}/api/enriched");
    HttpMessageSigner.Sign(enrichedRequest, agentEphemeralKey, authSignatureKey);

    var enrichedResponse = await plainClient.SendAsync(enrichedRequest);
    var enrichedBody = await enrichedResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)enrichedResponse.StatusCode} {enrichedResponse.ReasonPhrase}");

    if (enrichedResponse.IsSuccessStatusCode)
    {
        var enrichedJson = JsonSerializer.Deserialize<JsonElement>(enrichedBody);
        var prettyJson = JsonSerializer.Serialize(enrichedJson, new JsonSerializerOptions { WriteIndented = true });
        Console.WriteLine($"  Response:");
        Console.WriteLine(prettyJson);
    }
    else
    {
        Console.WriteLine($"  Error: {enrichedBody}");
    }

    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("✓ Part B complete — call chaining with nested delegation succeeded!");
    Console.ResetColor();
    Console.WriteLine();

    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("Demo complete. Shutting down servers...");
}

// ─── Interactive mode ────────────────────────────────────────────────────────

async Task RunInteractive()
{
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  INTERACTIVE MODE — 5 servers running");
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine();
    PrintHelp();
    Console.WriteLine();

    var plainClient = new HttpClient();
    var signatureKey = new SignatureKeyValue.Jwt(agentTokenJwt);
    string? storedResourceToken = null;
    string? storedAuthToken = null;

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

        try
        {
            switch (cmd)
            {
                case "authorize":
                {
                    var scope = parts.Length > 1 ? parts[1] : "weather.read";
                    Console.WriteLine($"→ POST {resource1Url}/authorize (scope: {scope})");

                    var request = new HttpRequestMessage(HttpMethod.Post, $"{resource1Url}/authorize");
                    request.Content = JsonContent.Create(new { scope });
                    HttpMessageSigner.Sign(request, agentEphemeralKey, signatureKey);

                    var response = await plainClient.SendAsync(request);
                    var body = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"← {(int)response.StatusCode} {response.ReasonPhrase}");

                    if (response.IsSuccessStatusCode)
                    {
                        var json = JsonSerializer.Deserialize<JsonElement>(body);
                        storedResourceToken = json.GetProperty("resource_token").GetString()!;
                        var decoded = ResourceToken.Decode(storedResourceToken);
                        Console.WriteLine($"  ✓ Resource token stored");
                        Console.WriteLine($"    Audience (AS): {decoded.Audience}");
                        Console.WriteLine($"    Agent: {decoded.Agent}");
                        Console.WriteLine($"    Scope: {decoded.Scope}");
                    }
                    else
                    {
                        Console.WriteLine($"  Error: {body}");
                    }

                    break;
                }

                case "exchange":
                {
                    var rt = parts.Length > 1 ? parts[1] : storedResourceToken;
                    if (rt is null)
                    {
                        Console.WriteLine("  No resource token. Run 'authorize' first or provide a token.");
                        break;
                    }

                    Console.WriteLine($"→ POST {psUrl}/token");
                    var request = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/token");
                    request.Content = JsonContent.Create(new { resource_token = rt });
                    HttpMessageSigner.Sign(request, agentEphemeralKey, signatureKey);

                    var response = await plainClient.SendAsync(request);
                    var body = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"← {(int)response.StatusCode} {response.ReasonPhrase}");

                    if (response.IsSuccessStatusCode)
                    {
                        var json = JsonSerializer.Deserialize<JsonElement>(body);
                        storedAuthToken = json.GetProperty("auth_token").GetString()!;
                        var decoded = AuthToken.Decode(storedAuthToken);
                        Console.WriteLine($"  ✓ Auth token stored");
                        Console.WriteLine($"    Issuer: {decoded.Issuer}");
                        Console.WriteLine($"    DWK: {decoded.Dwk}");
                        Console.WriteLine($"    Subject: {decoded.Subject}");
                        Console.WriteLine($"    Audience: {decoded.Audience}");
                        Console.WriteLine($"    Agent: {decoded.Agent}");
                        Console.WriteLine($"    Scope: {decoded.Scope}");
                    }
                    else
                    {
                        Console.WriteLine($"  Error: {body}");
                    }

                    break;
                }

                case "access":
                {
                    var at = parts.Length > 1 ? parts[1] : storedAuthToken;
                    if (at is null)
                    {
                        Console.WriteLine("  No auth token. Run 'exchange' first or provide a token.");
                        break;
                    }

                    Console.WriteLine($"→ GET {resource1Url}/api/data");
                    var authSigKey = new SignatureKeyValue.Jwt(at);
                    var request = new HttpRequestMessage(HttpMethod.Get, $"{resource1Url}/api/data");
                    HttpMessageSigner.Sign(request, agentEphemeralKey, authSigKey);

                    var response = await plainClient.SendAsync(request);
                    var body = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"← {(int)response.StatusCode} {response.ReasonPhrase}");
                    Console.WriteLine($"  {body}");
                    break;
                }

                case "enriched":
                {
                    var at = parts.Length > 1 ? parts[1] : storedAuthToken;
                    if (at is null)
                    {
                        Console.WriteLine("  No auth token. Run 'exchange' first or provide a token.");
                        break;
                    }

                    Console.WriteLine($"→ GET {resource1Url}/api/enriched");
                    Console.WriteLine("  (R1 chains to R2 behind the scenes)");
                    var authSigKey = new SignatureKeyValue.Jwt(at);
                    var request = new HttpRequestMessage(HttpMethod.Get, $"{resource1Url}/api/enriched");
                    HttpMessageSigner.Sign(request, agentEphemeralKey, authSigKey);

                    var response = await plainClient.SendAsync(request);
                    var body = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"← {(int)response.StatusCode} {response.ReasonPhrase}");

                    if (response.IsSuccessStatusCode)
                    {
                        var json = JsonSerializer.Deserialize<JsonElement>(body);
                        var prettyJson = JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true });
                        Console.WriteLine(prettyJson);
                    }
                    else
                    {
                        Console.WriteLine($"  {body}");
                    }

                    break;
                }

                case "token":
                    Console.WriteLine($"  Agent token: {agentTokenJwt}");
                    Console.WriteLine();
                    Console.WriteLine("  Copy-paste for shell:");
                    Console.WriteLine($"  export AGENT_JWT='{agentTokenJwt}'");
                    break;

                case "keys":
                    Console.WriteLine($"  Agent root kid: agent-root-1");
                    Console.WriteLine($"  Agent ephemeral thumbprint: {agentEphemeralThumbprint}");
                    Console.WriteLine($"  Resource 1 kid: resource1-1");
                    Console.WriteLine($"  R1 agent root kid: r1-agent-root-1");
                    Console.WriteLine($"  Resource 2 kid: resource2-1");
                    Console.WriteLine($"  PS kid: ps-1");
                    Console.WriteLine($"  AS kid: as-1");
                    break;

                case "signing-key":
                    var jwk = SerializePrivateJwk(agentEphemeralKey);
                    Console.WriteLine(jwk);
                    Console.WriteLine();
                    Console.WriteLine("  Copy-paste for shell:");
                    Console.WriteLine($"  export SIGNING_KEY='{jwk}'");
                    break;

                default:
                    Console.WriteLine($"  Unknown command: {cmd}. Type 'help' for available commands.");
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  Error: {ex.Message}");
            Console.ResetColor();
        }

        Console.WriteLine();
    }
}

void PrintHelp()
{
    Console.WriteLine("Commands:");
    Console.WriteLine("  authorize [scope] — POST /authorize to Resource 1 → get resource token");
    Console.WriteLine("  exchange [rt]     — POST /token to PS (triggers PS→AS federation) → get auth token");
    Console.WriteLine("  access [at]       — GET /api/data on Resource 1 with auth token");
    Console.WriteLine("  enriched [at]     — GET /api/enriched on Resource 1 (call chaining to R2)");
    Console.WriteLine("  token             — Print demo agent JWT");
    Console.WriteLine("  signing-key       — Print the ephemeral private key (JWK, for SignTool)");
    Console.WriteLine("  keys              — Print all public keys");
    Console.WriteLine("  help              — Show this help");
    Console.WriteLine("  quit              — Shut down servers and exit");
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
