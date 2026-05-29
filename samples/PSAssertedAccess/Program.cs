using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using PSAssertedAccess;

const int ResourcePort = 3012;
const int PsPort = 3013;
const int ApPort = 3011;
const string AgentId = "aauth:demo-agent@localhost";
var validationClockSkew = TimeSpan.FromMinutes(5);

Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║  Sample 3: PS-Asserted Access — Three-Party Flow           ║");
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

// 2. Create agent token (with ps claim pointing to Person Server)
var apUrl = $"https://localhost:{ApPort}";
var psUrl = $"https://localhost:{PsPort}";
Console.WriteLine("2. Creating self-signed agent token (with ps claim)...");
var rootSigningKey = new ECDsaSecurityKey(rootKey) { KeyId = rootPublicJwk.Kid };
var agentTokenJwt = AgentToken.Create(new AgentTokenOptions
{
    Issuer = apUrl,
    Subject = AgentId,
    PublicKey = ephemeralPublicJwk,
    PersonServerUrl = psUrl,
}, new SigningCredentials(rootSigningKey, SecurityAlgorithms.EcdsaSha256));

Console.WriteLine($"   Agent ID: {AgentId}");
Console.WriteLine($"   Issuer (AP): {apUrl}");
Console.WriteLine($"   Person Server: {psUrl}");
Console.WriteLine($"   Token: {agentTokenJwt[..40]}...");
Console.WriteLine();

// 3. Start servers
Console.WriteLine($"3. Starting Agent Provider on port {ApPort}...");
var apApp = AgentProviderServer.CreateApp(rootPublicJwk, ApPort);
await apApp.StartAsync();
Console.WriteLine($"   Metadata: {apUrl}/.well-known/aauth-agent.json");
Console.WriteLine();

Console.WriteLine($"4. Starting Resource Server on port {ResourcePort}...");
var resourceApp = ResourceServer.CreateApp(resourceKey, resourcePublicJwk, ResourcePort);
await resourceApp.StartAsync();
Console.WriteLine($"   Metadata: https://localhost:{ResourcePort}/.well-known/aauth-resource.json");
Console.WriteLine($"   API:      https://localhost:{ResourcePort}/api/documents");
Console.WriteLine();

Console.WriteLine($"5. Starting Person Server on port {PsPort}...");
var psApp = PersonServer.CreateApp(psKey, psPublicJwk, PsPort);
await psApp.StartAsync();
Console.WriteLine($"   Metadata: {psUrl}/.well-known/aauth-person.json");
Console.WriteLine($"   Token:    {psUrl}/token");
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
    await resourceApp.StopAsync();
    await psApp.StopAsync();
}

return;

// ─── Automated mode ──────────────────────────────────────────────────────────

async Task RunAutomated()
{
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  AUTOMATED MODE — Full three-party flow");
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine();

    var plainClient = new HttpClient();
    var signatureKey = new SignatureKeyValue.Jwt(agentTokenJwt);

    // Step 1: POST /authorize → get resource token
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 1: Request resource token from Resource Server ──────");
    Console.ResetColor();
    Console.WriteLine($"→ POST https://localhost:{ResourcePort}/authorize");

    var authorizeRequest = new HttpRequestMessage(HttpMethod.Post, $"https://localhost:{ResourcePort}/authorize");
    authorizeRequest.Content = JsonContent.Create(new { scope = "data.read" });
    HttpMessageSigner.Sign(authorizeRequest, ephemeralKey, signatureKey);

    var authorizeResponse = await plainClient.SendAsync(authorizeRequest);
    var authorizeBody = await authorizeResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)authorizeResponse.StatusCode} {authorizeResponse.ReasonPhrase}");

    if ((int)authorizeResponse.StatusCode != 200)
    {
        Console.WriteLine($"  Error: {authorizeBody}");
        return;
    }

    var authorizeJson = JsonSerializer.Deserialize<JsonElement>(authorizeBody);
    var resourceTokenJwt = authorizeJson.GetProperty("resource_token").GetString()!;
    Console.WriteLine($"  Resource token: {resourceTokenJwt[..40]}...");

    await JwtValidationHelpers.ValidateJwtSignatureAsync(resourceTokenJwt, resourcePublicJwk, $"https://localhost:{ResourcePort}", "aa-resource+jwt", validationClockSkew);
    var decodedResourceToken = ResourceToken.Decode(resourceTokenJwt);
    Console.WriteLine($"  → Audience (PS): {decodedResourceToken.Audience}");
    Console.WriteLine($"  → Agent: {decodedResourceToken.Agent}");
    Console.WriteLine($"  → Scope: {decodedResourceToken.Scope}");
    Console.WriteLine();

    // Step 2: POST /token on PS → get auth token
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 2: Exchange resource token at Person Server ─────────");
    Console.ResetColor();
    Console.WriteLine($"→ POST {psUrl}/token");

    var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/token");
    tokenRequest.Content = JsonContent.Create(new { resource_token = resourceTokenJwt });
    HttpMessageSigner.Sign(tokenRequest, ephemeralKey, signatureKey);

    var tokenResponse = await plainClient.SendAsync(tokenRequest);
    var tokenBody = await tokenResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)tokenResponse.StatusCode} {tokenResponse.ReasonPhrase}");

    if ((int)tokenResponse.StatusCode != 200)
    {
        Console.WriteLine($"  Error: {tokenBody}");
        return;
    }

    var tokenJson = JsonSerializer.Deserialize<JsonElement>(tokenBody);
    var authTokenJwt = tokenJson.GetProperty("auth_token").GetString()!;
    Console.WriteLine($"  Auth token: {authTokenJwt[..40]}...");

    // Production code must verify the JWT signature against the issuer's JWKS before calling Decode().
    await JwtValidationHelpers.ValidateJwtSignatureAsync(authTokenJwt, psPublicJwk, psUrl, "aa-auth+jwt", validationClockSkew);
    var decodedAuthToken = AuthToken.Decode(authTokenJwt);
    Console.WriteLine($"  → Subject: {decodedAuthToken.Subject}");
    Console.WriteLine($"  → Audience: {decodedAuthToken.Audience}");
    Console.WriteLine($"  → Agent: {decodedAuthToken.Agent}");
    Console.WriteLine($"  → Scope: {decodedAuthToken.Scope}");
    Console.WriteLine($"  → Issuer (PS): {decodedAuthToken.Issuer}");
    Console.WriteLine();

    // Step 3: GET /api/documents with auth token → access granted
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 3: Access resource with auth token ──────────────────");
    Console.ResetColor();
    Console.WriteLine($"→ GET https://localhost:{ResourcePort}/api/documents");

    var authSignatureKey = new SignatureKeyValue.Jwt(authTokenJwt);
    var accessRequest = new HttpRequestMessage(HttpMethod.Get, $"https://localhost:{ResourcePort}/api/documents");
    HttpMessageSigner.Sign(accessRequest, ephemeralKey, authSignatureKey);

    var accessResponse = await plainClient.SendAsync(accessRequest);
    var accessBody = await accessResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)accessResponse.StatusCode} {accessResponse.ReasonPhrase}");
    Console.WriteLine($"  Response: {accessBody}");
    Console.WriteLine();

    // Step 4: GET /api/documents with agent token → expect 401
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("─── Step 4: Attempt access with agent token (expect 401) ─────");
    Console.ResetColor();
    Console.WriteLine($"→ GET https://localhost:{ResourcePort}/api/documents (agent token only)");

    var rejectRequest = new HttpRequestMessage(HttpMethod.Get, $"https://localhost:{ResourcePort}/api/documents");
    HttpMessageSigner.Sign(rejectRequest, ephemeralKey, signatureKey);

    var rejectResponse = await plainClient.SendAsync(rejectRequest);
    var rejectBody = await rejectResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)rejectResponse.StatusCode} {rejectResponse.ReasonPhrase}");
    var requirementHeader = rejectResponse.Headers.TryGetValues("AAuth-Requirement", out var requirementValues)
        ? requirementValues.FirstOrDefault()
        : rejectResponse.Content.Headers.TryGetValues("AAuth-Requirement", out var contentRequirementValues)
            ? contentRequirementValues.FirstOrDefault()
            : null;
    if (requirementHeader is not null)
        Console.WriteLine($"  AAuth-Requirement: {requirementHeader}");
    Console.WriteLine($"  Response: {rejectBody}");
    Console.WriteLine();

    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("Demo complete. Shutting down servers...");
}

// ─── Interactive mode ────────────────────────────────────────────────────────

async Task RunInteractive()
{
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  INTERACTIVE MODE — servers are running");
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

        if (cmd == "token")
        {
            Console.WriteLine(agentTokenJwt);
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

        try
        {
            if (cmd == "authorize")
            {
                var scope = parts.Length > 1 ? parts[1] : "data.read";
                Console.WriteLine($"→ POST https://localhost:{ResourcePort}/authorize (scope: {scope})");

                var request = new HttpRequestMessage(HttpMethod.Post, $"https://localhost:{ResourcePort}/authorize");
                request.Content = JsonContent.Create(new { scope });
                HttpMessageSigner.Sign(request, ephemeralKey, signatureKey);

                var response = await plainClient.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"← {(int)response.StatusCode} {response.ReasonPhrase}");

                if ((int)response.StatusCode == 200)
                {
                    var json = JsonSerializer.Deserialize<JsonElement>(body);
                    storedResourceToken = json.GetProperty("resource_token").GetString()!;
                    Console.WriteLine($"  ✓ Resource token stored ({storedResourceToken[..40]}...)");
                    await JwtValidationHelpers.ValidateJwtSignatureAsync(storedResourceToken, resourcePublicJwk, $"https://localhost:{ResourcePort}", "aa-resource+jwt", validationClockSkew);
                    var decoded = ResourceToken.Decode(storedResourceToken);
                    Console.WriteLine($"    Audience (PS): {decoded.Audience}");
                    Console.WriteLine($"    Agent: {decoded.Agent}");
                    Console.WriteLine($"    Scope: {decoded.Scope}");
                }
                else
                {
                    Console.WriteLine($"  Response: {body}");
                }
            }
            else if (cmd == "exchange")
            {
                if (storedResourceToken is null)
                {
                    Console.WriteLine("  ✗ No resource token stored. Run 'authorize' first.");
                    Console.WriteLine();
                    continue;
                }

                Console.WriteLine($"→ POST {psUrl}/token");

                var request = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/token");
                request.Content = JsonContent.Create(new { resource_token = storedResourceToken });
                HttpMessageSigner.Sign(request, ephemeralKey, signatureKey);

                var response = await plainClient.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"← {(int)response.StatusCode} {response.ReasonPhrase}");

                if ((int)response.StatusCode == 200)
                {
                    var json = JsonSerializer.Deserialize<JsonElement>(body);
                    storedAuthToken = json.GetProperty("auth_token").GetString()!;
                    Console.WriteLine($"  ✓ Auth token stored ({storedAuthToken[..40]}...)");
                    // Production code must verify the JWT signature against the issuer's JWKS before calling Decode().
                    await JwtValidationHelpers.ValidateJwtSignatureAsync(storedAuthToken, psPublicJwk, psUrl, "aa-auth+jwt", validationClockSkew);
                    var decoded = AuthToken.Decode(storedAuthToken);
                    Console.WriteLine($"    Subject: {decoded.Subject}");
                    Console.WriteLine($"    Audience: {decoded.Audience}");
                    Console.WriteLine($"    Agent: {decoded.Agent}");
                    Console.WriteLine($"    Scope: {decoded.Scope}");
                }
                else
                {
                    Console.WriteLine($"  Response: {body}");
                }
            }
            else if (cmd == "access")
            {
                if (storedAuthToken is null)
                {
                    Console.WriteLine("  ✗ No auth token stored. Run 'authorize' then 'exchange' first.");
                    Console.WriteLine();
                    continue;
                }

                Console.WriteLine($"→ GET https://localhost:{ResourcePort}/api/documents (with auth token)");

                var authSigKey = new SignatureKeyValue.Jwt(storedAuthToken);
                var request = new HttpRequestMessage(HttpMethod.Get, $"https://localhost:{ResourcePort}/api/documents");
                HttpMessageSigner.Sign(request, ephemeralKey, authSigKey);

                var response = await plainClient.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"← {(int)response.StatusCode} {response.ReasonPhrase}");
                Console.WriteLine($"  Response: {body}");
            }
            else if (cmd == "flow")
            {
                var scope = parts.Length > 1 ? parts[1] : "data.read";
                Console.WriteLine($"  Running full three-party flow (scope: {scope})...");
                Console.WriteLine();

                // Step 1: Authorize
                Console.WriteLine($"  1. POST https://localhost:{ResourcePort}/authorize");
                var authzReq = new HttpRequestMessage(HttpMethod.Post, $"https://localhost:{ResourcePort}/authorize");
                authzReq.Content = JsonContent.Create(new { scope });
                HttpMessageSigner.Sign(authzReq, ephemeralKey, signatureKey);
                var authzRes = await plainClient.SendAsync(authzReq);
                var authzBody = await authzRes.Content.ReadAsStringAsync();
                Console.WriteLine($"     ← {(int)authzRes.StatusCode}");

                if ((int)authzRes.StatusCode != 200) { Console.WriteLine($"     Error: {authzBody}"); Console.WriteLine(); continue; }

                var authzJson = JsonSerializer.Deserialize<JsonElement>(authzBody);
                storedResourceToken = authzJson.GetProperty("resource_token").GetString()!;
                Console.WriteLine($"     ✓ Resource token received");

                // Step 2: Exchange
                Console.WriteLine($"  2. POST {psUrl}/token");
                var tokReq = new HttpRequestMessage(HttpMethod.Post, $"{psUrl}/token");
                tokReq.Content = JsonContent.Create(new { resource_token = storedResourceToken });
                HttpMessageSigner.Sign(tokReq, ephemeralKey, signatureKey);
                var tokRes = await plainClient.SendAsync(tokReq);
                var tokBody = await tokRes.Content.ReadAsStringAsync();
                Console.WriteLine($"     ← {(int)tokRes.StatusCode}");

                if ((int)tokRes.StatusCode != 200) { Console.WriteLine($"     Error: {tokBody}"); Console.WriteLine(); continue; }

                var tokJson = JsonSerializer.Deserialize<JsonElement>(tokBody);
                storedAuthToken = tokJson.GetProperty("auth_token").GetString()!;
                Console.WriteLine($"     ✓ Auth token received");

                // Step 3: Access
                Console.WriteLine($"  3. GET https://localhost:{ResourcePort}/api/documents");
                var authSigKey = new SignatureKeyValue.Jwt(storedAuthToken);
                var accessReq = new HttpRequestMessage(HttpMethod.Get, $"https://localhost:{ResourcePort}/api/documents");
                HttpMessageSigner.Sign(accessReq, ephemeralKey, authSigKey);
                var accessRes = await plainClient.SendAsync(accessReq);
                var accessBody = await accessRes.Content.ReadAsStringAsync();
                Console.WriteLine($"     ← {(int)accessRes.StatusCode}");
                Console.WriteLine($"     {accessBody}");
            }
            else if (cmd == "tokens")
            {
                Console.WriteLine("─── Stored Tokens ──────────────────────────────────────────");
                if (storedResourceToken is not null)
                {
                    await JwtValidationHelpers.ValidateJwtSignatureAsync(storedResourceToken, resourcePublicJwk, $"https://localhost:{ResourcePort}", "aa-resource+jwt", validationClockSkew);
                    var decoded = ResourceToken.Decode(storedResourceToken);
                    Console.WriteLine($"  Resource Token:");
                    Console.WriteLine($"    Issuer:   {decoded.Issuer}");
                    Console.WriteLine($"    Audience: {decoded.Audience}");
                    Console.WriteLine($"    Agent:    {decoded.Agent}");
                    Console.WriteLine($"    Scope:    {decoded.Scope}");
                    Console.WriteLine($"    Expires:  {decoded.ExpiresAt:u}");
                }
                else
                {
                    Console.WriteLine("  Resource Token: (none)");
                }

                Console.WriteLine();

                if (storedAuthToken is not null)
                {
                    // Production code must verify the JWT signature against the issuer's JWKS before calling Decode().
                    await JwtValidationHelpers.ValidateJwtSignatureAsync(storedAuthToken, psPublicJwk, psUrl, "aa-auth+jwt", validationClockSkew);
                    var decoded = AuthToken.Decode(storedAuthToken);
                    Console.WriteLine($"  Auth Token:");
                    Console.WriteLine($"    Issuer:   {decoded.Issuer}");
                    Console.WriteLine($"    Audience: {decoded.Audience}");
                    Console.WriteLine($"    Subject:  {decoded.Subject}");
                    Console.WriteLine($"    Agent:    {decoded.Agent}");
                    Console.WriteLine($"    Scope:    {decoded.Scope}");
                    Console.WriteLine($"    Expires:  {decoded.ExpiresAt:u}");
                }
                else
                {
                    Console.WriteLine("  Auth Token: (none)");
                }
            }
            else if (cmd == "metadata")
            {
                Console.WriteLine("─── Server Metadata URLs ───────────────────────────────────");
                Console.WriteLine($"  Agent Provider: {apUrl}/.well-known/aauth-agent.json");
                Console.WriteLine($"  Resource:       https://localhost:{ResourcePort}/.well-known/aauth-resource.json");
                Console.WriteLine($"  Person Server:  {psUrl}/.well-known/aauth-person.json");
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

void PrintHelp()
{
    Console.WriteLine("Commands:");
    Console.WriteLine("  authorize [scope]  POST /authorize → get resource token (default scope: data.read)");
    Console.WriteLine("  exchange           POST PS /token → exchange resource token for auth token");
    Console.WriteLine("  access             GET /api/documents with stored auth token");
    Console.WriteLine("  flow [scope]       Run all 3 steps in sequence");
    Console.WriteLine("  token              Print the full agent token (JWT)");
    Console.WriteLine("  keys               Print all public key identifiers");
    Console.WriteLine("  tokens             Show stored tokens (decoded claims)");
    Console.WriteLine("  metadata           Show all server metadata URLs");
    Console.WriteLine("  help               Show commands");
    Console.WriteLine("  quit               Shut down");
}
