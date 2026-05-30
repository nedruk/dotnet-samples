using System.Net.Http.Json;
using System.Security.Cryptography;
using AAuth.Agent;
using AAuth.Core.Discovery;
using AAuth.Core.Headers;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using FirstCallRegistration;
using Microsoft.IdentityModel.Tokens;

const int ApPort = 3011;
const int ResourcePort = 3012;
const string AgentId = "aauth:demo-agent@localhost";

Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║  Sample 2: First-Call Registration — Two-Party Access       ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
Console.WriteLine();

// 1. Generate ECDSA P-256 key pairs
Console.WriteLine("1. Generating ECDSA P-256 key pairs...");
var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var ephemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var resourceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

var rootPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(rootKey) { KeyId = "root-1" });
rootPublicJwk.Kid = "root-1";

var ephemeralPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(ephemeralKey));
var resourcePublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(new ECDsaSecurityKey(resourceKey) { KeyId = "resource-1" });
resourcePublicJwk.Kid = "resource-1";
var ephemeralThumbprint = JsonWebKeyThumbprint.Compute(ephemeralPublicJwk);
Console.WriteLine($"   Root key kid: root-1");
Console.WriteLine($"   Resource key kid: resource-1");
Console.WriteLine($"   Ephemeral key thumbprint: {ephemeralThumbprint}");
Console.WriteLine();

// 2. Create agent token
var apUrl = $"https://localhost:{ApPort}";
Console.WriteLine("2. Creating self-signed agent token...");
var agentToken = AgentToken.Create(new AgentTokenOptions
{
    Issuer = apUrl,
    Subject = AgentId,
    PublicKey = ephemeralPublicJwk,
}, new SigningCredentials(new ECDsaSecurityKey(rootKey), SecurityAlgorithms.EcdsaSha256));
Console.WriteLine($"   Agent ID: {AgentId}");
Console.WriteLine($"   Issuer (AP): {apUrl}");
Console.WriteLine();

// 3. Start Agent Provider
Console.WriteLine($"3. Starting Agent Provider on port {ApPort}...");
var apApp = AgentProviderServer.CreateApp(rootPublicJwk, ApPort);
await apApp.StartAsync();
Console.WriteLine($"   Metadata: {apUrl}/.well-known/aauth-agent.json");
Console.WriteLine();

// 4. Start Resource Server
Console.WriteLine($"4. Starting Resource Server on port {ResourcePort}...");
var resourceApp = ResourceServer.CreateApp(resourcePublicJwk, ResourcePort);
await resourceApp.StartAsync();
Console.WriteLine($"   API:      https://localhost:{ResourcePort}/api/data");
Console.WriteLine($"   Metadata: https://localhost:{ResourcePort}/.well-known/aauth-resource.json");
Console.WriteLine();

// Key material for signing
var keyMaterial = new KeyMaterial
{
    SigningKey = ephemeralKey,
    SignatureKey = new SignatureKeyValue.Jwt(agentToken),
};

var interactive = args.Contains("interactive") || args.Contains("--interactive");

if (interactive)
{
    // Interactive mode uses AAuthDelegatingHandler for convenience
    var keyResolver = new IssuerKeyResolver(new HttpClient());
    var agentOptions = new AAuthAgentOptions
    {
        GetKeyMaterial = () => Task.FromResult(keyMaterial)
    };
    var handler = new AAuthDelegatingHandler(agentOptions, keyResolver) { InnerHandler = new HttpClientHandler() };
    var signedClient = new HttpClient(handler);
    await RunInteractive(signedClient, keyMaterial);
}
else
{
    // Demo mode signs requests manually to show each step of the 202 flow
    await RunAutomated(keyMaterial);
}

await apApp.StopAsync();
await resourceApp.StopAsync();
return;

// ─── Automated mode ──────────────────────────────────────────────────────────

async Task RunAutomated(KeyMaterial km)
{
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  AUTOMATED MODE — Full two-party flow");
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine();

    var plainClient = new HttpClient();

    // Step 1: First call — sign manually so we can see the raw 202
    Console.WriteLine("─── Step 1: First API call (no access token) ─────────────────");
    Console.WriteLine($"→ GET https://localhost:{ResourcePort}/api/data");
    var request1 = CreateSignedGetRequest($"https://localhost:{ResourcePort}/api/data", km);
    var response1 = await plainClient.SendAsync(request1);
    Console.WriteLine($"← {(int)response1.StatusCode} {response1.ReasonPhrase}");

    if ((int)response1.StatusCode != 202)
    {
        Console.WriteLine($"  Expected 202, got {(int)response1.StatusCode}");
        return;
    }

    var requirementHeader = response1.Headers.TryGetValues("AAuth-Requirement", out var reqValues)
        ? reqValues.FirstOrDefault() ?? "" : "";
    var locationHeader = response1.Headers.Location?.ToString() ?? "";
    Console.WriteLine($"  AAuth-Requirement: {requirementHeader}");
    Console.WriteLine($"  Location: {locationHeader}");

    var challenge = AAuthRequirement.Parse(requirementHeader);
    Console.WriteLine($"  → Interaction URL: {challenge.Url}?code={challenge.Code}");
    Console.WriteLine();

    // Step 2: Simulate user approval
    Console.WriteLine("─── Step 2: Simulating user approval ─────────────────────────");
    Console.WriteLine($"→ POST https://localhost:{ResourcePort}/interact/approve");
    var approveResponse = await plainClient.PostAsJsonAsync(
        $"https://localhost:{ResourcePort}/interact/approve",
        new { code = challenge.Code });
    Console.WriteLine($"← {(int)approveResponse.StatusCode} (user approved)");
    Console.WriteLine();

    // Step 3: Poll pending URL
    Console.WriteLine("─── Step 3: Poll pending URL ─────────────────────────────────");
    Console.WriteLine($"→ GET {locationHeader}");
    var pollResponse = await plainClient.SendAsync(CreateSignedGetRequest(locationHeader, km));
    var pollBody = await pollResponse.Content.ReadAsStringAsync();
    var accessToken = pollResponse.Headers.TryGetValues("AAuth-Access", out var accessValues)
        ? accessValues.FirstOrDefault() ?? "" : "";
    Console.WriteLine($"← {(int)pollResponse.StatusCode} {pollResponse.ReasonPhrase}");
    Console.WriteLine($"  Body: {pollBody}");
    Console.WriteLine($"  AAuth-Access: {accessToken[..Math.Min(20, accessToken.Length)]}...");
    Console.WriteLine();

    Console.WriteLine("─── Step 3b: Re-poll consumed URL ────────────────────────────");
    Console.WriteLine($"→ GET {locationHeader}");
    var repollResponse = await plainClient.SendAsync(CreateSignedGetRequest(locationHeader, km));
    var repollBody = await repollResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)repollResponse.StatusCode} {repollResponse.ReasonPhrase}");
    Console.WriteLine($"  Body: {repollBody}");
    Console.WriteLine();

    // Step 4: Authorized request — sign manually with Authorization header
    Console.WriteLine("─── Step 4: Request with access token ────────────────────────");
    Console.WriteLine($"→ GET https://localhost:{ResourcePort}/api/data");
    Console.WriteLine($"  Authorization: AAuth {accessToken[..Math.Min(20, accessToken.Length)]}...");

    var authorizedRequest = new HttpRequestMessage(HttpMethod.Get, $"https://localhost:{ResourcePort}/api/data");
    authorizedRequest.Headers.TryAddWithoutValidation("Authorization", $"AAuth {accessToken}");
    HttpMessageSigner.Sign(authorizedRequest, km.SigningKey, km.SignatureKey, ["authorization"]);
    var authorizedResponse = await plainClient.SendAsync(authorizedRequest);
    var authorizedBody = await authorizedResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"← {(int)authorizedResponse.StatusCode} {authorizedResponse.ReasonPhrase}");
    Console.WriteLine($"  Response: {authorizedBody}");
    Console.WriteLine();

    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("Demo complete. Shutting down servers...");
}

// ─── Interactive mode ────────────────────────────────────────────────────────

async Task RunInteractive(HttpClient client, KeyMaterial km)
{
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  INTERACTIVE MODE — servers are running");
    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine();
    Console.WriteLine("Commands:");
    Console.WriteLine("  call       Make a signed request to /api/data (no access token)");
    Console.WriteLine("  poll <id>  Poll a pending URL by ID");
    Console.WriteLine("  use <tok>  Make a signed request with an access token");
    Console.WriteLine("  token      Print the full agent JWT (for manual .http flow)");
    Console.WriteLine("  help       Show commands");
    Console.WriteLine("  quit       Shut down");
    Console.WriteLine();

    var plainClient = new HttpClient();

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
            break;

        if (cmd == "token")
        {
            Console.WriteLine(agentToken);
            Console.WriteLine();
            Console.WriteLine("  Copy-paste for shell:");
            Console.WriteLine($"  export AGENT_JWT='{agentToken}'");
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

        if (cmd == "call")
        {
            try
            {
                Console.WriteLine($"→ GET https://localhost:{ResourcePort}/api/data");
                var res = await client.GetAsync($"https://localhost:{ResourcePort}/api/data");
                Console.WriteLine($"← {(int)res.StatusCode} {res.ReasonPhrase}");

                if (res.Headers.TryGetValues("AAuth-Requirement", out var rv))
                    Console.WriteLine($"  AAuth-Requirement: {rv.FirstOrDefault()}");
                if (res.Headers.Location is not null)
                    Console.WriteLine($"  Location: {res.Headers.Location}");
                if (res.Headers.TryGetValues("AAuth-Access", out var av))
                    Console.WriteLine($"  AAuth-Access: {av.FirstOrDefault()}");

                var body = await res.Content.ReadAsStringAsync();
                Console.WriteLine($"  Body: {body}");

                if ((int)res.StatusCode == 202)
                {
                    var req = res.Headers.TryGetValues("AAuth-Requirement", out var r)
                        ? r.FirstOrDefault() : null;
                    if (req is not null)
                    {
                        var c = AAuthRequirement.Parse(req);
                        Console.WriteLine();
                        Console.WriteLine($"  → Open in browser: {c.Url}?code={c.Code}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            Console.WriteLine();
            continue;
        }

        if (cmd == "poll")
        {
            var id = parts.Length > 1 ? parts[1] : null;
            if (id is null)
            {
                Console.WriteLine("Usage: poll <pending-id>");
                Console.WriteLine();
                continue;
            }

            try
            {
                var url = $"https://localhost:{ResourcePort}/pending/{id}";
                Console.WriteLine($"→ GET {url}");
                var res = await plainClient.SendAsync(CreateSignedGetRequest(url, km));
                Console.WriteLine($"← {(int)res.StatusCode} {res.ReasonPhrase}");
                if (res.Headers.TryGetValues("AAuth-Access", out var av))
                    Console.WriteLine($"  AAuth-Access: {av.FirstOrDefault()}");
                var body = await res.Content.ReadAsStringAsync();
                Console.WriteLine($"  Body: {body}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            Console.WriteLine();
            continue;
        }

        if (cmd == "use")
        {
            var token = parts.Length > 1 ? parts[1] : null;
            if (token is null)
            {
                Console.WriteLine("Usage: use <access-token>");
                Console.WriteLine();
                continue;
            }

            try
            {
                Console.WriteLine($"→ GET https://localhost:{ResourcePort}/api/data");
                Console.WriteLine($"  Authorization: AAuth {token[..Math.Min(20, token.Length)]}...");
                var req = new HttpRequestMessage(HttpMethod.Get, $"https://localhost:{ResourcePort}/api/data");
                req.Headers.TryAddWithoutValidation("Authorization", $"AAuth {token}");
                var res = await client.SendAsync(req);
                Console.WriteLine($"← {(int)res.StatusCode} {res.ReasonPhrase}");
                var body = await res.Content.ReadAsStringAsync();
                Console.WriteLine($"  Body: {body}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            Console.WriteLine();
            continue;
        }

        if (cmd == "help")
        {
            Console.WriteLine("Commands:");
            Console.WriteLine("  call       Make a signed request (no access token) — triggers 202");
            Console.WriteLine("  poll <id>  Poll pending URL (get from Location header)");
            Console.WriteLine("  use <tok>  Make a signed request WITH access token");
            Console.WriteLine("  token      Print the full agent JWT");
            Console.WriteLine("  signing-key Print the ephemeral private key (JWK, for SignTool)");
            Console.WriteLine("  quit       Shut down");
            Console.WriteLine();
            continue;
        }

        Console.WriteLine("Unknown command. Type \"help\" for options.");
        Console.WriteLine();
    }
}

HttpRequestMessage CreateSignedGetRequest(string url, KeyMaterial km)
{
    var request = new HttpRequestMessage(HttpMethod.Get, url);
    HttpMessageSigner.Sign(request, km.SigningKey, km.SignatureKey);
    return request;
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
