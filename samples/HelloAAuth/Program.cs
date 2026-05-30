using System.Security.Cryptography;
using AAuth.Agent;
using AAuth.Core.Discovery;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace HelloAAuth;

public class Program
{
    const int ApPort = 3011;
    const int ResourcePort = 3012;
    const string AgentId = "aauth:demo-agent@localhost";

    public static async Task Main(string[] args)
    {
        var interactive = args.Contains("interactive") || args.Contains("--interactive");

        PrintBanner();

        // 1. Generate ECDSA P-256 key pairs
        Console.WriteLine("1. Generating ECDSA P-256 key pairs...");
        using var rootEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ephemeralEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var rootPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
            new ECDsaSecurityKey(rootEcdsa));
        rootPublicJwk.Kid = "root-1";

        var ephemeralPublicJwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
            new ECDsaSecurityKey(ephemeralEcdsa));
        var ephemeralThumbprint = JsonWebKeyThumbprint.Compute(ephemeralPublicJwk);

        Console.WriteLine($"   Root key kid: {rootPublicJwk.Kid}");
        Console.WriteLine($"   Ephemeral key thumbprint: {ephemeralThumbprint}");
        Console.WriteLine();

        // 2. Create self-signed agent token
        var apUrl = $"https://localhost:{ApPort}";
        Console.WriteLine("2. Creating self-signed agent token (aa-agent+jwt)...");
        var signingCredentials = new SigningCredentials(
            new ECDsaSecurityKey(rootEcdsa), SecurityAlgorithms.EcdsaSha256);
        var agentToken = AgentToken.Create(new AgentTokenOptions
        {
            Issuer = apUrl,
            Subject = AgentId,
            PublicKey = ephemeralPublicJwk,
        }, signingCredentials);

        Console.WriteLine($"   Agent ID: {AgentId}");
        Console.WriteLine($"   Issuer (AP): {apUrl}");
        Console.WriteLine($"   Token: {agentToken[..40]}...");
        Console.WriteLine();

        // 3. Start Agent Provider
        Console.WriteLine($"3. Starting Agent Provider on port {ApPort}...");
        var apApp = AgentProviderServer.CreateApp(rootPublicJwk, ApPort);
        await apApp.StartAsync();
        Console.WriteLine($"   Metadata: {apUrl}/.well-known/aauth-agent.json");
        Console.WriteLine($"   JWKS:     {apUrl}/jwks");
        Console.WriteLine();

        // 4. Start Resource Server
        Console.WriteLine($"4. Starting Resource Server on port {ResourcePort}...");
        var resourceApp = ResourceServer.CreateApp([AgentId], ResourcePort);
        await resourceApp.StartAsync();
        Console.WriteLine($"   API:      https://localhost:{ResourcePort}/api/hello");
        Console.WriteLine($"   Allowed:  [{AgentId}]");
        Console.WriteLine();

        try
        {
            if (interactive)
                await RunInteractive(ephemeralEcdsa, agentToken, rootPublicJwk, ephemeralPublicJwk);
            else
                await RunAutomated(ephemeralEcdsa, rootEcdsa, agentToken);
        }
        finally
        {
            await apApp.StopAsync();
            await resourceApp.StopAsync();
        }
    }

    static async Task RunAutomated(ECDsa ephemeralKey, ECDsa rootKey, string agentToken)
    {
        var apUrl = $"https://localhost:{ApPort}";
        using var discoveryHttpClient = new HttpClient();
        using var keyResolver = new IssuerKeyResolver(discoveryHttpClient);

        // Scenario 1: Allowed agent
        PrintScenarioHeader("Request 1: Allowed agent");
        using var client = CreateSignedClient(ephemeralKey, agentToken, keyResolver);
        Console.WriteLine($"\u2192 GET https://localhost:{ResourcePort}/api/hello");
        using var response = await client.GetAsync($"https://localhost:{ResourcePort}/api/hello");
        var body = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"\u2190 {(int)response.StatusCode} {body}");
        Console.WriteLine();

        // Scenario 2: Unknown agent
        PrintScenarioHeader("Request 2: Unknown agent");
        var unknownAgentId = "aauth:unknown-agent@evil.example";
        var unknownToken = AgentToken.Create(new AgentTokenOptions
        {
            Issuer = apUrl,
            Subject = unknownAgentId,
            PublicKey = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
                new ECDsaSecurityKey(ephemeralKey)),
        }, new SigningCredentials(new ECDsaSecurityKey(rootKey), SecurityAlgorithms.EcdsaSha256));

        using var unknownClient = CreateSignedClient(ephemeralKey, unknownToken, keyResolver);
        Console.WriteLine($"\u2192 GET https://localhost:{ResourcePort}/api/hello (as {unknownAgentId})");
        using var response2 = await unknownClient.GetAsync($"https://localhost:{ResourcePort}/api/hello");
        var body2 = await response2.Content.ReadAsStringAsync();
        Console.WriteLine($"\u2190 {(int)response2.StatusCode} {body2}");
        Console.WriteLine();

        // Scenario 3: Unsigned request
        PrintScenarioHeader("Request 3: Unsigned request");
        using var plainClient = new HttpClient();
        Console.WriteLine($"\u2192 GET https://localhost:{ResourcePort}/api/hello (no signature)");
        using var response3 = await plainClient.GetAsync($"https://localhost:{ResourcePort}/api/hello");
        var body3 = await response3.Content.ReadAsStringAsync();
        Console.WriteLine($"\u2190 {(int)response3.StatusCode} {body3}");
        Console.WriteLine();

        // Show AAuth headers from scenario 1
        PrintScenarioHeader("AAuth Headers (from scenario 1)");
        using var inspectClient = CreateSignedClient(ephemeralKey, agentToken, keyResolver);
        using var inspectRequest = new HttpRequestMessage(HttpMethod.Get, $"https://localhost:{ResourcePort}/api/hello");
        using var inspectResponse = await inspectClient.SendAsync(inspectRequest);
        PrintRequestHeaders(inspectRequest);

        Console.WriteLine();
        Console.WriteLine("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550");
        Console.WriteLine("Demo complete. Shutting down servers...");
    }

    static async Task RunInteractive(ECDsa ephemeralKey, string agentToken,
        JsonWebKey rootPublicJwk, JsonWebKey ephemeralPublicJwk)
    {
        using var discoveryHttpClient = new HttpClient();
        using var keyResolver = new IssuerKeyResolver(discoveryHttpClient);

        Console.WriteLine("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550");
        Console.WriteLine("  INTERACTIVE MODE \u2014 servers are running");
        Console.WriteLine("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550");
        Console.WriteLine();
        PrintHelp();
        Console.WriteLine();

        while (true)
        {
            Console.Write("aauth> ");
            var input = Console.ReadLine()?.Trim().ToLowerInvariant() ?? "quit";

            if (input is "quit" or "exit" or "q")
            {
                Console.WriteLine("Shutting down servers...");
                break;
            }

            if (input == "help")
            {
                PrintHelp();
                Console.WriteLine();
                continue;
            }

            if (input == "token")
            {
                Console.WriteLine(agentToken);
                Console.WriteLine();
                Console.WriteLine("  Copy-paste for shell:");
                Console.WriteLine($"  export AGENT_JWT='{agentToken}'");
                Console.WriteLine();
                continue;
            }

            if (input == "keys")
            {
                Console.WriteLine("Root public key (signs agent tokens):");
                Console.WriteLine(JsonExtensions.SerializeJwk(rootPublicJwk));
                Console.WriteLine();
                Console.WriteLine("Ephemeral public key (signs HTTP requests):");
                Console.WriteLine(JsonExtensions.SerializeJwk(ephemeralPublicJwk));
                Console.WriteLine();
                continue;
            }

            if (input == "signing-key")
            {
                var jwk = SerializePrivateJwk(ephemeralKey);
                Console.WriteLine(jwk);
                Console.WriteLine();
                Console.WriteLine("  Copy-paste for shell:");
                Console.WriteLine($"  export SIGNING_KEY='{jwk}'");
                Console.WriteLine();
                continue;
            }

            try
            {
                if (input == "unsigned")
                {
                    Console.WriteLine($"\u2192 GET https://localhost:{ResourcePort}/api/hello (no signature)");
                    using var plainClient = new HttpClient();
                    using var res = await plainClient.GetAsync($"https://localhost:{ResourcePort}/api/hello");
                    var body = await res.Content.ReadAsStringAsync();
                    Console.WriteLine($"\u2190 {(int)res.StatusCode} {body}");
                }
                else if (input == "unknown")
                {
                    var unknownId = "aauth:unknown-agent@evil.example";
                    var unknownToken = CreateUnknownIssuerToken(ephemeralKey, unknownId);

                    using var unknownClient = CreateSignedClient(ephemeralKey, unknownToken, keyResolver);
                    Console.WriteLine($"\u2192 GET https://localhost:{ResourcePort}/api/hello (as {unknownId}, iss https://localhost:9999)");
                    using var res = await unknownClient.GetAsync($"https://localhost:{ResourcePort}/api/hello");
                    var body = await res.Content.ReadAsStringAsync();
                    Console.WriteLine($"\u2190 {(int)res.StatusCode} {body}");
                }
                else if (input == "valid")
                {
                    using var client = CreateSignedClient(ephemeralKey, agentToken, keyResolver);
                    Console.WriteLine($"\u2192 GET https://localhost:{ResourcePort}/api/hello");
                    using var res = await client.GetAsync($"https://localhost:{ResourcePort}/api/hello");
                    var body = await res.Content.ReadAsStringAsync();
                    Console.WriteLine($"\u2190 {(int)res.StatusCode} {body}");
                }
                else
                {
                    Console.WriteLine($"Unknown command: '{input}'. Type 'help' for available commands.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            Console.WriteLine();
        }
    }

    static string CreateUnknownIssuerToken(ECDsa requestSigningKey, string unknownId)
    {
        // This intentionally uses a fake self-issued issuer. With the current sample verifier,
        // the request may still reach allowlist checks because only claims are inspected.
        // Once JWT signature verification is enforced, the unreachable JWKS should cause auth failure.
        using var unknownIssuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return AgentToken.Create(new AgentTokenOptions
        {
            Issuer = "https://localhost:9999",
            Subject = unknownId,
            PublicKey = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
                new ECDsaSecurityKey(requestSigningKey)),
        }, new SigningCredentials(new ECDsaSecurityKey(unknownIssuerKey), SecurityAlgorithms.EcdsaSha256));
    }

    static HttpClient CreateSignedClient(ECDsa ephemeralKey, string token, IssuerKeyResolver keyResolver)
    {
        var options = new AAuthAgentOptions
        {
            GetKeyMaterial = async () => new KeyMaterial
            {
                SigningKey = ephemeralKey,
                SignatureKey = new SignatureKeyValue.Jwt(token),
            }
        };
        var handler = new AAuthDelegatingHandler(options, keyResolver)
        {
            InnerHandler = new HttpClientHandler()
        };
        return new HttpClient(handler);
    }

    static void PrintBanner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        Console.WriteLine("\u2551  Sample 1: Hello AAuth \u2014 Identity-Based Access             \u2551");
        Console.WriteLine("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");
        Console.ResetColor();
        Console.WriteLine();
    }

    static void PrintScenarioHeader(string title)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"\u2500\u2500\u2500 {title} \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500");
        Console.ResetColor();
    }

    static void PrintHelp()
    {
        Console.WriteLine("Commands:");
        Console.WriteLine("  valid      Send a signed request as the allowed agent");
        Console.WriteLine("  unknown    Send a signed request with an untrusted self-issued token");
        Console.WriteLine("  unsigned   Send an unsigned request (plain fetch)");
        Console.WriteLine("  token      Print the full agent token (JWT)");
        Console.WriteLine("  signing-key Print the ephemeral private key (JWK, for SignTool)");
        Console.WriteLine("  keys       Print the agent's public keys");
        Console.WriteLine("  help       Show commands");
        Console.WriteLine("  quit       Shut down");
    }

    static void PrintRequestHeaders(HttpRequestMessage request)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        if (request.Headers.TryGetValues("Signature", out var sig))
            Console.WriteLine($"  Signature: {string.Join("", sig)[..60]}...");
        if (request.Headers.TryGetValues("Signature-Input", out var sigInput))
            Console.WriteLine($"  Signature-Input: {string.Join("", sigInput)}");
        if (request.Headers.TryGetValues("Signature-Key", out var sigKey))
            Console.WriteLine($"  Signature-Key: {string.Join("", sigKey)[..60]}...");
        Console.ResetColor();
    }

    static string SerializePrivateJwk(ECDsa key)
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
}
