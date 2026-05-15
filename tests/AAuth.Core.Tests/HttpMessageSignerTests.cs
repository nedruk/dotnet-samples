using System.Security.Cryptography;
using AAuth.Core.Signatures;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Core.Tests;

public class HttpMessageSignerTests
{
    [Fact]
    public void Sign_AddsRequiredHeaders()
    {
        var (signingKey, jwk) = CreateEcdsaKeyPair();
        var signatureKey = new SignatureKeyValue.Jwt("test.jwt.token");
        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/resource");

        HttpMessageSigner.Sign(request, signingKey, signatureKey);

        Assert.True(request.Headers.Contains("Signature"));
        Assert.True(request.Headers.Contains("Signature-Input"));
        Assert.True(request.Headers.Contains("Signature-Key"));
    }

    [Fact]
    public void Sign_SignatureKeyHeaderContainsJwt()
    {
        var (signingKey, _) = CreateEcdsaKeyPair();
        var signatureKey = new SignatureKeyValue.Jwt("my.agent.token");
        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api");

        HttpMessageSigner.Sign(request, signingKey, signatureKey);

        var skHeader = request.Headers.GetValues("Signature-Key").First();
        Assert.Contains("jwt=", skHeader);
    }

    [Fact]
    public void Sign_SignatureInputContainsCoveredComponents()
    {
        var (signingKey, _) = CreateEcdsaKeyPair();
        var signatureKey = new SignatureKeyValue.Jwt("test.token");
        var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/api/data");

        HttpMessageSigner.Sign(request, signingKey, signatureKey);

        var siHeader = request.Headers.GetValues("Signature-Input").First();
        Assert.Contains("@method", siHeader);
        Assert.Contains("@authority", siHeader);
        Assert.Contains("@path", siHeader);
        Assert.Contains("signature-key", siHeader);
        Assert.Contains("created=", siHeader);
    }

    [Fact]
    public void SignAndVerify_RoundTrip_Succeeds()
    {
        var (signingKey, jwk) = CreateEcdsaKeyPair();

        // Create a minimal agent token JWT with cnf claim for the test
        var agentJwt = CreateTestAgentToken(signingKey, jwk);
        var signatureKey = new SignatureKeyValue.Jwt(agentJwt);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/test");
        HttpMessageSigner.Sign(request, signingKey, signatureKey);

        var result = HttpMessageSigner.Verify(request, jwk);

        Assert.True(result.IsValid, result.Error);
        Assert.NotNull(result.Thumbprint);
    }

    [Fact]
    public void Verify_TamperedRequest_Fails()
    {
        var (signingKey, jwk) = CreateEcdsaKeyPair();
        var agentJwt = CreateTestAgentToken(signingKey, jwk);
        var signatureKey = new SignatureKeyValue.Jwt(agentJwt);

        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/test");
        HttpMessageSigner.Sign(request, signingKey, signatureKey);

        // Tamper with the request URI
        request.RequestUri = new Uri("https://example.com/tampered");

        var result = HttpMessageSigner.Verify(request, jwk);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Verify_MissingHeaders_ReturnsInvalid()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/test");
        var result = HttpMessageSigner.Verify(request);
        Assert.False(result.IsValid);
        Assert.Contains("Missing signature headers", result.Error);
    }

    [Fact]
    public void Sign_WithAdditionalComponents_IncludesThemInSignature()
    {
        var (signingKey, _) = CreateEcdsaKeyPair();
        var signatureKey = new SignatureKeyValue.Jwt("test.token");
        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/api");
        request.Headers.TryAddWithoutValidation("AAuth-Mission", "approver=\"https://ps.example.com\"; s256=\"abc123\"");

        HttpMessageSigner.Sign(request, signingKey, signatureKey, new[] { "aauth-mission" });

        var siHeader = request.Headers.GetValues("Signature-Input").First();
        Assert.Contains("aauth-mission", siHeader);
    }

    private static (ECDsa key, JsonWebKey jwk) CreateEcdsaKeyPair()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);
        var jwk = new JsonWebKey
        {
            Kty = "EC",
            Crv = "P-256",
            X = Base64UrlEncoder.Encode(ecParams.Q.X!),
            Y = Base64UrlEncoder.Encode(ecParams.Q.Y!)
        };
        return (ecdsa, jwk);
    }

    private static string CreateTestAgentToken(ECDsa signingKey, JsonWebKey publicJwk)
    {
        var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
        var now = DateTimeOffset.UtcNow;

        var cnfJwk = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(
            System.Text.Json.JsonSerializer.Serialize(publicJwk))!;

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["iss"] = "https://agent.example.com",
                ["dwk"] = "aauth-agent.json",
                ["sub"] = "aauth:test-agent@example.com",
                ["jti"] = Guid.NewGuid().ToString(),
                ["cnf"] = new Dictionary<string, object> { ["jwk"] = cnfJwk },
                ["iat"] = now.ToUnixTimeSeconds(),
                ["exp"] = now.AddHours(1).ToUnixTimeSeconds()
            },
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(signingKey), SecurityAlgorithms.EcdsaSha256),
            TokenType = "aa-agent+jwt"
        };

        return handler.CreateToken(descriptor);
    }
}
