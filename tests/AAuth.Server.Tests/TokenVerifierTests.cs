using System.Security.Cryptography;
using System.Text.Json;
using AAuth.Core.Discovery;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Server.Tests;

public class TokenVerifierTests
{
    private const string IssuerUrl = "https://issuer.example.com";
    private const string AuthServerUrl = "https://auth.example.com";
    private const string ResourceUrl = "https://resource.example.com";
    private const string AgentUrl = "https://agent.example.com";

    [Fact]
    public async Task VerifyAgentSignature_ValidAgentToken_ReturnsVerifiedAgent()
    {
        // Arrange
        var (issuerEcdsa, issuerPubJwk, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, ephemeralThumbprint) = CreateEphemeralKey();

        var agentJwt = AgentToken.Create(
            new AgentTokenOptions
            {
                Issuer = IssuerUrl,
                Subject = AgentUrl,
                PublicKey = ephemeralPubJwk
            },
            new SigningCredentials(new ECDsaSecurityKey(issuerEcdsa), SecurityAlgorithms.EcdsaSha256));

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(agentJwt));

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, IssuerUrl, "aauth-agent.json", issuerPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act
        var result = await verifier.VerifyAgentSignatureAsync(request);

        // Assert
        Assert.Equal("agent", result.TokenType);
        Assert.Equal(AgentUrl, result.AgentIdentifier);
        Assert.Equal(ephemeralThumbprint, result.Thumbprint);
    }

    [Fact]
    public async Task VerifyAuthTokenSignature_ValidAuthToken_ReturnsVerifiedAgent()
    {
        // Arrange
        var (psEcdsa, psPubJwk, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, ephemeralThumbprint) = CreateEphemeralKey();

        var authJwt = CreateAuthTokenJwt(psEcdsa, ephemeralPubJwk);

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(authJwt));

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, AuthServerUrl, "aauth-person.json", psPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act
        var result = await verifier.VerifyAuthTokenSignatureAsync(request);

        // Assert
        Assert.Equal("auth", result.TokenType);
        Assert.Equal(AgentUrl, result.AgentIdentifier);
        Assert.Equal("user-456", result.Subject);
        Assert.Equal("files.read", result.Scope);
        Assert.Equal(ephemeralThumbprint, result.Thumbprint);
    }

    [Fact]
    public async Task VerifyAgentSignature_WrongSigningKey_ThrowsInvalidSignature()
    {
        // Arrange: sign the request with a different key than what's in cnf.jwk
        var (issuerEcdsa, issuerPubJwk, _) = CreateEphemeralKey();
        var (_, ephemeralPubJwk1, _) = CreateEphemeralKey();
        var (ephemeralEcdsa2, _, _) = CreateEphemeralKey();

        // Token contains ephemeralPubJwk1 in cnf, but we'll sign the request with ephemeralEcdsa2
        var agentJwt = AgentToken.Create(
            new AgentTokenOptions
            {
                Issuer = IssuerUrl,
                Subject = AgentUrl,
                PublicKey = ephemeralPubJwk1
            },
            new SigningCredentials(new ECDsaSecurityKey(issuerEcdsa), SecurityAlgorithms.EcdsaSha256));

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa2, new SignatureKeyValue.Jwt(agentJwt));

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, IssuerUrl, "aauth-agent.json", issuerPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAgentSignatureAsync(request));
        Assert.Equal("invalid_signature", ex.Code);
    }

    #region Helpers

    private static (ECDsa signingKey, JsonWebKey pubJwk, string thumbprint) CreateEphemeralKey()
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
        var thumbprint = JsonWebKeyThumbprint.Compute(jwk);
        return (ecdsa, jwk, thumbprint);
    }

    private static AAuthServerOptions CreateServerOptions() => new()
    {
        ServerIdentifier = ResourceUrl,
        GetKeyMaterial = () => throw new NotImplementedException(),
        ClockSkew = TimeSpan.FromMinutes(5)
    };

    private static string CreateAuthTokenJwt(ECDsa psEcdsa, JsonWebKey ephemeralPubJwk)
    {
        var handler = new JsonWebTokenHandler();
        var claims = new Dictionary<string, object>
        {
            ["iss"] = AuthServerUrl,
            ["dwk"] = "aauth-person.json",
            ["aud"] = ResourceUrl,
            ["agent"] = AgentUrl,
            ["sub"] = "user-456",
            ["scope"] = "files.read",
            ["jti"] = Guid.NewGuid().ToString(),
            ["cnf"] = new Dictionary<string, object>
            {
                ["jwk"] = JsonSerializer.Deserialize<Dictionary<string, object>>(
                    JsonSerializer.Serialize(ephemeralPubJwk))!
            },
            ["act"] = new Dictionary<string, object> { ["sub"] = AgentUrl },
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(psEcdsa), SecurityAlgorithms.EcdsaSha256),
            TokenType = "aa-auth+jwt"
        };

        return handler.CreateToken(descriptor);
    }

    private static void ConfigureMockJwks(
        MockHttpHandler handler, string issuerUrl, string dwk, JsonWebKey pubJwk)
    {
        var jwksUrl = $"{issuerUrl}/jwks";
        var metadataUrl = $"{issuerUrl}/.well-known/{dwk}";

        handler.AddResponse(metadataUrl, JsonSerializer.Serialize(new { jwks_uri = jwksUrl }));

        var jwks = new { keys = new[] { new { kty = pubJwk.Kty, crv = pubJwk.Crv, x = pubJwk.X, y = pubJwk.Y } } };
        handler.AddResponse(jwksUrl, JsonSerializer.Serialize(jwks));
    }

    private sealed class MockHttpHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, string> _responses = new();

        public void AddResponse(string url, string jsonBody) => _responses[url] = jsonBody;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_responses.TryGetValue(request.RequestUri!.ToString(), out var body))
            {
                return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json")
                });
            }

            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
        }
    }

    #endregion
}
