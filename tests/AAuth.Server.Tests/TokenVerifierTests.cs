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

    [Fact]
    public async Task VerifyAgentSignature_TokenSignedWithUnknownKey_ThrowsInvalidAgentToken()
    {
        // Arrange
        var (_, trustedIssuerPubJwk, _) = CreateEphemeralKey();
        var (rogueIssuerEcdsa, _, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();

        var agentJwt = AgentToken.Create(
            new AgentTokenOptions
            {
                Issuer = IssuerUrl,
                Subject = AgentUrl,
                PublicKey = ephemeralPubJwk
            },
            new SigningCredentials(new ECDsaSecurityKey(rogueIssuerEcdsa), SecurityAlgorithms.EcdsaSha256));

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(agentJwt));

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, IssuerUrl, "aauth-agent.json", trustedIssuerPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAgentSignatureAsync(request));
        Assert.Equal("invalid_agent_token", ex.Code);
    }

    [Fact]
    public async Task VerifyAuthTokenSignature_TokenSignedWithUnknownKey_ThrowsInvalidAuthToken()
    {
        // Arrange
        var (_, trustedPsPubJwk, _) = CreateEphemeralKey();
        var (roguePsEcdsa, _, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();

        var authJwt = CreateAuthTokenJwt(roguePsEcdsa, ephemeralPubJwk);

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(authJwt));

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, AuthServerUrl, "aauth-person.json", trustedPsPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAuthTokenSignatureAsync(request));
        Assert.Equal("invalid_auth_token", ex.Code);
    }

    [Fact]
    public async Task VerifyAuthTokenSignature_RequiredScopeMissing_ThrowsInsufficientScope()
    {
        // Arrange
        var (psEcdsa, psPubJwk, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();

        var authJwt = CreateAuthTokenJwt(psEcdsa, ephemeralPubJwk, scope: null);

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(authJwt));

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, AuthServerUrl, "aauth-person.json", psPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        options.RequiredScope = "files.read";
        var verifier = new TokenVerifier(options, keyResolver);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAuthTokenSignatureAsync(request));
        Assert.Equal("insufficient_scope", ex.Code);
    }

    [Fact]
    public async Task VerifyAuthTokenSignature_RequiredScopePartiallyMissing_ThrowsInsufficientScope()
    {
        // Arrange
        var (psEcdsa, psPubJwk, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();

        var authJwt = CreateAuthTokenJwt(psEcdsa, ephemeralPubJwk, scope: "files.read");

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(authJwt));

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, AuthServerUrl, "aauth-person.json", psPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        options.RequiredScope = "files.read profile.read";
        var verifier = new TokenVerifier(options, keyResolver);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAuthTokenSignatureAsync(request));
        Assert.Equal("insufficient_scope", ex.Code);
    }

    [Fact]
    public async Task VerifyAuthTokenSignature_InvalidIssuerFormat_ThrowsInvalidAuthTokenBeforeKeyDiscovery()
    {
        // Arrange
        var (psEcdsa, _, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();

        var authJwt = CreateAuthTokenJwt(psEcdsa, ephemeralPubJwk, issuer: "http://AUTH.example.com/path");

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(authJwt));

        var mockHandler = new MockHttpHandler();
        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAuthTokenSignatureAsync(request));
        Assert.Equal("invalid_auth_token", ex.Code);
        Assert.Empty(mockHandler.SentRequests);
    }

    [Fact]
    public async Task VerifyAgentSignature_InvalidIssuerFormat_ThrowsInvalidAgentTokenBeforeKeyDiscovery()
    {
        // Arrange
        var (issuerEcdsa, _, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();

        var agentJwt = AgentToken.Create(
            new AgentTokenOptions
            {
                Issuer = "http://ISSUER.example.com/path",
                Subject = AgentUrl,
                PublicKey = ephemeralPubJwk
            },
            new SigningCredentials(new ECDsaSecurityKey(issuerEcdsa), SecurityAlgorithms.EcdsaSha256));

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(agentJwt));

        var mockHandler = new MockHttpHandler();
        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAgentSignatureAsync(request));
        Assert.Equal("invalid_agent_token", ex.Code);
        Assert.Empty(mockHandler.SentRequests);
    }

    [Fact]
    public async Task VerifyAgentSignature_LocalhostIssuerWithPort_IsAcceptedForDevSamples()
    {
        // Arrange
        var (issuerEcdsa, issuerPubJwk, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();
        const string loopbackIssuer = "https://localhost:3011";

        var agentJwt = AgentToken.Create(
            new AgentTokenOptions
            {
                Issuer = loopbackIssuer,
                Subject = AgentUrl,
                PublicKey = ephemeralPubJwk
            },
            new SigningCredentials(new ECDsaSecurityKey(issuerEcdsa), SecurityAlgorithms.EcdsaSha256));

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(agentJwt));

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, loopbackIssuer, "aauth-agent.json", issuerPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act
        var result = await verifier.VerifyAgentSignatureAsync(request);

        // Assert
        Assert.Equal("agent", result.TokenType);
        Assert.Equal(AgentUrl, result.AgentIdentifier);
    }

    [Fact]
    public async Task VerifyAuthTokenSignature_SignatureInputMissingRequiredComponent_ThrowsInvalidSignature()
    {
        // Arrange
        var (psEcdsa, psPubJwk, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();

        var authJwt = CreateAuthTokenJwt(psEcdsa, ephemeralPubJwk);

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(authJwt));

        var parsedInput = SignatureInput.Parse(request.Headers.GetValues("Signature-Input").First());
        var tamperedComponents = parsedInput.CoveredComponents
            .Where(component => component != "@path")
            .ToList();

        request.Headers.Remove("Signature-Input");
        request.Headers.TryAddWithoutValidation(
            "Signature-Input",
            new SignatureInput(tamperedComponents, parsedInput.Created).Serialize());

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, AuthServerUrl, "aauth-person.json", psPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAuthTokenSignatureAsync(request));
        Assert.Equal("invalid_signature", ex.Code);
    }

    [Fact]
    public async Task VerifyAuthTokenSignature_OverlongLifetime_ThrowsInvalidAuthToken()
    {
        // Arrange
        var (psEcdsa, psPubJwk, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();
        var issuedAt = DateTimeOffset.UtcNow;

        var authJwt = CreateAuthTokenJwt(
            psEcdsa,
            ephemeralPubJwk,
            issuedAt: issuedAt,
            expiresAt: issuedAt.AddHours(2));

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(authJwt));

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, AuthServerUrl, "aauth-person.json", psPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAuthTokenSignatureAsync(request));
        Assert.Equal("invalid_auth_token", ex.Code);
    }

    [Fact]
    public async Task VerifyAgentSignature_ValidPsClaim_AcceptedAndValidated()
    {
        // Arrange
        var (issuerEcdsa, issuerPubJwk, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();

        var agentJwt = AgentToken.Create(
            new AgentTokenOptions
            {
                Issuer = IssuerUrl,
                Subject = AgentUrl,
                PublicKey = ephemeralPubJwk,
                PersonServerUrl = "https://ps.example.com"
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
    }

    [Fact]
    public async Task VerifyAgentSignature_InvalidPsClaim_ThrowsInvalidAgentToken()
    {
        // Arrange: ps claim with invalid format (http, not https)
        var (issuerEcdsa, issuerPubJwk, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();

        var agentJwt = AgentToken.Create(
            new AgentTokenOptions
            {
                Issuer = IssuerUrl,
                Subject = AgentUrl,
                PublicKey = ephemeralPubJwk,
                PersonServerUrl = "http://ps.example.com/path"
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

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAgentSignatureAsync(request));
        Assert.Equal("invalid_agent_token", ex.Code);
    }

    [Fact]
    public async Task VerifyAuthTokenSignature_ActSubMismatch_ThrowsInvalidAuthToken()
    {
        // Arrange: act.sub doesn't match agent claim
        var (psEcdsa, psPubJwk, _) = CreateEphemeralKey();
        var (ephemeralEcdsa, ephemeralPubJwk, _) = CreateEphemeralKey();

        var authJwt = CreateAuthTokenJwt(psEcdsa, ephemeralPubJwk, actSub: "https://wrong-agent.example.com");

        var request = new HttpRequestMessage(HttpMethod.Get, $"{ResourceUrl}/api/data");
        HttpMessageSigner.Sign(request, ephemeralEcdsa, new SignatureKeyValue.Jwt(authJwt));

        var mockHandler = new MockHttpHandler();
        ConfigureMockJwks(mockHandler, AuthServerUrl, "aauth-person.json", psPubJwk);

        using var httpClient = new HttpClient(mockHandler);
        var keyResolver = new IssuerKeyResolver(httpClient);
        var options = CreateServerOptions();
        var verifier = new TokenVerifier(options, keyResolver);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<AAuthTokenException>(
            () => verifier.VerifyAuthTokenSignatureAsync(request));
        Assert.Equal("invalid_auth_token", ex.Code);
        Assert.Contains("act.sub", ex.Message);
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

    private static string CreateAuthTokenJwt(
        ECDsa psEcdsa,
        JsonWebKey ephemeralPubJwk,
        string? issuer = null,
        string? audience = null,
        string? subject = "user-456",
        string? scope = "files.read",
        string? actSub = null,
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null)
    {
        var handler = new JsonWebTokenHandler();
        var now = issuedAt ?? DateTimeOffset.UtcNow;
        var exp = expiresAt ?? now.AddHours(1);
        var claims = new Dictionary<string, object>
        {
            ["iss"] = issuer ?? AuthServerUrl,
            ["dwk"] = "aauth-person.json",
            ["aud"] = audience ?? ResourceUrl,
            ["agent"] = AgentUrl,
            ["jti"] = Guid.NewGuid().ToString(),
            ["cnf"] = new Dictionary<string, object>
            {
                ["jwk"] = JsonSerializer.Deserialize<Dictionary<string, object>>(
                    JsonSerializer.Serialize(ephemeralPubJwk))!
            },
            ["act"] = new Dictionary<string, object> { ["sub"] = actSub ?? AgentUrl },
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds()
        };

        if (subject is not null)
            claims["sub"] = subject;
        if (scope is not null)
            claims["scope"] = scope;

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
        public List<HttpRequestMessage> SentRequests { get; } = new();

        public void AddResponse(string url, string jsonBody) => _responses[url] = jsonBody;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            SentRequests.Add(request);

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
