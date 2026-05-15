using System.Security.Cryptography;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Core.Tests;

public class TokenTests
{
    [Fact]
    public void AgentToken_CreateAndDecode_RoundTrip()
    {
        var (ecdsa, jwk) = CreateEcdsaKeyPair();

        var jwt = AgentToken.Create(new AgentTokenOptions
        {
            Issuer = "https://agent-server.example.com",
            Subject = "aauth:test-agent@example.com",
            PublicKey = jwk,
            Lifetime = TimeSpan.FromHours(1)
        }, new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256));

        var decoded = AgentToken.Decode(jwt);

        Assert.Equal("https://agent-server.example.com", decoded.Issuer);
        Assert.Equal("aauth:test-agent@example.com", decoded.Subject);
        Assert.Equal("aauth-agent.json", decoded.Dwk);
        Assert.NotNull(decoded.ConfirmationKey);
        Assert.NotNull(decoded.Jti);
    }

    [Fact]
    public void AgentToken_WithPersonServer_IncludesPsClaim()
    {
        var (ecdsa, jwk) = CreateEcdsaKeyPair();

        var jwt = AgentToken.Create(new AgentTokenOptions
        {
            Issuer = "https://agent-server.example.com",
            Subject = "aauth:agent@example.com",
            PublicKey = jwk,
            PersonServerUrl = "https://ps.example.com"
        }, new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256));

        var decoded = AgentToken.Decode(jwt);
        Assert.Equal("https://ps.example.com", decoded.PersonServerUrl);
    }

    [Fact]
    public void ResourceToken_CreateAndDecode_RoundTrip()
    {
        var (ecdsa, _) = CreateEcdsaKeyPair();

        var jwt = ResourceToken.Create(new ResourceTokenOptions
        {
            Resource = "https://resource.example.com",
            AuthServer = "https://ps.example.com",
            Agent = "aauth:agent@example.com",
            AgentJkt = "thumbprint123",
            Scope = "read write"
        }, new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256));

        var decoded = ResourceToken.Decode(jwt);

        Assert.Equal("https://resource.example.com", decoded.Issuer);
        Assert.Equal("aauth-resource.json", decoded.Dwk);
        Assert.Equal("https://ps.example.com", decoded.Audience);
        Assert.Equal("aauth:agent@example.com", decoded.Agent);
        Assert.Equal("thumbprint123", decoded.AgentJkt);
        Assert.Equal("read write", decoded.Scope);
    }

    [Fact]
    public void ResourceToken_WithMission_IncludesMission()
    {
        var (ecdsa, _) = CreateEcdsaKeyPair();

        var jwt = ResourceToken.Create(new ResourceTokenOptions
        {
            Resource = "https://resource.example.com",
            AuthServer = "https://ps.example.com",
            Agent = "aauth:agent@example.com",
            AgentJkt = "thumbprint",
            Mission = new Mission("https://approver.example.com", "sha256value")
        }, new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256));

        var decoded = ResourceToken.Decode(jwt);
        Assert.NotNull(decoded.Mission);
        Assert.Equal("https://approver.example.com", decoded.Mission.Approver);
        Assert.Equal("sha256value", decoded.Mission.S256);
    }

    [Fact]
    public void AgentToken_WrongType_ThrowsAAuthTokenException()
    {
        var (ecdsa, _) = CreateEcdsaKeyPair();

        // Create a resource token but try to decode as agent token
        var jwt = ResourceToken.Create(new ResourceTokenOptions
        {
            Resource = "https://resource.example.com",
            AuthServer = "https://ps.example.com",
            Agent = "aauth:agent@example.com",
            AgentJkt = "thumb"
        }, new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256));

        var ex = Assert.Throws<AAuthTokenException>(() => AgentToken.Decode(jwt));
        Assert.Equal("invalid_agent_token", ex.Code);
    }

    [Fact]
    public void Mission_Equality()
    {
        var a = new Mission("https://ps.example.com", "hash1");
        var b = new Mission("https://ps.example.com", "hash1");
        Assert.Equal(a, b);
    }

    [Fact]
    public void ActorClaim_NestedChain()
    {
        var inner = new ActorClaim("aauth:inner@example.com", null);
        var outer = new ActorClaim("aauth:outer@example.com", inner);

        Assert.Equal("aauth:outer@example.com", outer.Subject);
        Assert.NotNull(outer.Nested);
        Assert.Equal("aauth:inner@example.com", outer.Nested!.Subject);
        Assert.Null(outer.Nested.Nested);
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
}
