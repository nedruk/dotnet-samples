using AAuth.Core.Signatures;
using Xunit;

namespace AAuth.Core.Tests;

public class SignatureKeyHeaderTests
{
    [Fact]
    public void Build_JwtKey_ProducesCorrectFormat()
    {
        var key = new SignatureKeyValue.Jwt("eyJhbGciOiJFUzI1NiJ9.test.sig");
        var header = SignatureKeyHeader.Build(key);
        Assert.Equal("sig=jwt;jwt=\"eyJhbGciOiJFUzI1NiJ9.test.sig\"", header);
    }

    [Fact]
    public void Build_JwksUriKey_ProducesCorrectFormat()
    {
        var key = new SignatureKeyValue.JwksUri("https://example.com/.well-known/jwks.json");
        var header = SignatureKeyHeader.Build(key);
        Assert.Equal("sig=jwks_uri;jwks_uri=\"https://example.com/.well-known/jwks.json\"", header);
    }

    [Fact]
    public void Parse_JwtKey_Succeeds()
    {
        var parsed = SignatureKeyHeader.Parse("jwt=\"my.test.token\"");
        var jwt = Assert.IsType<SignatureKeyValue.Jwt>(parsed);
        Assert.Equal("my.test.token", jwt.Token);
    }

    [Fact]
    public void Parse_JwksUriKey_Succeeds()
    {
        var parsed = SignatureKeyHeader.Parse("jwks_uri=\"https://example.com/jwks\"");
        var uri = Assert.IsType<SignatureKeyValue.JwksUri>(parsed);
        Assert.Equal("https://example.com/jwks", uri.Uri);
    }

    [Fact]
    public void ExtractJwt_FromJwtHeader_ReturnsToken()
    {
        var jwt = SignatureKeyHeader.ExtractJwt("jwt=\"my.jwt.token\"");
        Assert.Equal("my.jwt.token", jwt);
    }

    [Fact]
    public void ExtractJwt_FromNonJwtHeader_ReturnsNull()
    {
        var jwt = SignatureKeyHeader.ExtractJwt("jwks_uri=\"https://example.com\"");
        Assert.Null(jwt);
    }
}
