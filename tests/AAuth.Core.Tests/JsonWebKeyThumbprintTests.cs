using System.Security.Cryptography;
using AAuth.Core.Signatures;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Core.Tests;

public class JsonWebKeyThumbprintTests
{
    [Fact]
    public void Compute_EcKey_ProducesConsistentThumbprint()
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

        var thumbprint1 = JsonWebKeyThumbprint.Compute(jwk);
        var thumbprint2 = JsonWebKeyThumbprint.Compute(jwk);

        Assert.Equal(thumbprint1, thumbprint2);
        Assert.NotEmpty(thumbprint1);
    }

    [Fact]
    public void Compute_DifferentKeys_ProduceDifferentThumbprints()
    {
        var ecdsa1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var params1 = ecdsa1.ExportParameters(false);
        var jwk1 = new JsonWebKey
        {
            Kty = "EC", Crv = "P-256",
            X = Base64UrlEncoder.Encode(params1.Q.X!),
            Y = Base64UrlEncoder.Encode(params1.Q.Y!)
        };

        var ecdsa2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var params2 = ecdsa2.ExportParameters(false);
        var jwk2 = new JsonWebKey
        {
            Kty = "EC", Crv = "P-256",
            X = Base64UrlEncoder.Encode(params2.Q.X!),
            Y = Base64UrlEncoder.Encode(params2.Q.Y!)
        };

        Assert.NotEqual(
            JsonWebKeyThumbprint.Compute(jwk1),
            JsonWebKeyThumbprint.Compute(jwk2));
    }
}
