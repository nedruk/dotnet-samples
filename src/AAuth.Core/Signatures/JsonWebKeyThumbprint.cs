using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Core.Signatures;

/// <summary>
/// Computes JWK Thumbprints per RFC 7638.
/// </summary>
public static class JsonWebKeyThumbprint
{
    /// <summary>
    /// Compute the base64url-encoded SHA-256 JWK Thumbprint for a key.
    /// </summary>
    public static string Compute(JsonWebKey jwk)
    {
        // Per RFC 7638: lexicographically sorted required members
        string json;

        if (jwk.Kty == "OKP")
        {
            // OKP: crv, kty, x
            json = JsonSerializer.Serialize(new { crv = jwk.Crv, kty = jwk.Kty, x = jwk.X });
        }
        else if (jwk.Kty == "EC")
        {
            // EC: crv, kty, x, y
            json = JsonSerializer.Serialize(new { crv = jwk.Crv, kty = jwk.Kty, x = jwk.X, y = jwk.Y });
        }
        else if (jwk.Kty == "RSA")
        {
            // RSA: e, kty, n
            json = JsonSerializer.Serialize(new { e = jwk.E, kty = jwk.Kty, n = jwk.N });
        }
        else
        {
            throw new NotSupportedException($"Unsupported key type: {jwk.Kty}");
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Base64UrlEncoder.Encode(hash);
    }
}
