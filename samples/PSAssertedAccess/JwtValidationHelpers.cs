using AAuth.Core.Discovery;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace PSAssertedAccess;

internal static class JwtValidationHelpers
{
    public static async Task ValidateJwtSignatureFromIssuerAsync(
        string jwt,
        string issuer,
        string dwk,
        string expectedType,
        TimeSpan clockSkew)
    {
        try
        {
            using var httpClient = new HttpClient();
            using var keyResolver = new IssuerKeyResolver(httpClient);
            var keySet = await keyResolver.ResolveKeysAsync(issuer, dwk);
            await ValidateJwtSignatureAsync(jwt, keySet.Keys, issuer, expectedType, clockSkew);
        }
        catch (AAuthTokenException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AAuthTokenException("invalid_token_signature", $"Failed to validate {expectedType} signature", ex);
        }
    }

    public static Task ValidateJwtSignatureAsync(
        string jwt,
        JsonWebKey signingKey,
        string issuer,
        string expectedType,
        TimeSpan clockSkew) =>
        ValidateJwtSignatureAsync(jwt, new[] { signingKey }, issuer, expectedType, clockSkew);

    private static async Task ValidateJwtSignatureAsync(
        string jwt,
        IEnumerable<JsonWebKey> signingKeys,
        string issuer,
        string expectedType,
        TimeSpan clockSkew)
    {
        var keys = signingKeys.ToArray();
        if (keys.Length == 0)
            throw new AAuthTokenException("no_issuer_keys", $"No signing keys available for {issuer}");

        var handler = new JsonWebTokenHandler();
        var validationResult = await handler.ValidateTokenAsync(jwt, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = clockSkew,
            RequireSignedTokens = true,
            ValidTypes = new[] { expectedType },
            IssuerSigningKeys = keys,
        });

        if (!validationResult.IsValid)
        {
            throw new AAuthTokenException(
                "invalid_token_signature",
                $"Failed to validate {expectedType} signature",
                validationResult.Exception ?? new InvalidOperationException("Token validation failed"));
        }
    }
}
