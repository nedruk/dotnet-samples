using System.Text.RegularExpressions;

namespace AAuth.Core.Signatures;

/// <summary>
/// Parses and builds the Signature-Key header for AAuth.
/// Supports schemes: jwt and jwks_uri.
/// </summary>
public static partial class SignatureKeyHeader
{
    /// <summary>
    /// Build a Signature-Key header value.
    /// </summary>
    public static string Build(SignatureKeyValue value)
    {
        return value switch
        {
            SignatureKeyValue.Jwt jwt => $"sig=jwt;jwt=\"{jwt.Token}\"",
            SignatureKeyValue.JwksUri jwksUri => $"sig=jwks_uri;jwks_uri=\"{jwksUri.Uri}\"",
            _ => throw new ArgumentException($"Unknown SignatureKeyValue type: {value.GetType()}")
        };
    }

    /// <summary>
    /// Parse a Signature-Key header value.
    /// </summary>
    public static SignatureKeyValue Parse(string headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
            throw new FormatException("Empty Signature-Key header");

        var jwtMatch = JwtRegex().Match(headerValue);
        if (jwtMatch.Success)
            return new SignatureKeyValue.Jwt(jwtMatch.Groups[1].Value);

        var jwksUriMatch = JwksUriRegex().Match(headerValue);
        if (jwksUriMatch.Success)
            return new SignatureKeyValue.JwksUri(jwksUriMatch.Groups[1].Value);

        throw new FormatException($"Unsupported Signature-Key scheme: {headerValue}");
    }

    /// <summary>
    /// Extract the raw JWT string from a Signature-Key header value, regardless of scheme.
    /// Returns null if the header does not contain a JWT.
    /// </summary>
    public static string? ExtractJwt(string headerValue)
    {
        var match = JwtRegex().Match(headerValue);
        return match.Success ? match.Groups[1].Value : null;
    }

    [GeneratedRegex("jwt=\"([^\"]+)\"")]
    private static partial Regex JwtRegex();

    [GeneratedRegex("jwks_uri=\"([^\"]+)\"")]
    private static partial Regex JwksUriRegex();
}
