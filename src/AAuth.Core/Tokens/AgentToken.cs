using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Core.Tokens;

/// <summary>
/// Options for creating an agent token.
/// </summary>
public sealed class AgentTokenOptions
{
    public required string Issuer { get; init; }
    public required string Subject { get; init; }
    public required JsonWebKey PublicKey { get; init; }
    public string? PersonServerUrl { get; init; }
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromHours(24);
}

/// <summary>
/// Represents a verified AAuth agent token (typ: aa-agent+jwt).
/// </summary>
public sealed class AgentToken
{
    public string Issuer { get; }
    public string Dwk { get; }
    public string Subject { get; }
    public string Jti { get; }
    public JsonWebKey ConfirmationKey { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public string? PersonServerUrl { get; }
    public string RawJwt { get; }

    private AgentToken(string issuer, string dwk, string subject, string jti,
        JsonWebKey confirmationKey, DateTimeOffset issuedAt, DateTimeOffset expiresAt,
        string? personServerUrl, string rawJwt)
    {
        Issuer = issuer;
        Dwk = dwk;
        Subject = subject;
        Jti = jti;
        ConfirmationKey = confirmationKey;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        PersonServerUrl = personServerUrl;
        RawJwt = rawJwt;
    }

    /// <summary>
    /// Create a new agent token JWT.
    /// </summary>
    public static string Create(AgentTokenOptions options, SigningCredentials signingCredentials)
    {
        var now = DateTimeOffset.UtcNow;
        var handler = new JsonWebTokenHandler();

        var claims = new Dictionary<string, object>
        {
            ["iss"] = options.Issuer,
            ["dwk"] = "aauth-agent.json",
            ["sub"] = options.Subject,
            ["jti"] = Guid.NewGuid().ToString(),
            ["cnf"] = new Dictionary<string, object>
            {
                ["jwk"] = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(
                    System.Text.Json.JsonSerializer.Serialize(options.PublicKey))!
            },
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.Add(options.Lifetime).ToUnixTimeSeconds()
        };

        if (options.PersonServerUrl is not null)
            claims["ps"] = options.PersonServerUrl;

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = signingCredentials,
            TokenType = "aa-agent+jwt"
        };

        return handler.CreateToken(descriptor);
    }

    /// <summary>
    /// Decode and validate an agent token from a raw JWT string.
    /// Does NOT verify the JWT signature (use with pre-verified JWTs or call full verification separately).
    /// </summary>
    public static AgentToken Decode(string rawJwt)
    {
        var handler = new JsonWebTokenHandler();
        var token = handler.ReadJsonWebToken(rawJwt);

        var typ = token.Typ;
        if (typ != "aa-agent+jwt")
            throw new AAuthTokenException("invalid_agent_token", $"Expected typ aa-agent+jwt, got {typ}");

        var dwk = token.GetClaim("dwk").Value;
        if (dwk != "aauth-agent.json")
            throw new AAuthTokenException("invalid_agent_token", $"Expected dwk aauth-agent.json, got {dwk}");

        var iss = token.Issuer;
        var sub = token.Subject;
        var jti = token.Id;

        // Extract cnf.jwk
        var cnfClaim = token.GetClaim("cnf");
        var cnfJson = cnfClaim.Value;
        var cnfDict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(cnfJson)!;
        var jwkJson = cnfDict["jwk"].GetRawText();
        var confirmationKey = new JsonWebKey(jwkJson);

        var iat = DateTimeOffset.FromUnixTimeSeconds(token.GetClaim("iat").GetLong());
        var exp = DateTimeOffset.FromUnixTimeSeconds(token.GetClaim("exp").GetLong());

        string? ps = null;
        if (token.TryGetClaim("ps", out var psClaim))
            ps = psClaim.Value;

        return new AgentToken(iss, dwk, sub, jti, confirmationKey, iat, exp, ps, rawJwt);
    }
}

internal static class ClaimExtensions
{
    public static long GetLong(this System.Security.Claims.Claim claim)
    {
        return long.Parse(claim.Value);
    }
}
