using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Core.Tokens;

/// <summary>
/// Options for creating a resource token.
/// </summary>
public sealed class ResourceTokenOptions
{
    public required string Resource { get; init; }
    public required string AuthServer { get; init; }
    public required string Agent { get; init; }
    public required string AgentJkt { get; init; }
    public string? Scope { get; init; }
    public Mission? Mission { get; init; }
    public int LifetimeSeconds { get; init; } = 300;
}

/// <summary>
/// Represents a verified AAuth resource token (typ: aa-resource+jwt).
/// </summary>
public sealed class ResourceToken
{
    public string Issuer { get; }
    public string Dwk { get; }
    public string Audience { get; }
    public string Jti { get; }
    public string Agent { get; }
    public string AgentJkt { get; }
    public string? Scope { get; }
    public Mission? Mission { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public string RawJwt { get; }

    private ResourceToken(string issuer, string dwk, string audience, string jti,
        string agent, string agentJkt, string? scope, Mission? mission,
        DateTimeOffset issuedAt, DateTimeOffset expiresAt, string rawJwt)
    {
        Issuer = issuer;
        Dwk = dwk;
        Audience = audience;
        Jti = jti;
        Agent = agent;
        AgentJkt = agentJkt;
        Scope = scope;
        Mission = mission;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        RawJwt = rawJwt;
    }

    /// <summary>
    /// Create a new resource token JWT.
    /// </summary>
    public static string Create(ResourceTokenOptions options, SigningCredentials signingCredentials)
    {
        var now = DateTimeOffset.UtcNow;
        var handler = new JsonWebTokenHandler();

        var claims = new Dictionary<string, object>
        {
            ["iss"] = options.Resource,
            ["dwk"] = "aauth-resource.json",
            ["aud"] = options.AuthServer,
            ["jti"] = Guid.NewGuid().ToString(),
            ["agent"] = options.Agent,
            ["agent_jkt"] = options.AgentJkt,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddSeconds(options.LifetimeSeconds).ToUnixTimeSeconds()
        };

        if (options.Scope is not null)
            claims["scope"] = options.Scope;

        if (options.Mission is not null)
        {
            claims["mission"] = new Dictionary<string, object>
            {
                ["approver"] = options.Mission.Approver,
                ["s256"] = options.Mission.S256
            };
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = signingCredentials,
            TokenType = "aa-resource+jwt"
        };

        return handler.CreateToken(descriptor);
    }

    /// <summary>
    /// Decode a resource token from a raw JWT string without signature verification.
    /// </summary>
    public static ResourceToken Decode(string rawJwt)
    {
        var handler = new JsonWebTokenHandler();
        var token = handler.ReadJsonWebToken(rawJwt);

        var typ = token.Typ;
        if (typ != "aa-resource+jwt")
            throw new AAuthTokenException("invalid_resource_token", $"Expected typ aa-resource+jwt, got {typ}");

        var dwk = token.GetClaim("dwk").Value;
        if (dwk != "aauth-resource.json")
            throw new AAuthTokenException("invalid_resource_token", $"Expected dwk aauth-resource.json, got {dwk}");

        var iss = token.Issuer;
        var aud = token.Audiences.FirstOrDefault() ?? throw new AAuthTokenException("invalid_resource_token", "Missing aud");
        var jti = token.Id;
        var agent = token.GetClaim("agent").Value;
        var agentJkt = token.GetClaim("agent_jkt").Value;

        string? scope = null;
        if (token.TryGetClaim("scope", out var scopeClaim))
            scope = scopeClaim.Value;

        Mission? mission = null;
        if (token.TryGetClaim("mission", out var missionClaim))
        {
            var missionDict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(missionClaim.Value);
            if (missionDict is not null && missionDict.TryGetValue("approver", out var approver) &&
                missionDict.TryGetValue("s256", out var s256))
            {
                mission = new Mission(approver, s256);
            }
        }

        var iat = DateTimeOffset.FromUnixTimeSeconds(token.GetClaim("iat").GetLong());
        var exp = DateTimeOffset.FromUnixTimeSeconds(token.GetClaim("exp").GetLong());

        return new ResourceToken(iss, dwk, aud, jti, agent, agentJkt, scope, mission, iat, exp, rawJwt);
    }
}
