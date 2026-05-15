using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Core.Tokens;

/// <summary>
/// Represents a verified AAuth auth token (typ: aa-auth+jwt).
/// </summary>
public sealed class AuthToken
{
    public string Issuer { get; }
    public string Dwk { get; }
    public string Audience { get; }
    public string Jti { get; }
    public string Agent { get; }
    public JsonWebKey ConfirmationKey { get; }
    public ActorClaim Actor { get; }
    public string? Subject { get; }
    public string? Scope { get; }
    public string? Tenant { get; }
    public Mission? Mission { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public string RawJwt { get; }

    private AuthToken(string issuer, string dwk, string audience, string jti,
        string agent, JsonWebKey confirmationKey, ActorClaim actor,
        string? subject, string? scope, string? tenant, Mission? mission,
        DateTimeOffset issuedAt, DateTimeOffset expiresAt, string rawJwt)
    {
        Issuer = issuer;
        Dwk = dwk;
        Audience = audience;
        Jti = jti;
        Agent = agent;
        ConfirmationKey = confirmationKey;
        Actor = actor;
        Subject = subject;
        Scope = scope;
        Tenant = tenant;
        Mission = mission;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        RawJwt = rawJwt;
    }

    /// <summary>
    /// Decode an auth token from a raw JWT string without signature verification.
    /// </summary>
    public static AuthToken Decode(string rawJwt)
    {
        var handler = new JsonWebTokenHandler();
        var token = handler.ReadJsonWebToken(rawJwt);

        var typ = token.Typ;
        if (typ != "aa-auth+jwt")
            throw new AAuthTokenException("invalid_auth_token", $"Expected typ aa-auth+jwt, got {typ}");

        var dwk = token.GetClaim("dwk").Value;
        if (dwk != "aauth-access.json" && dwk != "aauth-person.json")
            throw new AAuthTokenException("invalid_auth_token", $"Expected dwk aauth-access.json or aauth-person.json, got {dwk}");

        var iss = token.Issuer;
        var aud = token.Audiences.FirstOrDefault() ?? throw new AAuthTokenException("invalid_auth_token", "Missing aud");
        var jti = token.Id;
        var agent = token.GetClaim("agent").Value;

        // Extract cnf.jwk
        var cnfClaim = token.GetClaim("cnf");
        var cnfDict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(cnfClaim.Value)!;
        var jwkJson = cnfDict["jwk"].GetRawText();
        var confirmationKey = new JsonWebKey(jwkJson);

        // Extract act claim
        var actClaim = token.GetClaim("act");
        var actor = ParseActorClaim(actClaim.Value);

        string? subject = null;
        if (token.TryGetClaim("sub", out var subClaim))
            subject = subClaim.Value;

        string? scope = null;
        if (token.TryGetClaim("scope", out var scopeClaim))
            scope = scopeClaim.Value;

        string? tenant = null;
        if (token.TryGetClaim("tenant", out var tenantClaim))
            tenant = tenantClaim.Value;

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

        // At least one of sub or scope must be present
        if (subject is null && scope is null)
            throw new AAuthTokenException("invalid_auth_token", "Auth token must contain at least sub or scope");

        var iat = DateTimeOffset.FromUnixTimeSeconds(token.GetClaim("iat").GetLong());
        var exp = DateTimeOffset.FromUnixTimeSeconds(token.GetClaim("exp").GetLong());

        return new AuthToken(iss, dwk, aud, jti, agent, confirmationKey, actor,
            subject, scope, tenant, mission, iat, exp, rawJwt);
    }

    private static ActorClaim ParseActorClaim(string actJson)
    {
        var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(actJson)!;
        var sub = dict["sub"].GetString() ?? throw new AAuthTokenException("invalid_auth_token", "act.sub is required");

        ActorClaim? nested = null;
        if (dict.TryGetValue("act", out var nestedAct))
        {
            nested = ParseActorClaim(nestedAct.GetRawText());
        }

        return new ActorClaim(sub, nested);
    }
}
