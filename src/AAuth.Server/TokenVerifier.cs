using AAuth.Core.Discovery;
using AAuth.Core.Identifiers;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Server;

/// <summary>
/// Result of token verification.
/// </summary>
public sealed class VerifiedAgent
{
    public required string AgentIdentifier { get; init; }
    public required string Thumbprint { get; init; }
    public string? Subject { get; init; }
    public string? Scope { get; init; }
    public string? Tenant { get; init; }
    public Mission? Mission { get; init; }
    public string TokenType { get; init; } = "agent";
}

/// <summary>
/// Verifies agent identity from AAuth-signed requests.
/// </summary>
public sealed class TokenVerifier
{
    private static readonly TimeSpan MaxAuthTokenLifetime = TimeSpan.FromHours(1);
    private readonly AAuthServerOptions _options;
    private readonly IssuerKeyResolver _keyResolver;

    public TokenVerifier(AAuthServerOptions options, IssuerKeyResolver keyResolver)
    {
        _options = options;
        _keyResolver = keyResolver;
    }

    /// <summary>
    /// Verify a signed request containing an agent token in the Signature-Key header.
    /// </summary>
    public async Task<VerifiedAgent> VerifyAgentSignatureAsync(
        HttpRequestMessage request, CancellationToken ct = default)
    {
        // 1. Parse signature-key header to get the JWT
        var signatureKeyHeader = request.Headers.GetValues("Signature-Key").FirstOrDefault()
            ?? throw new AAuthTokenException("missing_signature_key", "Missing Signature-Key header");

        var jwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeader)
            ?? throw new AAuthTokenException("invalid_signature_key", "Signature-Key does not contain a JWT");

        // 2. Decode agent token
        var agentToken = AgentToken.Decode(jwt);

        ValidateServerIdentifierClaim(agentToken.Issuer, "invalid_agent_token", "iss");

        // 3. Discover issuer keys and verify JWT signature
        await ValidateJwtSignatureAsync(
            jwt,
            agentToken.Issuer,
            agentToken.Dwk,
            "aa-agent+jwt",
            "invalid_agent_token",
            ct);

        // 4. Validate token claims
        ValidateAgentTokenClaims(agentToken);

        // 5. Verify HTTP message signature using the confirmation key from the token
        var verifyResult = HttpMessageSigner.Verify(request);
        if (!verifyResult.IsValid)
            throw new AAuthTokenException("invalid_signature", "HTTP message signature verification failed");

        // 6. Verify that the signature was made with the key bound in the token (cnf.jwk)
        var expectedThumbprint = JsonWebKeyThumbprint.Compute(agentToken.ConfirmationKey);
        if (verifyResult.Thumbprint != expectedThumbprint)
            throw new AAuthTokenException("key_mismatch", "Signature key does not match token confirmation key");

        return new VerifiedAgent
        {
            AgentIdentifier = agentToken.Subject,
            Thumbprint = expectedThumbprint,
            TokenType = "agent"
        };
    }

    /// <summary>
    /// Verify a signed request containing an auth token in the Signature-Key header.
    /// </summary>
    public async Task<VerifiedAgent> VerifyAuthTokenSignatureAsync(
        HttpRequestMessage request, CancellationToken ct = default)
    {
        var signatureKeyHeader = request.Headers.GetValues("Signature-Key").FirstOrDefault()
            ?? throw new AAuthTokenException("missing_signature_key", "Missing Signature-Key header");

        var jwt = SignatureKeyHeader.ExtractJwt(signatureKeyHeader)
            ?? throw new AAuthTokenException("invalid_signature_key", "Signature-Key does not contain a JWT");

        var authToken = AuthToken.Decode(jwt);

        ValidateServerIdentifierClaim(authToken.Issuer, "invalid_auth_token", "iss");
        ValidateServerIdentifierClaim(authToken.Audience, "invalid_auth_token", "aud");

        // Verify audience matches this server
        if (!string.Equals(authToken.Audience, _options.ServerIdentifier, StringComparison.OrdinalIgnoreCase))
            throw new AAuthTokenException("invalid_audience", $"Token audience {authToken.Audience} does not match server {_options.ServerIdentifier}");

        // Discover PS keys and verify JWT signature
        await ValidateJwtSignatureAsync(
            jwt,
            authToken.Issuer,
            authToken.Dwk,
            "aa-auth+jwt",
            "invalid_auth_token",
            ct);

        // Validate claims
        ValidateAuthTokenClaims(authToken);

        // Verify HTTP message signature
        var verifyResult = HttpMessageSigner.Verify(request);
        if (!verifyResult.IsValid)
            throw new AAuthTokenException("invalid_signature", "HTTP message signature verification failed");

        var expectedThumbprint = JsonWebKeyThumbprint.Compute(authToken.ConfirmationKey);
        if (verifyResult.Thumbprint != expectedThumbprint)
            throw new AAuthTokenException("key_mismatch", "Signature key does not match token confirmation key");

        return new VerifiedAgent
        {
            AgentIdentifier = authToken.Agent,
            Thumbprint = expectedThumbprint,
            Subject = authToken.Subject,
            Scope = authToken.Scope,
            Tenant = authToken.Tenant,
            Mission = authToken.Mission,
            TokenType = "auth"
        };
    }

    private async Task ValidateJwtSignatureAsync(
        string jwt,
        string issuer,
        string dwk,
        string tokenType,
        string errorCode,
        CancellationToken ct)
    {
        var keys = await _keyResolver.ResolveKeysAsync(issuer, dwk, ct);
        if (keys.Keys.Count == 0)
            throw new AAuthTokenException("no_issuer_keys", $"No keys found for issuer {issuer}");

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            IssuerSigningKeys = keys.Keys,
            ValidTypes = new[] { tokenType }
        };

        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(jwt, validationParameters);
        if (!result.IsValid)
        {
            var detail = result.Exception?.Message ?? "JWT signature validation failed";
            throw new AAuthTokenException(errorCode, detail);
        }
    }

    private void ValidateAgentTokenClaims(AgentToken token)
    {
        var now = DateTimeOffset.UtcNow;
        if (token.ExpiresAt + _options.ClockSkew < now)
            throw new AAuthTokenException("token_expired", "Agent token has expired");
        if (token.IssuedAt - _options.ClockSkew > now)
            throw new AAuthTokenException("token_not_yet_valid", "Agent token is not yet valid");

        // Spec: If ps is present, verify it is a valid HTTPS URL conforming to Server Identifier requirements
        if (token.PersonServerUrl is not null)
            ValidateServerIdentifierClaim(token.PersonServerUrl, "invalid_agent_token", "ps");
    }

    private void ValidateAuthTokenClaims(AuthToken token)
    {
        var now = DateTimeOffset.UtcNow;
        if (token.ExpiresAt + _options.ClockSkew < now)
            throw new AAuthTokenException("token_expired", "Auth token has expired");
        if (token.IssuedAt - _options.ClockSkew > now)
            throw new AAuthTokenException("token_not_yet_valid", "Auth token is not yet valid");
        if (token.ExpiresAt - token.IssuedAt > MaxAuthTokenLifetime + _options.ClockSkew)
            throw new AAuthTokenException("invalid_auth_token", "Auth token lifetime exceeds maximum allowed duration");

        // Spec: Verify act is present and act.sub matches the agent identifier
        if (token.Actor is null)
            throw new AAuthTokenException("invalid_auth_token", "Auth token must contain act claim");
        if (!string.Equals(token.Actor.Subject, token.Agent, StringComparison.Ordinal))
            throw new AAuthTokenException("invalid_auth_token", "Auth token act.sub does not match agent claim");

        if (_options.RequiredScope is not null)
        {
            if (string.IsNullOrWhiteSpace(token.Scope))
                throw new AAuthTokenException("insufficient_scope", "Token scope is insufficient");

            var grantedScopes = token.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var requiredScopes = _options.RequiredScope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (!requiredScopes.All(r => grantedScopes.Contains(r, StringComparer.Ordinal)))
                throw new AAuthTokenException("insufficient_scope", "Token scope is insufficient");
        }

        if (_options.RequireMission && token.Mission is null)
            throw new AAuthTokenException("mission_required", "Mission context is required");
    }

    private static void ValidateServerIdentifierClaim(string value, string errorCode, string claimName)
    {
        try
        {
            ServerIdentifier.Validate(value);
        }
        catch (FormatException ex)
        {
            if (IsAllowedDevLoopbackIdentifier(value))
                return;

            throw new AAuthTokenException(errorCode, $"Token claim '{claimName}' is not a valid server identifier: {ex.Message}");
        }
    }

    private static bool IsAllowedDevLoopbackIdentifier(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            return false;

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!(uri.IsLoopback || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)))
            return false;

        if (uri.AbsolutePath != "/")
            return false;

        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            return false;

        return true;
    }
}
