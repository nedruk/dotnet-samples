using AAuth.Core.Headers;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Server;

/// <summary>
/// Creates resource tokens for the three-party auth flow.
/// </summary>
public sealed class ResourceTokenFactory
{
    private readonly AAuthServerOptions _options;

    public ResourceTokenFactory(AAuthServerOptions options)
    {
        _options = options;
    }

    /// <summary>
    /// Create a resource token and build the 401 challenge response.
    /// </summary>
    public async Task<ChallengeResponse> CreateChallengeAsync(
        VerifiedAgent agent, string? scope = null, Mission? mission = null)
    {
        if (_options.AuthServerUrl is null)
            throw new InvalidOperationException("AuthServerUrl is required for three-party mode");

        var km = await _options.GetKeyMaterial();

        SigningCredentials signingCredentials;

        // For resource tokens, the server signs with its own key
        if (km.SigningKey is System.Security.Cryptography.ECDsa ecdsa)
        {
            var ecKey = new ECDsaSecurityKey(ecdsa);
            signingCredentials = new SigningCredentials(ecKey, SecurityAlgorithms.EcdsaSha256);
        }
        else
        {
            throw new NotSupportedException($"Unsupported signing key type: {km.SigningKey.GetType()}");
        }

        var resourceTokenJwt = ResourceToken.Create(new ResourceTokenOptions
        {
            Resource = _options.ServerIdentifier,
            AuthServer = _options.AuthServerUrl,
            Agent = agent.AgentIdentifier,
            AgentJkt = agent.Thumbprint,
            Scope = scope ?? _options.RequiredScope,
            Mission = mission
        }, signingCredentials);

        var requirementHeader = AAuthRequirement.BuildAuthToken(resourceTokenJwt);

        return new ChallengeResponse(resourceTokenJwt, requirementHeader);
    }
}

/// <summary>
/// The 401 challenge response to send back to the agent.
/// </summary>
public sealed record ChallengeResponse(string ResourceToken, string RequirementHeader);
