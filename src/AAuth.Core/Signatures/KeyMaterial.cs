using System.Security.Cryptography;

namespace AAuth.Core.Signatures;

/// <summary>
/// Represents the key material needed for AAuth HTTP Message Signatures.
/// </summary>
public sealed class KeyMaterial
{
    /// <summary>
    /// The private key used to create HTTP Message Signatures (Ed25519 or ECDsa).
    /// </summary>
    public required AsymmetricAlgorithm SigningKey { get; init; }

    /// <summary>
    /// The value for the Signature-Key header (JWT token or JWKS URI).
    /// </summary>
    public required SignatureKeyValue SignatureKey { get; init; }
}

/// <summary>
/// Value types for the Signature-Key header.
/// </summary>
public abstract record SignatureKeyValue
{
    /// <summary>JWT-based signature key (scheme=jwt). Used with agent tokens and auth tokens.</summary>
    public sealed record Jwt(string Token) : SignatureKeyValue;

    /// <summary>JWKS URI-based signature key (scheme=jwks_uri). Used for PS-to-AS federation.</summary>
    public sealed record JwksUri(string Uri) : SignatureKeyValue;
}

/// <summary>
/// Delegate to obtain key material for signing requests.
/// </summary>
public delegate Task<KeyMaterial> GetKeyMaterial();
