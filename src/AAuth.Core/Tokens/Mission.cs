namespace AAuth.Core.Tokens;

/// <summary>
/// Represents an AAuth mission context (approver URL and SHA-256 hash of the approved mission JSON).
/// </summary>
public sealed record Mission(string Approver, string S256);

/// <summary>
/// Represents the actor claim (act) in auth tokens, supporting nested delegation chains.
/// </summary>
public sealed record ActorClaim(string Subject, ActorClaim? Nested = null);
