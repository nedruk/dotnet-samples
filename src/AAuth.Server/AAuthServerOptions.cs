using AAuth.Core.Signatures;
using AAuth.Core.Tokens;

namespace AAuth.Server;

/// <summary>
/// Configuration options for the AAuth server-side authentication handler.
/// </summary>
public sealed class AAuthServerOptions
{
    /// <summary>
    /// The server's own identifier (HTTPS origin).
    /// </summary>
    public required string ServerIdentifier { get; set; }

    /// <summary>
    /// Delegate to obtain the server's signing key material for creating resource tokens.
    /// </summary>
    public required GetKeyMaterial GetKeyMaterial { get; set; }

    /// <summary>
    /// The auth server URL that resource tokens should be directed to.
    /// Required for three-party mode.
    /// </summary>
    public string? AuthServerUrl { get; set; }

    /// <summary>
    /// Access modes the server supports.
    /// </summary>
    public AccessMode SupportedModes { get; set; } = AccessMode.IdentityBased;

    /// <summary>
    /// Required scope for access. Null means no scope enforcement.
    /// </summary>
    public string? RequiredScope { get; set; }

    /// <summary>
    /// Whether to require a mission context.
    /// </summary>
    public bool RequireMission { get; set; }

    /// <summary>
    /// Clock skew tolerance for token validation. Default 5 minutes.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);
}

[Flags]
public enum AccessMode
{
    IdentityBased = 1,
    TwoParty = 2,
    ThreeParty = 4,
    FourParty = 8
}
