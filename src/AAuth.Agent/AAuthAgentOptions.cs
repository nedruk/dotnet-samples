using AAuth.Core.Signatures;
using AAuth.Core.Tokens;

namespace AAuth.Agent;

/// <summary>
/// Configuration options for the AAuth agent-side handler.
/// </summary>
public sealed class AAuthAgentOptions
{
    /// <summary>
    /// Delegate to obtain the signing key and signature key (agent token JWT).
    /// </summary>
    public required GetKeyMaterial GetKeyMaterial { get; set; }

    /// <summary>
    /// The PS URL to use for token exchange. If null, discovered from agent token's ps claim.
    /// </summary>
    public string? AuthServerUrl { get; set; }

    /// <summary>
    /// Capabilities the agent supports (interaction, clarification, payment).
    /// </summary>
    public IReadOnlyList<string>? Capabilities { get; set; }

    /// <summary>
    /// Active mission context, if any.
    /// </summary>
    public Mission? Mission { get; set; }

    /// <summary>
    /// Justification string to include in token requests.
    /// </summary>
    public string? Justification { get; set; }

    /// <summary>
    /// Login hint for PS token requests.
    /// </summary>
    public string? LoginHint { get; set; }

    /// <summary>
    /// Tenant identifier for PS token requests.
    /// </summary>
    public string? Tenant { get; set; }

    /// <summary>
    /// Callback for when user interaction is required. Parameters: (url, code).
    /// </summary>
    public Func<string, string, Task>? OnInteraction { get; set; }

    /// <summary>
    /// Callback for when clarification is needed. Parameter: question. Returns: answer.
    /// </summary>
    public Func<string, Task<string>>? OnClarification { get; set; }
}
