using AAuth.Core.Tokens;

namespace AAuth.Core.Headers;

/// <summary>
/// Builds and parses the AAuth-Requirement response header.
/// </summary>
public static class AAuthRequirement
{
    public static string BuildAuthToken(string resourceToken) =>
        $"requirement=auth-token; resource-token=\"{resourceToken}\"";

    public static string BuildInteraction(string url, string code) =>
        $"requirement=interaction; url=\"{url}\"; code=\"{code}\"";

    public static string BuildApproval() => "requirement=approval";
    public static string BuildClarification() => "requirement=clarification";
    public static string BuildClaims() => "requirement=claims";

    /// <summary>
    /// Parse an AAuth-Requirement header value into a challenge record.
    /// </summary>
    public static AAuthChallenge Parse(string headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
            throw new FormatException("Empty AAuth-Requirement header");

        string? requirement = null;
        string? resourceToken = null;
        string? url = null;
        string? code = null;

        // Parse key=value and key="value" pairs
        var parts = headerValue.Split(';', StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            var eqIndex = part.IndexOf('=');
            if (eqIndex < 0) continue;

            var key = part[..eqIndex].Trim();
            var value = part[(eqIndex + 1)..].Trim().Trim('"');

            switch (key)
            {
                case "requirement":
                    requirement = value;
                    break;
                case "resource-token":
                    resourceToken = value;
                    break;
                case "url":
                    url = value;
                    break;
                case "code":
                    code = value;
                    break;
            }
        }

        if (requirement is null)
            throw new FormatException("AAuth-Requirement header missing requirement parameter");

        return new AAuthChallenge(requirement, resourceToken, url, code);
    }
}

/// <summary>
/// Parsed AAuth-Requirement challenge.
/// </summary>
public sealed record AAuthChallenge(
    string Requirement,
    string? ResourceToken = null,
    string? Url = null,
    string? Code = null);
