namespace AAuth.Core.Headers;

/// <summary>
/// Builds and parses the AAuth-Capabilities request header.
/// </summary>
public static class AAuthCapabilitiesHeader
{
    private static readonly HashSet<string> ValidCapabilities = new(StringComparer.OrdinalIgnoreCase)
    {
        "interaction", "clarification", "payment"
    };

    public static string Build(IEnumerable<string> capabilities) =>
        string.Join(", ", capabilities);

    public static IReadOnlyList<string> Parse(string headerValue)
    {
        return headerValue
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Where(s => ValidCapabilities.Contains(s))
            .ToList();
    }
}
