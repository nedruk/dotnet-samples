using System.Text;
using System.Text.RegularExpressions;

namespace AAuth.Core.Signatures;

/// <summary>
/// Represents and parses/serializes the Signature-Input header per RFC 9421.
/// </summary>
public sealed partial class SignatureInput
{
    public IReadOnlyList<string> CoveredComponents { get; }
    public long Created { get; }

    public SignatureInput(IReadOnlyList<string> coveredComponents, long created)
    {
        CoveredComponents = coveredComponents;
        Created = created;
    }

    /// <summary>
    /// Serialize to header value: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
    /// </summary>
    public string Serialize()
    {
        return $"sig={SerializeComponents(CoveredComponents, Created)}";
    }

    /// <summary>
    /// Serialize the inner component list with params.
    /// </summary>
    internal static string SerializeComponents(IReadOnlyList<string> components, long created)
    {
        var sb = new StringBuilder();
        sb.Append('(');
        for (int i = 0; i < components.Count; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append('"');
            sb.Append(components[i]);
            sb.Append('"');
        }
        sb.Append(')');
        sb.Append(";created=");
        sb.Append(created);
        return sb.ToString();
    }

    /// <summary>
    /// Parse a Signature-Input header value.
    /// Expected format: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
    /// </summary>
    public static SignatureInput Parse(string headerValue)
    {
        // Remove the "sig=" prefix if present
        var value = headerValue;
        if (value.StartsWith("sig=", StringComparison.OrdinalIgnoreCase))
            value = value[4..];

        // Extract components from parentheses
        var parenStart = value.IndexOf('(');
        var parenEnd = value.IndexOf(')');
        if (parenStart < 0 || parenEnd < 0 || parenEnd <= parenStart)
            throw new FormatException("Invalid Signature-Input: missing component list");

        var componentStr = value[(parenStart + 1)..parenEnd];
        var components = ComponentRegex()
            .Matches(componentStr)
            .Select(m => m.Groups[1].Value)
            .ToList();

        // Extract created parameter
        var paramsStr = value[(parenEnd + 1)..];
        var createdMatch = CreatedRegex().Match(paramsStr);
        if (!createdMatch.Success)
            throw new FormatException("Invalid Signature-Input: missing created parameter");

        var created = long.Parse(createdMatch.Groups[1].Value);

        return new SignatureInput(components, created);
    }

    [GeneratedRegex("\"([^\"]+)\"")]
    private static partial Regex ComponentRegex();

    [GeneratedRegex(@"created=(\d+)")]
    private static partial Regex CreatedRegex();
}
