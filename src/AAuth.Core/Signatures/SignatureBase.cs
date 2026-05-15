using System.Text;

namespace AAuth.Core.Signatures;

/// <summary>
/// Builds RFC 9421 signature base strings for the AAuth profile.
/// </summary>
public static class SignatureBase
{
    /// <summary>
    /// Build the signature base string from an HTTP request.
    /// AAuth requires: @method, @authority, @path, signature-key.
    /// Additional components can be specified (e.g., aauth-mission, authorization, content-digest).
    /// </summary>
    public static string Build(
        HttpMethod method,
        Uri requestUri,
        string signatureKeyHeaderValue,
        IReadOnlyDictionary<string, string>? headerValues = null,
        IReadOnlyList<string>? additionalComponents = null,
        long created = 0)
    {
        var components = GetCoveredComponents(additionalComponents);
        var sb = new StringBuilder();

        foreach (var component in components)
        {
            sb.Append('"');
            sb.Append(component);
            sb.Append("\": ");

            var value = component switch
            {
                "@method" => method.Method,
                "@authority" => requestUri.Authority.ToLowerInvariant(),
                "@path" => requestUri.AbsolutePath,
                "signature-key" => signatureKeyHeaderValue,
                _ => headerValues?.GetValueOrDefault(component)
                     ?? throw new ArgumentException($"Missing header value for component: {component}")
            };

            sb.Append(value);
            sb.Append('\n');
        }

        // Final line: signature params
        sb.Append("\"@signature-params\": ");
        sb.Append(SignatureInput.SerializeComponents(components, created));

        return sb.ToString();
    }

    internal static IReadOnlyList<string> GetCoveredComponents(IReadOnlyList<string>? additional)
    {
        var baseComponents = new List<string> { "@method", "@authority", "@path", "signature-key" };

        if (additional is { Count: > 0 })
        {
            foreach (var c in additional)
            {
                if (!baseComponents.Contains(c, StringComparer.OrdinalIgnoreCase))
                    baseComponents.Add(c);
            }
        }

        return baseComponents;
    }
}
