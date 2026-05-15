namespace AAuth.Core.Identifiers;

/// <summary>
/// Validates AAuth server identifiers (HTTPS URLs with no port, path, query, or fragment).
/// </summary>
public static class ServerIdentifier
{
    public static bool IsValid(string? url)
    {
        if (string.IsNullOrEmpty(url))
            return false;

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        if (uri.Scheme != "https")
            return false;

        if (!uri.IsDefaultPort)
            return false;

        if (uri.AbsolutePath != "/")
            return false;

        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            return false;

        if (url.EndsWith('/'))
            return false;

        if (url != url.ToLowerInvariant())
            return false;

        return true;
    }

    public static void Validate(string url)
    {
        if (!IsValid(url))
            throw new FormatException(
                $"Invalid server identifier '{url}'. Must be HTTPS, lowercase, with no port, path, query, or fragment.");
    }
}
