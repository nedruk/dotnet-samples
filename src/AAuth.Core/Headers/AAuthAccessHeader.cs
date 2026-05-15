namespace AAuth.Core.Headers;

/// <summary>
/// Builds and parses the AAuth-Access response header (opaque token for two-party mode).
/// </summary>
public static class AAuthAccessHeader
{
    public static string Build(string opaqueToken) => opaqueToken;
    public static string Parse(string headerValue) => headerValue.Trim();
}
