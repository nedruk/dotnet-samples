using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace AAuth.Core.Identifiers;

/// <summary>
/// Represents an AAuth agent identifier URI of the form aauth:local@domain.
/// </summary>
public readonly partial struct AAuthIdentifier : IEquatable<AAuthIdentifier>
{
    private static readonly Regex LocalPartRegex = CreateLocalPartRegex();

    public string Local { get; }
    public string Domain { get; }

    private AAuthIdentifier(string local, string domain)
    {
        Local = local;
        Domain = domain;
    }

    public static AAuthIdentifier Parse(string uri)
    {
        if (!TryParse(uri, out var result))
            throw new FormatException($"Invalid AAuth identifier: {uri}");
        return result;
    }

    public static bool TryParse(string? uri, [NotNullWhen(true)] out AAuthIdentifier result)
    {
        result = default;

        if (string.IsNullOrEmpty(uri))
            return false;

        if (!uri.StartsWith("aauth:", StringComparison.Ordinal))
            return false;

        var rest = uri.AsSpan(6); // skip "aauth:"
        var atIndex = rest.IndexOf('@');
        if (atIndex <= 0 || atIndex == rest.Length - 1)
            return false;

        var local = rest[..atIndex].ToString();
        var domain = rest[(atIndex + 1)..].ToString();

        if (local.Length > 255)
            return false;

        if (!LocalPartRegex.IsMatch(local))
            return false;

        // Domain must be a valid hostname (simplified: no scheme, no port, no path)
        if (domain.Contains("://", StringComparison.Ordinal) ||
            domain.Contains('/', StringComparison.Ordinal) ||
            domain.Contains(':', StringComparison.Ordinal) ||
            domain.Contains(' ', StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(domain))
            return false;

        result = new AAuthIdentifier(local, domain);
        return true;
    }

    public override string ToString() => $"aauth:{Local}@{Domain}";

    public bool Equals(AAuthIdentifier other) =>
        string.Equals(Local, other.Local, StringComparison.Ordinal) &&
        string.Equals(Domain, other.Domain, StringComparison.Ordinal);

    public override bool Equals(object? obj) => obj is AAuthIdentifier other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(Local, Domain);

    public static bool operator ==(AAuthIdentifier left, AAuthIdentifier right) => left.Equals(right);
    public static bool operator !=(AAuthIdentifier left, AAuthIdentifier right) => !left.Equals(right);

    [GeneratedRegex("^[a-z0-9\\-_+.]+$")]
    private static partial Regex CreateLocalPartRegex();
}
