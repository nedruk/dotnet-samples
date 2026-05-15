using System.Text.RegularExpressions;
using AAuth.Core.Tokens;

namespace AAuth.Core.Headers;

/// <summary>
/// Builds and parses the AAuth-Mission request header.
/// </summary>
public static partial class AAuthMissionHeader
{
    public static string Build(Mission mission) =>
        $"approver=\"{mission.Approver}\"; s256=\"{mission.S256}\"";

    public static Mission Parse(string headerValue)
    {
        var approverMatch = ApproverRegex().Match(headerValue);
        var s256Match = S256Regex().Match(headerValue);

        if (!approverMatch.Success || !s256Match.Success)
            throw new FormatException("Invalid AAuth-Mission header: missing approver or s256");

        return new Mission(approverMatch.Groups[1].Value, s256Match.Groups[1].Value);
    }

    [GeneratedRegex("approver=\"([^\"]+)\"")]
    private static partial Regex ApproverRegex();

    [GeneratedRegex("s256=\"([^\"]+)\"")]
    private static partial Regex S256Regex();
}
