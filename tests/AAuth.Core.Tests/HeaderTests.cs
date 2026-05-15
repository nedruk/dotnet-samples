using AAuth.Core.Headers;
using AAuth.Core.Tokens;
using Xunit;

namespace AAuth.Core.Tests;

public class HeaderTests
{
    [Fact]
    public void AAuthRequirement_BuildAuthToken_RoundTrip()
    {
        var header = AAuthRequirement.BuildAuthToken("eyJ.test.token");
        var challenge = AAuthRequirement.Parse(header);
        Assert.Equal("auth-token", challenge.Requirement);
        Assert.Equal("eyJ.test.token", challenge.ResourceToken);
    }

    [Fact]
    public void AAuthRequirement_BuildInteraction_RoundTrip()
    {
        var header = AAuthRequirement.BuildInteraction("https://ps.example.com/interact", "abc123");
        var challenge = AAuthRequirement.Parse(header);
        Assert.Equal("interaction", challenge.Requirement);
        Assert.Equal("https://ps.example.com/interact", challenge.Url);
        Assert.Equal("abc123", challenge.Code);
    }

    [Fact]
    public void AAuthRequirement_BuildApproval_RoundTrip()
    {
        var header = AAuthRequirement.BuildApproval();
        var challenge = AAuthRequirement.Parse(header);
        Assert.Equal("approval", challenge.Requirement);
    }

    [Fact]
    public void AAuthCapabilities_BuildAndParse()
    {
        var header = AAuthCapabilitiesHeader.Build(new[] { "interaction", "clarification" });
        var parsed = AAuthCapabilitiesHeader.Parse(header);
        Assert.Contains("interaction", parsed);
        Assert.Contains("clarification", parsed);
    }

    [Fact]
    public void AAuthCapabilities_FiltersInvalid()
    {
        var parsed = AAuthCapabilitiesHeader.Parse("interaction, invalid, clarification");
        Assert.Equal(2, parsed.Count);
        Assert.DoesNotContain("invalid", parsed);
    }

    [Fact]
    public void AAuthMission_RoundTrip()
    {
        var mission = new Mission("https://ps.example.com", "sha256hash");
        var header = AAuthMissionHeader.Build(mission);
        var parsed = AAuthMissionHeader.Parse(header);
        Assert.Equal(mission.Approver, parsed.Approver);
        Assert.Equal(mission.S256, parsed.S256);
    }

    [Fact]
    public void AAuthAccessHeader_RoundTrip()
    {
        var token = "opaque-access-token-123";
        var header = AAuthAccessHeader.Build(token);
        Assert.Equal(token, AAuthAccessHeader.Parse(header));
    }
}
