using AAuth.Core.Signatures;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Core.Tests;

public class SignatureInputTests
{
    [Fact]
    public void Serialize_ProducesValidFormat()
    {
        var input = new SignatureInput(
            new[] { "@method", "@authority", "@path", "signature-key" },
            1700000000L);

        var serialized = input.Serialize();

        Assert.StartsWith("sig=(", serialized);
        Assert.Contains("\"@method\"", serialized);
        Assert.Contains(";created=1700000000", serialized);
    }

    [Fact]
    public void Parse_RoundTrip_Succeeds()
    {
        var original = new SignatureInput(
            new[] { "@method", "@authority", "@path", "signature-key" },
            1700000000L);

        var serialized = original.Serialize();
        var parsed = SignatureInput.Parse(serialized);

        Assert.Equal(original.CoveredComponents.Count, parsed.CoveredComponents.Count);
        Assert.Equal(original.Created, parsed.Created);
    }
}
