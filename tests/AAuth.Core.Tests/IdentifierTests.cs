using AAuth.Core.Identifiers;
using Xunit;

namespace AAuth.Core.Tests;

public class AAuthIdentifierTests
{
    [Theory]
    [InlineData("aauth:agent@example.com")]
    [InlineData("aauth:my-agent@sub.domain.com")]
    [InlineData("aauth:agent_1+test@example.com")]
    [InlineData("aauth:a@b.co")]
    public void Parse_ValidIdentifiers_Succeeds(string input)
    {
        var id = AAuthIdentifier.Parse(input);
        Assert.NotNull(id.Local);
        Assert.NotNull(id.Domain);
    }

    [Fact]
    public void Parse_ExtractsComponents()
    {
        var id = AAuthIdentifier.Parse("aauth:my-agent@example.com");
        Assert.Equal("my-agent", id.Local);
        Assert.Equal("example.com", id.Domain);
        Assert.Equal("aauth:my-agent@example.com", id.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("agent@example.com")]
    [InlineData("aauth:@example.com")]
    [InlineData("aauth:agent@")]
    [InlineData("aauth:UPPER@example.com")]
    [InlineData("aauth:inv alid@example.com")]
    public void Parse_InvalidIdentifiers_Throws(string input)
    {
        Assert.Throws<FormatException>(() => AAuthIdentifier.Parse(input));
    }

    [Fact]
    public void TryParse_ValidInput_ReturnsTrue()
    {
        Assert.True(AAuthIdentifier.TryParse("aauth:test@example.com", out var id));
        Assert.Equal("test", id.Local);
    }

    [Fact]
    public void TryParse_InvalidInput_ReturnsFalse()
    {
        Assert.False(AAuthIdentifier.TryParse("invalid", out _));
    }

    [Fact]
    public void Equality_SameIdentifier_Equal()
    {
        var a = AAuthIdentifier.Parse("aauth:test@example.com");
        var b = AAuthIdentifier.Parse("aauth:test@example.com");
        Assert.Equal(a, b);
        Assert.True(a == b);
    }

    [Fact]
    public void Equality_DifferentIdentifier_NotEqual()
    {
        var a = AAuthIdentifier.Parse("aauth:test@example.com");
        var b = AAuthIdentifier.Parse("aauth:other@example.com");
        Assert.NotEqual(a, b);
    }
}
