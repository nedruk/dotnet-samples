using AAuth.Core.Identifiers;
using Xunit;

namespace AAuth.Core.Tests;

public class ServerIdentifierTests
{
    [Theory]
    [InlineData("https://example.com")]
    [InlineData("https://sub.domain.example.com")]
    public void IsValid_ValidIdentifiers_ReturnsTrue(string input)
    {
        Assert.True(ServerIdentifier.IsValid(input));
    }

    [Theory]
    [InlineData("http://example.com")]
    [InlineData("https://example.com:8080")]
    [InlineData("https://example.com/path")]
    [InlineData("https://example.com?query=1")]
    [InlineData("https://EXAMPLE.COM")]
    [InlineData("")]
    [InlineData("not-a-url")]
    public void IsValid_InvalidIdentifiers_ReturnsFalse(string input)
    {
        Assert.False(ServerIdentifier.IsValid(input));
    }

    [Fact]
    public void Validate_InvalidIdentifier_Throws()
    {
        Assert.Throws<FormatException>(() => ServerIdentifier.Validate("http://example.com"));
    }

    [Fact]
    public void Validate_ValidIdentifier_DoesNotThrow()
    {
        ServerIdentifier.Validate("https://example.com");
    }
}
