namespace AAuth.Core.Tokens;

/// <summary>
/// Exception thrown when AAuth token validation fails.
/// </summary>
public sealed class AAuthTokenException : Exception
{
    public string Code { get; }

    public AAuthTokenException(string code, string message) : base(message)
    {
        Code = code;
    }

    public AAuthTokenException(string code, string message, Exception innerException) : base(message, innerException)
    {
        Code = code;
    }
}
