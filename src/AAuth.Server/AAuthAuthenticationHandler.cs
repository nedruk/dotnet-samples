using System.Security.Claims;
using System.Text.Encodings.Web;
using AAuth.Core.Discovery;
using AAuth.Core.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AAuth.Server;

/// <summary>
/// ASP.NET Core authentication handler for AAuth protocol.
/// </summary>
public sealed class AAuthAuthenticationHandler : AuthenticationHandler<AAuthAuthenticationSchemeOptions>
{
    private readonly TokenVerifier _verifier;

    public AAuthAuthenticationHandler(
        IOptionsMonitor<AAuthAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        TokenVerifier verifier)
        : base(options, logger, encoder)
    {
        _verifier = verifier;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Check for Signature header (required for AAuth)
        if (!Request.Headers.ContainsKey("Signature"))
            return AuthenticateResult.NoResult();

        try
        {
            // Convert ASP.NET Core request to HttpRequestMessage for signature verification
            var httpRequest = await ConvertToHttpRequestMessage();

            // Check if this is an auth token or agent token request
            var signatureKeyHeader = Request.Headers["Signature-Key"].FirstOrDefault();
            if (signatureKeyHeader is null)
                return AuthenticateResult.Fail("Missing Signature-Key header");

            VerifiedAgent verified;
            var jwt = AAuth.Core.Signatures.SignatureKeyHeader.ExtractJwt(signatureKeyHeader);
            if (jwt is not null)
            {
                // Try to detect token type from JWT header
                var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
                var token = handler.ReadJsonWebToken(jwt);

                if (token.Typ == "aa-auth+jwt")
                    verified = await _verifier.VerifyAuthTokenSignatureAsync(httpRequest);
                else
                    verified = await _verifier.VerifyAgentSignatureAsync(httpRequest);
            }
            else
            {
                return AuthenticateResult.Fail("Invalid Signature-Key format");
            }

            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, verified.AgentIdentifier),
                new("aauth_thumbprint", verified.Thumbprint),
                new("aauth_token_type", verified.TokenType)
            };

            if (verified.Subject is not null)
                claims.Add(new Claim(ClaimTypes.Name, verified.Subject));
            if (verified.Scope is not null)
                claims.Add(new Claim("scope", verified.Scope));
            if (verified.Tenant is not null)
                claims.Add(new Claim("tenant", verified.Tenant));

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        catch (AAuthTokenException ex)
        {
            Logger.LogWarning(ex, "AAuth token validation failed: {Code}", ex.Code);
            return AuthenticateResult.Fail(ex.Message);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "AAuth authentication error");
            return AuthenticateResult.Fail("Authentication failed");
        }
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 401;
        Response.Headers["WWW-Authenticate"] = "AAuth";
        return Task.CompletedTask;
    }

    private async Task<HttpRequestMessage> ConvertToHttpRequestMessage()
    {
        var request = new HttpRequestMessage(
            new HttpMethod(Request.Method),
            new Uri($"{Request.Scheme}://{Request.Host}{Request.PathBase}{Request.Path}{Request.QueryString}"));

        foreach (var header in Request.Headers)
        {
            if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                request.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
        }

        if (Request.ContentLength > 0 || Request.Body.CanRead)
        {
            var ms = new MemoryStream();
            await Request.Body.CopyToAsync(ms);
            ms.Position = 0;
            request.Content = new StreamContent(ms);

            if (Request.ContentType is not null)
                request.Content.Headers.TryAddWithoutValidation("Content-Type", Request.ContentType);
        }

        return request;
    }
}

/// <summary>
/// Options for the AAuth authentication scheme.
/// </summary>
public sealed class AAuthAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
}
