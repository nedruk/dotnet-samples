using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AAuth.Core.Discovery;
using AAuth.Core.Headers;
using AAuth.Core.Identifiers;
using AAuth.Core.Signatures;
using AAuth.Core.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Agent;

/// <summary>
/// DelegatingHandler that adds AAuth HTTP Message Signatures to outgoing requests
/// and handles 401 AAuth challenges (token exchange) and 202 deferred responses.
/// </summary>
public sealed class AAuthDelegatingHandler : DelegatingHandler
{
    private static readonly TimeSpan ResourceTokenClockSkew = TimeSpan.FromMinutes(5);

    private readonly AAuthAgentOptions _options;
    private readonly IssuerKeyResolver _keyResolver;
    private readonly TokenCache _tokenCache = new();

    public AAuthDelegatingHandler(AAuthAgentOptions options, IssuerKeyResolver keyResolver)
    {
        _options = options;
        _keyResolver = keyResolver;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var resourceOrigin = new Uri(request.RequestUri!.GetLeftPart(UriPartial.Authority));

        // 1. Try cached auth token
        var cached = _tokenCache.FindAuthToken(resourceOrigin.ToString());
        if (cached is not null)
        {
            var response = await SendSignedWithAuthToken(request, cached.Token, cancellationToken);
            if (response.StatusCode != HttpStatusCode.Unauthorized)
            {
                CacheAccessTokenFromResponse(resourceOrigin.ToString(), response);
                return await HandleResourceInteraction(response, cancellationToken);
            }
            _tokenCache.RemoveAuthToken(resourceOrigin.ToString(), cached.AuthServer);
        }

        // 2. Try cached opaque access token (two-party)
        var cachedAccess = _tokenCache.FindAccessToken(resourceOrigin.ToString());
        if (cachedAccess is not null)
        {
            var response = await SendSignedWithAccessToken(request, cachedAccess, cancellationToken);
            if (response.StatusCode != HttpStatusCode.Unauthorized)
            {
                CacheAccessTokenFromResponse(resourceOrigin.ToString(), response);
                return await HandleResourceInteraction(response, cancellationToken);
            }
            _tokenCache.RemoveAccessToken(resourceOrigin.ToString());
        }

        // 3. Send signed request with agent token
        var signedResponse = await SendSignedWithAgentToken(request, cancellationToken);

        // 200: cache access token if present
        if (signedResponse.StatusCode == HttpStatusCode.OK)
        {
            CacheAccessTokenFromResponse(resourceOrigin.ToString(), signedResponse);
            return signedResponse;
        }

        // 401 with AAuth-Requirement: token exchange flow
        if (signedResponse.StatusCode == HttpStatusCode.Unauthorized)
        {
            if (signedResponse.Headers.TryGetValues("aauth-requirement", out var reqValues))
            {
                var challenge = AAuthRequirement.Parse(reqValues.First());
                if (challenge.Requirement == "auth-token" && challenge.ResourceToken is not null)
                {
                    return await HandleAuthTokenChallenge(
                        request, resourceOrigin.ToString(), challenge.ResourceToken, cancellationToken);
                }
            }
        }

        // 202: resource-level interaction (two-party mode)
        if (signedResponse.StatusCode == HttpStatusCode.Accepted)
        {
            var terminalResponse = await HandleResourceInteraction(signedResponse, cancellationToken);
            CacheAccessTokenFromResponse(resourceOrigin.ToString(), terminalResponse);
            return terminalResponse;
        }

        return signedResponse;
    }

    private async Task<HttpResponseMessage> SendSignedWithAgentToken(
        HttpRequestMessage request, CancellationToken ct)
    {
        var km = await _options.GetKeyMaterial();
        AddAAuthHeaders(request);
        HttpMessageSigner.Sign(request, km.SigningKey, km.SignatureKey, GetAdditionalComponents(request));
        return await base.SendAsync(request, ct);
    }

    private async Task<HttpResponseMessage> SendSignedWithAuthToken(
        HttpRequestMessage request, string authToken, CancellationToken ct)
    {
        var km = await _options.GetKeyMaterial();
        var authSignatureKey = new SignatureKeyValue.Jwt(authToken);
        HttpMessageSigner.Sign(request, km.SigningKey, authSignatureKey);
        return await base.SendAsync(request, ct);
    }

    private async Task<HttpResponseMessage> SendSignedWithAccessToken(
        HttpRequestMessage request, string accessToken, CancellationToken ct)
    {
        var km = await _options.GetKeyMaterial();
        request.Headers.TryAddWithoutValidation("Authorization", $"AAuth {accessToken}");
        var additionalComponents = new List<string> { "authorization" };
        HttpMessageSigner.Sign(request, km.SigningKey, km.SignatureKey, additionalComponents);
        return await base.SendAsync(request, ct);
    }

    private async Task<HttpResponseMessage> HandleAuthTokenChallenge(
        HttpRequestMessage originalRequest, string resourceOrigin,
        string resourceToken, CancellationToken ct)
    {
        var validatedResourceToken = await ValidateResourceTokenAsync(resourceToken, resourceOrigin, ct);

        // Determine PS URL: from options or from agent token's ps claim
        var authServerUrl = _options.AuthServerUrl;
        if (authServerUrl is null)
        {
            authServerUrl = validatedResourceToken.Audience;
        }
        else
        {
            ServerIdentifier.Validate(authServerUrl);
            if (!string.Equals(authServerUrl, validatedResourceToken.Audience, StringComparison.OrdinalIgnoreCase))
            {
                throw new AAuthTokenException(
                    "invalid_resource_token",
                    $"Configured auth server {authServerUrl} does not match token audience {validatedResourceToken.Audience}");
            }
        }

        // Discover PS metadata
        var metadataUrl = $"{authServerUrl.TrimEnd('/')}/.well-known/aauth-person.json";
        var metadataResponse = await SendSignedRequest(HttpMethod.Get, metadataUrl, null, ct);
        if (!metadataResponse.IsSuccessStatusCode)
            throw new InvalidOperationException($"Failed to fetch PS metadata: {metadataResponse.StatusCode}");

        var metadata = await metadataResponse.Content.ReadFromJsonAsync<JsonElement>(ct);
        var tokenEndpoint = metadata.GetProperty("token_endpoint").GetString()!;

        // POST resource_token to token endpoint
        var body = new Dictionary<string, object> { ["resource_token"] = resourceToken };
        if (_options.Justification is not null) body["justification"] = _options.Justification;
        if (_options.LoginHint is not null) body["login_hint"] = _options.LoginHint;
        if (_options.Tenant is not null) body["tenant"] = _options.Tenant;

        var tokenResponse = await SendSignedRequest(HttpMethod.Post, tokenEndpoint,
            JsonContent.Create(body), ct);

        string authToken;
        int expiresIn;

        if (tokenResponse.StatusCode == HttpStatusCode.OK)
        {
            var result = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>(ct);
            authToken = result.GetProperty("auth_token").GetString()!;
            expiresIn = result.GetProperty("expires_in").GetInt32();
        }
        else if (tokenResponse.StatusCode == HttpStatusCode.Accepted)
        {
            // Deferred response — poll
            var locationUrl = tokenResponse.Headers.Location?.ToString();
            if (locationUrl is null)
                throw new InvalidOperationException("202 response missing Location header");

            if (!Uri.IsWellFormedUriString(locationUrl, UriKind.Absolute))
                locationUrl = new Uri(new Uri(authServerUrl), locationUrl).ToString();

            string? interactionUrl = null;
            string? interactionCode = null;
            if (tokenResponse.Headers.TryGetValues("aauth-requirement", out var reqValues))
            {
                try
                {
                    var challenge = AAuthRequirement.Parse(reqValues.First());
                    if (challenge.Requirement == "interaction")
                    {
                        interactionUrl = challenge.Url;
                        interactionCode = challenge.Code;
                    }
                }
                catch { /* ignore parse errors */ }
            }

            // Use a simple HttpClient for polling (already signed by handler)
            var deferredResult = await DeferredResponseLoop.PollAsync(
                new HttpClient(new AAuthSigningInnerHandler(_options) { InnerHandler = new HttpClientHandler() }),
                locationUrl,
                new DeferredOptions
                {
                    InteractionUrl = interactionUrl,
                    InteractionCode = interactionCode,
                    OnInteraction = _options.OnInteraction,
                    OnClarification = _options.OnClarification
                }, ct);

            if (deferredResult.Response.StatusCode != HttpStatusCode.OK)
                return deferredResult.Response;

            var result = await deferredResult.Response.Content.ReadFromJsonAsync<JsonElement>(ct);
            authToken = result.GetProperty("auth_token").GetString()!;
            expiresIn = result.GetProperty("expires_in").GetInt32();
        }
        else
        {
            return tokenResponse;
        }

        // Cache the auth token (after verifying claims per spec)
        await VerifyReceivedAuthTokenAsync(authToken, resourceOrigin);
        _tokenCache.CacheAuthToken(resourceOrigin, authServerUrl, authToken, expiresIn);

        // Retry the original request with the auth token
        var retryRequest = await CloneRequest(originalRequest);
        return await SendSignedWithAuthToken(retryRequest, authToken, ct);
    }

    /// <summary>
    /// Verify received auth token claims per spec: aud, cnf.jwk, agent, act.sub must match agent's own values.
    /// </summary>
    private async Task VerifyReceivedAuthTokenAsync(string rawAuthToken, string expectedResourceOrigin)
    {
        var authToken = AuthToken.Decode(rawAuthToken);
        var km = await _options.GetKeyMaterial();

        // Extract agent identifier from the agent token in the signature key
        if (km.SignatureKey is not SignatureKeyValue.Jwt jwtKey)
            throw new InvalidOperationException("Cannot verify auth token without JWT-based signature key");
        var agentToken = AgentToken.Decode(jwtKey.Token);

        // Verify aud matches the resource the agent intends to access
        var normalizedOrigin = expectedResourceOrigin.TrimEnd('/');
        if (!string.Equals(authToken.Audience, normalizedOrigin, StringComparison.OrdinalIgnoreCase))
            throw new AAuthTokenException("invalid_auth_token",
                $"Auth token aud '{authToken.Audience}' does not match target resource '{normalizedOrigin}'");

        // Verify cnf.jwk matches the agent's own signing key
        var agentThumbprint = JsonWebKeyThumbprint.Compute(agentToken.ConfirmationKey);
        var authTokenThumbprint = JsonWebKeyThumbprint.Compute(authToken.ConfirmationKey);
        if (agentThumbprint != authTokenThumbprint)
            throw new AAuthTokenException("invalid_auth_token",
                "Auth token cnf.jwk does not match agent's signing key");

        // Verify agent matches the agent's own identifier
        if (!string.Equals(authToken.Agent, agentToken.Subject, StringComparison.Ordinal))
            throw new AAuthTokenException("invalid_auth_token",
                $"Auth token agent '{authToken.Agent}' does not match agent identifier '{agentToken.Subject}'");

        // Verify act.sub matches the agent's own identifier
        if (authToken.Actor is null || !string.Equals(authToken.Actor.Subject, agentToken.Subject, StringComparison.Ordinal))
            throw new AAuthTokenException("invalid_auth_token",
                "Auth token act.sub does not match agent identifier");
    }

    private async Task<ResourceToken> ValidateResourceTokenAsync(
        string rawResourceToken, string expectedIssuer, CancellationToken ct)
    {
        var decoded = ResourceToken.Decode(rawResourceToken);

        try
        {
            ServerIdentifier.Validate(decoded.Issuer);
            ServerIdentifier.Validate(decoded.Audience);
        }
        catch (FormatException ex)
        {
            throw new AAuthTokenException("invalid_resource_token", ex.Message);
        }

        if (!AAuthIdentifier.TryParse(decoded.Agent, out _))
            throw new AAuthTokenException("invalid_resource_token", $"Invalid agent identifier: {decoded.Agent}");

        var normalizedExpectedIssuer = expectedIssuer.TrimEnd('/');
        if (!string.Equals(decoded.Issuer, normalizedExpectedIssuer, StringComparison.OrdinalIgnoreCase))
        {
            throw new AAuthTokenException(
                "invalid_resource_token",
                $"Resource token issuer {decoded.Issuer} does not match resource {normalizedExpectedIssuer}");
        }

        JsonWebKeySet keys;
        try
        {
            keys = await _keyResolver.ResolveKeysAsync(decoded.Issuer, decoded.Dwk, ct);
        }
        catch (Exception ex)
        {
            throw new AAuthTokenException("invalid_resource_token", $"Unable to resolve issuer keys: {ex.Message}");
        }

        if (keys.Keys.Count == 0)
            throw new AAuthTokenException("invalid_resource_token", $"No keys found for issuer {decoded.Issuer}");

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            IssuerSigningKeys = keys.Keys,
            ValidTypes = new[] { "aa-resource+jwt" }
        };

        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(rawResourceToken, validationParameters);
        if (!result.IsValid)
        {
            if (result.Exception is SecurityTokenExpiredException)
                throw new AAuthTokenException("token_expired", "Resource token has expired");
            if (result.Exception is SecurityTokenNotYetValidException)
                throw new AAuthTokenException("token_not_yet_valid", "Resource token is not yet valid");

            var detail = result.Exception?.Message ?? "Resource token signature validation failed";
            throw new AAuthTokenException("invalid_resource_token", detail);
        }

        var now = DateTimeOffset.UtcNow;
        if (decoded.ExpiresAt + ResourceTokenClockSkew < now)
            throw new AAuthTokenException("token_expired", "Resource token has expired");
        if (decoded.IssuedAt - ResourceTokenClockSkew > now)
            throw new AAuthTokenException("token_not_yet_valid", "Resource token is not yet valid");

        return decoded;
    }

    private async Task<HttpResponseMessage> HandleResourceInteraction(
        HttpResponseMessage response, CancellationToken ct)
    {
        if (response.StatusCode != HttpStatusCode.Accepted) return response;

        var locationUrl = response.Headers.Location?.ToString();
        if (locationUrl is null) return response;

        string? interactionUrl = null;
        string? interactionCode = null;
        if (response.Headers.TryGetValues("aauth-requirement", out var reqValues))
        {
            try
            {
                var challenge = AAuthRequirement.Parse(reqValues.First());
                if (challenge.Requirement == "interaction")
                {
                    interactionUrl = challenge.Url;
                    interactionCode = challenge.Code;
                }
            }
            catch { /* ignore */ }
        }

        var deferredResult = await DeferredResponseLoop.PollAsync(
            new HttpClient(new AAuthSigningInnerHandler(_options) { InnerHandler = new HttpClientHandler() }),
            locationUrl,
            new DeferredOptions
            {
                InteractionUrl = interactionUrl,
                InteractionCode = interactionCode,
                OnInteraction = _options.OnInteraction,
                OnClarification = _options.OnClarification
            }, ct);

        return deferredResult.Response;
    }

    private async Task<HttpResponseMessage> SendSignedRequest(
        HttpMethod method, string url, HttpContent? content, CancellationToken ct)
    {
        var request = new HttpRequestMessage(method, url) { Content = content };
        var km = await _options.GetKeyMaterial();
        HttpMessageSigner.Sign(request, km.SigningKey, km.SignatureKey);
        return await new HttpClient().SendAsync(request, ct);
    }

    private void AddAAuthHeaders(HttpRequestMessage request)
    {
        if (_options.Capabilities is { Count: > 0 })
            request.Headers.TryAddWithoutValidation("AAuth-Capabilities",
                AAuthCapabilitiesHeader.Build(_options.Capabilities));

        if (_options.Mission is not null)
            request.Headers.TryAddWithoutValidation("AAuth-Mission",
                AAuthMissionHeader.Build(_options.Mission));
    }

    private IReadOnlyList<string>? GetAdditionalComponents(HttpRequestMessage request)
    {
        var additional = new List<string>();
        if (request.Headers.Contains("aauth-mission"))
            additional.Add("aauth-mission");
        if (request.Headers.Contains("authorization"))
            additional.Add("authorization");
        return additional.Count > 0 ? additional : null;
    }

    private void CacheAccessTokenFromResponse(string resourceOrigin, HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues("aauth-access", out var values))
            _tokenCache.CacheAccessToken(resourceOrigin, values.First());
    }

    private static async Task<HttpRequestMessage> CloneRequest(HttpRequestMessage original)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri);
        if (original.Content is not null)
        {
            var content = await original.Content.ReadAsByteArrayAsync();
            clone.Content = new ByteArrayContent(content);
            if (original.Content.Headers.ContentType is not null)
                clone.Content.Headers.ContentType = original.Content.Headers.ContentType;
        }
        foreach (var header in original.Headers)
        {
            if (header.Key is "Signature" or "Signature-Input" or "Signature-Key") continue;
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        return clone;
    }
}

/// <summary>
/// Minimal inner handler that signs requests for polling loops.
/// </summary>
internal sealed class AAuthSigningInnerHandler : DelegatingHandler
{
    private readonly AAuthAgentOptions _options;

    public AAuthSigningInnerHandler(AAuthAgentOptions options)
    {
        _options = options;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var km = await _options.GetKeyMaterial();
        HttpMessageSigner.Sign(request, km.SigningKey, km.SignatureKey);
        return await base.SendAsync(request, ct);
    }
}
