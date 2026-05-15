using System.Collections.Concurrent;

namespace AAuth.Agent;

/// <summary>
/// Caches auth tokens and opaque access tokens per resource origin.
/// </summary>
internal sealed class TokenCache
{
    private readonly ConcurrentDictionary<string, CachedAuthToken> _authTokens = new();
    private readonly ConcurrentDictionary<string, string> _accessTokens = new();

    private static readonly TimeSpan ExpiryBuffer = TimeSpan.FromSeconds(60);

    public CachedAuthToken? FindAuthToken(string resourceOrigin)
    {
        foreach (var kvp in _authTokens)
        {
            if (kvp.Key.StartsWith($"{resourceOrigin}|", StringComparison.Ordinal))
            {
                if (kvp.Value.ExpiresAt > DateTimeOffset.UtcNow + ExpiryBuffer)
                    return kvp.Value;

                _authTokens.TryRemove(kvp.Key, out _);
            }
        }
        return null;
    }

    public void CacheAuthToken(string resourceOrigin, string authServer, string authToken, int expiresInSeconds)
    {
        var key = $"{resourceOrigin}|{authServer}";
        _authTokens[key] = new CachedAuthToken(authToken, authServer,
            DateTimeOffset.UtcNow.AddSeconds(expiresInSeconds));
    }

    public void RemoveAuthToken(string resourceOrigin, string authServer)
    {
        _authTokens.TryRemove($"{resourceOrigin}|{authServer}", out _);
    }

    public string? FindAccessToken(string resourceOrigin) =>
        _accessTokens.GetValueOrDefault(resourceOrigin);

    public void CacheAccessToken(string resourceOrigin, string token) =>
        _accessTokens[resourceOrigin] = token;

    public void RemoveAccessToken(string resourceOrigin) =>
        _accessTokens.TryRemove(resourceOrigin, out _);
}

internal sealed record CachedAuthToken(string Token, string AuthServer, DateTimeOffset ExpiresAt);
