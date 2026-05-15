using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Core.Discovery;

/// <summary>
/// Resolves issuer signing keys by fetching well-known metadata and JWKS endpoints.
/// Implements caching with rate limiting per the AAuth spec.
/// </summary>
public sealed class IssuerKeyResolver : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ConcurrentDictionary<string, CachedMetadata> _metadataCache = new();
    private readonly ConcurrentDictionary<string, CachedJwks> _jwksCache = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastFetchTime = new();

    private static readonly TimeSpan MetadataCacheTtl = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan JwksCacheMaxTtl = TimeSpan.FromHours(24);
    private static readonly TimeSpan MinFetchInterval = TimeSpan.FromMinutes(1);

    public IssuerKeyResolver(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    /// <summary>
    /// Resolve the JWKS for an issuer via its well-known metadata.
    /// Uses pattern: {iss}/.well-known/{dwk} → metadata → jwks_uri → JWKS.
    /// </summary>
    public async Task<JsonWebKeySet> ResolveKeysAsync(string issuer, string dwk, CancellationToken ct = default)
    {
        var jwksUri = await ResolveJwksUriAsync(issuer, dwk, ct);
        return await FetchJwksAsync(jwksUri, ct);
    }

    /// <summary>
    /// Find a specific key by kid. If not found in cache, refresh the JWKS once
    /// (rate-limited to 1 fetch per minute per issuer).
    /// </summary>
    public async Task<JsonWebKey?> FindKeyAsync(string issuer, string dwk, string kid, CancellationToken ct = default)
    {
        var jwksUri = await ResolveJwksUriAsync(issuer, dwk, ct);

        // Try cached first
        if (_jwksCache.TryGetValue(jwksUri, out var cached) && !cached.IsExpired)
        {
            var key = cached.KeySet.Keys.FirstOrDefault(k => k.Kid == kid);
            if (key is not null) return key;
        }

        // Key not found — try refreshing (rate-limited)
        if (CanFetch(jwksUri))
        {
            var freshJwks = await FetchJwksAsync(jwksUri, ct, forceRefresh: true);
            return freshJwks.Keys.FirstOrDefault(k => k.Kid == kid);
        }

        return null;
    }

    public void ClearCache()
    {
        _metadataCache.Clear();
        _jwksCache.Clear();
        _lastFetchTime.Clear();
    }

    public void Dispose()
    {
        // HttpClient lifecycle is managed externally
    }

    private async Task<string> ResolveJwksUriAsync(string issuer, string dwk, CancellationToken ct)
    {
        var metadataUrl = $"{issuer.TrimEnd('/')}/.well-known/{dwk}";

        if (_metadataCache.TryGetValue(metadataUrl, out var cached) && !cached.IsExpired)
            return cached.JwksUri;

        var response = await _httpClient.GetAsync(metadataUrl, ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Failed to fetch metadata from {metadataUrl}: {response.StatusCode}");

        var json = await response.Content.ReadAsStringAsync(ct);
        var metadata = JsonSerializer.Deserialize<JsonElement>(json);

        if (!metadata.TryGetProperty("jwks_uri", out var jwksUriProp))
            throw new InvalidOperationException($"No jwks_uri in metadata from {metadataUrl}");

        var jwksUri = jwksUriProp.GetString()!;
        _metadataCache[metadataUrl] = new CachedMetadata(jwksUri, DateTimeOffset.UtcNow);
        return jwksUri;
    }

    private async Task<JsonWebKeySet> FetchJwksAsync(string jwksUri, CancellationToken ct, bool forceRefresh = false)
    {
        if (!forceRefresh && _jwksCache.TryGetValue(jwksUri, out var cached) && !cached.IsExpired)
            return cached.KeySet;

        if (!CanFetch(jwksUri) && !forceRefresh)
        {
            // Rate limited — return cached if available
            if (_jwksCache.TryGetValue(jwksUri, out var rateLimited))
                return rateLimited.KeySet;
            throw new InvalidOperationException($"Rate limited and no cached JWKS for {jwksUri}");
        }

        _lastFetchTime[jwksUri] = DateTimeOffset.UtcNow;

        var response = await _httpClient.GetAsync(jwksUri, ct);
        if (!response.IsSuccessStatusCode)
        {
            if (_jwksCache.TryGetValue(jwksUri, out var fallback))
                return fallback.KeySet;
            throw new InvalidOperationException($"Failed to fetch JWKS from {jwksUri}: {response.StatusCode}");
        }

        var json = await response.Content.ReadAsStringAsync(ct);
        var keySet = new JsonWebKeySet(json);

        _jwksCache[jwksUri] = new CachedJwks(keySet, DateTimeOffset.UtcNow);
        return keySet;
    }

    private bool CanFetch(string key)
    {
        if (!_lastFetchTime.TryGetValue(key, out var lastFetch))
            return true;
        return DateTimeOffset.UtcNow - lastFetch >= MinFetchInterval;
    }

    private sealed record CachedMetadata(string JwksUri, DateTimeOffset FetchedAt)
    {
        public bool IsExpired => DateTimeOffset.UtcNow - FetchedAt > MetadataCacheTtl;
    }

    private sealed record CachedJwks(JsonWebKeySet KeySet, DateTimeOffset FetchedAt)
    {
        public bool IsExpired => DateTimeOffset.UtcNow - FetchedAt > JwksCacheMaxTtl;
    }
}
