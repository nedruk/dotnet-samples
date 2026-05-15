# AAuth .NET Implementation Plan

## Goal

Enable .NET applications to participate in the AAuth protocol — both as agents (calling resources) and as resources (serving agents). Port only the minimal functionality needed; lean on existing .NET libraries.

## Source Analysis

The TypeScript implementation (`aauth-dev/packages-js`) has 8 packages:

| Package | Purpose | Port? | Rationale |
|---|---|---|---|
| `@aauth/mcp-agent` | Agent-side: signed fetch, challenge-response, token exchange | **Yes** | Core agent functionality |
| `@aauth/mcp-server` | Server-side: token verification, challenge building, resource tokens | **Yes** | Core resource functionality |
| `@aauth/local-keys` | Key management across hardware/software backends (YubiKey, Secure Enclave, OS keychain) | **No** | Platform-native binding complexity; .NET has `System.Security.Cryptography` for software keys; hardware keys can come later |
| `@aauth/bootstrap` | CLI for key setup and PS registration | **No** | Tooling, not library functionality |
| `@aauth/fetch` | CLI for making authenticated HTTP requests | **No** | Tooling, not library functionality |
| `@aauth/hardware-keys` | Native bindings (Rust/Swift) for YubiKey PIV and Secure Enclave | **No** | Heavy native interop; not needed for initial adoption |
| `@aauth/mcp-stdio` | stdio-to-HTTP proxy with AAuth signatures | **No** | MCP transport-specific |
| `@aauth/mcp-openclaw` | OpenClaw plugin | **No** | Plugin-specific |

**Bottom line**: Port `mcp-agent` and `mcp-server` functionality into .NET libraries, with a shared core.

## What .NET Already Provides

These are the building blocks we do **not** need to reimplement:

| Capability | .NET Library | Notes |
|---|---|---|
| JWT creation and validation | `Microsoft.IdentityModel.JsonWebTokens` | Industry standard in .NET; handles signing, claims, validation |
| JWK / JWKS | `Microsoft.IdentityModel.Tokens` (`JsonWebKey`, `JsonWebKeySet`) | Parsing, thumbprints (RFC 7638), key sets |
| Ed25519 / ECDSA signing | `System.Security.Cryptography` | Ed25519 added in .NET 9; ECDSA P-256 long available |
| HTTP client with extensibility | `System.Net.Http.HttpClient` + `DelegatingHandler` | Pipeline pattern for adding signatures to outbound requests |
| Server middleware pipeline | ASP.NET Core middleware | Natural place for server-side signature verification |
| JSON handling | `System.Text.Json` | Serialization, deserialization |
| SHA-256 hashing | `System.Security.Cryptography.SHA256` | For mission `s256` computation |
| Base64url encoding | `Microsoft.IdentityModel.Tokens.Base64UrlEncoder` | Used throughout JWT/JWK handling |
| HTTP structured fields (RFC 8941) | **Not available** | Need to implement or find a package |
| HTTP Message Signatures (RFC 9421) | **Not available** | Need to implement |

## What We Need to Build

### Package 1: `AAuth.Core`

Shared primitives used by both agent and server sides.

**HTTP Message Signatures (RFC 9421 profile)**

This is the biggest gap. The spec requires signing `@method`, `@authority`, `@path`, and `signature-key` on every request. We need:

- Signature creation (sign covered components with Ed25519/ECDSA)
- Signature verification
- `Signature-Input` header generation and parsing
- `Signature-Key` header generation and parsing (schemes: `jwt`, `jwks_uri`)

Scope this tightly to the AAuth profile — not a full RFC 9421 implementation. Only the derived components and parameters AAuth requires.

**JWT token types**

Strongly typed wrappers around `Microsoft.IdentityModel` for the three AAuth token types:

- `AgentToken` (`aa-agent+jwt`) — claims: `iss`, `dwk`, `sub`, `jti`, `cnf`, `iat`, `exp`, optional `ps`
- `ResourceToken` (`aa-resource+jwt`) — claims: `iss`, `dwk`, `aud`, `jti`, `agent`, `agent_jkt`, `scope`, `iat`, `exp`, optional `mission`
- `AuthToken` (`aa-auth+jwt`) — claims: `iss`, `dwk`, `aud`, `jti`, `agent`, `cnf`, `act`, `iat`, `exp`, conditional `sub`/`scope`

Each type: creation, validation (including `dwk`-based JWKS discovery), strongly typed claim access.

**AAuth headers**

Parsing and building for the AAuth-specific HTTP headers:

- `AAuth-Requirement` (structured dictionary: `requirement`, `resource-token`, `url`, `code`)
- `AAuth-Access` (opaque token)
- `AAuth-Capabilities` (structured list)
- `AAuth-Mission` (structured dictionary: `approver`, `s256`)

**JWKS discovery and caching**

- Fetch `{iss}/.well-known/{dwk}` metadata, extract `jwks_uri`, fetch JWKS
- Cache with HTTP cache header respect
- Refresh on unknown `kid`; rate-limit to 1 fetch/minute/issuer
- 24-hour max cache TTL

Use `IMemoryCache` or a simple `ConcurrentDictionary` with expiration.

**Identifiers**

- `AAuthIdentifier` — parse/validate `aauth:local@domain` URIs
- Server identifier validation (HTTPS, no port/path/query/fragment, lowercase)

### Package 2: `AAuth.Agent`

Agent-side functionality — making authenticated requests to AAuth-protected resources.

**`AAuthDelegatingHandler` (the core piece)**

A `DelegatingHandler` that wraps `HttpClient` and:

1. Signs every outgoing request with HTTP Message Signatures
2. Attaches `Signature-Key` header with the agent token (`scheme=jwt`)
3. Attaches `AAuth-Capabilities` header
4. Optionally attaches `AAuth-Mission` header

**Challenge handling**

When the handler receives a `401` with `AAuth-Requirement: requirement=auth-token`:

1. Extract and verify the `resource-token`
2. POST it to the PS token endpoint (signed)
3. Handle deferred response loop (`202` polling with `Retry-After`)
4. Retry the original request with the auth token

**Deferred response loop**

Implement the state machine from the spec: `202` → poll `Location` → handle `200`/`403`/`408`/`410`/`429`. Used for token endpoint responses and interaction flows.

**Token caching**

Cache auth tokens per resource, auto-refresh before expiry.

### Package 3: `AAuth.Server`

Server-side functionality — verifying signed requests and issuing challenges.

**ASP.NET Core middleware / authentication handler**

- Verify HTTP Message Signatures on incoming requests
- Extract and verify token from `Signature-Key` header (agent token or auth token)
- Verify `cnf.jwk` matches the request signing key
- Populate `HttpContext.User` or a custom `AAuthContext` with verified identity

**Token verification**

- `VerifyAgentToken(jwt, httpSignatureThumbprint)` → `VerifiedAgentToken`
- `VerifyAuthToken(jwt, httpSignatureThumbprint)` → `VerifiedAuthToken`
- Both use JWKS discovery via `Core`

**Challenge building**

- `BuildAAuthRequirement(requirement, params)` → header string
- `BuildAAuthAccess(token)` → header string

**Resource token creation**

- `CreateResourceToken(options, signingKey)` → JWT string
- Sets `iss`, `dwk`, `aud` (PS or AS URL), `agent`, `agent_jkt`, `scope`, optional `mission`

**`AAuth-Capabilities` parsing**

- `ParseCapabilities(headerValue)` → `string[]`

**`AAuth-Mission` parsing**

- `ParseMission(headerValue)` → `Mission`

## What We Explicitly Skip (For Now)

| Feature | Why skip |
|---|---|
| Hardware key backends (YubiKey, Secure Enclave) | Heavy native interop; software keys suffice for initial use |
| Bootstrap CLI | Not a library concern; can be a separate tool later |
| Person Server implementation | Large surface; the plan enables agents and resources, not PS |
| Access Server implementation | Same — focus is agent and resource roles |
| Mission creation/management | Agent can participate in missions created by other impls |
| Call chaining | Advanced feature; identity-based and two/three-party modes first |
| Four-party federation | Three-party covers the primary use case |
| Clarification chat | Nice-to-have, not required for basic flows |
| Token revocation | Short-lived tokens reduce urgency |
| `InteractionManager` (202 pending state) | Server-side state management; each app will have its own pattern |

## Suggested Project Structure

```
dotnet-samples.sln
├── src/
│   ├── AAuth.Core/
│   │   ├── Signatures/          # HTTP Message Signatures (RFC 9421 profile)
│   │   ├── Tokens/              # AgentToken, ResourceToken, AuthToken
│   │   ├── Headers/             # AAuth header parsing/building
│   │   ├── Discovery/           # JWKS discovery and caching
│   │   └── Identifiers/         # AAuth URI and server identifier types
│   ├── AAuth.Agent/
│   │   ├── AAuthDelegatingHandler.cs
│   │   ├── ChallengeHandler.cs
│   │   ├── DeferredResponseLoop.cs
│   │   └── ServiceCollectionExtensions.cs   # DI registration
│   └── AAuth.Server/
│       ├── AAuthAuthenticationHandler.cs
│       ├── TokenVerifier.cs
│       ├── ChallengeBuilder.cs
│       ├── ResourceTokenFactory.cs
│       └── ServiceCollectionExtensions.cs   # DI registration
└── tests/
    ├── AAuth.Core.Tests/
    ├── AAuth.Agent.Tests/
    └── AAuth.Server.Tests/
```

## Dependencies

- `Microsoft.IdentityModel.JsonWebTokens` (JWT handling)
- `Microsoft.IdentityModel.Tokens` (JWK, JWKS)
- `Microsoft.AspNetCore.Authentication` (server-side auth handler, `AAuth.Server` only)
- `Microsoft.Extensions.Http` (DI for `HttpClient`, `AAuth.Agent` only)
- `Microsoft.Extensions.Caching.Memory` (JWKS caching)

No third-party crypto libraries — `System.Security.Cryptography` covers Ed25519 and ECDSA P-256.

## Implementation Order

1. **`AAuth.Core` — Signatures** — HTTP Message Signatures is the foundation everything else depends on
2. **`AAuth.Core` — Tokens** — JWT type wrappers with creation and validation
3. **`AAuth.Core` — Headers + Discovery + Identifiers** — Supporting infrastructure
4. **`AAuth.Agent`** — `DelegatingHandler` with signing, challenge handling, deferred response loop
5. **`AAuth.Server`** — Authentication handler, token verification, challenge/resource-token building
6. **Tests at each step**

## Key Design Decisions

1. **`DelegatingHandler` for agent-side signing** — idiomatic .NET; composes with `HttpClientFactory`; transparent to calling code
2. **ASP.NET Core `AuthenticationHandler` for server-side** — plugs into the standard auth pipeline; works with `[Authorize]`
3. **Tight RFC 9421 scope** — only implement the AAuth profile, not a general-purpose signatures library
4. **`Microsoft.IdentityModel` for all JWT work** — battle-tested, maintained by Microsoft, already handles the hard parts
5. **No MCP coupling** — the TypeScript packages are named `mcp-*` but the protocol is transport-agnostic; our packages should be named `AAuth.*` without MCP in the name

---

## Detailed Implementation Plan

### Step 1: AAuth.Core — HTTP Message Signatures (RFC 9421 AAuth Profile)

The TypeScript implementation delegates to `@hellocoop/httpsig` for the actual signing. We need a minimal, AAuth-scoped implementation.

#### 1a. Signature Base Construction

Per RFC 9421 §2, build the signature base string from covered components. AAuth requires exactly these covered components on every request:

```
"@method": GET
"@authority": resource.example
"@path": /api/data
"signature-key": sig=jwt;jwt="eyJhbGc..."
```

Implementation:

```csharp
// Signatures/SignatureBase.cs
public static class SignatureBase
{
    /// <summary>
    /// Build the RFC 9421 signature base from an HttpRequestMessage.
    /// Covers: @method, @authority, @path, signature-key, plus any
    /// additional components (e.g., aauth-mission, authorization, content-digest).
    /// </summary>
    public static string Build(
        HttpRequestMessage request,
        string signatureKeyHeaderValue,
        IReadOnlyList<string>? additionalComponents = null)
    {
        // For each component: output '"component-name": value\n'
        // Final line: '"@signature-params": (components);created=unix-ts'
    }
}
```

Only support derived components `@method`, `@authority`, `@path` and header fields. No `@query`, `@query-param`, `@status`, etc. — AAuth doesn't use them.

#### 1b. Signature-Input Header

```
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
```

```csharp
// Signatures/SignatureInput.cs
public sealed class SignatureInput
{
    public IReadOnlyList<string> CoveredComponents { get; }
    public long Created { get; }

    public string Serialize();                              // → header value string
    public static SignatureInput Parse(string headerValue); // ← from incoming request
}
```

#### 1c. Signature-Key Header

Two schemes needed: `jwt` (agent token or auth token) and `jwks_uri` (PS-to-AS).

```
Signature-Key: sig=jwt;jwt="eyJhbGc..."
Signature-Key: sig=jwks_uri;jwks_uri="https://ps.example/.well-known/jwks.json"
```

```csharp
// Signatures/SignatureKey.cs
public abstract record SignatureKeyValue
{
    public sealed record Jwt(string Token) : SignatureKeyValue;
    public sealed record JwksUri(string Uri) : SignatureKeyValue;
}

public static class SignatureKeyHeader
{
    public static string Build(SignatureKeyValue value);
    public static SignatureKeyValue Parse(string headerValue);
}
```

#### 1d. Signing and Verification

```csharp
// Signatures/HttpMessageSigner.cs
public sealed class HttpMessageSigner
{
    /// <summary>
    /// Sign an outgoing request. Adds Signature, Signature-Input,
    /// and Signature-Key headers.
    /// </summary>
    public static void Sign(
        HttpRequestMessage request,
        AsymmetricAlgorithm signingKey,      // Ed25519 or ECDsa
        SignatureKeyValue signatureKey,
        IReadOnlyList<string>? additionalComponents = null);

    /// <summary>
    /// Verify an incoming request's signature. Returns the JWK thumbprint
    /// of the signing key (needed for cnf binding checks).
    /// </summary>
    public static SignatureVerificationResult Verify(HttpRequestMessage request);
}

public sealed record SignatureVerificationResult(
    bool IsValid,
    string? Thumbprint,           // JWK Thumbprint (RFC 7638) of signing key
    SignatureKeyValue? SignatureKey,
    string? Error);
```

Use `System.Security.Cryptography.Ed25519` (new in .NET 9) and `ECDsa` with `ECCurve.NamedCurves.nistP256`. The `alg` in the JWK determines which to use.

#### 1e. Key Material Types

```csharp
// Signatures/KeyMaterial.cs
public sealed class KeyMaterial
{
    public required AsymmetricAlgorithm SigningKey { get; init; }
    public required SignatureKeyValue SignatureKey { get; init; }
}

public delegate Task<KeyMaterial> GetKeyMaterial();
```

This mirrors the TS `GetKeyMaterial` callback — the caller provides the private key and the token/key reference.

---

### Step 2: AAuth.Core — Token Types

Strongly typed wrappers over `Microsoft.IdentityModel.JsonWebTokens`.

#### 2a. Agent Token

```csharp
// Tokens/AgentToken.cs
public sealed class AgentToken
{
    public string Issuer { get; }           // iss (agent provider URL)
    public string Dwk { get; }             // "aauth-agent.json"
    public string Subject { get; }          // sub (agent identifier aauth:local@domain)
    public string Jti { get; }
    public JsonWebKey ConfirmationKey { get; }  // cnf.jwk
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public string? PersonServerUrl { get; }    // ps (optional)

    public string RawJwt { get; }  // original JWT string

    public static AgentToken Create(AgentTokenOptions options, SigningCredentials signingCredentials);
    public static AgentToken Verify(string jwt, string httpSignatureThumbprint, IssuerKeyResolver resolver);
}
```

Verification flow (mirrors TS `verifyToken` for `aa-agent+jwt`):
1. Decode header → check `typ == "aa-agent+jwt"`
2. Check `dwk == "aauth-agent.json"` → discover JWKS at `{iss}/.well-known/aauth-agent.json`
3. Validate JWT signature with issuer's JWKS
4. Check `exp` not past, `iat` not future (60s clock skew)
5. Verify `cnf.jwk` thumbprint matches `httpSignatureThumbprint`

#### 2b. Resource Token

```csharp
// Tokens/ResourceToken.cs
public sealed class ResourceToken
{
    public string Issuer { get; }          // iss (resource URL)
    public string Dwk { get; }            // "aauth-resource.json"
    public string Audience { get; }        // aud (PS or AS URL)
    public string Jti { get; }
    public string Agent { get; }           // agent identifier
    public string AgentJkt { get; }        // JWK Thumbprint
    public string? Scope { get; }
    public Mission? Mission { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

    public string RawJwt { get; }

    public static string Create(ResourceTokenOptions options, SigningCredentials signingCredentials);
    public static ResourceToken Verify(string jwt, string expectedAudience, IssuerKeyResolver resolver);
}
```

Factory mirrors TS `createResourceToken` — caller provides `resource`, `authServer`, `agent`, `agentJkt`, `scope`, optional `mission`, `lifetime`. The `sign` callback in TS becomes `SigningCredentials` in .NET (more idiomatic — the key is passed in, not a callback).

#### 2c. Auth Token

```csharp
// Tokens/AuthToken.cs
public sealed class AuthToken
{
    public string Issuer { get; }         // iss (AS or PS URL)
    public string Dwk { get; }           // "aauth-access.json" or "aauth-person.json"
    public string Audience { get; }       // aud (resource URL)
    public string Jti { get; }
    public string Agent { get; }          // agent identifier
    public JsonWebKey ConfirmationKey { get; }  // cnf.jwk
    public ActorClaim Actor { get; }      // act (delegation chain)
    public string? Subject { get; }       // sub (directed user identifier)
    public string? Scope { get; }
    public string? Tenant { get; }
    public Mission? Mission { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

    public string RawJwt { get; }

    public static AuthToken Verify(string jwt, string httpSignatureThumbprint, IssuerKeyResolver resolver);
}

public sealed record ActorClaim(string Subject, ActorClaim? Nested);
```

#### 2d. Mission Type

```csharp
// Tokens/Mission.cs
public sealed record Mission(string Approver, string S256);
```

---

### Step 3: AAuth.Core — Headers, Discovery, Identifiers

#### 3a. AAuth Headers

```csharp
// Headers/AAuthRequirement.cs
public static class AAuthRequirement
{
    public static string BuildAuthToken(string resourceToken);
    public static string BuildInteraction(string url, string code);
    public static string BuildApproval();
    public static string BuildClarification();
    public static string BuildClaims();

    public static AAuthChallenge Parse(string headerValue);
}

public sealed record AAuthChallenge(
    string Requirement,            // "auth-token", "interaction", etc.
    string? ResourceToken = null,  // for auth-token
    string? Url = null,            // for interaction
    string? Code = null);          // for interaction

// Headers/AAuthAccess.cs
public static class AAuthAccessHeader
{
    public static string Build(string opaqueToken);
    public static string Parse(string headerValue);
}

// Headers/AAuthCapabilities.cs
public static class AAuthCapabilitiesHeader
{
    public static string Build(IEnumerable<string> capabilities);
    public static IReadOnlyList<string> Parse(string headerValue);
}

// Headers/AAuthMissionHeader.cs
public static class AAuthMissionHeader
{
    public static string Build(Mission mission);
    public static Mission Parse(string headerValue);
}
```

Parsing approach: These are simple structured dictionaries with known keys. Use regex/string parsing — no need for a full RFC 8941 structured fields parser. The TS implementation does exactly this.

#### 3b. JWKS Discovery and Caching

```csharp
// Discovery/IssuerKeyResolver.cs
public sealed class IssuerKeyResolver : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ConcurrentDictionary<string, CachedJwks> _cache;

    /// <summary>
    /// Resolve signing keys for an issuer. Fetches {iss}/.well-known/{dwk},
    /// extracts jwks_uri, fetches JWKS.
    /// </summary>
    public Task<IReadOnlyList<JsonWebKey>> ResolveKeys(string issuer, string dwk, CancellationToken ct = default);

    /// <summary>
    /// Find a specific key by kid. If not found in cache, refresh once
    /// (rate-limited to 1 fetch/min/issuer).
    /// </summary>
    public Task<JsonWebKey?> FindKey(string issuer, string dwk, string kid, CancellationToken ct = default);

    public void ClearCache();
}
```

Internal `CachedJwks` record holds the `JsonWebKeySet`, `fetchedAt` timestamp, and metadata (jwks_uri). Cache entry eviction at 24 hours max, or when HTTP cache headers dictate earlier.

#### 3c. Identifiers

```csharp
// Identifiers/AAuthIdentifier.cs
public readonly struct AAuthIdentifier : IEquatable<AAuthIdentifier>
{
    public string Local { get; }   // the local part
    public string Domain { get; }  // the domain part

    public static AAuthIdentifier Parse(string uri);  // "aauth:local@domain"
    public static bool TryParse(string uri, out AAuthIdentifier result);
    public override string ToString() => $"aauth:{Local}@{Domain}";
}

// Identifiers/ServerIdentifier.cs
public static class ServerIdentifier
{
    public static bool IsValid(string url);  // HTTPS, no port/path/query/fragment, lowercase
    public static void Validate(string url); // throws on invalid
}
```

---

### Step 4: AAuth.Agent

#### 4a. AAuthDelegatingHandler

```csharp
// AAuthDelegatingHandler.cs
public sealed class AAuthDelegatingHandler : DelegatingHandler
{
    private readonly GetKeyMaterial _getKeyMaterial;
    private readonly AAuthAgentOptions _options;
    private readonly IssuerKeyResolver _keyResolver;
    private readonly TokenCache _tokenCache;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        // 1. Check token cache for a valid auth token for this resource origin
        //    If cached → sign with auth token, send, return (unless 401 → fall through)
        //
        // 2. Check access token cache (two-party mode opaque token)
        //    If cached → add Authorization header, sign with agent token, send
        //
        // 3. Sign request with agent token + add capabilities/mission headers
        //
        // 4. Send request
        //    - 200: cache AAuth-Access if present, return
        //    - 401 with AAuth-Requirement auth-token: start challenge flow
        //    - 202 with interaction: start deferred response loop
        //    - other: return as-is
        //
        // Challenge flow:
        //    a. Extract resource-token from AAuth-Requirement header
        //    b. Discover PS metadata (/.well-known/aauth-person.json)
        //    c. POST resource_token to PS token_endpoint (signed)
        //    d. Handle deferred response (202 polling)
        //    e. Cache returned auth_token
        //    f. Retry original request with auth token
    }
}
```

#### 4b. Deferred Response Loop

```csharp
// DeferredResponseLoop.cs
public static class DeferredResponseLoop
{
    public static async Task<DeferredResult> Poll(
        HttpClient signedClient,          // pre-configured with signing handler
        string locationUrl,
        DeferredOptions options,
        CancellationToken cancellationToken = default);
}

public sealed class DeferredOptions
{
    public string? InteractionUrl { get; init; }
    public string? InteractionCode { get; init; }
    public Func<string, string, Task>? OnInteraction { get; init; }
    public Func<string, Task<string>>? OnClarification { get; init; }
    public int MaxPollDurationSeconds { get; init; } = 300;
    public int PreferWaitSeconds { get; init; } = 45;
}

public sealed record DeferredResult(
    HttpResponseMessage Response,
    AAuthError? Error = null);

public sealed record AAuthError(
    string ErrorCode,
    string? ErrorDescription = null);
```

State machine (from spec and TS `pollDeferred`):
```
GET locationUrl (with Prefer: wait=45)
  200 → done (return response)
  202 → check clarification in body → continue polling
  400/401/403/408/410/500 → terminal (return response + error)
  429 → increase interval by 5s, retry
  503 → back off per Retry-After, retry
```

#### 4c. Token Cache

```csharp
// TokenCache.cs
internal sealed class TokenCache
{
    // Keyed by "{resourceOrigin}|{authServer}"
    private readonly ConcurrentDictionary<string, CachedAuthToken> _authTokens;
    // Keyed by resource origin
    private readonly ConcurrentDictionary<string, string> _accessTokens;

    public CachedAuthToken? FindAuthToken(string resourceOrigin);
    public void CacheAuthToken(string resourceOrigin, string authServer, string authToken, int expiresIn);
    public void RemoveAuthToken(string resourceOrigin, string authServer);

    public string? FindAccessToken(string resourceOrigin);
    public void CacheAccessToken(string resourceOrigin, string token);
    public void RemoveAccessToken(string resourceOrigin);
}
```

60-second buffer before expiry (matches TS implementation).

#### 4d. DI Registration

```csharp
// ServiceCollectionExtensions.cs
public static class AAuthAgentServiceCollectionExtensions
{
    public static IHttpClientBuilder AddAAuthAgent(
        this IServiceCollection services,
        Action<AAuthAgentOptions> configure)
    {
        // Register IssuerKeyResolver as singleton
        // Register AAuthDelegatingHandler as transient
        // Return IHttpClientBuilder for further HttpClient config
    }
}

public sealed class AAuthAgentOptions
{
    public required GetKeyMaterial GetKeyMaterial { get; set; }
    public string? AuthServerUrl { get; set; }
    public IReadOnlyList<string>? Capabilities { get; set; }
    public Mission? Mission { get; set; }
    public string? Justification { get; set; }
    public string? LoginHint { get; set; }
    public string? Tenant { get; set; }
    public Func<string, string, Task>? OnInteraction { get; set; }
    public Func<string, Task<string>>? OnClarification { get; set; }
}
```

Usage:

```csharp
services.AddAAuthAgent(options =>
{
    options.GetKeyMaterial = async () => new KeyMaterial
    {
        SigningKey = myEd25519Key,
        SignatureKey = new SignatureKeyValue.Jwt(myAgentToken)
    };
});

// Inject HttpClient via IHttpClientFactory — signing is transparent
```

---

### Step 5: AAuth.Server

#### 5a. Authentication Handler

```csharp
// AAuthAuthenticationHandler.cs
public sealed class AAuthAuthenticationHandler
    : AuthenticationHandler<AAuthServerOptions>
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // 1. Extract Signature, Signature-Input, Signature-Key from request
        //    → Fail("Missing AAuth signature headers") if absent
        //
        // 2. Verify HTTP Message Signature
        //    → Fail("Invalid signature") if verification fails
        //
        // 3. Extract JWT from Signature-Key header
        //
        // 4. Check JWT typ:
        //    - "aa-agent+jwt" → verify as agent token
        //    - "aa-auth+jwt"  → verify as auth token
        //    → Fail("Unknown token type") otherwise
        //
        // 5. Verify cnf.jwk thumbprint matches signature key thumbprint
        //    → Fail("Key binding failed") if mismatch
        //
        // 6. Build ClaimsPrincipal from verified token
        //    → return AuthenticateResult.Success(ticket)
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        // If properties contains a resource token, build 401 with
        // AAuth-Requirement: requirement=auth-token; resource-token="..."
        // Otherwise, plain 401 with Signature-Error header
    }
}
```

#### 5b. Server Options

```csharp
// AAuthServerOptions.cs
public sealed class AAuthServerOptions : AuthenticationSchemeOptions
{
    public string? ResourceUrl { get; set; }              // this resource's identifier (iss for resource tokens)
    public string? AuthorizationEndpoint { get; set; }
    public int SignatureWindowSeconds { get; set; } = 60;
    public IReadOnlyList<string>? AdditionalSignatureComponents { get; set; }
}
```

#### 5c. Token Verifier

```csharp
// TokenVerifier.cs
public sealed class TokenVerifier
{
    private readonly IssuerKeyResolver _keyResolver;

    public Task<VerifiedToken> VerifyToken(string jwt, string httpSignatureThumbprint, CancellationToken ct = default);
}

public abstract record VerifiedToken;
public sealed record VerifiedAgentToken(
    string Issuer, string Subject, JsonWebKey ConfirmationKey,
    string? PersonServerUrl, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt) : VerifiedToken;
public sealed record VerifiedAuthToken(
    string Issuer, string Audience, string Agent, JsonWebKey ConfirmationKey,
    string? Subject, string? Scope, string? Tenant,
    ActorClaim Actor, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt) : VerifiedToken;
```

#### 5d. Resource Token Factory

```csharp
// ResourceTokenFactory.cs
public sealed class ResourceTokenFactory
{
    public string Create(ResourceTokenOptions options, SigningCredentials signingCredentials);
}

public sealed class ResourceTokenOptions
{
    public required string Resource { get; init; }     // iss
    public required string AuthServer { get; init; }   // aud (PS or AS URL)
    public required string Agent { get; init; }
    public required string AgentJkt { get; init; }
    public string? Scope { get; init; }
    public Mission? Mission { get; init; }
    public int LifetimeSeconds { get; init; } = 300;
}
```

#### 5e. Challenge Builder

```csharp
// ChallengeBuilder.cs
public static class ChallengeBuilder
{
    public static string BuildAuthTokenChallenge(string resourceToken);
    public static string BuildInteractionChallenge(string url, string code);
    public static string BuildAAuthAccess(string opaqueToken);
}
```

#### 5f. Header Parsers

```csharp
// HeaderParsers.cs (thin wrappers over Core)
public static class HeaderParsers
{
    public static IReadOnlyList<string> ParseCapabilities(string headerValue);
    public static Mission ParseMission(string headerValue);
}
```

#### 5g. DI Registration

```csharp
// ServiceCollectionExtensions.cs
public static class AAuthServerServiceCollectionExtensions
{
    public static AuthenticationBuilder AddAAuth(
        this AuthenticationBuilder builder,
        Action<AAuthServerOptions>? configure = null)
    {
        // Register IssuerKeyResolver (shared with Agent if both used)
        // Register TokenVerifier
        // Register ResourceTokenFactory
        // Add AAuthAuthenticationHandler as authentication scheme "AAuth"
    }
}
```

Usage:

```csharp
builder.Services.AddAuthentication("AAuth")
    .AddAAuth(options =>
    {
        options.ResourceUrl = "https://api.example.com";
    });

// In controllers:
[Authorize(AuthenticationSchemes = "AAuth")]
public IActionResult GetData()
{
    var identity = HttpContext.Features.Get<AAuthIdentity>();
    // identity.AgentIdentifier, identity.Subject, identity.Scope, etc.
}
```

---

### Step 6: Tests

#### Unit Test Strategy

| Area | What to test | Approach |
|---|---|---|
| Signature base construction | Component serialization matches RFC 9421 examples | Hardcoded request → expected string |
| Signature round-trip | Sign → verify with Ed25519 and ECDSA P-256 | Generate key pair, sign, verify |
| Token creation/verification | All three token types round-trip | Create with known claims → verify → assert claims |
| Token rejection | Wrong typ, expired, bad cnf, bad dwk | Assert specific error codes |
| JWKS discovery | Cache hit, cache miss, kid refresh, rate limiting | Mock HttpClient with message handler |
| AAuth header parse/build | Round-trip all header types | Parse(Build(x)) == x |
| Agent identifier | Valid/invalid parsing, string comparison | Parse known-good and known-bad identifiers |
| Deferred response loop | 202→200, 202→403, 429 backoff, timeout | Mock responses in sequence |
| Challenge flow | 401→exchange→retry | Mock resource + PS responses |
| Auth handler | Valid request accepted, missing sig rejected | In-memory test server |

#### Integration Test

One end-to-end test: agent HttpClient (with `AAuthDelegatingHandler`) → ASP.NET Core test server (with `AAuthAuthenticationHandler`):
1. Agent signs and sends request
2. Server verifies signature and agent token
3. Server returns 200 with data

This validates the full signing → verification path without any external dependencies.

---

### File-by-File Implementation Sequence

This is the order files should be created, with each step producing compilable, testable code:

```
 1. src/AAuth.Core/AAuth.Core.csproj
 2. src/AAuth.Core/Identifiers/AAuthIdentifier.cs
 3. src/AAuth.Core/Identifiers/ServerIdentifier.cs
 4. tests/AAuth.Core.Tests/AAuth.Core.Tests.csproj
 5. tests/AAuth.Core.Tests/Identifiers/AAuthIdentifierTests.cs
 6. src/AAuth.Core/Signatures/SignatureBase.cs
 7. src/AAuth.Core/Signatures/SignatureInput.cs
 8. src/AAuth.Core/Signatures/SignatureKeyHeader.cs
 9. src/AAuth.Core/Signatures/KeyMaterial.cs
10. src/AAuth.Core/Signatures/HttpMessageSigner.cs
11. tests/AAuth.Core.Tests/Signatures/SignatureBaseTests.cs
12. tests/AAuth.Core.Tests/Signatures/HttpMessageSignerTests.cs
13. src/AAuth.Core/Tokens/Mission.cs
14. src/AAuth.Core/Tokens/AgentToken.cs
15. src/AAuth.Core/Tokens/ResourceToken.cs
16. src/AAuth.Core/Tokens/AuthToken.cs
17. tests/AAuth.Core.Tests/Tokens/AgentTokenTests.cs
18. tests/AAuth.Core.Tests/Tokens/ResourceTokenTests.cs
19. src/AAuth.Core/Headers/AAuthRequirement.cs
20. src/AAuth.Core/Headers/AAuthAccessHeader.cs
21. src/AAuth.Core/Headers/AAuthCapabilitiesHeader.cs
22. src/AAuth.Core/Headers/AAuthMissionHeader.cs
23. tests/AAuth.Core.Tests/Headers/AAuthHeaderTests.cs
24. src/AAuth.Core/Discovery/IssuerKeyResolver.cs
25. tests/AAuth.Core.Tests/Discovery/IssuerKeyResolverTests.cs
26. src/AAuth.Agent/AAuth.Agent.csproj
27. src/AAuth.Agent/AAuthAgentOptions.cs
28. src/AAuth.Agent/TokenCache.cs
29. src/AAuth.Agent/DeferredResponseLoop.cs
30. src/AAuth.Agent/AAuthDelegatingHandler.cs
31. src/AAuth.Agent/ServiceCollectionExtensions.cs
32. tests/AAuth.Agent.Tests/AAuth.Agent.Tests.csproj
33. tests/AAuth.Agent.Tests/DeferredResponseLoopTests.cs
34. tests/AAuth.Agent.Tests/AAuthDelegatingHandlerTests.cs
35. src/AAuth.Server/AAuth.Server.csproj
36. src/AAuth.Server/AAuthServerOptions.cs
37. src/AAuth.Server/TokenVerifier.cs
38. src/AAuth.Server/ResourceTokenFactory.cs
39. src/AAuth.Server/ChallengeBuilder.cs
40. src/AAuth.Server/HeaderParsers.cs
41. src/AAuth.Server/AAuthAuthenticationHandler.cs
42. src/AAuth.Server/ServiceCollectionExtensions.cs
43. tests/AAuth.Server.Tests/AAuth.Server.Tests.csproj
44. tests/AAuth.Server.Tests/TokenVerifierTests.cs
45. tests/AAuth.Server.Tests/AAuthAuthenticationHandlerTests.cs
46. tests/AAuth.Integration.Tests/EndToEndTests.cs
```
