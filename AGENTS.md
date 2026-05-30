# AAuth Utilities and Packages

This repo contains .NET libraries for AAuth (Agent Auth) — an agent-aware auth protocol for modern distributed systems.

This repo is the .NET counterpart to the original TypeScript implementation:
- GitHub: https://github.com/DickHardt/AAuth

This repo will evolve along with the original, which is still in experimentation phase. Expect frequent changes.

## Packages

| Package | Path | Description |
|---------|------|-------------|
| `AAuth.Core` | `src/AAuth.Core/` | Shared primitives: identifiers, HTTP message signatures, JWT token types, protocol headers, JWKS discovery |
| `AAuth.Agent` | `src/AAuth.Agent/` | Agent-side `DelegatingHandler` for signing requests, challenge handling, and token exchange |
| `AAuth.Server` | `src/AAuth.Server/` | ASP.NET Core `AuthenticationHandler` for verifying agent signatures and issuing resource tokens |

## Build and Test

```bash
dotnet build
dotnet test
```

Run a single test project:

```bash
dotnet test tests/AAuth.Core.Tests
dotnet test tests/AAuth.Agent.Tests
dotnet test tests/AAuth.Server.Tests
dotnet test tests/AAuth.Integration.Tests
```

## AAuth Specification

The evolving AAuth specification lives in a separate repo and is included here as a Git submodule:

- GitHub: https://github.com/DickHardt/AAuth
- Local path: `docs/aauth-spec/` (submodule)

Key spec documents (inside the submodule):
- `README.md` — full specification overview
- `aauth-explainer.md` — explainer document
- `AAuth_Spec_Complete.md` — complete specification
- `draft-hardt-aauth.md` — IETF-style draft

To update the spec to the latest version:

```bash
git submodule update --remote docs/aauth-spec
```

If the submodule is not initialized after cloning:

```bash
git submodule update --init docs/aauth-spec
```

## Key Design Decisions

- Targets .NET 10 (`net10.0`).
- Uses `Microsoft.IdentityModel.JsonWebTokens` for all JWT/JWK operations.
- HTTP Message Signatures support Ed25519 (EdDSA) and ECDSA P-256 (ES256 compatibility).
- HTTP Message Signatures scoped to the AAuth profile of RFC 9421 (not a full implementation).
- Agent-side uses `DelegatingHandler` pipeline pattern; server-side uses ASP.NET Core `AuthenticationHandler`.
- JWKS discovery implements rate-limited caching (1 min between fetches, 24 hr max TTL).

## Coding Conventions

### Naming

- **Private fields**: `_camelCase` (e.g., `_options`, `_keyResolver`, `_tokenCache`).
- **Public properties**: `PascalCase` (e.g., `ServerIdentifier`, `GetKeyMaterial`).
- **Methods**: `PascalCase`, with `Async` suffix for async methods (e.g., `VerifyAgentSignatureAsync`).
- **Parameters**: `camelCase` (e.g., `request`, `authToken`).
- **Constants**: `PascalCase` (e.g., `AAuthRequirement.Scheme`).

### Code Style

- **File-scoped namespaces** everywhere (`namespace AAuth.Core.Tokens;`).
- **Namespaces mirror folder paths** (e.g., `src/AAuth.Core/Tokens/` → `AAuth.Core.Tokens`).
- **`var`** is used throughout; avoid explicit types unless clarity requires it.
- **Records** for simple value/data types (e.g., `Mission`, `ActorClaim`, `AAuthChallenge`, `SignatureVerificationResult`).
- **Classes** for stateful services and handlers.
- **Expression-bodied members** for small helper methods.
- **XML doc comments** (`/// <summary>`) on all public types and members.
- **Nullable reference types** enabled in all projects.
- **Implicit usings** enabled in all projects.

### Error Handling

- **Throw exceptions** for invalid inputs and unexpected state — no `Result<T>` pattern.
- **`AAuthTokenException`** (`AAuth.Core.Tokens`) for all token validation failures (parsing, expired, wrong audience, missing claims, etc.).
- **`FormatException`** for malformed header values and identifiers.
- **`InvalidOperationException`** for missing configuration or invalid state.
- **`NotSupportedException`** for unsupported algorithms.
- **`TimeoutException`** for deferred response polling timeouts.
- Server-side code catches `AAuthTokenException` and maps it to authentication failures (not 500s).

### Dependencies

| Package | Used In | Purpose |
|---------|---------|---------|
| `Microsoft.IdentityModel.JsonWebTokens` | Core | JWT creation and validation |
| `Microsoft.IdentityModel.Tokens` | Core | JWK, JWKS, key types, Base64Url |
| `Microsoft.Extensions.Caching.Memory` | Core | JWKS discovery cache |
| `Microsoft.Extensions.Http` | Agent | `IHttpClientFactory` integration |
| `Microsoft.AspNetCore.App` (framework ref) | Server | ASP.NET Core authentication pipeline |

### Testing

- **Framework**: xUnit (all test projects).
- **No mocking library** — tests use hand-written fakes (custom `HttpMessageHandler` subclasses like `MockInnerHandler`, `MockHttpHandler`).
- **Test helpers** are private methods within each test class (e.g., `CreateEcdsaKeyPair`, `CreateTestKeyMaterial`, `ConfigureMockJwks`). There is no shared test utility project.
- **Pattern**: Arrange test data with helper methods → act on the class under test → assert with xUnit assertions.

When writing new tests, follow the existing pattern: create a private inner mock handler or helper method rather than adding an external mocking library.

## TypeScript ↔ .NET Package Mapping

This .NET repo ports functionality from the TypeScript monorepo at [`aauth-dev/packages-js`](https://github.com/AAuth-dev/packages-js).

| TypeScript Package | .NET Package | Notes |
|---|---|---|
| `@aauth/mcp-agent` | `AAuth.Agent` | Agent-side signing, challenge-response, token exchange |
| `@aauth/mcp-server` | `AAuth.Server` | Server-side verification, challenge building, resource tokens |
| *(shared internals)* | `AAuth.Core` | Signatures, tokens, headers, identifiers — extracted into a shared library in .NET |
| `@aauth/local-keys` | — | Not ported; .NET uses `System.Security.Cryptography` directly |
| `@aauth/bootstrap` | — | CLI tooling, not ported |
| `@aauth/fetch` | — | CLI tooling, not ported |
| `@aauth/hardware-keys` | — | Native interop, not ported |
| `@aauth/mcp-stdio` | — | MCP transport-specific, not ported |
| `@aauth/mcp-openclaw` | — | Plugin-specific, not ported |

## Key Public API Surface

### AAuth.Core

| Area | Key Types |
|------|-----------|
| Tokens | `AgentToken`, `AgentTokenOptions`, `ResourceToken`, `ResourceTokenOptions`, `AuthToken`, `Mission`, `AAuthTokenException` |
| Signatures | `HttpMessageSigner`, `SignatureBase`, `SignatureInput`, `SignatureKeyHeader`, `SignatureVerificationResult`, `JsonWebKeyThumbprint` |
| Headers | `AAuthRequirement`, `AAuthChallenge`, `AAuthAccessHeader`, `AAuthCapabilitiesHeader`, `AAuthMissionHeader` |
| Identifiers | `AAuthIdentifier`, `ServerIdentifier` |
| Discovery | `IssuerKeyResolver`, `KeyMaterial` |

### AAuth.Agent

| Type | Purpose |
|------|---------|
| `AAuthDelegatingHandler` | Signs outbound HTTP requests, handles 401 challenges and token exchange |
| `AAuthAgentOptions` | Configuration: key material, auth server URL, capabilities, callbacks |
| `DeferredResponseLoop` | Polls 202 deferred responses until terminal status |
| `TokenCache` | Caches auth tokens and access tokens per resource origin |
| `ServiceCollectionExtensions` | `AddAAuthAgent()` for DI registration |

### AAuth.Server

| Type | Purpose |
|------|---------|
| `AAuthAuthenticationHandler` | ASP.NET Core authentication handler for incoming requests |
| `AAuthServerOptions` | Configuration: server identifier, key material, required scope |
| `TokenVerifier` | Validates agent tokens, auth tokens, and confirmation key binding |
| `ResourceTokenFactory` | Issues resource tokens for the three-party flow |
| `ServiceCollectionExtensions` | `AddAAuth()` for DI registration |

## Publishing Packages

TBA
