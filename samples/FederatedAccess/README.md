# Sample 5: Federated Access — Four-Party Flow with Call Chaining

Demonstrates four-party federated resource access (Agent → Resource → PS → AS → auth token) and call chaining where a resource acts as an agent to access a downstream resource.

## What It Demonstrates

- **Four-party federated access**: Agent → Resource 1 → PS → Access Server → auth token
- **PS↔AS federation**: PS discovers and calls the AS token endpoint when the resource token audience is not the PS itself
- **Call chaining**: Resource 1 acts as an agent to call Resource 2, forwarding delegation context
- **Role collocation**: Resource 1 runs both `aauth-resource.json` and `aauth-agent.json` on the same server
- **Nested `act` claims**: Preserves the full delegation chain (`{ sub: "resource1-agent", act: { sub: "demo-agent" } }`)
- **AS-issued auth tokens**: Tokens carry `dwk: aauth-access.json` and are issued by the Access Server

## Architecture

Five servers participate in this sample:

| Server | Port | Role |
|--------|------|------|
| Agent Provider | 3011 | AP — agent identity and signing keys |
| Resource 1 | 3012 | Resource + Agent (dual role for call chaining) |
| Person Server | 3013 | PS — federates to AS when needed |
| Access Server | 3014 | AS — issues auth tokens for its resources |
| Resource 2 | 3015 | Downstream resource accessed via call chaining |

```
┌──────────┐     ┌─────────────┐     ┌───────────────┐     ┌───────────────┐
│  Agent   │────▶│ Resource 1  │     │ Person Server │────▶│ Access Server │
│  :3011   │◀────│ :3012       │     │ :3013         │◀────│ :3014         │
└──────────┘     │ (R + A)     │     └───────────────┘     └───────────────┘
                 │             │
                 │ call chain  │     ┌───────────────┐
                 │             │────▶│ Resource 2    │
                 │             │◀────│ :3015         │
                 └─────────────┘     └───────────────┘
```

## Quick Start

```bash
# From the repo root
dotnet build

# Run the demo
cd samples/FederatedAccess
dotnet run

# Interactive mode
dotnet run -- interactive
```

> Uses `https://localhost` endpoints. If certificate validation fails locally, run `dotnet dev-certs https --trust` once (on Linux/OpenSSL, also set `SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust:/usr/lib/ssl/certs"`).

## Part A — Four-Party Flow

The agent accesses Resource 1 through a four-party flow where the PS federates to the AS:

```
Agent → Resource1 /authorize         → resource_token (aud=AS)
Agent → PS /token (resource_token)   → PS discovers AS, forwards
PS → AS /token                       → AS issues auth_token
Agent → Resource1 /api/data          → 200 OK with weather data
```

1. **Authorize** — Agent POSTs to Resource 1's `/authorize` endpoint. Resource 1 issues a resource token with `aud` set to the **Access Server URL** (not the PS).
2. **Exchange at PS** — Agent sends the resource token to the PS `/token` endpoint. The PS inspects the `aud` claim and detects it does not match itself.
3. **PS→AS federation** — PS discovers the AS via `/.well-known/aauth-access.json`, then forwards the token exchange request to the AS `/token` endpoint, signing the request with its own key.
4. **Auth token** — The AS issues an auth token (`dwk: aauth-access.json`, `iss: AS URL`). The PS returns it to the agent.
5. **Access** — Agent calls Resource 1 `/api/data` with the auth token. Resource 1 verifies it against the AS.

## Part B — Call Chaining

Resource 1 acts as an agent to access Resource 2, passing the delegation chain downstream:

```
Agent → Resource1 /api/enriched
  Resource1 (as agent) → Resource2 /authorize → resource_token
  Resource1 → PS /token (upstream_token)      → PS → AS → auth_token
  Resource1 → Resource2 /api/data             → flight data
Agent ← combined weather + flight data
```

1. **Enriched request** — Agent calls Resource 1 `/api/enriched` with its auth token.
2. **Resource 1 as agent** — Resource 1 uses its agent identity (`aauth-agent.json`) to call Resource 2's `/authorize` endpoint, obtaining a new resource token.
3. **Chained exchange** — Resource 1 exchanges the resource token at the PS, including the `upstream_token` (the original auth token) for delegation context. PS federates to AS again.
4. **Nested act claims** — The AS issues an auth token with nested `act` claims: `{ sub: "resource1-agent", act: { sub: "demo-agent" } }`, preserving the full delegation chain.
5. **Downstream access** — Resource 1 calls Resource 2 `/api/data` with the chained auth token, receives flight data.
6. **Combined response** — Resource 1 merges its own weather data with Resource 2's flight data and returns the combined result to the agent.

## Key Protocol Concepts

### Resource Token `aud` = AS URL

In the three-party flow (sample 03), the resource token's `aud` is set to the PS URL. In the four-party flow, the resource sets `aud` to the **Access Server URL**, signaling that the AS (not the PS) is the token authority.

### PS Federation

When the PS receives a resource token with `aud ≠ PS URL`, it performs federation:
1. Fetches `{aud}/.well-known/aauth-access.json` to discover the AS token endpoint
2. Forwards the token exchange to the AS
3. Signs requests to the AS with `Signature-Key: sig=jwks_uri` (server-to-server key)

### AS Auth Tokens

Auth tokens issued by the AS carry:
- `dwk: aauth-access.json` — discovery well-known key indicating AS provenance
- `iss` — set to the AS URL
- Standard claims: `sub`, `aud`, `scope`, `cnf`, `act`

### Call Chaining and Role Collocation

Resource 1 serves both `/.well-known/aauth-resource.json` and `/.well-known/aauth-agent.json`, acting as a resource for incoming requests and as an agent for outgoing requests to Resource 2.

### Upstream Token and Delegation Context

When Resource 1 exchanges a resource token for a downstream call, it includes the `upstream_token` — the original auth token from the inbound request. This gives the AS visibility into the full delegation chain.

### Nested `act` Claims

The downstream auth token contains nested `act` claims:
```json
{
  "sub": "resource1-agent",
  "act": {
    "sub": "demo-agent"
  }
}
```
This tells Resource 2: "resource1-agent is acting, on behalf of demo-agent."

## Interactive Mode Commands

| Command | Action |
|---------|--------|
| `authorize [scope]` | POST /authorize to Resource 1 → get resource token |
| `exchange [rt]` | POST /token to PS (triggers PS→AS federation) → get auth token |
| `access [at]` | GET /api/data on Resource 1 with auth token |
| `enriched [at]` | GET /api/enriched on Resource 1 (call chaining to R2) |
| `token` | Print demo agent JWT |
| `keys` | Print all public keys |
| `help` | Show commands |
| `quit` | Shut down servers and exit |

## Spec References

| Concept | Spec Section |
|---------|-------------|
| Four-Party Overview | §3.4 |
| AS Federation | §9 |
| Auth Tokens (AS-issued) | §10 |
| Multi-Hop Delegation | §11 |
| Call Chaining Flow | §12 |

## Files

| File | Purpose |
|------|---------|
| `Program.cs` | Demo orchestrator — key gen, server startup, Part A + Part B, interactive REPL |
| `AgentProviderServer.cs` | Agent Provider (port 3011) — agent identity and signing keys |
| `ResourceServer.cs` | Resource 1 (port 3012) — dual role: resource server + agent for call chaining |
| `PersonServer.cs` | Person Server (port 3013) — token exchange with AS federation |
| `AccessServer.cs` | Access Server (port 3014) — issues auth tokens, JWKS, metadata |
| `Resource2Server.cs` | Resource 2 (port 3015) — downstream resource accessed via call chaining |

## Demo Limitations

This sample is a learning tool, not production code. Key simplifications:

- **Trusted local TLS required** — The sample binds `https://localhost` and expects a trusted ASP.NET Core development certificate (`dotnet dev-certs https --trust`).
- **ECDSA P-256 only** — Uses ES256 instead of Ed25519 (EdDSA) because `Microsoft.IdentityModel.JsonWebTokens` does not yet support Ed25519. The spec lists Ed25519 as a MUST-support algorithm.
- **In-memory state** — All keys, tokens, and server state are ephemeral. A production system would use persistent storage and proper key management.
- **No token revocation** — Tokens are accepted until expiry. A production system would implement revocation checking.
- **Simplified routing** — Call chaining always routes through the PS. The spec allows direct AS routing in some cases.
