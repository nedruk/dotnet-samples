# Sample 1: Hello AAuth — Identity-Based Access

The simplest AAuth flow: an agent signs HTTP requests with its cryptographic identity, and a resource verifies who the agent is.

## What This Demonstrates

- **Agent identity** via `aauth:local@domain` identifiers
- **Self-hosted Agent Provider** publishing metadata at `/.well-known/aauth-agent.json`
- **JWKS key discovery** for verifying agent tokens
- **HTTP Message Signatures** (RFC 9421) on every request
- **Proof-of-possession** — the agent token's `cnf.jwk` is bound to the ECDSA P-256 signing key
- **Identity-based access control** — the resource grants/denies based on an allowlist

## Architecture

```
┌─────────────────────┐             ┌──────────────────────┐
│   Agent Provider    │             │   Resource Server    │
│  (self-hosted AP)   │             │   :3012              │
│   :3011             │  ← JWKS ──  │  1. Verify HTTP sig  │
│                     │  discovery  │  2. Verify agent JWT │
│  /.well-known/      │             │  3. Check allowlist  │
│    aauth-agent.json │             │  4. Grant/deny       │
│  /jwks              │             │                      │
└─────────────────────┘             └──────────────────────┘
         ↑                                    ↑
         │ issues token                       │ signed request
         │                                    │
    ┌────┴────────────────────────────────────┴───┐
    │                  Agent                       │
    │  • Holds ephemeral ECDSA P-256 signing key   │
    │  • Signs requests with HTTP Message Sigs     │
    │  • Carries agent token (aa-agent+jwt)        │
    └──────────────────────────────────────────────┘
```

## Running

```bash
# Automated demo — runs all 3 scenarios
dotnet run

# Interactive mode — REPL with running servers
dotnet run -- interactive
```

> Uses `https://localhost` endpoints. If certificate validation fails locally, run `dotnet dev-certs https --trust` once (on Linux/OpenSSL, also set `SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust:/usr/lib/ssl/certs"`).

## Demo Scenarios

The automated demo runs three scenarios:

1. **Allowed agent** — request succeeds (200)
2. **Unknown agent** — valid signature but not in allowlist (403)
3. **Unsigned request** — no signature at all (401)

After the scenarios, the demo prints the AAuth HTTP headers (`Signature`, `Signature-Input`, `Signature-Key`) to show what the library adds to each request.

## Interactive Mode Commands

| Command | What it does |
|---------|-------------|
| `Enter` | Send a signed request as the allowed agent |
| `unknown` | Send a signed request as an unknown agent |
| `unsigned` | Send an unsigned request |
| `token` | Print the full agent token (JWT) |
| `keys` | Print the agent's public keys |
| `help` | Show commands |
| `quit` | Shut down servers and exit |

## Key Concepts

| Concept | Where in code |
|---------|---------------|
| ECDSA P-256 key generation | `Program.cs` — setup section |
| Agent token creation (aa-agent+jwt) | `Program.cs` → `AgentToken.Create()` |
| Well-known metadata & JWKS | `AgentProviderServer.cs` |
| HTTP signature signing (client side) | `Program.cs` → `AAuthDelegatingHandler` |
| Signature + token verification (server side) | `ResourceServer.cs` → `AddAAuth()` handler |
| Allowlist access control | `ResourceServer.cs` → `/api/hello` endpoint |

## Demo Limitations

This sample is a learning tool, not production code. Key simplifications:

- **Trusted local TLS required** — The sample binds `https://localhost` and expects a trusted ASP.NET Core development certificate (`dotnet dev-certs https --trust`).
- **ECDSA P-256 only** — Uses ES256 instead of Ed25519 (EdDSA) because `Microsoft.IdentityModel.JsonWebTokens` does not yet support Ed25519. The spec lists Ed25519 as a MUST-support algorithm.
- **In-memory state** — All keys, tokens, and server state are ephemeral. A production system would use persistent storage and proper key management.
- **No scope or authorization policy** — The resource uses a simple allowlist. Production resources would evaluate scopes, missions, and richer policy.
