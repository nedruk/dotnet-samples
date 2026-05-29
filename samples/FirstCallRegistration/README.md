# Sample 2: First-Call Registration — Two-Party Resource-Managed Access

An agent calls a resource it has never seen before, triggering a browser-based consent flow. The resource handles authorization itself — no Person Server, no Access Server.

## What This Demonstrates

- **Resource-managed access** — the resource handles auth without external infrastructure
- **AAuth-Requirement header** — `requirement=interaction` with URL and code
- **Deferred response pattern** — 202 → poll → terminal response
- **Browser-based consent** — user approves/denies in a web page
- **AAuth-Access opaque token** — resource issues access token after approval
- **Proof-of-possession binding** — access token is useless without agent's signing key (ECDSA P-256)
- **"First call is the registration"** — no pre-registration needed

## Architecture

```
┌──────────────────┐          ┌─────────────────────────────┐
│  Agent Provider  │          │      Resource Server        │
│  (self-hosted)   │          │      :3012                  │
│                  │ ← JWKS   │                             │
│  /.well-known/   │ discovery│  GET /api/data              │
│  /jwks           │          │    → verify sig + token     │
│  :3011           │          │    → no access token? 202   │
└──────────────────┘          │                             │
       ↑                      │  GET /interact?code=...     │
       │ issues token         │    → consent page (HTML)    │
       │ (ECDSA P-256)        │                             │
┌──────┴──────────┐           │  GET /pending/:id           │
│     Agent       │           │    → 202 (pending)          │
│                 │ ─signed──→│    → 200 + AAuth-Access     │
│  1. call → 202  │           │                             │
│  2. show URL    │           │  GET /api/data + Auth header│
│  3. poll        │           │    → 200 (access granted)   │
│  4. use token   │           └─────────────────────────────┘
└─────────────────┘                        ↑
                                           │ browser
                                    ┌──────┴──────┐
                                    │    User     │
                                    │  (approve)  │
                                    └─────────────┘
```

## Running

```bash
dotnet run                    # automated — full flow with simulated approval
dotnet run -- interactive     # manual — step-by-step with real browser consent
```

> Uses `https://localhost` endpoints. If certificate validation fails locally, run `dotnet dev-certs https --trust` once (on Linux/OpenSSL, also set `SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust:/usr/lib/ssl/certs"`).

### Interactive Mode Commands

| Command | What it does |
|---------|-------------|
| `call` | Make a signed request to `/api/data` — triggers 202 + interaction |
| `poll <id>` | Poll a pending URL by ID (from Location header) |
| `use <token>` | Make a signed request with an AAuth-Access token |
| `help` | Show commands |
| `quit` | Shut down servers and exit |

### Interactive Mode Walkthrough

1. Type `call` — note the interaction URL and pending ID in the output
2. Open the interaction URL in your browser — click **Approve**
3. Type `poll <pending-id>` — you'll get the access token
4. Type `use <access-token>` — access granted!

## Notes

- Resource metadata intentionally omits `authorization_endpoint` because this sample uses the direct `202 + AAuth-Requirement` interaction flow.
- Polling `GET /pending/{id}` must be signed by the same agent that initiated the flow.
- Pending interactions expire after 5 minutes.
- Once an approved pending interaction returns `200` with `AAuth-Access`, later polls return `410 Gone`.

## Key Concepts

| Concept | Where in code |
|---------|---------------|
| Interaction flow (202 + requirement) | `ResourceServer.cs` → `/api/data` handler |
| Pending authorization store | `PendingStore.cs` |
| Browser consent page | `InteractionPage.cs` |
| Polling endpoint | `ResourceServer.cs` → `/pending/{id}` |
| AAuth-Access token issuance | `ResourceServer.cs` → poll returns `AAuth-Access` header |
| Access token validation + key binding | `ResourceServer.cs` + `PendingStore.cs` → `ValidateAccessToken()` |
| Resource metadata | `ResourceServer.cs` → `/.well-known/aauth-resource.json` |

## Flow vs Sample 01

| Sample 01 (HelloAAuth) | Sample 02 (FirstCallRegistration) |
|-----------|-----------|
| Static allowlist → immediate 200/403 | No prior knowledge → 202 + consent flow |
| No browser involvement | User approves in browser |
| No access tokens | Opaque AAuth-Access token for subsequent calls |
| `Authorization` header not used | `Authorization: AAuth <token>` (signed!) |

## Demo Limitations

This sample is a learning tool, not production code. Key simplifications:

- **Trusted local TLS required** — The sample binds `https://localhost` and expects a trusted ASP.NET Core development certificate (`dotnet dev-certs https --trust`).
- **ECDSA P-256 only** — Uses ES256 instead of Ed25519 (EdDSA) because `Microsoft.IdentityModel.JsonWebTokens` does not yet support Ed25519. The spec lists Ed25519 as a MUST-support algorithm.
- **In-memory state** — All keys, tokens, and server state are ephemeral. A production system would use persistent storage and proper key management.
- **Simplified consent flow** — The browser interaction page is a minimal HTML form. A production resource would integrate with a full identity/consent UI.
