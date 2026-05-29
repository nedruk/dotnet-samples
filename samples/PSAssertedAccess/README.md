# Sample 3: PS-Asserted Access — Three-Party Flow

## What This Demonstrates

This sample shows the **three-party AAuth flow**, where a Person Server (PS) asserts the user's identity to a Resource Server. Unlike [Sample 1](../HelloAAuth/) (identity-based) and [Sample 2](../FirstCallRegistration/) (first-call registration), this flow separates authentication from authorization:

- The **Agent** proves its identity with a self-signed agent token
- The **Resource Server** issues a resource token directing the agent to the PS
- The **Person Server** verifies the resource token and issues an auth token
- The **Agent** presents the auth token to access the resource

## Architecture

```
 ┌─────────────┐     ┌──────────────────┐     ┌───────────────┐
 │    Agent     │     │  Resource Server  │     │ Person Server  │
 │  (client)    │     │   :3012           │     │   :3013        │
 └──────┬───────┘     └────────┬──────────┘     └───────┬────────┘
        │                      │                        │
        │  1. POST /authorize  │                        │
        │  (agent token + sig) │                        │
        │─────────────────────>│                        │
        │  ← resource token    │                        │
        │<─────────────────────│                        │
        │                      │                        │
        │  2. POST /token (resource token + agent sig)  │
        │──────────────────────────────────────────────>│
        │  ← auth token                                 │
        │<──────────────────────────────────────────────│
        │                      │                        │
        │  3. GET /api/documents                        │
        │  (auth token + sig)  │                        │
        │─────────────────────>│                        │
        │  ← documents         │                        │
        │<─────────────────────│                        │
        │                      │                        │

 Agent Provider :3011 — serves JWKS for agent token verification
```

## Running

### Automated mode (default)

Runs the full three-party flow end-to-end:

```bash
dotnet run --project samples/PSAssertedAccess
```

### Interactive mode

Start servers and use commands to explore each step:

```bash
dotnet run --project samples/PSAssertedAccess -- interactive
```

> Uses `https://localhost` endpoints. If certificate validation fails locally, run `dotnet dev-certs https --trust` once (on Linux/OpenSSL, also set `SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust:/usr/lib/ssl/certs"`).

## Interactive Mode Commands

| Command | Description |
|---------|-------------|
| `authorize [scope]` | `POST /authorize` — get resource token (default scope: `data.read`) |
| `exchange` | `POST /token` on PS — exchange stored resource token for auth token |
| `access` | `GET /api/documents` with stored auth token |
| `flow [scope]` | Run all 3 steps in sequence |
| `tokens` | Show stored tokens with decoded claims |
| `metadata` | Show all server metadata URLs |
| `help` | Show commands |
| `quit` | Shut down servers and exit |

## Interactive Mode Walkthrough

```
aauth> authorize
→ POST https://localhost:3012/authorize (scope: data.read)
← 200 OK
  ✓ Resource token stored (eyJ...)

aauth> exchange
→ POST https://localhost:3013/token
← 200 OK
  ✓ Auth token stored (eyJ...)

aauth> access
→ GET https://localhost:3012/api/documents (with auth token)
← 200 OK
  Response: {"message":"Here are your documents!","documents":[...]}

aauth> tokens
─── Stored Tokens ──────────────────────────────────────────
  Resource Token:
    Issuer:   https://localhost:3012
    Audience: https://localhost:3013
    Agent:    aauth:demo-agent@localhost
    Scope:    data.read
  Auth Token:
    Issuer:   https://localhost:3013
    Audience: https://localhost:3012
    Subject:  user-a1b2c3d4e5f6
    Agent:    aauth:demo-agent@localhost
    Scope:    data.read
```

## Key Concepts

| Concept | Source File | Description |
|---------|------------|-------------|
| Agent token with `ps` claim | `Program.cs` | Agent token includes Person Server URL |
| Resource token issuance | `ResourceServer.cs` | Resource issues token directing agent to PS |
| Auth token issuance | `PersonServer.cs` | PS verifies resource token, issues auth token |
| Token-type gating | `ResourceServer.cs` | `/api/documents` rejects agent tokens, requires auth tokens |
| Three-party flow | `Program.cs` | Orchestrates authorize → exchange → access |

## Flow vs Previous Samples

| | Sample 1 (HelloAAuth) | Sample 2 (FirstCallRegistration) | Sample 3 (PSAssertedAccess) |
|---|---|---|---|
| **Parties** | Agent ↔ Resource | Agent ↔ Resource + User | Agent ↔ Resource ↔ Person Server |
| **Auth model** | Identity-based allowlist | First-call registration + 202 polling | PS-asserted three-party flow |
| **Token used** | Agent token | Agent token + AAuth-Access opaque token | Agent token → Resource token → Auth token |
| **User involvement** | None | Browser consent flow | PS auto-approves (demo) |
| **Resource token?** | No | No | Yes — signed by Resource, sent to PS |
| **Auth token?** | No | No | Yes — signed by PS, presented to Resource |

## Demo Limitations

This sample is a learning tool, not production code. Key simplifications:

- **Trusted local TLS required** — The sample binds `https://localhost` and expects a trusted ASP.NET Core development certificate (`dotnet dev-certs https --trust`).
- **ECDSA P-256 only** — Uses ES256 instead of Ed25519 (EdDSA) because `Microsoft.IdentityModel.JsonWebTokens` does not yet support Ed25519. The spec lists Ed25519 as a MUST-support algorithm.
- **In-memory state** — All keys, tokens, and server state are ephemeral. A production system would use persistent storage and proper key management.
- **Single-user PS** — The Person Server issues the same identity for all agents. A production PS would authenticate the user and bind identity per-session.
