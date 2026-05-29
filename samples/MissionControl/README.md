# Sample 04: Mission Control — Agent Governance Dashboard

Demonstrates AAuth's mission lifecycle and Person Server governance endpoints — an orthogonal layer on top of three-party resource access.

## What It Shows

- **Missions**: Agent proposes a natural-language description of intent → PS/user approve → immutable `s256` binding
- **Permission endpoint**: Agent requests approval for local actions (tool calls, file writes)
- **Audit endpoint**: Agent logs actions performed, building a mission log
- **Interaction endpoint**: Agent relays questions and proposes mission completion
- **AAuth-Mission header**: Carries mission context to resources, included in resource tokens and auth tokens
- **Web dashboard**: Real-time governance UI for the user to manage everything

## Architecture

```
┌─────────┐     ┌──────────┐     ┌──────────────────┐
│  Agent   │────▶│ Resource │────▶│  Person Server   │
│ (demo)   │◀────│ :3012    │     │  :3013           │
└─────────┘     └──────────┘     │                  │
     │                           │  /mission        │
     │  mission, permission,     │  /permission     │
     │  audit, interaction       │  /audit          │
     └──────────────────────────▶│  /interaction    │
                                 │  /token          │
                                 │  /dashboard  ◀──── 👤 User (browser)
                                 └──────────────────┘
     Agent Provider :3011
```

## Quick Start

```bash
# From repo root — automated mode (all approvals auto-granted)
dotnet run --project samples/MissionControl

# Interactive mode with dashboard
dotnet run --project samples/MissionControl -- --interactive
```

> Uses `https://localhost` endpoints. If certificate validation fails locally, run `dotnet dev-certs https --trust` once (on Linux/OpenSSL, also set `SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust:/usr/lib/ssl/certs"`).

In interactive mode, open **https://localhost:3013/dashboard** in your browser.

## Automated Demo

Runs the full mission lifecycle with auto-approval (7 steps):

1. **Propose mission** → PS auto-approves, returns `AAuth-Mission` header with `s256`
2. **Request permission** for `WebSearch` → auto-granted (in `approved_tools`)
3. **Log audit record** for the search action
4. **Authorize at resource** with `AAuth-Mission` → resource token includes `mission` claim
5. **Exchange at PS** → auth token includes `mission` claim
6. **Access resource** with auth token → data returned with mission context
7. **Propose completion** → PS auto-accepts, mission terminated

## Interactive Commands

| Command | Description |
|---------|-------------|
| `mission [desc]` | Propose a mission (polls until approved via dashboard) |
| `permission <action>` | Request permission for an action (polls until granted/denied) |
| `audit <action> [desc]` | Log an audit record (requires active mission) |
| `authorize [scope]` | POST /authorize with mission context → resource token |
| `exchange` | Exchange resource token at PS → auth token |
| `access` | GET /api/data with auth token |
| `complete [summary]` | Propose mission completion (polls until accepted) |
| `flow [scope]` | Full flow: authorize → exchange → access |
| `status` | Show current mission and token state |
| `help` | Show commands |
| `quit` | Shut down |

## Files

| File | Purpose |
|------|---------|
| `Program.cs` | Entry point — key generation, server startup, 7-step demo + interactive REPL |
| `PersonServer.cs` | Person Server with token exchange + all governance endpoints + dashboard APIs |
| `ResourceServer.cs` | Mission-aware resource server (authorize with AAuth-Mission, protected API) |
| `GovernanceStore.cs` | In-memory store for missions, permissions, audits, interactions |
| `Dashboard.cs` | HTML/CSS/JS governance dashboard (served by Person Server) |
| `AgentProviderServer.cs` | Agent Provider metadata + JWKS |

## Demo Limitations

This sample is a learning tool, not production code. Key simplifications:

- **Trusted local TLS required** — The sample binds `https://localhost` and expects a trusted ASP.NET Core development certificate (`dotnet dev-certs https --trust`).
- **ECDSA P-256 only** — Uses ES256 instead of Ed25519 (EdDSA) because `Microsoft.IdentityModel.JsonWebTokens` does not yet support Ed25519. The spec lists Ed25519 as a MUST-support algorithm.
- **In-memory state** — All keys, tokens, and server state are ephemeral. A production system would use persistent storage and proper key management.
- **Dashboard is localhost-only** — The governance dashboard mutation APIs restrict access to localhost connections. A production PS would use proper authentication for its control plane.
- **Simplified governance** — Permission and audit decisions use basic logic. A production PS would implement rich policy evaluation.
