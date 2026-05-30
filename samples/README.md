# AAuth Samples

Progressive reference implementations of the [AAuth protocol](https://github.com/dickhardt/AAuth) in .NET — from simple identity-based access to full federated flows.

## Prerequisites

- .NET 10 SDK
- Trusted ASP.NET Core HTTPS development certificate (`dotnet dev-certs https --trust`)

## Quick Start

```bash
# From the repo root
dotnet build

# Run a sample (e.g., sample 1)
cd samples/HelloAAuth
dotnet run
```

If `dotnet dev-certs https --trust` reports OpenSSL trust issues on Linux, run samples with:

```bash
export SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust:/usr/lib/ssl/certs"
```

Each sample has two modes:
- `dotnet run` — automated end-to-end flow with console output
- `dotnet run -- interactive` — manual REPL / step-by-step exploration

All sample identifiers, metadata documents, JWKS URIs, and token endpoints now use `https://localhost`.

## Samples

| # | Sample | What it demonstrates |
|---|--------|---------------------|
| 1 | [Hello AAuth](HelloAAuth/) | Identity-based access — agent signs requests, resource checks allowlist |
| 2 | [First-Call Registration](FirstCallRegistration/) | Two-party resource-managed access — browser consent, polling, access tokens |
| 3 | [PS-Asserted Access](PSAssertedAccess/) | Three-party flow — resource tokens, auth tokens, Person Server identity assertion |
| 4 | [Mission Control](MissionControl/) | Mission lifecycle, governance endpoints (permission, audit, interaction), web dashboard |
| 5 | [Federated Access](FederatedAccess/) | Four-party flow with PS→AS federation, call chaining, nested delegation |

See each sample's README for architecture diagrams, running instructions, and key concepts.

## Note on Key Algorithm

These samples use **ECDSA P-256 (ES256)** for key generation. The core library also supports **Ed25519 (EdDSA)**.
