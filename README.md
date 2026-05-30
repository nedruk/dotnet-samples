# AAuth for .NET

.NET libraries for the [AAuth protocol](https://github.com/DickHardt/AAuth) — agent-aware authentication for modern distributed systems. This is the .NET counterpart to the [TypeScript reference implementation](https://github.com/AAuth-dev/packages-js).

## Packages

| Package | Purpose |
|---------|---------|
| `AAuth.Core` | Shared primitives: identifiers, HTTP message signatures (RFC 9421 profile), JWT token types, protocol headers, JWKS discovery |
| `AAuth.Agent` | Agent-side `DelegatingHandler` that signs outbound requests, handles 401 challenges and token exchange, and polls 202 deferred responses |
| `AAuth.Server` | ASP.NET Core `AuthenticationHandler` that verifies agent signatures, validates tokens, and issues resource tokens for the three-party flow |

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/products/docker-desktop)
- [Visual Studio Code](https://code.visualstudio.com/) with the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
- .NET 10 SDK (included in the dev container)

### Using the Dev Container

1. Clone this repository.
2. Open the repository in Visual Studio Code.
3. When prompted, click **Reopen in Container** (or run the **Dev Containers: Reopen in Container** command from the Command Palette).
4. VS Code will build the Docker image defined in `.devcontainer/Dockerfile` using the .NET 10 SDK and open the project inside the container.

### Build and Test

```bash
dotnet build
dotnet test
```

## Agent Usage

Register the `AAuthDelegatingHandler` on an `HttpClient` to sign all outbound requests automatically:

```csharp
services.AddAAuthAgent("my-agent", options =>
{
    options.GetKeyMaterial = async () => new KeyMaterial(signingKey, signatureKey);
    options.AuthServerUrl = "https://ps.example.com";
    options.Capabilities = new[] { "interaction" };
    options.OnInteraction = async (url, code) =>
    {
        Console.WriteLine($"Visit {url} and enter code {code}");
    };
});
```

The handler:

- Signs every request with HTTP Message Signatures (RFC 9421 AAuth profile).
- Handles 401 responses with `AAuth-Requirement: requirement=auth-token` by performing token exchange with the Person Server.
- Polls 202 deferred responses until a terminal status is reached.
- Caches auth tokens and access tokens per resource origin.

## Server Usage

Add AAuth authentication to an ASP.NET Core application:

```csharp
builder.Services.AddAuthentication()
    .AddAAuth(options =>
    {
        options.ServerIdentifier = "https://resource.example.com";
        options.GetKeyMaterial = async () => new KeyMaterial(serverKey, serverSignatureKey);
        options.AuthServerUrl = "https://ps.example.com";
        options.RequiredScope = "read write";
    });
```

The handler:

- Verifies HTTP Message Signatures on incoming requests.
- Validates agent tokens and auth tokens (type, expiry, audience, scope, mission).
- Binds confirmation keys (`cnf.jwk`) to the signature key used in the request.
- Populates `ClaimsPrincipal` with agent identity, scope, and tenant claims.

## Samples

Working examples demonstrating AAuth flows end-to-end. See the [samples README](samples/) for details.

| # | Sample | What it demonstrates |
|---|--------|---------------------|
| 1 | [Hello AAuth](samples/HelloAAuth/) | Identity-based access — agent signs requests, resource checks allowlist |
| 2 | [First-Call Registration](samples/FirstCallRegistration/) | Two-party resource-managed access — browser consent, polling, access tokens |
| 3 | [PS-Asserted Access](samples/PSAssertedAccess/) | Three-party flow — resource tokens, auth tokens, Person Server identity assertion |
| 4 | [Mission Control](samples/MissionControl/) | Mission lifecycle, governance endpoints (permission, audit, interaction), web dashboard |

```bash
cd samples/HelloAAuth && dotnet run              # automated demo
cd samples/FirstCallRegistration && dotnet run    # automated demo
cd samples/PSAssertedAccess && dotnet run         # automated demo
cd samples/MissionControl && dotnet run           # automated demo
```

## Project Structure

```
src/
  AAuth.Core/           Shared primitives
    Discovery/          JWKS endpoint discovery and caching
    Headers/            AAuth protocol headers (Requirement, Access, Capabilities, Mission)
    Identifiers/        AAuth identifier and server identifier validation
    Signatures/         HTTP Message Signatures (sign, verify, input, key header, thumbprint)
    Tokens/             JWT token types (AgentToken, ResourceToken, AuthToken, Mission)
  AAuth.Agent/          Agent-side HttpClient handler
  AAuth.Server/         Server-side ASP.NET Core authentication
samples/
  HelloAAuth/           Sample 1: Identity-based access
  FirstCallRegistration/ Sample 2: Two-party resource-managed access
  PSAssertedAccess/     Sample 3: Three-party PS-asserted access
  MissionControl/       Sample 4: Mission lifecycle and governance dashboard
tests/
  AAuth.Core.Tests/     Unit tests for core primitives
  AAuth.Agent.Tests/    Agent handler tests
  AAuth.Server.Tests/   Server handler tests
  AAuth.Integration.Tests/  End-to-end tests
```

## Protocol Support

This implementation covers:

- **Access modes**: identity-based, two-party, three-party (four-party is structurally supported)
- **Token types**: `aa-agent+jwt`, `aa-resource+jwt`, `aa-auth+jwt`
- **Signatures**: RFC 9421 HTTP Message Signatures with Ed25519 (EdDSA) and ECDSA P-256 (ES256 compatibility)
- **Headers**: `AAuth-Requirement`, `AAuth-Access`, `AAuth-Capabilities`, `AAuth-Mission`
- **Discovery**: `{iss}/.well-known/{dwk}` metadata fetch with rate-limited JWKS caching
- **Deferred responses**: 202 polling with `Prefer: wait=`, retry-after, clarification, and interaction callbacks

## AAuth Specification

The evolving AAuth specification lives in a separate repository:
- GitHub: https://github.com/DickHardt/AAuth

## Dev Container Details

The dev container is configured in `.devcontainer/`:

| File | Description |
|------|-------------|
| `Dockerfile` | Builds an image based on `mcr.microsoft.com/dotnet/sdk:10.0` |
| `devcontainer.json` | Configures VS Code extensions and the post-create restore command |

Included VS Code extensions:
- **C# Dev Kit** (`ms-dotnettools.csdevkit`)
- **C#** (`ms-dotnettools.csharp`)
- **.NET Runtime Install Tool** (`ms-dotnettools.vscode-dotnet-runtime`)

### Cross-referencing the TypeScript AAuth Samples

If you're also working on the [TypeScript AAuth samples](https://github.com/nedruk/aauth-samples), you can mount that folder into the dev container for cross-reference. Set the `AAUTH_TS_SAMPLES` environment variable on your **host machine** to the local path of the TS samples repo:

```bash
# Add to your shell profile (~/.zshrc, ~/.bashrc, etc.)
export AAUTH_TS_SAMPLES="/path/to/your/aauth-samples"
```

The folder will be available inside the container at `/workspaces/aauth-samples`.

If the variable is not set, an empty placeholder directory is mounted instead — the dev container works normally either way.
