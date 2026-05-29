# AAuth .NET Labs Playbook

This playbook gives you **two ways** to validate implementation + samples before production:

1. **Mode A (semi-automated):** run each sample in `--interactive` and use built-in commands.
2. **Mode B (fully manual):** use `.http` request files + helper signing script and inspect headers/status yourself.

---

## Lab structure

```text
labs/
  playbook.md
  http/
    sample1-hello.http
    sample2-first-call.http
    sample3-ps-asserted.http
    sample4-mission-control.http
    sample5-federated.http
  scripts/
    AAuth.SignTool/          # .NET signing helper (uses AAuth.Core)
```

---

## Prerequisites

1. Trust localhost cert:
   ```bash
   dotnet dev-certs https --trust
   ```
2. Linux/OpenSSL trust path (same shell where you run tests):
   ```bash
   export SSL_CERT_DIR="$HOME/.aspnet/dev-certs/trust:/usr/lib/ssl/certs"
   ```
3. Build and tests:
   ```bash
   dotnet build
   dotnet test
   ```
4. For manual header signing helper:
   ```bash
   dotnet run --project labs/scripts/AAuth.SignTool -- --help
   ```

---

## Mode A: Interactive CLI labs

> Each sample runs local servers and provides a REPL for exploration.
> Some commands (Sample 2 `call`, Sample 4 `mission`/`permission`/`complete`) block
> the REPL while waiting for user approval — this is by design, mirroring how
> `AAuthDelegatingHandler` and `DeferredResponseLoop` work in production.
> Use Mode B (`.http` files) for step-by-step protocol exploration.

### Sample 1 — HelloAAuth

**What you'll learn:**
- How HTTP Message Signatures prove agent identity (proof-of-possession via `cnf.jwk`).
- How the resource server discovers the agent's public keys via AP metadata + JWKS.
- How an allowlist controls access — same signature mechanism, different authorization outcome.
- The structure of `Signature`, `Signature-Input`, and `Signature-Key` headers.

```bash
dotnet run --project samples/HelloAAuth -- interactive
```
Commands to run:
- `valid`: expected `200` — agent is on the allowlist
- `unknown`: expected `401` — self-issued token with unknown issuer (JWKS unreachable)
- `unsigned`: expected `401` — no signature headers at all
- `token`, `keys` for inspection

**What to observe:**
- `200` vs `401` demonstrates that the resource trusts the **signature chain** (JWT issuer → JWKS → public key → HTTP signature), not just any valid JWT.
- The `unknown` case fails because the resource cannot fetch JWKS from `https://localhost:9999`.

### Sample 2 — FirstCallRegistration

**What you'll learn:**
- Two-party resource-managed access: the resource server controls consent, not a separate AS.
- The 202 deferred response pattern: the resource returns a pending URL + interaction URL instead of blocking.
- How `AAuthDelegatingHandler` automates the entire flow: sign → receive 202 → poll `DeferredResponseLoop` → receive `AAuth-Access` → retry with cached token.
- How the opaque `AAuth-Access` token is bound to the agent's proof-of-possession key.

```bash
dotnet run --project samples/FirstCallRegistration -- interactive
```
Commands:
- `call` — sends a signed `GET /api/data` through `AAuthDelegatingHandler`
- `poll <id>` — manually poll a pending URL (Mode B helper)
- `use <AAuth-Access-token>` — manually call with explicit access token (Mode B helper)
- `token` — print agent JWT (for manual `.http` flow)

**How `call` works behind the scenes:**

1. `AAuthDelegatingHandler` signs the request with the agent token and sends it.
2. The resource returns **202 Accepted** with:
   - `AAuth-Requirement: requirement=interaction; url="…/interact"; code="…"` — where the user can approve.
   - `Location: /pending/{id}` — the polling URL.
3. The handler prints the interaction URL and starts `DeferredResponseLoop`, which polls `/pending/{id}` with exponential backoff.
4. **The REPL blocks here** — open the printed URL in a browser (or `POST /interact/approve` from another terminal) to approve.
5. Once approved, the pending URL returns **200** with `AAuth-Access` header.
6. The handler caches the access token and retries the original request with `Authorization: AAuth <token>`.
7. The resource returns **200** with the protected data.

**After approval:**
Subsequent `call` requests succeed immediately — the handler finds the cached `AAuth-Access` token and signs the request with it. No 202/polling cycle occurs.

**To explore protocol steps manually,** use Mode B (`.http` files) which lets you perform each step independently: send raw signed request → see 202 → approve → poll → use access token.

**Observing the pending URL lifecycle:**
- Before approval: `GET /pending/{id}` returns **202** (still pending).
- After approval: returns **200** + `AAuth-Access` header (one-time retrieval).
- After retrieval: returns **410 Gone** (consumed).

### Sample 3 — PSAssertedAccess

**What you'll learn:**
- The three-party flow: Resource → resource token → Person Server → auth token → Resource.
- How the resource token is a scoped, signed invitation for the PS to vouch for the agent.
- How the auth token (issued by PS) asserts the person's identity and binds it to the agent's key.
- Token-type gating: the resource rejects agent tokens on protected endpoints and requires an auth token (`AAuth-Requirement: requirement=auth-token`).

```bash
dotnet run --project samples/PSAssertedAccess -- interactive
```
Commands:
- `authorize [scope]` — POST `/authorize` → get resource token
- `exchange` — POST PS `/token` with resource token → get auth token
- `access` — GET `/api/documents` with auth token
- `flow [scope]` — run all three steps automatically
- `token` — print the full agent token JWT (for Mode B signing)
- `keys` — print all public key identifiers
- `tokens`, `metadata` — inspect stored tokens and server metadata

**What to observe:**
- The resource token's `aud` points to the Person Server, not the resource itself.
- The auth token's `sub` identifies the person, `aud` identifies the resource, and `cnf` binds to the agent's key.
- Calling `/api/documents` with just an agent token returns 401 + `AAuth-Requirement` header demanding an auth token.

### Sample 4 — MissionControl

**What you'll learn:**
- Mission lifecycle: propose → approve → execute → complete.
- How the `AAuth-Mission` header carries mission context in signed requests.
- Governance endpoints: `permission` (request tool-level approval), `audit` (log actions), `interaction` (completion).
- How mission context flows through the token chain: mission hash (`s256`) is embedded in resource and auth tokens.
- Dashboard-driven approval: the Person Server exposes a web UI for human-in-the-loop governance.

```bash
dotnet run --project samples/MissionControl -- interactive
```
Commands:
- `mission [desc]` — propose a mission (blocks until approved via dashboard)
- `permission <action>` — request permission for a specific tool (blocks until approved)
- `audit <action> [desc]` — log an action taken during the mission
- `authorize [scope]` — POST `/authorize` with `AAuth-Mission` header
- `exchange` — exchange resource token for auth token at PS
- `access` — access protected resource with auth token
- `complete [summary]` — mark mission as complete (blocks until accepted)
- `flow [scope]`, `status` — automated flow and state inspection
- `token` — print the full agent token JWT (for Mode B signing)
- `keys` — print all public key identifiers

**Note:** `mission`, `permission`, and `complete` block the REPL while polling for dashboard approval — open `{psUrl}/dashboard` in a browser to approve.

### Sample 5 — FederatedAccess

**What you'll learn:**
- The four-party flow: Agent → Resource 1 → PS → Access Server → auth token.
- PS↔AS federation: the Person Server discovers the Access Server and forwards the token exchange.
- AS-issued auth tokens: the auth token's `dwk` points to `aauth-access.json` (AS discovery), not `aauth-person.json`.
- Call chaining: Resource 1 acts as an agent to access Resource 2, creating a delegation chain.
- Nested `act` claims: the auth token for Resource 2 contains an `act` claim showing the full delegation path.

```bash
dotnet run --project samples/FederatedAccess -- interactive
```
Commands:
- `authorize [scope]` — POST `/authorize` to Resource 1 → get resource token (aud=AS)
- `exchange [rt]` — POST `/token` to PS (triggers PS→AS federation) → get auth token
- `access [at]` — GET `/api/data` on Resource 1 with auth token
- `enriched [at]` — GET `/api/enriched` on Resource 1 (triggers R1→R2 call chaining)
- `token`, `keys` — inspect demo agent JWT and all party keys

**What to observe:**
- The resource token's `aud` points to the Access Server, not the PS directly.
- The `enriched` response shows data from both Resource 1 and Resource 2.
- Resource 1 acts as an agent (has its own agent token and ephemeral key) when calling Resource 2.

---

## Mode B: Fully manual via `.http` + signing helper

Use files in `labs/http/`.

### 1) Start the target sample
Run sample in a separate terminal (`--interactive` is convenient because it prints useful tokens/URLs).

### 2) Get a JWT for signing
For sample flows, use `token` command in interactive mode and copy JWT to shell:

```bash
export AGENT_JWT='<paste JWT>'
```

### 3) Generate AAuth signature headers

> **Important:** Signed headers are only valid for about **60 seconds** (`created` window).  
> Generate headers, paste them, and send the request immediately. If you wait too long, regenerate them.

Example:
```bash
dotnet run --project labs/scripts/AAuth.SignTool -- \
  --jwt "$AGENT_JWT" \
  --method GET \
  --url "https://localhost:3012/api/hello"
```

If request includes `Authorization` and you need it signed:
```bash
dotnet run --project labs/scripts/AAuth.SignTool -- \
  --jwt "$AGENT_JWT" \
  --method GET \
  --url "https://localhost:3012/api/data" \
  --component authorization \
  --header "authorization:AAuth <access-token>"
```

If signing with an **auth token** (Samples 3–5, access steps):  
The auth token's `cnf.jwk` only has the public key — the PS/AS doesn't know your private key.  
Use `--key-jwt` to supply the agent token (which has the private key) for signing:
```bash
export AUTH_TOKEN='<paste auth token from exchange step>'
dotnet run --project labs/scripts/AAuth.SignTool -- \
  --jwt "$AUTH_TOKEN" \
  --key-jwt "$AGENT_JWT" \
  --method GET \
  --url "https://localhost:3012/api/documents"
```
`--jwt` sets the `Signature-Key` header value (auth token), `--key-jwt` provides the private key for the actual signature.

If request includes `AAuth-Mission` and you need it signed:
```bash
dotnet run --project labs/scripts/AAuth.SignTool -- \
  --jwt "$AGENT_JWT" \
  --method POST \
  --url "https://localhost:3012/authorize" \
  --component aauth-mission \
  --header "aauth-mission:<mission-header-value>"
```

Paste emitted `Signature-Key`, `Signature-Input`, `Signature` into corresponding `.http` request blocks.

### 4) Execute lab `.http` files

- `labs/http/sample1-hello.http`
- `labs/http/sample2-first-call.http`
- `labs/http/sample3-ps-asserted.http`
- `labs/http/sample4-mission-control.http`
- `labs/http/sample5-federated.http`

Each file includes:
- metadata checks
- required headers
- expected status and key headers to inspect
- negative checks

### Quick way to create a forged token for negative tests

1. Copy a valid JWT.
2. Change one character in the **3rd JWT segment** (signature part, after the second `.`).
3. Re-sign the HTTP request using that tampered JWT and send immediately.
4. Expected result: `401` or `403`.

---

## Spec checks to pay attention to while running manual requests

1. **Agent token verification**
   - verify typ/dwk/signature/lifetime/issuer/cnf binding
2. **Auth-token challenge**
   - `401` with `AAuth-Requirement: requirement=auth-token; resource-token="..."`
3. **AAuth-Access binding**
   - `Authorization: AAuth ...` must be included in signed components
4. **Pending URL behavior**
   - polling identity checked
   - terminal URL returns `410 Gone`
5. **Mission signing**
   - when `AAuth-Mission` header present, `aauth-mission` should be covered in signature input
6. **Federated flow**
   - AS-issued auth token (`dwk=aauth-access.json`)
   - call chaining works and delegation chain is preserved

---

## Evidence to collect

- Terminal output from Mode A commands.
- Saved request/response snapshots from `.http` runs.
- Headers observed for key checks:
  - `AAuth-Requirement`
  - `AAuth-Access`
  - `Signature`, `Signature-Input`, `Signature-Key`
- Any failed case + exact response body/headers.
