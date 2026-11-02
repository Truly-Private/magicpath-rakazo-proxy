# magicpath-rakazo-proxy

A single-account Node.js/TypeScript bridge between MagicPath's OAuth-protected MCP endpoint and a client using a static Bearer token. It proxies JSON-RPC and Streamable HTTP responses, including SSE, and generates an OpenAPI 3.0.3 interface from the **live authenticated tool catalog**. No MagicPath tool names or Canvas APIs are invented.

## What is verified and what is not

- Public discovery checked on 2026-11-02: resource `https://api.magicpath.ai/mcp`, issuer `https://api.magicpath.ai/`, authorization `/authorize`, token `/token`, registration `/register`, PKCE `S256`, scopes `magicpath:read magicpath:write`, grants authorization code and refresh token; public-client `none` and `client_secret_post` are advertised.
- MagicPath's current endpoint reports that it is **stateless and accepts POST requests**. This proxy forwards GET/DELETE as well for protocol compatibility, but does not fabricate legacy SSE support when upstream returns 405. SSE **POST response** forwarding is implemented.
- Automated tests use fixture accounts/tokens and mocked HTTPS upstream responses plus real loopback HTTP calls to this server. No live account was connected, client registered, tool called, or refresh rotation tested with MagicPath. Actual callback acceptance, client registration policy, supported version and catalog require operator-approved live testing.
- Current Rakazo has a direct-MCP OAuth flow already. This bridge is for static-token/older connector paths or OpenAPI convenience, not a requirement for every Rakazo installation.

Sources: [MagicPath official plugin](https://github.com/MagicPathAI/magicpath-agent-plugin), [resource metadata](https://api.magicpath.ai/.well-known/oauth-protected-resource/mcp), [authorization metadata](https://api.magicpath.ai/.well-known/oauth-authorization-server), [Rakazo](https://github.com/elie222/rakazo), [MCP authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization).

## Native setup (recommended for initial authorization)

Requires Node.js 22+ and npm. Never use the malformed URL ending in a backtick from copied Markdown.

```sh
npm ci
cp .env.example .env
# Edit .env as described below. Never commit it.
npm run build
npm start
```

Configure these values yourself:

1. `RAKAZO_SECRET_TOKEN`: high-entropy secret, minimum 32 non-whitespace characters. This grants **all capabilities of the connected MagicPath account**; dedicate an account/workspace and minimize OAuth scopes if possible.
2. `TOKEN_ENCRYPTION_KEY`: independent, base64-encoded 32 random bytes. Retain securely across restarts. Losing it requires reconnecting; rotation is not automatic. For example, run `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"` locally twice for distinct values. These are user-initiated credential generation instructions, not values embedded in this project.
3. `MAGICPATH_CLIENT_ID`: a client registered through MagicPath's approved process with redirect URI **exactly** `http://localhost:3100/auth/callback` (or your configured loopback `PUBLIC_URL`). This project does **not** automatically register an OAuth client or assume the advertised registration endpoint permits registration. Obtain approval and register a public client (`token_endpoint_auth_method: none`) or set `MAGICPATH_CLIENT_SECRET` only for a registered `client_secret_post` client. Other client-auth methods are not implemented.
4. Optional `MAGICPATH_SCOPES`: defaults to the two advertised scopes; no fabricated `offline_access` scope. Refresh issuance depends on provider policy.

At first startup:

```text
[MagicPath Proxy] Please visit http://localhost:3100/auth/login to complete initial MagicPath browser authentication.
```

Open that page, click **Authorize MagicPath**, and complete the provider's browser consent. The callback stores encrypted tokens locally and never displays them. Login includes a single-use CSRF form, PKCE S256, one-time state and a matching HttpOnly browser cookie. Only the operator initiates this flow. Access tokens are refreshed proactively and on demand; refresh calls are single-flight and refresh-token rotation is persisted atomically. On invalid consent/refresh, reconnect locally. This is not an infinite-lifetime guarantee.

**Port conflict:** Rakazo's own API commonly uses port 3100. Do not stop it. Use `PORT=3101`, `PUBLIC_URL=http://localhost:3101`, and register the matching callback instead.

## Connect Rakazo

`npm run config` prints a **credential-redacted connection payload template**, also printed at startup. Replace the placeholder inside Rakazo's secure credential field, not in shared logs. Based on Rakazo's `rpc.mcp.servers.create` contract (reviewed main commit `9375bced1cf01bd1b4e21df4441585e8cd84b364`):

```json
{
  "slug": "magicpath-proxy",
  "name": "MagicPath proxy",
  "transport": "streamable_http",
  "endpoint": "http://localhost:3100/mcp",
  "headers": {},
  "secret": "<your RAKAZO_SECRET_TOKEN>",
  "enabled": true
}
```

This is a Rakazo RPC payload, **not** a generic `mcpServers` file or a claim that every UI version accepts pasted JSON. In the direct MCP Server UI choose HTTP/Streamable HTTP, enter the endpoint and the access-token/secret field. Rakazo injects `Authorization: Bearer …`.

For the installed OpenAPI connector path, use the reachable `/openapi.json` URL and a separately stored Bearer credential. Its reviewed install payload is:

```json
{
  "kind": "api",
  "name": "MagicPath proxy",
  "source": "http://localhost:3100/openapi.json",
  "config": { "openApi": true, "auth": { "type": "bearer" }, "headers": {} },
  "credential": "<your RAKAZO_SECRET_TOKEN>"
}
```

Do not put secrets in installed-connector `config.headers`; Rakazo rejects sensitive public headers there. The live OpenAPI spec itself is Bearer-protected, so the importing client must attach the credential while fetching it. If your UI fetches the spec before applying credentials, securely fetch/import the JSON manually according to that UI's supported workflow; do not make the schema public as a workaround.

`/swagger` is an operator-only interactive Swagger UI. Connect OAuth first, then select **Authorize** and supply the static proxy token for tool calls. Authorization is kept in browser memory, not localStorage. Tool calls can mutate your real MagicPath account: use read-only operations first and review arguments.

### Container/network caveats

`localhost` inside a Rakazo container is that container, not this proxy's host. Set `RAKAZO_PROXY_URL` to an origin the API and worker can reach, e.g. `http://host.docker.internal:3100` on a supported Docker Desktop setup. It controls the generated OpenAPI server URL and permitted Host header; OAuth callback remains loopback `PUBLIC_URL`. Linux may require an explicitly configured host-gateway or host network; verify routing, firewall and isolation rather than exposing a token-bearing service publicly. No network/security settings are changed by this project.

Rakazo rejects private endpoints by default; if your installation requires `MCP_ALLOW_PRIVATE_ENDPOINT=true` on API and worker, enabling it is an **operator security-policy choice**, not something this proxy silently changes. Prefer a narrowly trusted deployment and never expose this HTTP service to untrusted networks. For cross-host access, add operator-managed TLS and a separate design review; remote browser OAuth setup is intentionally unsupported by default.

## Docker

```sh
# Populate .env, including a separate ADMIN_SECRET_TOKEN (>=32 characters).
docker compose up --build
```

Compose publishes only `127.0.0.1:3100`, runs as the nonroot `node` user with dropped capabilities, and stores encrypted tokens in a named volume. Browser requests traversing Docker aren't loopback peers inside the container; `ADMIN_SECRET_TOKEN` enables HTTP Basic authentication for setup/Swagger/status. Use username `admin` and that separate secret. It is also enforced for native setup when configured. Keep the port bound to loopback; Basic auth is not a replacement for TLS on an exposed network. Cookie and Host/Origin checks still apply. Ensure `PUBLIC_URL`, published port and registered redirect match when changing ports. Docker image construction/runtime has not been independently exercised in this workspace.

## API and protocol behavior

| Route                                 | Access                                        | Behavior                                             |
| ------------------------------------- | --------------------------------------------- | ---------------------------------------------------- |
| GET `/healthz`                        | Host/Origin checks                            | Liveness only; no token material                     |
| GET `/auth/login`, POST `/auth/login` | Local operator or configured admin Basic auth | Page and one-time PKCE consent initiation            |
| GET `/auth/callback`                  | Same admin policy + browser state cookie      | Code exchange, encrypted persistence                 |
| GET `/auth/status`                    | Operator only                                 | Boolean connection/refresh/client status             |
| POST/GET/DELETE `/mcp`                | Static Bearer                                 | Raw JSON-RPC forwarding, valid OAuth injected        |
| GET `/openapi.json`                   | Static Bearer                                 | Live `tools/list` → OpenAPI 3.0.3; 503 before auth   |
| POST `/api/tools/tool_<hash>`         | Static Bearer                                 | Arguments object → actual `tools/call` result        |
| GET `/swagger`                        | Operator only                                 | Local bundled Swagger UI, catalog loaded after OAuth |

The transparent MCP route covers tools/resources/prompts and notifications without whitelisting method names. It forwards protocol/session/reconnect headers, propagates upstream status and SSE bytes, aborts upstream when the client disconnects and bounds each proxy response to 120 seconds. That timeout is configurable in code, not a promise to support indefinite streams. No automatic replay of `tools/call`, including on HTTP 401, because an uncertain side effect must not be duplicated. Upstream 401 becomes sanitized 502 with a reconnect instruction, not a downstream OAuth challenge.

The OpenAPI adapter uses its own initialized MCP session, negotiates a known protocol version, pages the actual catalog and uses stable hashed operation IDs. It checks JSON-RPC IDs/errors and supports JSON or SSE replies. Returned MCP `isError: true` is a tool-level error even with HTTP 200; consumers must inspect it. Schema mapping resolves local `$ref`s and translates common nullable/union forms. Recursive/external references and unsupported JSON Schema conditionals fail closed (503 catalog) rather than silently inventing a request schema; use native `/mcp` for such tools until an explicit adapter is added. The original schema is retained in `x-original-json-schema`. There is no claim that OpenAPI 3.0 represents every JSON Schema 2020-12 feature or multimodal MCP feature.

## Security / operational boundaries

- One OAuth account, one process, one trusted Rakazo principal. Not multitenant and not HA: do not share the state file across processes. Static token holders inherit all connected-account tools.
- HTTPS upstreams only; trusted OAuth origins explicitly configured; resource and issuer checked; discovery and token requests reject redirects. Do not loosen the allowlist to untrusted issuers. No arbitrary target URL parameter exists.
- AES-256-GCM token file with random nonce, authenticated ciphertext, atomic rename, owner-only file/directory permissions. The encryption key remains in `.env`/your secret store, not beside the ciphertext in public source. `.env`, state and archives are ignored by Git and Docker.
- Default loopback binding, no CORS, strict Host/Origin checks, bounded request bodies, no access-token/refresh-token/request-body logging. Protect the host: local malicious processes with filesystem access are outside this boundary.
- Consent endpoints create only short-lived PKCE/CSRF randomness. This program never creates persistent credentials automatically. Registration, credential setup, account connection and publishing are operator actions.
- Restart loses pending login state and OpenAPI MCP session, but retains encrypted OAuth state. Re-run login if a callback crosses a restart. If the provider invalidates a session, restart the adapter/proxy; no unsafe automatic tool retry occurs.
- Dependency versions are locked. Docker base tags remain mutable: production deployment should pin an approved image digest and review dependency advisories.

## Development and verification

```sh
npm ci
npm run check
npm test
npm run build
```

Tests cover configuration, ciphertext/mode/reload/wrong-key handling, static auth, hostile Host/Origin, transparent SSE/session/payload forwarding, no 401 replay, concurrent refresh/rotation, PKCE cookie/state replay, hostile issuer rejection, live tool-derived schema and local-ref handling. They do not exercise live OAuth consent, MagicPath tool behavior, a Rakazo installation, Docker or exhaustive MCP conformance. A passing fixture suite is not evidence of a connected account.

## Files

`src/index.ts` server and route authorization; `auth.ts` discovery/PKCE/refresh; `store.ts` encrypted state; `mcp-proxy.ts` streaming proxy and catalog client; `openapi.ts` tool mapping; `config.ts` validated configuration; `test/` fixture integration tests.
