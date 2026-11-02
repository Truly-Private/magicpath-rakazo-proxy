import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, stat, rm, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { request } from "node:http";
import { config, Config, equalSecret } from "../src/config.js";
import { Auth, Fetch } from "../src/auth.js";
import { TokenStore } from "../src/store.js";
import { createApp } from "../src/index.js";
import { specification, toolId } from "../src/openapi.js";
const secret = "fixture-only-static-secret-not-production";
function cfg(file: string): Config {
  return config({
    RAKAZO_SECRET_TOKEN: secret,
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
    TOKEN_STATE_FILE: file,
    MAGICPATH_CLIENT_ID: "fixture-client",
  });
}
async function setup(mock?: Fetch) {
  const dir = await mkdtemp(join(tmpdir(), "magicpath-test-"));
  const c = cfg(join(dir, "tokens.json"));
  const store = new TokenStore(c.stateFile, c.key);
  const auth = new Auth(c, store, mock);
  const app = createApp(c, auth, mock);
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  c.port = (server.address() as any).port;
  c.publicUrl = `http://127.0.0.1:${c.port}`;
  return {
    c,
    auth,
    store,
    base: c.publicUrl,
    close: async () => {
      await new Promise<void>((r) => server.close(() => r()));
      await rm(dir, { recursive: true, force: true });
    },
  };
}
const liveTokens = {
  access_token: "fixture-access-token",
  refresh_token: "fixture-refresh",
  token_type: "Bearer",
  expires_at: Date.now() + 3600000,
};
function discovery(url: string) {
  if (url.includes("oauth-protected-resource"))
    return Response.json({
      resource: "https://api.magicpath.ai/mcp",
      authorization_servers: ["https://api.magicpath.ai/"],
    });
  if (url.includes("oauth-authorization-server"))
    return Response.json({
      issuer: "https://api.magicpath.ai/",
      authorization_endpoint: "https://api.magicpath.ai/authorize",
      token_endpoint: "https://api.magicpath.ai/token",
      code_challenge_methods_supported: ["S256"],
    });
}
test("configuration rejects weak secrets and unsafe endpoint", () => {
  assert.throws(() => config({}));
  assert.throws(() =>
    config({
      ...process.env,
      RAKAZO_SECRET_TOKEN: secret,
      TOKEN_ENCRYPTION_KEY: Buffer.alloc(32).toString("base64"),
      MAGICPATH_MCP_URL: "http://evil.test/mcp",
    }),
  );
  assert.equal(equalSecret("abc", "abd"), false);
});
test("encrypted owner-only storage survives reload without plaintext", async () => {
  const x = await setup();
  try {
    await x.store.write(liveTokens);
    const raw = await readFile(x.c.stateFile, "utf8");
    assert(!raw.includes(liveTokens.access_token));
    assert.equal((await stat(x.c.stateFile)).mode & 0o777, 0o600);
    assert.deepEqual(await x.store.read(), liveTokens);
  } finally {
    await x.close();
  }
});
test("wrong encryption key fails closed", async () => {
  const x = await setup();
  try {
    await x.store.write(liveTokens);
    await assert.rejects(
      new TokenStore(x.c.stateFile, Buffer.alloc(32, 9)).read(),
    );
  } finally {
    await x.close();
  }
});
test("static auth and Origin/Host protections precede upstream", async () => {
  let calls = 0;
  const x = await setup((async () => {
    calls++;
    throw Error();
  }) as Fetch);
  try {
    assert.equal(
      (await fetch(x.base + "/mcp", { method: "POST", body: "{}" })).status,
      401,
    );
    assert.equal(
      (
        await fetch(x.base + "/mcp", {
          headers: {
            authorization: `Bearer ${secret}`,
            origin: "https://evil.test",
          },
        })
      ).status,
      403,
    );
    assert.equal(
      await new Promise<number>((resolve) => {
        const r = request(
          x.base + "/healthz",
          { headers: { host: "evil.test" } },
          (res) => {
            res.resume();
            resolve(res.statusCode!);
          },
        );
        r.end();
      }),
      403,
    );
    assert.equal(calls, 0);
  } finally {
    await x.close();
  }
});
test("MCP JSON and SSE forwarding preserves payload/session, replaces credentials", async () => {
  let received: any;
  const x = await setup((async (_url, init) => {
    received = init;
    return new Response(
      'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n',
      {
        headers: {
          "content-type": "text/event-stream",
          "mcp-session-id": "upstream-session",
        },
      },
    );
  }) as Fetch);
  try {
    await x.store.write(liveTokens);
    await x.auth.load();
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
    });
    const r = await fetch(x.base + "/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${secret}`,
        "content-type": "application/json",
        "mcp-session-id": "previous",
        "mcp-protocol-version": "2025-03-26",
      },
      body,
    });
    assert.equal(r.status, 200);
    assert((await r.text()).includes("event: message"));
    assert.equal(r.headers.get("mcp-session-id"), "upstream-session");
    assert.equal(
      received.headers.get("authorization"),
      `Bearer ${liveTokens.access_token}`,
    );
    assert.equal(received.headers.get("mcp-session-id"), "previous");
    assert.equal(received.body.toString(), body);
  } finally {
    await x.close();
  }
});
test("MCP mutating requests never retry after upstream 401", async () => {
  let calls = 0;
  const x = await setup((async () => {
    calls++;
    return new Response("sensitive failure", { status: 401 });
  }) as Fetch);
  try {
    await x.store.write(liveTokens);
    await x.auth.load();
    const r = await fetch(x.base + "/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${secret}`,
        "content-type": "application/json",
      },
      body: '{"method":"tools/call"}',
    });
    assert.equal(r.status, 502);
    assert(!(await r.text()).includes("sensitive"));
    assert.equal(calls, 1);
  } finally {
    await x.close();
  }
});
test("refresh is single-flight and retains rotated refresh token", async () => {
  let exchanges = 0;
  const mock = (async (url, init) => {
    const d = discovery(String(url));
    if (d) return d;
    exchanges++;
    assert.equal(
      new URLSearchParams(String(init?.body)).get("resource"),
      "https://api.magicpath.ai/mcp",
    );
    await new Promise((r) => setTimeout(r, 15));
    return Response.json({
      access_token: "new",
      refresh_token: "rotated",
      expires_in: 3600,
      token_type: "Bearer",
    });
  }) as Fetch;
  const x = await setup(mock);
  try {
    await x.store.write({ ...liveTokens, expires_at: 0 });
    await x.auth.load();
    const values = await Promise.all(
      Array.from({ length: 10 }, () => x.auth.accessToken()),
    );
    assert(values.every((t) => t === "new"));
    assert.equal(exchanges, 1);
    assert.equal((await x.store.read())?.refresh_token, "rotated");
  } finally {
    await x.close();
  }
});
test("PKCE browser state is bound and one-time, token exchange occurs only after matching cookie", async () => {
  let exchange = 0;
  let challenge = "";
  const mock = (async (url, init) => {
    const d = discovery(String(url));
    if (d) return d;
    exchange++;
    const b = new URLSearchParams(String(init?.body));
    assert(b.get("code_verifier")!.length >= 43);
    assert.equal(
      createHash("sha256").update(b.get("code_verifier")!).digest("base64url"),
      challenge,
    );
    assert.equal(b.get("grant_type"), "authorization_code");
    return Response.json({
      access_token: "fixture-new",
      refresh_token: "fixture-refresh",
      expires_in: 3600,
      token_type: "Bearer",
    });
  }) as Fetch;
  const x = await setup(mock);
  try {
    const page = await fetch(x.base + "/auth/login");
    const cookie = page.headers.get("set-cookie")!.split(";")[0];
    const csrf = (await page.text()).match(/name="csrf" value="([^"]+)"/)![1];
    const login = await fetch(x.base + "/auth/login", {
      method: "POST",
      redirect: "manual",
      headers: {
        cookie,
        "content-type": "application/x-www-form-urlencoded",
        origin: x.base,
      },
      body: new URLSearchParams({ csrf }),
    });
    assert.equal(login.status, 302);
    const location = new URL(login.headers.get("location")!);
    assert.equal(location.searchParams.get("code_challenge_method"), "S256");
    assert.equal(
      location.searchParams.get("resource"),
      "https://api.magicpath.ai/mcp",
    );
    challenge = location.searchParams.get("code_challenge")!;
    const state = location.searchParams.get("state");
    const cb = x.base + `/auth/callback?code=fixture-code&state=${state}`;
    assert.equal((await fetch(cb)).status, 400);
    assert.equal(exchange, 0);
    const browser = login.headers.get("set-cookie")!.split(";")[0];
    assert.equal(
      (await fetch(cb, { headers: { cookie: browser } })).status,
      200,
    );
    assert.equal(exchange, 1);
    assert.equal(
      (await fetch(cb, { headers: { cookie: browser } })).status,
      400,
    );
  } finally {
    await x.close();
  }
});
test("OAuth discovery rejects hostile issuer before fetch", async () => {
  let calls = 0;
  const x = await setup((async () => {
    calls++;
    return Response.json({
      resource: "https://api.magicpath.ai/mcp",
      authorization_servers: ["https://evil.test/"],
    });
  }) as Fetch);
  try {
    await assert.rejects(x.auth.discover(), /Untrusted/);
    assert.equal(calls, 1);
  } finally {
    await x.close();
  }
});
test("OpenAPI dynamically maps real tools and does not invent capabilities", async () => {
  const calls: string[] = [];
  const mock = (async (_url, init) => {
    const q = JSON.parse(String(init?.body));
    calls.push(q.method);
    const headers = new Headers(init?.headers);
    assert.equal(
      headers.get("mcp-protocol-version"),
      q.method === "initialize" ? null : "2025-03-26",
    );
    if (q.method === "notifications/initialized")
      return new Response(null, { status: 202 });
    return Response.json({
      jsonrpc: "2.0",
      id: q.id,
      result:
        q.method === "initialize"
          ? {
              protocolVersion: "2025-03-26",
              capabilities: {},
              serverInfo: { name: "fixture", version: "1" },
            }
          : q.method === "tools/list"
            ? {
                tools: [
                  {
                    name: "fixture.create_canvas",
                    inputSchema: {
                      type: "object",
                      properties: { title: { type: "string" } },
                      required: ["title"],
                    },
                  },
                ],
              }
            : { content: [{ type: "text", text: "created" }], isError: false },
    });
  }) as Fetch;
  const x = await setup(mock);
  try {
    await x.store.write(liveTokens);
    await x.auth.load();
    const headers = { authorization: `Bearer ${secret}` };
    const r = await fetch(x.base + "/openapi.json", { headers });
    assert.equal(r.status, 200);
    const spec = (await r.json()) as any;
    assert.equal(spec.openapi, "3.0.3");
    const swagger = await fetch(x.base + "/swagger/swagger-ui-init.js");
    assert.equal(swagger.status, 200);
    assert.equal(
      swagger.headers.get("cross-origin-resource-policy"),
      "same-origin",
    );
    const path = Object.keys(spec.paths)[0];
    assert.equal(path, `/api/tools/${toolId("fixture.create_canvas")}`);
    const result = await fetch(x.base + path, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: '{"title":"fixture"}',
    });
    assert.equal(result.status, 200);
    assert(calls.includes("tools/call"));
    assert.equal(calls.filter((v) => v === "initialize").length, 1);
  } finally {
    await x.close();
  }
});
test("OpenAPI unavailable before OAuth; private catalog requires static bearer", async () => {
  const x = await setup();
  try {
    assert.equal((await fetch(x.base + "/openapi.json")).status, 401);
    assert.equal(
      (
        await fetch(x.base + "/openapi.json", {
          headers: { authorization: `Bearer ${secret}` },
        })
      ).status,
      503,
    );
  } finally {
    await x.close();
  }
});

test("OpenAPI resolves local JSON Schema refs and rejects unsupported recursive schemas", () => {
  const schema = {
    type: "object",
    properties: { item: { $ref: "#/$defs/item" } },
    $defs: {
      item: { type: "object", properties: { label: { type: "string" } } },
    },
  };
  const spec = specification("http://localhost:3100", [
    { name: "ref-tool", inputSchema: schema },
  ]) as any;
  assert.equal(
    spec.paths["/api/tools/" + toolId("ref-tool")].post.requestBody.content[
      "application/json"
    ].schema.properties.item.properties.label.type,
    "string",
  );
  assert.throws(
    () =>
      specification("http://localhost:3100", [
        {
          name: "recursive",
          inputSchema: {
            $ref: "#/$defs/x",
            $defs: { x: { $ref: "#/$defs/x" } },
          },
        },
      ]),
    /recursive/,
  );
});
test("OpenAPI rejects unsupported constraints instead of silently widening", () => {
  for (const inputSchema of [
    { type: "number", exclusiveMinimum: 0 },
    { type: "array", contains: { type: "string" } },
    { type: "object", dependentRequired: { a: ["b"] } },
  ])
    assert.throws(
      () =>
        specification("http://localhost:3100", [
          { name: "complex", inputSchema },
        ]),
      /Unsupported/,
    );
  const s = specification("http://localhost:3100", [
    {
      name: "intersection",
      inputSchema: {
        $ref: "#/$defs/x",
        type: "integer",
        $defs: { x: { type: "string" } },
      },
    },
  ]) as any;
  assert.deepEqual(
    s.paths["/api/tools/" + toolId("intersection")].post.requestBody.content[
      "application/json"
    ].schema.allOf,
    [{ type: "string" }, { type: "integer" }],
  );
});
test("token mutations serialize refresh and login, stale refresh cannot replace new account", async () => {
  let refreshes = 0;
  const mock = (async (url, init) => {
    const d = discovery(String(url));
    if (d) return d;
    const p = new URLSearchParams(String(init?.body));
    if (p.get("grant_type") === "refresh_token") {
      refreshes++;
      await new Promise((r) => setTimeout(r, 20));
      return Response.json({
        access_token: "old-account-refreshed",
        refresh_token: "old-rotated",
        expires_in: 3600,
        token_type: "Bearer",
      });
    }
    return Response.json({
      access_token: "new-account",
      refresh_token: "new-refresh",
      expires_in: 3600,
      token_type: "Bearer",
    });
  }) as Fetch;
  const x = await setup(mock);
  try {
    await x.store.write({ ...liveTokens, expires_at: 0 });
    await x.auth.load();
    const refresh = x.auth.accessToken();
    const login = (x.auth as any).exchange({
      grant_type: "authorization_code",
      code: "new",
    });
    const stale = (x.auth as any).exchange({
      grant_type: "refresh_token",
      refresh_token: "fixture-refresh",
    });
    await Promise.all([refresh, login, stale]);
    assert.equal((await x.store.read())?.access_token, "new-account");
    assert.equal(refreshes, 1);
  } finally {
    await x.close();
  }
});
test("admin secret is distinct and required when configured", async () => {
  const x = await setup();
  x.c.adminSecret = "fixture-admin-secret-32-plus-characters";
  try {
    assert.equal((await fetch(x.base + "/auth/status")).status, 401);
    assert.equal(
      (
        await fetch(x.base + "/auth/status", {
          headers: { authorization: `Bearer ${secret}` },
        })
      ).status,
      401,
    );
    assert.equal(
      (
        await fetch(x.base + "/auth/status", {
          headers: {
            authorization:
              "Basic " +
              Buffer.from("admin:" + x.c.adminSecret).toString("base64"),
          },
        })
      ).status,
      200,
    );
  } finally {
    await x.close();
  }
});
test("discovered token endpoint on a foreign origin is rejected", async () => {
  const x = await setup((async (url) =>
    String(url).includes("protected-resource")
      ? Response.json({
          resource: "https://api.magicpath.ai/mcp",
          authorization_servers: ["https://api.magicpath.ai/"],
        })
      : Response.json({
          issuer: "https://api.magicpath.ai/",
          authorization_endpoint: "https://api.magicpath.ai/authorize",
          token_endpoint: "https://evil.test/token",
          code_challenge_methods_supported: ["S256"],
        })) as Fetch);
  try {
    await assert.rejects(x.auth.discover(), /Untrusted/);
  } finally {
    await x.close();
  }
});

test("token store rejects permissive file and parent directory modes", async () => {
  const x = await setup();
  try {
    await x.store.write(liveTokens);
    await chmod(x.c.stateFile, 0o644);
    await assert.rejects(x.store.read());
    await chmod(x.c.stateFile, 0o600);
    await chmod(join(x.c.stateFile, ".."), 0o755);
    await assert.rejects(x.store.read());
  } finally {
    await chmod(join(x.c.stateFile, ".."), 0o700);
    await x.close();
  }
});

test("OpenAPI edge schemas fail closed and null-only unions remain valid", () => {
  for (const inputSchema of [
    { type: "array", items: false },
    { type: ["string", "number"], anyOf: [{ type: "boolean" }] },
    { $ref: "#/constructor" },
  ])
    assert.throws(() =>
      specification("http://localhost", [{ name: "edge", inputSchema }]),
    );
  const spec: any = specification("http://localhost", [
    { name: "null", inputSchema: { type: ["null"] } },
  ]);
  assert.deepEqual(
    spec.paths["/api/tools/" + toolId("null")].post.requestBody.content[
      "application/json"
    ].schema.enum,
    [null],
  );
});
