import { timingSafeEqual } from "node:crypto";
export interface Config {
  port: number;
  host: string;
  publicUrl: string;
  upstream: string;
  secret: string;
  key: Buffer;
  stateFile: string;
  clientId: string;
  clientSecret?: string;
  scope: string;
  trustedOrigins: Set<string>;
  adminSecret?: string;
  apiUrl: string;
}
export function config(env: NodeJS.ProcessEnv = process.env): Config {
  const port = Number(env.PORT || 3100);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw Error("Invalid PORT");
  const host = env.HOST || "127.0.0.1";
  if (!["127.0.0.1", "::1", "0.0.0.0"].includes(host))
    throw Error("HOST must be loopback or 0.0.0.0 (container only)");
  const publicUrl = env.PUBLIC_URL || `http://localhost:${port}`;
  const p = new URL(publicUrl);
  if (
    !["localhost", "127.0.0.1", "[::1]"].includes(p.hostname) ||
    p.protocol !== "http:" ||
    p.pathname !== "/" ||
    p.search ||
    p.hash ||
    p.username ||
    p.password
  )
    throw Error("PUBLIC_URL must be a loopback HTTP origin");
  const apiUrl = env.RAKAZO_PROXY_URL || p.origin;
  const api = new URL(apiUrl);
  if (
    !["http:", "https:"].includes(api.protocol) ||
    api.username ||
    api.password ||
    api.pathname !== "/" ||
    api.search ||
    api.hash
  )
    throw Error("RAKAZO_PROXY_URL must be an origin");
  const upstream = env.MAGICPATH_MCP_URL || "https://api.magicpath.ai/mcp";
  const u = new URL(upstream);
  if (u.protocol !== "https:" || u.username || u.password || u.hash)
    throw Error("Upstream must be HTTPS");
  const secret = env.RAKAZO_SECRET_TOKEN || "";
  if (secret.length < 32 || /\s/.test(secret))
    throw Error(
      "RAKAZO_SECRET_TOKEN must be at least 32 non-whitespace characters",
    );
  const encoded = env.TOKEN_ENCRYPTION_KEY || "";
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32 || key.toString("base64") !== encoded)
    throw Error("TOKEN_ENCRYPTION_KEY must be canonical base64 for 32 bytes");
  if (env.ADMIN_SECRET_TOKEN && env.ADMIN_SECRET_TOKEN.length < 32)
    throw Error("ADMIN_SECRET_TOKEN must be at least 32 characters");
  const trustedOrigins = new Set([
    u.origin,
    ...(env.OAUTH_TRUSTED_ORIGINS || "")
      .split(",")
      .filter(Boolean)
      .map((s) => new URL(s.trim()).origin),
  ]);
  for (const o of trustedOrigins)
    if (!o.startsWith("https://"))
      throw Error("Trusted OAuth origins must use HTTPS");
  return {
    port,
    host,
    publicUrl: p.origin,
    upstream: u.href,
    secret,
    key,
    stateFile: env.TOKEN_STATE_FILE || "./state/tokens.enc.json",
    clientId: env.MAGICPATH_CLIENT_ID || "",
    clientSecret: env.MAGICPATH_CLIENT_SECRET || undefined,
    scope: env.MAGICPATH_SCOPES || "magicpath:read magicpath:write",
    trustedOrigins,
    adminSecret: env.ADMIN_SECRET_TOKEN || undefined,
    apiUrl: api.origin,
  };
}
export function equalSecret(a: string, b: string): boolean {
  const x = Buffer.from(a),
    y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
export function trustedUrl(value: string, c: Config): URL {
  const u = new URL(value);
  if (
    u.protocol !== "https:" ||
    u.username ||
    u.password ||
    u.hash ||
    !c.trustedOrigins.has(u.origin)
  )
    throw Error("Untrusted OAuth endpoint");
  return u;
}
