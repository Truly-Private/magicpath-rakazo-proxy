import { randomBytes, createHash } from "node:crypto";
import type { Request, Response } from "express";
import { Config, trustedUrl, equalSecret } from "./config.js";
import { TokenStore, Tokens } from "./store.js";
export type Fetch = typeof fetch;
interface Metadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  code_challenge_methods_supported?: string[];
}
interface Pending {
  verifier: string;
  browser: string;
  expires: number;
}
export class Auth {
  private mutation: Promise<unknown> = Promise.resolve();
  private tokens?: Tokens;
  private flight?: Promise<string>;
  private metadata?: Metadata;
  private pending = new Map<string, Pending>();
  private forms = new Map<string, number>();
  constructor(
    public c: Config,
    private store: TokenStore,
    private http: Fetch = fetch,
  ) {}
  async load() {
    this.tokens = await this.store.read();
  }
  status() {
    return {
      authenticated: !!this.tokens && this.tokens.expires_at > Date.now(),
      refreshAvailable: !!this.tokens?.refresh_token,
      clientConfigured: !!this.c.clientId,
    };
  }
  async discover(): Promise<Metadata> {
    if (this.metadata) return this.metadata;
    const u = new URL(this.c.upstream);
    const prm = new URL(
      `/.well-known/oauth-protected-resource${u.pathname === "/" ? "" : u.pathname}`,
      u.origin,
    );
    const r = await this.http(prm, {
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) throw Error("OAuth protected-resource discovery failed");
    const resource = (await r.json()) as {
      resource: string;
      authorization_servers: string[];
    };
    if (
      resource.resource !== this.c.upstream ||
      !Array.isArray(resource.authorization_servers) ||
      !resource.authorization_servers.length
    )
      throw Error("OAuth resource metadata mismatch");
    const issuer = trustedUrl(resource.authorization_servers[0], this.c);
    const metaUrl = new URL(
      `/.well-known/oauth-authorization-server${issuer.pathname === "/" ? "" : issuer.pathname}`,
      issuer.origin,
    );
    const mr = await this.http(metaUrl, {
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
    if (!mr.ok) throw Error("Authorization-server discovery failed");
    const m = (await mr.json()) as Metadata;
    if (
      new URL(m.issuer).href !== issuer.href ||
      !m.code_challenge_methods_supported?.includes("S256")
    )
      throw Error("Invalid issuer or missing S256");
    trustedUrl(m.authorization_endpoint, this.c);
    trustedUrl(m.token_endpoint, this.c);
    this.metadata = m;
    return m;
  }
  private prune() {
    const now = Date.now();
    for (const [k, v] of this.pending)
      if (v.expires < now) this.pending.delete(k);
    for (const [k, v] of this.forms) if (v < now) this.forms.delete(k);
  }
  loginPage(_req: Request, res: Response) {
    this.prune();
    if (this.forms.size >= 100)
      return res.status(429).send("Too many login requests");
    const nonce = randomBytes(32).toString("base64url");
    this.forms.set(nonce, Date.now() + 300000);
    res.cookie("mp_login", nonce, {
      httpOnly: true,
      sameSite: "strict",
      path: "/auth",
      maxAge: 300000,
    });
    res
      .type("html")
      .send(
        `<!doctype html><html><head><meta charset="utf-8"><title>MagicPath authorization</title></head><body><h1>Connect MagicPath</h1><p>Connect your account to this local proxy. Only continue if you started this setup.</p><form method="post" action="/auth/login"><input type="hidden" name="csrf" value="${nonce}"><button>Authorize MagicPath</button></form></body></html>`,
      );
  }
  async login(req: Request, res: Response) {
    this.prune();
    const csrf = String(req.body?.csrf || "");
    if (!this.forms.has(csrf) || !equalSecret(csrf, cookie(req, "mp_login")))
      return res.status(403).send("Invalid login request");
    this.forms.delete(csrf);
    if (!this.c.clientId)
      return res
        .status(503)
        .send(
          "Set MAGICPATH_CLIENT_ID to a registered OAuth client ID; see README.",
        );
    const m = await this.discover(),
      state = randomBytes(32).toString("base64url"),
      verifier = randomBytes(32).toString("base64url"),
      browser = randomBytes(32).toString("base64url");
    if (this.pending.size >= 100)
      return res.status(429).send("Too many pending logins");
    this.pending.set(state, {
      verifier,
      browser,
      expires: Date.now() + 600000,
    });
    res.cookie("mp_oauth", browser, {
      httpOnly: true,
      sameSite: "lax",
      path: "/auth/callback",
      maxAge: 600000,
    });
    const u = new URL(m.authorization_endpoint);
    u.search = new URLSearchParams({
      response_type: "code",
      client_id: this.c.clientId,
      redirect_uri: `${this.c.publicUrl}/auth/callback`,
      scope: this.c.scope,
      state,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      resource: this.c.upstream,
    }).toString();
    res.redirect(u.href);
  }
  async callback(req: Request, res: Response) {
    this.prune();
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const pending = this.pending.get(state);
    if (!pending || !equalSecret(cookie(req, "mp_oauth"), pending.browser))
      return res.status(400).send("Invalid or expired OAuth state");
    this.pending.delete(state);
    res.clearCookie("mp_oauth", { path: "/auth/callback" });
    if (req.query.error)
      return res
        .status(400)
        .send("MagicPath authorization was declined or failed.");
    const code = typeof req.query.code === "string" ? req.query.code : "";
    if (!code) return res.status(400).send("Missing authorization code");
    await this.exchange({
      grant_type: "authorization_code",
      code,
      code_verifier: pending.verifier,
      redirect_uri: `${this.c.publicUrl}/auth/callback`,
    });
    res
      .type("html")
      .send(
        "<h1>MagicPath connected</h1><p>You may close this window. Use npm run config for the Rakazo connection template. No credentials are shown here.</p>",
      );
  }
  private exchange(fields: Record<string, string>): Promise<string> {
    const run = this.mutation.then(() => {
      if (
        fields.grant_type === "refresh_token" &&
        fields.refresh_token !== this.tokens?.refresh_token
      ) {
        if (this.tokens) return this.tokens.access_token;
        throw Error("Stale refresh");
      }
      return this.exchangeImpl(fields);
    });
    this.mutation = run.catch(() => {});
    return run;
  }
  private async exchangeImpl(fields: Record<string, string>) {
    const m = await this.discover();
    const body = new URLSearchParams({
      ...fields,
      client_id: this.c.clientId,
      resource: this.c.upstream,
    });
    if (this.c.clientSecret) body.set("client_secret", this.c.clientSecret);
    const r = await this.http(m.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok)
      throw Error(
        "OAuth token exchange failed; reconnect if refresh consent expired",
      );
    const v = (await r.json()) as Record<string, unknown>;
    if (
      typeof v.access_token !== "string" ||
      !v.access_token ||
      String(v.token_type).toLowerCase() !== "bearer" ||
      typeof v.expires_in !== "number" ||
      !Number.isFinite(v.expires_in) ||
      v.expires_in <= 0
    )
      throw Error("Invalid token response");
    const tokens: Tokens = {
      access_token: v.access_token,
      token_type: "Bearer",
      expires_at: Date.now() + v.expires_in * 1000,
      refresh_token:
        typeof v.refresh_token === "string"
          ? v.refresh_token
          : fields.grant_type === "refresh_token"
            ? this.tokens?.refresh_token
            : undefined,
      scope: typeof v.scope === "string" ? v.scope : undefined,
    };
    await this.store.write(tokens);
    this.tokens = tokens;
    return tokens.access_token;
  }
  async accessToken(): Promise<string> {
    if (this.tokens && this.tokens.expires_at > Date.now() + 60000)
      return this.tokens.access_token;
    if (!this.tokens?.refresh_token)
      throw Error("MagicPath authentication required");
    if (!this.flight) {
      this.flight = this.exchange({
        grant_type: "refresh_token",
        refresh_token: this.tokens.refresh_token,
      }).finally(() => {
        this.flight = undefined;
      });
    }
    return this.flight;
  }
  startRefresh() {
    const timer = setInterval(() => {
      if (
        this.tokens?.refresh_token &&
        this.tokens.expires_at < Date.now() + 90000
      )
        this.accessToken().catch(() =>
          console.warn(
            "[MagicPath Proxy] Refresh failed; visit /auth/login if reconnection is required.",
          ),
        );
    }, 30000);
    timer.unref();
    return timer;
  }
}
function cookie(req: Request, name: string) {
  return (
    (req.headers.cookie || "")
      .split(";")
      .map((s) => s.trim())
      .find((s) => s.startsWith(`${name}=`))
      ?.slice(name.length + 1) || ""
  );
}
