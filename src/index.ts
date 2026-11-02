import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import swaggerUi from "swagger-ui-express";
import { pathToFileURL } from "node:url";
import { config, Config, equalSecret } from "./config.js";
import { Auth, Fetch } from "./auth.js";
import { TokenStore } from "./store.js";
import { proxy, McpClient } from "./mcp-proxy.js";
import { specification, toolId } from "./openapi.js";
export function createApp(c: Config, auth: Auth, http: Fetch = fetch) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", false);
  app.use((req, res, next) => {
    res.set({
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
      "Cross-Origin-Resource-Policy": "same-origin",
    });
    const origin = req.headers.origin;
    if (origin && origin !== c.publicUrl)
      return res.status(403).json({ error: "Origin rejected" });
    const hosts = new Set([
      new URL(c.publicUrl).host,
      new URL(c.apiUrl).host,
      `127.0.0.1:${c.port}`,
      `localhost:${c.port}`,
      `[::1]:${c.port}`,
    ]);
    if (!hosts.has(req.headers.host || ""))
      return res.status(403).json({ error: "Host rejected" });
    next();
  });
  const bearer = (req: Request, res: Response, next: NextFunction) => {
    if (!equalSecret(req.header("authorization") || "", `Bearer ${c.secret}`)) {
      res.setHeader(
        "WWW-Authenticate",
        'Bearer realm="magicpath-rakazo-proxy"',
      );
      return res.status(401).json({ error: "Unauthorized" });
    }
    next();
  };
  const admin = (req: Request, res: Response, next: NextFunction) => {
    const loopback = ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(
      req.socket.remoteAddress || "",
    );
    if (loopback && !c.adminSecret) return next();
    const h = req.header("authorization") || "";
    const decoded = h.startsWith("Basic ")
      ? Buffer.from(h.slice(6), "base64").toString()
      : "";
    const password = decoded.slice(decoded.indexOf(":") + 1);
    if (!c.adminSecret || !equalSecret(password, c.adminSecret)) {
      res.setHeader("WWW-Authenticate", 'Basic realm="Local MagicPath setup"');
      return res.status(401).send("Local setup credentials required");
    }
    next();
  };
  app.get("/healthz", (_req, res) => res.json({ ok: true }));
  app.get("/auth/status", admin, (_req, res) => res.json(auth.status()));
  app.get("/auth/login", admin, (req, res) => {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
    );
    auth.loginPage(req, res);
  });
  app.post(
    "/auth/login",
    admin,
    express.urlencoded({ extended: false, limit: "8kb" }),
    (req, res) => auth.login(req, res),
  );
  app.get("/auth/callback", admin, (req, res) => auth.callback(req, res));
  app.all(
    "/mcp",
    bearer,
    express.raw({ type: () => true, limit: "2mb" }),
    (req, res) => {
      if (!["GET", "POST", "DELETE"].includes(req.method))
        return res.status(405).set("Allow", "GET, POST, DELETE").end();
      if (req.method === "POST" && !req.is("application/json"))
        return res.status(415).json({ error: "Expected application/json" });
      return proxy(req, res, auth, http);
    },
  );
  const client = new McpClient(auth, http);
  app.get("/openapi.json", bearer, async (_req, res) => {
    try {
      res.json(specification(c.apiUrl, await client.tools()));
    } catch {
      res.status(503).json({
        error: "Connect MagicPath first; live tool discovery is unavailable",
      });
    }
  });
  app.post(
    "/api/tools/:id",
    bearer,
    express.json({ limit: "2mb" }),
    async (req, res) => {
      try {
        if (
          !req.body ||
          Array.isArray(req.body) ||
          typeof req.body !== "object"
        )
          return res
            .status(400)
            .json({ error: "Tool arguments must be a JSON object" });
        const tool = (await client.tools()).find(
          (t) => toolId(t.name) === req.params.id,
        );
        if (!tool) return res.status(404).json({ error: "Unknown tool" });
        const result = await client.call(tool.name, req.body);
        res.json(result);
      } catch {
        res.status(502).json({
          error:
            "MagicPath tool invocation failed; no automatic retry was attempted",
        });
      }
    },
  );
  // Operator-only UI; use the browser-reachable same-origin URL for Try it out.
  app.use(
    "/swagger",
    admin,
    swaggerUi.serve,
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const spec = specification(c.publicUrl, await client.tools());
        swaggerUi.setup(spec, {
          swaggerOptions: { persistAuthorization: false },
          customSiteTitle: "MagicPath Proxy",
        })(req, res, next);
      } catch {
        res
          .status(503)
          .send("Connect MagicPath at /auth/login before opening Swagger.");
      }
    },
  );
  app.use((_req, res) => res.status(404).json({ error: "Not found" }));
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const code =
      err?.type === "entity.too.large"
        ? 413
        : err instanceof SyntaxError
          ? 400
          : 500;
    res.status(code).json({
      error:
        code === 413
          ? "Payload too large"
          : code === 400
            ? "Malformed request"
            : "Request failed; check local OAuth setup and configuration",
    });
  });
  return app;
}
export function rakazoTemplate(c: Pick<Config, "apiUrl">) {
  return {
    slug: "magicpath-proxy",
    name: "MagicPath proxy",
    transport: "streamable_http",
    enabled: true,
    headers: {},
    endpoint: `${c.apiUrl}/mcp`,
    secret: "<paste the value of RAKAZO_SECRET_TOKEN securely>",
  };
}
async function main() {
  const c = config();
  if (process.argv.includes("--config")) {
    console.log(JSON.stringify(rakazoTemplate(c), null, 2));
    return;
  }
  const auth = new Auth(c, new TokenStore(c.stateFile, c.key));
  await auth.load();
  const app = createApp(c, auth);
  const server = app.listen(c.port, c.host, () => {
    console.log(`[MagicPath Proxy] Listening on ${c.publicUrl}`);
    if (!auth.status().authenticated)
      console.log(
        `[MagicPath Proxy] Please visit ${c.publicUrl}/auth/login to complete initial MagicPath browser authentication.`,
      );
    console.log(
      "[MagicPath Proxy] Rakazo HTTP configuration (template; substitute secret in Rakazo, never paste it in logs):",
    );
    console.log(JSON.stringify(rakazoTemplate(c), null, 2));
  });
  server.on("error", () => {
    console.error(
      "[MagicPath Proxy] Listen failed; port may already be used (Rakazo defaults to 3100). Try PORT=3101 and matching PUBLIC_URL.",
    );
    process.exitCode = 1;
  });
  const timer = auth.startRefresh();
  for (const signal of ["SIGTERM", "SIGINT"])
    process.once(signal, () => {
      clearInterval(timer);
      server.close();
      setTimeout(() => process.exit(0), 5000).unref();
    });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch(() => {
    console.error(
      "[MagicPath Proxy] Startup failed. Check .env, token-key format and owner-only state directory permissions.",
    );
    process.exitCode = 1;
  });
