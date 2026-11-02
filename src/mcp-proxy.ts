import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { Request, Response } from "express";
import { Auth, Fetch } from "./auth.js";
const outgoing = [
  "accept",
  "content-type",
  "mcp-session-id",
  "mcp-protocol-version",
  "last-event-id",
];
const incoming = [
  "content-type",
  "mcp-session-id",
  "mcp-protocol-version",
  "cache-control",
  "retry-after",
  "allow",
];
export async function proxy(
  req: Request,
  res: Response,
  auth: Auth,
  http: Fetch = fetch,
) {
  let token: string;
  try {
    token = await auth.accessToken();
  } catch {
    return res.status(503).json({
      error:
        "MagicPath authentication unavailable; reconnect locally at /auth/login",
    });
  }
  const controller = new AbortController();
  req.once("aborted", () => controller.abort());
  res.once("close", () => {
    if (!res.writableEnded) controller.abort();
  });
  const headers = new Headers({ authorization: `Bearer ${token}` });
  for (const name of outgoing) {
    const v = req.header(name);
    if (v) headers.set(name, v);
  }
  if (!headers.has("accept"))
    headers.set("accept", "application/json, text/event-stream");
  const timeout = setTimeout(() => controller.abort(), 120000); // bounded entire SSE response; reconnect using Last-Event-ID where supported
  try {
    const result = await http(auth.c.upstream, {
      method: req.method,
      headers,
      body: ["GET", "HEAD", "DELETE"].includes(req.method)
        ? undefined
        : req.body,
      redirect: "error",
      signal: controller.signal,
    });
    res.status(result.status);
    for (const name of incoming) {
      const v = result.headers.get(name);
      if (v) res.setHeader(name, v);
    }
    res.setHeader("cache-control", "no-store");
    // Never replay tools/call after 401: it may have already changed remote state.
    if (result.status === 401) {
      res.setHeader("content-type", "application/json");
      await result.body?.cancel();
      return res.status(502).json({
        error:
          "MagicPath rejected the OAuth token; reconnect at the local /auth/login page",
      });
    }
    if (!result.body) return res.end();
    await pipeline(Readable.fromWeb(result.body as never), res);
  } catch {
    if (!res.headersSent)
      res.status(502).json({ error: "MagicPath upstream request failed" });
    else res.destroy();
  } finally {
    clearTimeout(timeout);
  }
}
export interface Tool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}
export class McpClient {
  private session?: string;
  private protocol = "2025-11-25";
  private initialized?: Promise<void>;
  private id = 0;
  constructor(
    private auth: Auth,
    private http: Fetch = fetch,
  ) {}
  private async rpc(
    method: string,
    params?: unknown,
    notification = false,
  ): Promise<any> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${await this.auth.accessToken()}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    };
    if (method !== "initialize")
      headers["mcp-protocol-version"] = this.protocol;
    if (this.session) headers["mcp-session-id"] = this.session;
    const id = ++this.id;
    const r = await this.http(this.auth.c.upstream, {
      method: "POST",
      headers,
      body: JSON.stringify({
        jsonrpc: "2.0",
        ...(notification ? {} : { id }),
        method,
        ...(params ? { params } : {}),
      }),
      redirect: "error",
      signal: AbortSignal.timeout(60000),
    });
    if (!r.ok) throw Error(`Upstream MCP HTTP ${r.status}`);
    const session = r.headers.get("mcp-session-id");
    if (session) this.session = session;
    if (notification || r.status === 202) {
      await r.body?.cancel();
      return;
    }
    let message: any;
    if (r.headers.get("content-type")?.includes("text/event-stream")) {
      const reader = r.body?.getReader();
      if (!reader) throw Error("Missing SSE body");
      const decoder = new TextDecoder();
      let buffer = "";
      let total = 0;
      try {
        while (!message) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > 4 * 1024 * 1024)
            throw Error("MCP response exceeds limit");
          buffer += decoder.decode(value, { stream: true });
          buffer = buffer.replaceAll("\r\n", "\n");
          let boundary;
          while ((boundary = buffer.indexOf("\n\n")) >= 0) {
            const event = buffer.slice(0, boundary);
            buffer = buffer.slice(boundary + 2);
            const data = event
              .split("\n")
              .filter((s) => s.startsWith("data:"))
              .map((s) => s.slice(5).trimStart())
              .join("\n");
            if (!data) continue;
            const parsed = JSON.parse(data);
            if (parsed.id === id) {
              message = parsed;
              break;
            }
          }
        }
      } finally {
        await reader.cancel();
      }
    } else {
      const reader = r.body?.getReader();
      if (!reader) throw Error("Missing JSON body");
      let total = 0;
      const chunks: Uint8Array[] = [];
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > 4 * 1024 * 1024)
            throw Error("MCP response exceeds limit");
          chunks.push(value);
        }
      } finally {
        await reader.cancel();
      }
      message = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    }

    if (
      !message ||
      message.id !== id ||
      message.jsonrpc !== "2.0" ||
      message.error
    )
      throw Error("Upstream MCP returned no matching successful response");
    return message.result;
  }
  private async init() {
    if (!this.initialized)
      this.initialized = (async () => {
        const result = await this.rpc("initialize", {
          protocolVersion: this.protocol,
          capabilities: {},
          clientInfo: {
            name: "magicpath-rakazo-proxy-openapi",
            version: "0.1.0",
          },
        });
        if (
          !["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"].includes(
            result.protocolVersion,
          )
        )
          throw Error("Unsupported negotiated MCP version");
        this.protocol = result.protocolVersion;
        await this.rpc("notifications/initialized", undefined, true);
      })().catch((e) => {
        this.initialized = undefined;
        this.session = undefined;
        throw e;
      });
    await this.initialized;
  }
  async tools(): Promise<Tool[]> {
    await this.init();
    const tools: Tool[] = [];
    let cursor: string | undefined;
    const seen = new Set<string>();
    do {
      const page = await this.rpc("tools/list", cursor ? { cursor } : {});
      if (!Array.isArray(page.tools)) throw Error("Invalid tools/list");
      for (const t of page.tools) {
        if (
          typeof t.name !== "string" ||
          !t.inputSchema ||
          typeof t.inputSchema !== "object"
        )
          throw Error("Invalid tool schema");
        tools.push(t);
      }
      cursor = page.nextCursor;
      if (cursor) {
        if (seen.has(cursor) || seen.size >= 100)
          throw Error("Invalid pagination");
        seen.add(cursor);
      }
    } while (cursor);
    return tools;
  }
  async call(name: string, args: unknown) {
    await this.init();
    return this.rpc("tools/call", { name, arguments: args });
  }
}
