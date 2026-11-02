import { createHash } from "node:crypto";
import { Tool } from "./mcp-proxy.js";
export function toolId(name: string) {
  return `tool_${createHash("sha256").update(name).digest("hex").slice(0, 20)}`;
}
// OAS 3.0 supports only a JSON Schema subset. Preserve originals as an extension;
// avoid pretending to validate unsupported dialects locally. Upstream validates arguments.
export function oasSchema(
  input: unknown,
  root: unknown = input,
  refs: string[] = [],
): any {
  if (input === true) return {};
  if (input === false)
    throw Error("Boolean false schema cannot be represented in OpenAPI 3.0");
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw Error("Invalid JSON Schema");
  if (refs.length > 30) throw Error("Schema reference depth exceeded");
  const s = input as Record<string, any>,
    out: Record<string, any> = {};
  const allowed = new Set([
    "$schema",
    "$id",
    "$defs",
    "definitions",
    "$ref",
    "title",
    "description",
    "enum",
    "const",
    "default",
    "type",
    "minimum",
    "maximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minProperties",
    "maxProperties",
    "required",
    "format",
    "properties",
    "items",
    "additionalProperties",
    "oneOf",
    "anyOf",
    "allOf",
    "readOnly",
    "writeOnly",
    "deprecated",
    "examples",
  ]);
  for (const k of Object.keys(s))
    if (!allowed.has(k) && !k.startsWith("x-"))
      throw Error("Unsupported schema keyword: " + k);
  if (s.$ref) {
    if (
      typeof s.$ref !== "string" ||
      !s.$ref.startsWith("#/") ||
      refs.includes(s.$ref)
    )
      throw Error("Unsupported external or recursive tool schema reference");
    const ref = s.$ref;
    const target = ref
      .slice(2)
      .split("/")
      .reduce((v: any, k: string) => {
        const key = k.replaceAll("~1", "/").replaceAll("~0", "~");
        return v && typeof v === "object" && Object.hasOwn(v, key)
          ? v[key]
          : undefined;
      }, root);
    if (!target) throw Error("Unresolved tool schema reference");
    const siblings = Object.fromEntries(
      Object.entries(s).filter(
        ([k]) =>
          !["$ref", "$defs", "definitions", "$schema", "$id"].includes(k),
      ),
    );
    if (Object.keys(siblings).length)
      return {
        allOf: [
          oasSchema(target, root, [...refs, ref]),
          oasSchema(siblings, root, refs),
        ],
      };
    return oasSchema(target, root, [...refs, ref]);
  }
  for (const unsupported of [
    "if",
    "then",
    "else",
    "not",
    "patternProperties",
    "unevaluatedProperties",
    "prefixItems",
    "dependentSchemas",
  ])
    if (unsupported in s)
      throw Error(
        "Tool schema needs manual OpenAPI adaptation: " + unsupported,
      );
  for (const k of [
    "title",
    "description",
    "enum",
    "default",
    "minimum",
    "maximum",
    "multipleOf",
    "minProperties",
    "maxProperties",
    "readOnly",
    "writeOnly",
    "deprecated",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "uniqueItems",
    "required",
    "format",
  ])
    if (k in s) out[k] = s[k];
  if (typeof s.type === "string" && s.type !== "null") out.type = s.type;
  if (Array.isArray(s.type)) {
    if (!s.type.length || ["oneOf", "anyOf", "allOf"].some((k) => k in s))
      throw Error("Unsupported combined type union");
    if (s.type.length === 1 && s.type[0] === "null")
      return oasSchema({ ...s, type: "null" }, root, refs);
    const nonNull = s.type.filter((x: string) => x !== "null");
    if (nonNull.length === 1) out.type = nonNull[0];
    else
      out.anyOf = nonNull.map((type: string) => ({
        type,
        ...(s.type.includes("null") ? { nullable: true } : {}),
      }));
    if (s.type.includes("null")) out.nullable = true;
  }
  if (s.type === "null") {
    if (
      ("enum" in s && (s.enum.length !== 1 || s.enum[0] !== null)) ||
      ("const" in s && s.const !== null)
    )
      throw Error("Unsupported conflicting null schema");
    out.type = "string";
    out.nullable = true;
    out.enum = [null];
  }
  if (s.const !== undefined) {
    if (
      "enum" in s &&
      !s.enum.some(
        (v: unknown) => JSON.stringify(v) === JSON.stringify(s.const),
      )
    )
      throw Error("Unsupported conflicting enum and const");
    out.enum = [s.const];
  }
  if (s.properties)
    out.properties = Object.fromEntries(
      Object.entries(s.properties).map(([k, v]) => [
        k,
        oasSchema(v, root, refs),
      ]),
    );
  if (out.type === "array" && !("items" in s)) out.items = {};
  if ("items" in s) out.items = oasSchema(s.items, root, refs);
  if (typeof s.additionalProperties === "boolean")
    out.additionalProperties = s.additionalProperties;
  else if (s.additionalProperties)
    out.additionalProperties = oasSchema(s.additionalProperties, root, refs);
  for (const k of ["oneOf", "anyOf", "allOf"])
    if (Array.isArray(s[k]))
      out[k] = s[k].map((v: unknown) => oasSchema(v, root, refs));
  return out;
}
export function specification(baseUrl: string, tools: Tool[]) {
  const paths: Record<string, unknown> = {};
  for (const t of tools) {
    paths[`/api/tools/${toolId(t.name)}`] = {
      post: {
        operationId: toolId(t.name),
        summary: t.name,
        description: t.description || "MagicPath MCP tool",
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                ...oasSchema(t.inputSchema),
                "x-original-json-schema": t.inputSchema,
              },
            },
          },
        },
        responses: {
          "200": {
            description:
              "MCP CallToolResult; inspect isError for tool-level errors",
            content: {
              "application/json": {
                schema: { type: "object", additionalProperties: true },
              },
            },
          },
          "401": { description: "Invalid proxy bearer token" },
          "502": { description: "Upstream failure" },
          "503": { description: "OAuth connection unavailable" },
        },
      },
    };
  }
  return {
    openapi: "3.0.3",
    info: {
      title: "MagicPath Rakazo Proxy",
      version: "0.1.0",
      description:
        "Generated from the authenticated MagicPath tools/list response. Tool names and schemas are not hard-coded.",
    },
    servers: [{ url: baseUrl }],
    components: {
      securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } },
    },
    security: [{ bearerAuth: [] }],
    paths,
  };
}
