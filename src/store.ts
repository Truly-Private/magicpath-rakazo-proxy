import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import {
  mkdir,
  readFile,
  rename,
  writeFile,
  unlink,
  lstat,
} from "node:fs/promises";
import { dirname, resolve } from "node:path";
export interface Tokens {
  access_token: string;
  refresh_token?: string;
  expires_at: number;
  scope?: string;
  token_type: string;
}
export class TokenStore {
  constructor(
    private file: string,
    private key: Buffer,
  ) {}
  async read(): Promise<Tokens | undefined> {
    let raw: string;
    try {
      const dir = await lstat(dirname(resolve(this.file)));
      if (
        !dir.isDirectory() ||
        dir.isSymbolicLink() ||
        (dir.mode & 0o077) !== 0
      )
        throw Error("Token directory must be owner-only");
      const stat = await lstat(this.file);
      if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0)
        throw Error("Token file must be a regular owner-only file");
      raw = await readFile(this.file, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
      throw e;
    }
    const v = JSON.parse(raw);
    const d = createDecipheriv(
      "aes-256-gcm",
      this.key,
      Buffer.from(v.iv, "base64"),
    );
    d.setAuthTag(Buffer.from(v.tag, "base64"));
    const data = JSON.parse(
      Buffer.concat([
        d.update(Buffer.from(v.data, "base64")),
        d.final(),
      ]).toString(),
    );
    if (
      typeof data.access_token !== "string" ||
      typeof data.expires_at !== "number" ||
      data.token_type?.toLowerCase() !== "bearer"
    )
      throw Error("Invalid token state");
    return data;
  }
  async write(t: Tokens) {
    const path = resolve(this.file),
      dir = dirname(path);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const s = await lstat(dir);
    if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o077) !== 0)
      throw Error("Token directory must be owner-only");
    const iv = randomBytes(12),
      c = createCipheriv("aes-256-gcm", this.key, iv);
    const data = Buffer.concat([c.update(JSON.stringify(t)), c.final()]);
    const tmp = `${path}.${randomBytes(8).toString("hex")}.tmp`;
    try {
      await writeFile(
        tmp,
        JSON.stringify({
          v: 1,
          iv: iv.toString("base64"),
          tag: c.getAuthTag().toString("base64"),
          data: data.toString("base64"),
        }),
        { mode: 0o600, flag: "wx" },
      );
      await rename(tmp, path);
    } finally {
      await unlink(tmp).catch(() => {});
    }
  }
}
