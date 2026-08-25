import { PGlite } from "@electric-sql/pglite";
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "../config.js";
import { log } from "../observability/logger.js";

export interface QueryResult<T> {
  rows: T[];
  affectedRows?: number;
}

export interface Db {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<QueryResult<T>>;
  close(): Promise<void>;
}

let singleton: Db | null = null;
let pglite: PGlite | null = null;

const here = dirname(fileURLToPath(import.meta.url));

export async function getDb(): Promise<Db> {
  if (singleton) return singleton;
  if (config.databaseDriver === "postgresql") {
    throw new Error("Set DATABASE_DRIVER=pglite for this environment or wire pg in production");
  }
  mkdirSync(config.pgliteDir, { recursive: true });
  pglite = new PGlite(config.pgliteDir);
  await pglite.waitReady;
  singleton = {
    async query<T>(sql: string, params: unknown[] = []) {
      const res = await pglite!.query<T>(sql, params);
      return { rows: res.rows ?? [], affectedRows: (res as { affectedRows?: number }).affectedRows };
    },
    async close() {
      await pglite?.close();
      singleton = null;
      pglite = null;
    },
  };
  await migrate(singleton);
  return singleton;
}

export async function migrate(db: Db): Promise<void> {
  await db.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  const dir = resolve(here, "../../migrations");
  const files = readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const file of files) {
    const applied = await db.query<{ id: string }>("SELECT id FROM schema_migrations WHERE id = $1", [file]);
    if (applied.rows.length) continue;
    const sql = readFileSync(resolve(dir, file), "utf8");
    const statements = sql
      .split(/;\s*\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && !s.startsWith("--"));
    for (const stmt of statements) {
      await db.query(stmt.endsWith(";") ? stmt : `${stmt};`);
    }
    await db.query("INSERT INTO schema_migrations (id) VALUES ($1)", [file]);
    log.info("applied migration", { file });
  }
}

export async function closeDb(): Promise<void> {
  await singleton?.close();
}
