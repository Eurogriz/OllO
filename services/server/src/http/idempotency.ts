import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { ApiError, authFromAccess, readBearer } from "../http.js";

const PENDING = -1;
const TTL_MS = 24 * 60 * 60 * 1000;
const PENDING_TTL_MS = 120_000;
const MAX_BODY = 65_536;

const slots = new WeakMap<FastifyRequest, { scope: string; key: string }>();

function mutating(method: string): boolean {
  return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
}

function scopeOf(req: FastifyRequest): string {
  const token = readBearer(req);
  if (token) {
    try {
      return `user:${authFromAccess(token).userId}`;
    } catch {
      /* public mutating route */
    }
  }
  return `ip:${req.ip || "0.0.0.0"}`;
}

function skipPath(path: string, contentType: string): boolean {
  if (!path.startsWith("/v1/")) return true;
  if (path === "/v1/realtime") return true;
  if (path.endsWith("/data")) return true;
  if (contentType.includes("octet-stream")) return true;
  return false;
}

async function claim(db: Db, scope: string, key: string): Promise<boolean> {
  const r = await db.query<{ key: string }>(
    `INSERT INTO idempotency (scope, key, status, body)
     VALUES ($1, $2, $3, '')
     ON CONFLICT (scope, key) DO NOTHING
     RETURNING key`,
    [scope, key, PENDING],
  );
  return Boolean(r.rows[0]);
}

export async function registerIdempotency(app: FastifyInstance, db: Db): Promise<void> {
  app.addHook("preHandler", async (req, reply) => {
    if (!mutating(req.method)) return;
    const path = (req.url ?? "").split("?")[0] ?? "";
    const ct = String(req.headers["content-type"] ?? "");
    if (skipPath(path, ct)) return;
    const raw = req.headers["idempotency-key"];
    if (raw === undefined) return;
    if (typeof raw !== "string" || !z.string().uuid().safeParse(raw).success) {
      throw new ApiError("validation", "Invalid Idempotency-Key", 400);
    }
    const scope = scopeOf(req);
    const key = raw;
    if (await claim(db, scope, key)) {
      slots.set(req, { scope, key });
      return;
    }
    const existing = await db.query<{ status: number; body: string; created_at: string }>(
      `SELECT status, body, created_at FROM idempotency WHERE scope = $1 AND key = $2`,
      [scope, key],
    );
    const row = existing.rows[0];
    if (!row) {
      if (await claim(db, scope, key)) slots.set(req, { scope, key });
      return;
    }
    const age = Date.now() - new Date(row.created_at).getTime();
    const stale = age > TTL_MS || (row.status === PENDING && age > PENDING_TTL_MS);
    if (stale) {
      await db.query(`DELETE FROM idempotency WHERE scope = $1 AND key = $2`, [scope, key]);
      if (await claim(db, scope, key)) {
        slots.set(req, { scope, key });
        return;
      }
      throw new ApiError("conflict", "Idempotency request in progress", 409);
    }
    if (row.status === PENDING) {
      throw new ApiError("conflict", "Idempotency request in progress", 409);
    }
    reply.header("Idempotent-Replayed", "1");
    let parsed: unknown = row.body;
    try {
      parsed = JSON.parse(row.body) as unknown;
    } catch {
      parsed = row.body;
    }
    return reply.code(row.status).send(parsed);
  });

  app.addHook("onSend", async (req, reply, payload) => {
    const slot = slots.get(req);
    if (!slot) return payload;
    slots.delete(req);
    const status = reply.statusCode;
    const drop = async (): Promise<typeof payload> => {
      await db.query(`DELETE FROM idempotency WHERE scope = $1 AND key = $2 AND status = $3`, [
        slot.scope,
        slot.key,
        PENDING,
      ]);
      return payload;
    };
    if (status < 200 || status >= 300) return drop();
    let body = "";
    if (typeof payload === "string") body = payload;
    else if (Buffer.isBuffer(payload)) body = payload.toString("utf8");
    else {
      try {
        body = JSON.stringify(payload);
      } catch {
        return drop();
      }
    }
    if (body.length > MAX_BODY) return drop();
    await db.query(
      `UPDATE idempotency SET status = $3, body = $4 WHERE scope = $1 AND key = $2 AND status = $5`,
      [slot.scope, slot.key, status, body, PENDING],
    );
    return payload;
  });
}
