import Fastify, { type FastifyError, type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import websocket from "@fastify/websocket";
import { ZodError } from "zod";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { canSeePresence, hiddenPresence } from "@ollo/shared";
import { config } from "./config.js";
import type { Db } from "./db/index.js";
import { ApiError, assertLiveDevice, authFromAccess, readBearer, requestId, requireAuth, sendError } from "./http.js";
import { registerAttachments } from "./modules/attachments.js";
import { registerAuth } from "./modules/auth.js";
import { registerBackups } from "./modules/backups.js";
import { registerCalls } from "./modules/calls.js";
import { registerGroups } from "./modules/groups.js";
import { registerKeys } from "./modules/keys.js";
import { registerMessaging } from "./modules/messaging.js";
import { registerNotifications } from "./modules/notifications.js";
import { registerUsers } from "./modules/users.js";
import { log } from "./observability/logger.js";
import { httpRequests, registry } from "./observability/metrics.js";
import { helloAccessToken } from "./realtime/hello.js";
import { attach, detach, type SocketClient, connectionCount, isOnline } from "./realtime/hub.js";
import { randomToken } from "./security/crypto-utils.js";

function originAllowed(origin: string | undefined): boolean {
  if (!origin) return true;
  if (config.corsOrigins.includes(origin)) return true;
  if (origin.endsWith(".e2b.app") || origin.endsWith(".arena.ai")) return true;
  if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return true;
  return false;
}

export async function buildApp(db: Db): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false,
    trustProxy: true,
    bodyLimit: config.attachmentMaxBytes + 1024 * 1024,
    genReqId: (req) => String(req.headers["x-request-id"] ?? randomToken(8)),
  });

  await app.register(cors, {
    origin: (origin, cb) => cb(null, originAllowed(origin)),
    credentials: true,
    allowedHeaders: ["Authorization", "Content-Type", "Idempotency-Key", "X-Request-Id"],
  });

  await app.register(rateLimit, {
    max: config.rateLimitMax,
    timeWindow: config.rateLimitWindowMs,
    allowList: (req) => req.url.startsWith("/healthz") || req.url.startsWith("/readyz"),
  });

  await app.register(websocket, { options: { maxPayload: 256 * 1024 } });

  app.addContentTypeParser("application/octet-stream", { parseAs: "buffer" }, (_req, body, done) => {
    done(null, body);
  });

  const publicV1 = new Set([
    "POST /v1/auth/request-otp",
    "POST /v1/auth/verify-otp",
    "POST /v1/auth/refresh",
  ]);

  app.addHook("preHandler", async (req) => {
    const path = (req.url ?? "").split("?")[0] ?? "";
    if (!path.startsWith("/v1/")) return;
    if (publicV1.has(`${req.method} ${path}`)) return;
    const token = readBearer(req);
    if (!token) return;
    let auth;
    try {
      auth = authFromAccess(token);
    } catch {
      return;
    }
    await assertLiveDevice(db, auth);
  });

  app.addHook("onRequest", async (req, reply) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()");
    reply.header("X-Request-Id", req.id);
    if (config.isProd) {
      reply.header("strict-transport-security", "max-age=63072000; includeSubDomains");
    }
  });

  app.addHook("onResponse", async (req, reply) => {
    const route = req.routeOptions?.url ?? "unknown";
    httpRequests.inc({ route, code: String(reply.statusCode), method: req.method });
  });

  app.setErrorHandler((err: FastifyError, req, reply) => {
    const rid = requestId(req);
    if (err instanceof ApiError) {
      sendError(reply, err, rid);
      return;
    }
    if (err instanceof ZodError) {
      sendError(reply, new ApiError("validation", "Invalid request", 400), rid);
      return;
    }
    if ((err as { statusCode?: number }).statusCode === 429) {
      sendError(reply, new ApiError("rate_limited", "Too many requests", 429), rid);
      return;
    }
    log.error("unhandled", { request_id: rid, err: err.message });
    sendError(reply, new ApiError("internal", "Internal error", 500), rid);
  });

  app.get("/healthz", async () => ({ ok: true, service: "ollo", time: new Date().toISOString() }));
  app.get("/readyz", async () => {
    await db.query("SELECT 1");
    return { ok: true };
  });
  app.get("/metrics", async (_req, reply) => {
    reply.header("content-type", registry.contentType);
    return registry.metrics();
  });

  await registerAuth(app, db);
  await registerUsers(app, db);
  await registerKeys(app, db);
  await registerMessaging(app, db);
  await registerGroups(app, db);
  await registerAttachments(app, db);
  await registerCalls(app, db);
  await registerNotifications(app, db);
  await registerBackups(app, db);

  app.get("/v1/presence/:userId", async (req) => {
    const auth = requireAuth(req);
    const userId = (req.params as { userId: string }).userId;
    let isContact = false;
    if (auth.userId !== userId) {
      const contact = await db.query(
        "SELECT 1 FROM contacts WHERE user_id = $1 AND contact_user_id = $2",
        [auth.userId, userId],
      );
      isContact = Boolean(contact.rows[0]);
    }
    if (!canSeePresence(auth.userId, userId, isContact)) return hiddenPresence(userId);
    const row = await db.query<{ last_seen_at: string }>(
      `SELECT last_seen_at FROM devices WHERE user_id = $1 AND revoked_at IS NULL
       ORDER BY last_seen_at DESC LIMIT 1`,
      [userId],
    );
    const last = row.rows[0]?.last_seen_at;
    return {
      user_id: userId,
      state: isOnline(userId) ? "online" : "offline",
      last_seen_day: last ? String(last).slice(0, 10) : null,
    };
  });

  app.get("/v1/realtime", { websocket: true }, (socket, req) => {
    let client: SocketClient | null = null;
    socket.on("message", (raw) => {
      let msg: { op?: string; resume?: string; after?: string; ids?: string[]; access_token?: string };
      try {
        msg = JSON.parse(String(raw));
      } catch {
        socket.send(JSON.stringify({ op: "error", code: "validation" }));
        return;
      }
      if (msg.op === "hello") {
        const token = helloAccessToken(msg.access_token, readBearer(req));
        void (async () => {
          try {
            if (!token) throw new ApiError("unauthorized", "Missing bearer token", 401);
            const auth = authFromAccess(token);
            await assertLiveDevice(db, auth);
            client = {
              deviceId: auth.deviceId,
              userId: auth.userId,
              ws: socket,
              resume: msg.resume ?? randomToken(12),
            };
            attach(client);
            await db.query("UPDATE devices SET last_seen_at = now() WHERE id = $1", [auth.deviceId]);
            socket.send(
              JSON.stringify({
                op: "welcome",
                resume: client.resume,
                server_time: new Date().toISOString(),
                connections: connectionCount(),
              }),
            );
          } catch {
            socket.send(JSON.stringify({ op: "error", code: "unauthorized" }));
            socket.close();
          }
        })();
        return;
      }
      if (msg.op === "ping") {
        socket.send(JSON.stringify({ op: "pong", t: Date.now() }));
        return;
      }
      if (msg.op === "ack" && client && msg.ids?.length) {
        void db.query(
          `UPDATE envelopes SET acked_at = now()
           WHERE recipient_device_id = $1 AND id = ANY($2::uuid[])`,
          [client.deviceId, msg.ids],
        );
      }
    });
    socket.on("close", () => {
      if (client) detach(client);
    });
  });

  const webDist = resolve(process.cwd(), "../../apps/web/dist");
  const webDistAlt = resolve(process.cwd(), "../apps/web/dist");
  const staticDir = existsSync(webDist) ? webDist : existsSync(webDistAlt) ? webDistAlt : null;
  if (staticDir) {
    const staticPlugin = (await import("@fastify/static")).default;
    await app.register(staticPlugin, { root: staticDir, wildcard: false });
    app.setNotFoundHandler((req, reply) => {
      if (req.url.startsWith("/v1/") || req.url.startsWith("/healthz") || req.url.startsWith("/readyz")) {
        sendError(reply, new ApiError("not_found", "Not found", 404), requestId(req));
        return;
      }
      void reply.sendFile("index.html");
    });
  }

  return app;
}
