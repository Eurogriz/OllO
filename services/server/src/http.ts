import type { FastifyReply, FastifyRequest } from "fastify";
import type { ApiErrorCode } from "@ollo/protocol";
import type { Db } from "./db/index.js";
import type { AccessClaims } from "./security/crypto-utils.js";
import { verifyAccess } from "./security/crypto-utils.js";

export class ApiError extends Error {
  constructor(
    public code: ApiErrorCode,
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}

export function sendError(reply: FastifyReply, err: ApiError, requestId: string): void {
  void reply.code(err.status).send({
    error: { code: err.code, message: err.message, request_id: requestId },
  });
}

export interface Authed {
  userId: string;
  deviceId: string;
  claims: AccessClaims;
}

/** Bearer header only. Query-string tokens leak into logs and referrers. */
export function readBearer(req: FastifyRequest): string | undefined {
  const header = req.headers.authorization;
  if (header?.startsWith("Bearer ")) return header.slice(7);
  return undefined;
}

export function authFromAccess(token: string): Authed {
  const claims = verifyAccess(token);
  if (!claims) throw new ApiError("unauthorized", "Invalid or expired token", 401);
  return { userId: claims.sub, deviceId: claims.did, claims };
}

export function requireAuth(req: FastifyRequest): Authed {
  const token = readBearer(req);
  if (!token) {
    throw new ApiError("unauthorized", "Missing bearer token", 401);
  }
  return authFromAccess(token);
}

export async function assertLiveDevice(db: Db, auth: Authed): Promise<void> {
  const row = await db.query<{ revoked_at: string | null; deleted_at: string | null }>(
    `SELECT d.revoked_at, u.deleted_at
     FROM devices d JOIN users u ON u.id = d.user_id
     WHERE d.id = $1 AND d.user_id = $2`,
    [auth.deviceId, auth.userId],
  );
  const live = row.rows[0];
  if (!live || live.revoked_at || live.deleted_at) {
    throw new ApiError("unauthorized", "Device revoked", 401);
  }
}

export function requestId(req: FastifyRequest): string {
  return String(req.headers["x-request-id"] ?? req.id);
}
