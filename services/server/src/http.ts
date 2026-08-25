import type { FastifyReply, FastifyRequest } from "fastify";
import type { ApiErrorCode } from "@ollo/protocol";
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

export function requireAuth(req: FastifyRequest): Authed {
  const header = req.headers.authorization;
  const q = (req.query as { access_token?: string } | undefined)?.access_token;
  const token = header?.startsWith("Bearer ") ? header.slice(7) : q;
  if (!token) {
    throw new ApiError("unauthorized", "Missing bearer token", 401);
  }
  const claims = verifyAccess(token);
  if (!claims) throw new ApiError("unauthorized", "Invalid or expired token", 401);
  return { userId: claims.sub, deviceId: claims.did, claims };
}

export function requestId(req: FastifyRequest): string {
  return String(req.headers["x-request-id"] ?? req.id);
}
