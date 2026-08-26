/**
 * Thin Redis client (RESP2) used for rate-limit and presence.
 * No extra dependency. Fail closed when REDIS_REQUIRED / production.
 *
 * Commands on one socket are serialized. INCR+EXPIRE is a single EVAL so a
 * crash cannot leave a limiter key without a TTL (permanent lockout).
 * `rediss://` and REDIS_TLS open a TLS socket (ElastiCache transit encryption).
 */
import { Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import type { RouteOptions } from "fastify";
import { config } from "./config.js";

export class RedisError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RedisError";
  }
}

export interface RedisClient {
  incrEx(key: string, ttlSeconds: number): Promise<number>;
  get(key: string): Promise<string | null>;
  setEx(key: string, ttlSeconds: number, value: string): Promise<void>;
  del(key: string): Promise<void>;
  ping(): Promise<string>;
  close(): void;
}

export interface RedisEndpoint {
  host: string;
  port: number;
  tls: boolean;
  username: string | null;
  password: string | null;
}

/** Atomic INCR that sets TTL only when the key is created. */
export const INCR_EXPIRE_LUA =
  "local n=redis.call('INCR',KEYS[1]) if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end return n";

class MemoryRedis implements RedisClient {
  private readonly store = new Map<string, { v: string; exp: number }>();

  private live(key: string): { v: string; exp: number } | undefined {
    const cur = this.store.get(key);
    if (!cur) return undefined;
    if (cur.exp < Date.now()) {
      this.store.delete(key);
      return undefined;
    }
    return cur;
  }

  async incrEx(key: string, ttlSeconds: number): Promise<number> {
    const cur = this.live(key);
    const n = (cur ? Number(cur.v) : 0) + 1;
    const exp = cur?.exp ?? Date.now() + ttlSeconds * 1000;
    this.store.set(key, { v: String(n), exp });
    return n;
  }

  async get(key: string): Promise<string | null> {
    return this.live(key)?.v ?? null;
  }

  async setEx(key: string, ttlSeconds: number, value: string): Promise<void> {
    this.store.set(key, { v: value, exp: Date.now() + ttlSeconds * 1000 });
  }

  async del(key: string): Promise<void> {
    this.store.delete(key);
  }

  async ping(): Promise<string> {
    return "PONG";
  }

  close(): void {
    this.store.clear();
  }
}

export function encodeCommand(args: string[]): Buffer {
  const parts: Buffer[] = [Buffer.from(`*${args.length}\r\n`)];
  for (const a of args) {
    const b = Buffer.from(a, "utf8");
    parts.push(Buffer.from(`$${b.length}\r\n`), b, Buffer.from("\r\n"));
  }
  return Buffer.concat(parts);
}

export function parseResp(buf: Buffer): { value: unknown; rest: Buffer } {
  if (buf.length < 3) throw new RedisError("incomplete");
  const kind = String.fromCharCode(buf[0]!);
  if (kind === "+" || kind === "-" || kind === ":") {
    const end = buf.indexOf("\r\n");
    if (end < 0) throw new RedisError("incomplete");
    const payload = buf.subarray(1, end).toString("utf8");
    const rest = buf.subarray(end + 2);
    if (kind === "-") throw new RedisError(payload);
    if (kind === ":") return { value: Number(payload), rest };
    return { value: payload, rest };
  }
  if (kind === "$") {
    const end = buf.indexOf("\r\n");
    if (end < 0) throw new RedisError("incomplete");
    const n = Number(buf.subarray(1, end).toString("utf8"));
    if (n < 0) return { value: null, rest: buf.subarray(end + 2) };
    const start = end + 2;
    const stop = start + n;
    if (buf.length < stop + 2) throw new RedisError("incomplete");
    return { value: buf.subarray(start, stop).toString("utf8"), rest: buf.subarray(stop + 2) };
  }
  throw new RedisError("unsupported RESP");
}

export function redisEndpoint(url: string, forceTls = false): RedisEndpoint {
  const u = new URL(url);
  const username = u.username ? decodeURIComponent(u.username) : null;
  const password = u.password ? decodeURIComponent(u.password) : null;
  return {
    host: u.hostname,
    port: Number(u.port || (u.protocol === "rediss:" ? 6379 : 6379)),
    tls: forceTls || u.protocol === "rediss:",
    username: username && username !== "default" ? username : null,
    password,
  };
}

class NetRedis implements RedisClient {
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly socket: Socket) {}

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.chain.then(fn, fn);
    this.chain = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  private async call(...args: string[]): Promise<unknown> {
    return this.enqueue(() => this.roundTrip(args));
  }

  private async roundTrip(args: string[]): Promise<unknown> {
    const payload = encodeCommand(args);
    return await new Promise((resolve, reject) => {
      let acc = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        acc = Buffer.concat([acc, chunk]);
        try {
          const parsed = parseResp(acc);
          this.socket.off("data", onData);
          resolve(parsed.value);
        } catch (e) {
          if (e instanceof RedisError && e.message === "incomplete") return;
          this.socket.off("data", onData);
          reject(e);
        }
      };
      this.socket.on("data", onData);
      this.socket.write(payload, (err) => {
        if (err) {
          this.socket.off("data", onData);
          reject(err);
        }
      });
    });
  }

  async incrEx(key: string, ttlSeconds: number): Promise<number> {
    return Number(await this.call("EVAL", INCR_EXPIRE_LUA, "1", key, String(ttlSeconds)));
  }

  async get(key: string): Promise<string | null> {
    const v = await this.call("GET", key);
    return v == null ? null : String(v);
  }

  async setEx(key: string, ttlSeconds: number, value: string): Promise<void> {
    await this.call("SETEX", key, String(ttlSeconds), value);
  }

  async del(key: string): Promise<void> {
    await this.call("DEL", key);
  }

  async ping(): Promise<string> {
    return String(await this.call("PING"));
  }

  async auth(password: string, username?: string | null): Promise<void> {
    if (username) await this.call("AUTH", username, password);
    else await this.call("AUTH", password);
  }

  close(): void {
    this.socket.destroy();
  }
}

let client: RedisClient | null = null;
let connecting: Promise<RedisClient> | null = null;

export function memoryRedis(): RedisClient {
  return new MemoryRedis();
}

async function connectNet(url: string, tlsForced: boolean): Promise<NetRedis> {
  const ep = redisEndpoint(url, tlsForced);
  const sock = await new Promise<Socket>((resolve, reject) => {
    if (ep.tls) {
      const s: TLSSocket = tlsConnect(
        { host: ep.host, port: ep.port, servername: ep.host },
        () => resolve(s),
      );
      s.once("error", reject);
      return;
    }
    const s = new Socket();
    s.once("error", reject);
    s.connect(ep.port, ep.host, () => resolve(s));
  });
  const net = new NetRedis(sock);
  if (ep.password) await net.auth(ep.password, ep.username);
  const pong = await net.ping();
  if (pong !== "PONG") throw new RedisError("redis ping failed");
  return net;
}

export async function getRedis(): Promise<RedisClient> {
  if (client) return client;
  if (connecting) return connecting;
  connecting = (async () => {
    if (!config.redisUrl) {
      if (config.redisRequired || config.isProd) {
        throw new RedisError("REDIS_URL required");
      }
      client = new MemoryRedis();
      return client;
    }
    client = await connectNet(config.redisUrl, config.redisTls);
    return client;
  })();
  try {
    return await connecting;
  } finally {
    connecting = null;
  }
}

export async function takeWindow(key: string, max: number, windowSeconds: number): Promise<boolean> {
  const r = await getRedis();
  const n = await r.incrEx(key, windowSeconds);
  return n <= max;
}

/**
 * Fastify `@fastify/rate-limit` store backed by the same Redis client as OTP
 * windows. Multi-instance deployments share one counter.
 */
export class RedisWindowStore {
  private readonly timeWindowMs: number;

  constructor(options: { timeWindow?: number } = {}) {
    this.timeWindowMs = typeof options.timeWindow === "number" ? options.timeWindow : 60_000;
  }

  incr(
    key: string,
    callback: (error: Error | null, result?: { current: number; ttl: number }) => void,
    timeWindow?: number,
  ): void {
    const ttlMs = typeof timeWindow === "number" ? timeWindow : this.timeWindowMs;
    const ttlSec = Math.max(1, Math.ceil(ttlMs / 1000));
    void getRedis()
      .then((r) => r.incrEx(`http:${key}`, ttlSec))
      .then((n) => callback(null, { current: n, ttl: ttlMs }))
      .catch((err) => callback(err instanceof Error ? err : new Error(String(err))));
  }

  child(routeOptions: RouteOptions & { timeWindow?: number }): RedisWindowStore {
    const next =
      typeof routeOptions.timeWindow === "number" ? routeOptions.timeWindow : this.timeWindowMs;
    return new RedisWindowStore({ timeWindow: next });
  }
}

export function resetRedisForTests(next?: RedisClient): void {
  client?.close();
  client = next ?? null;
  connecting = null;
}
