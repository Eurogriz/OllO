/**
 * Thin Redis client (RESP2) used for rate-limit and presence.
 * No extra dependency. Fail closed when REDIS_REQUIRED / production.
 */
import { Socket } from "node:net";
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

function encodeCommand(args: string[]): Buffer {
  let out = `*${args.length}\r\n`;
  for (const a of args) {
    const b = Buffer.from(a, "utf8");
    out += `$${b.length}\r\n${a}\r\n`;
  }
  return Buffer.from(out, "utf8");
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

class NetRedis implements RedisClient {
  constructor(private readonly socket: Socket) {}

  private async call(...args: string[]): Promise<unknown> {
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
    const n = Number(await this.call("INCR", key));
    if (n === 1) await this.call("EXPIRE", key, String(ttlSeconds));
    return n;
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

  async auth(password: string): Promise<void> {
    await this.call("AUTH", password);
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
    const u = new URL(config.redisUrl);
    const sock = await new Promise<Socket>((resolve, reject) => {
      const s = new Socket();
      s.once("error", reject);
      s.connect(Number(u.port || 6379), u.hostname, () => resolve(s));
    });
    const net = new NetRedis(sock);
    if (u.password) {
      await net.auth(decodeURIComponent(u.password));
    }
    const pong = await net.ping();
    if (pong !== "PONG") throw new RedisError("redis ping failed");
    client = net;
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

export function resetRedisForTests(next?: RedisClient): void {
  client?.close();
  client = next ?? null;
  connecting = null;
}
