import { createWriteStream, createReadStream, existsSync, mkdirSync, statSync } from "node:fs";
import { unlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { config } from "./config.js";
import { createS3Store, s3Configured, type ObjectStore } from "./s3.js";
import { randomToken } from "./security/crypto-utils.js";

export function newObjectKey(): string {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  return `${y}/${m}/${randomToken(18)}`;
}

export function objectPath(key: string): string {
  if (key.includes("..") || key.startsWith("/")) throw new Error("bad object key");
  return resolve(config.localObjectDir, key);
}

class LocalStore implements ObjectStore {
  async put(key: string, body: Buffer): Promise<number> {
    const p = objectPath(key);
    mkdirSync(dirname(p), { recursive: true });
    const { writeFile } = await import("node:fs/promises");
    await writeFile(p, body);
    return body.length;
  }
  async get(key: string): Promise<Buffer> {
    const { readFile } = await import("node:fs/promises");
    return readFile(objectPath(key));
  }
  async exists(key: string): Promise<boolean> {
    return existsSync(objectPath(key));
  }
  async size(key: string): Promise<number> {
    return statSync(objectPath(key)).size;
  }
  async delete(key: string): Promise<void> {
    const p = objectPath(key);
    if (existsSync(p)) await unlink(p);
  }
}

let store: ObjectStore | null = null;

export function objectStore(): ObjectStore {
  if (store) return store;
  if (s3Configured()) store = createS3Store();
  else {
    if (config.isProd) throw new Error("S3 is required in production");
    store = new LocalStore();
  }
  return store;
}

export function resetObjectStoreForTests(next?: ObjectStore): void {
  store = next ?? null;
}

export async function putObject(key: string, body: Buffer): Promise<number> {
  return objectStore().put(key, body);
}

export async function getObject(key: string): Promise<Buffer> {
  return objectStore().get(key);
}

export async function objectExists(key: string): Promise<boolean> {
  return objectStore().exists(key);
}

export async function objectSize(key: string): Promise<number> {
  return objectStore().size(key);
}

export async function deleteObject(key: string): Promise<void> {
  await objectStore().delete(key);
}

export async function streamToObject(key: string, stream: NodeJS.ReadableStream): Promise<number> {
  if (s3Configured()) {
    const chunks: Buffer[] = [];
    for await (const c of stream) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    return putObject(key, Buffer.concat(chunks));
  }
  const p = objectPath(key);
  mkdirSync(dirname(p), { recursive: true });
  await pipeline(stream, createWriteStream(p));
  return statSync(p).size;
}

export function streamFromObject(key: string) {
  if (s3Configured()) {
    throw new Error("streamFromObject is local-only; use getObject");
  }
  return createReadStream(objectPath(key));
}
