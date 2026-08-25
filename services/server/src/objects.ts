import { createWriteStream, createReadStream, existsSync, mkdirSync, statSync } from "node:fs";
import { unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { config } from "./config.js";
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

export async function putObject(key: string, body: Buffer): Promise<number> {
  const p = objectPath(key);
  mkdirSync(dirname(p), { recursive: true });
  const { writeFile } = await import("node:fs/promises");
  await writeFile(p, body);
  return body.length;
}

export async function getObject(key: string): Promise<Buffer> {
  const { readFile } = await import("node:fs/promises");
  return readFile(objectPath(key));
}

export function objectExists(key: string): boolean {
  return existsSync(objectPath(key));
}

export function objectSize(key: string): number {
  return statSync(objectPath(key)).size;
}

export async function deleteObject(key: string): Promise<void> {
  const p = objectPath(key);
  if (existsSync(p)) await unlink(p);
}

export async function streamToObject(key: string, stream: NodeJS.ReadableStream): Promise<number> {
  const p = objectPath(key);
  mkdirSync(dirname(p), { recursive: true });
  await pipeline(stream, createWriteStream(p));
  return objectSize(key);
}

export function streamFromObject(key: string) {
  return createReadStream(objectPath(key));
}

void join;
