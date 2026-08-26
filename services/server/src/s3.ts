/**
 * S3 / MinIO adapter (AWS Signature Version 4). Official signing algorithm,
 * not a homemade cipher. Ciphertext blobs only — no plaintext filenames.
 */
import { createHash, createHmac } from "node:crypto";
import { config } from "./config.js";

export interface ObjectStore {
  put(key: string, body: Buffer): Promise<number>;
  get(key: string): Promise<Buffer>;
  exists(key: string): Promise<boolean>;
  size(key: string): Promise<number>;
  delete(key: string): Promise<void>;
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

function amzDate(now = new Date()): { amz: string; day: string } {
  const iso = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return { amz: iso.slice(0, 15) + "Z", day: iso.slice(0, 8) };
}

export function signingKey(secret: string, day: string, region: string, service = "s3"): Buffer {
  const kDate = hmac(`AWS4${secret}`, day);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

export function canonicalRequest(args: {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  payloadHash: string;
}): string {
  const lowered: Record<string, string> = {};
  for (const [k, v] of Object.entries(args.headers)) lowered[k.toLowerCase()] = v;
  const names = Object.keys(lowered).sort();
  const headerLines = names.map((n) => `${n}:${lowered[n]!.trim()}`).join("\n");
  return [
    args.method,
    args.path,
    args.query,
    `${headerLines}\n`,
    names.join(";"),
    args.payloadHash,
  ].join("\n");
}

export function stringToSign(amz: string, day: string, region: string, canonical: string): string {
  return [
    "AWS4-HMAC-SHA256",
    amz,
    `${day}/${region}/s3/aws4_request`,
    sha256Hex(canonical),
  ].join("\n");
}

function hostOf(endpoint: string, bucket: string): { host: string; url: (key: string) => string; path: (key: string) => string } {
  const base = endpoint.replace(/\/$/, "");
  const u = new URL(base);
  if (u.hostname.startsWith(`${bucket}.`)) {
    return {
      host: u.host,
      url: (key) => `${base}/${encodeURI(key)}`,
      path: (key) => `/${encodeURI(key)}`,
    };
  }
  return {
    host: u.host,
    url: (key) => `${base}/${bucket}/${encodeURI(key)}`,
    path: (key) => `/${bucket}/${encodeURI(key)}`,
  };
}

export class S3Store implements ObjectStore {
  constructor(
    private readonly endpoint: string,
    private readonly region: string,
    private readonly bucket: string,
    private readonly accessKey: string,
    private readonly secretKey: string,
  ) {
    if (!endpoint || !bucket || !accessKey || !secretKey) throw new Error("S3 config incomplete");
  }

  private signed(method: string, key: string, body: Buffer, now = new Date()) {
    const { amz, day } = amzDate(now);
    const loc = hostOf(this.endpoint, this.bucket);
    const payloadHash = sha256Hex(body);
    const headers: Record<string, string> = {
      host: loc.host,
      "x-amz-content-sha256": payloadHash,
      "x-amz-date": amz,
    };
    const canon = canonicalRequest({
      method,
      path: loc.path(key),
      query: "",
      headers,
      payloadHash,
    });
    const toSign = stringToSign(amz, day, this.region, canon);
    const sig = createHmac("sha256", signingKey(this.secretKey, day, this.region))
      .update(toSign, "utf8")
      .digest("hex");
    const signedHeaders = Object.keys(headers)
      .map((k) => k.toLowerCase())
      .sort()
      .join(";");
    const authorization =
      `AWS4-HMAC-SHA256 Credential=${this.accessKey}/${day}/${this.region}/s3/aws4_request, ` +
      `SignedHeaders=${signedHeaders}, Signature=${sig}`;
    return {
      url: loc.url(key),
      headers: {
        ...headers,
        authorization,
      },
    };
  }

  async put(key: string, body: Buffer): Promise<number> {
    const req = this.signed("PUT", key, body);
    const res = await fetch(req.url, { method: "PUT", headers: req.headers, body });
    if (!res.ok) throw new Error(`S3 PUT ${res.status}`);
    return body.length;
  }

  async get(key: string): Promise<Buffer> {
    const req = this.signed("GET", key, Buffer.alloc(0));
    const res = await fetch(req.url, { method: "GET", headers: req.headers });
    if (res.status === 404) throw new Error("object missing");
    if (!res.ok) throw new Error(`S3 GET ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }

  async exists(key: string): Promise<boolean> {
    const req = this.signed("HEAD", key, Buffer.alloc(0));
    const res = await fetch(req.url, { method: "HEAD", headers: req.headers });
    return res.ok;
  }

  async size(key: string): Promise<number> {
    const req = this.signed("HEAD", key, Buffer.alloc(0));
    const res = await fetch(req.url, { method: "HEAD", headers: req.headers });
    if (!res.ok) throw new Error(`S3 HEAD ${res.status}`);
    return Number(res.headers.get("content-length") ?? 0);
  }

  async delete(key: string): Promise<void> {
    const req = this.signed("DELETE", key, Buffer.alloc(0));
    const res = await fetch(req.url, { method: "DELETE", headers: req.headers });
    if (!res.ok && res.status !== 404) throw new Error(`S3 DELETE ${res.status}`);
  }
}

export function s3Configured(): boolean {
  return Boolean(config.s3Bucket && config.s3AccessKey && config.s3SecretKey && (config.s3Endpoint || config.s3Region));
}

export function createS3Store(): S3Store {
  const endpoint =
    config.s3Endpoint ||
    `https://${config.s3Bucket}.s3.${config.s3Region}.amazonaws.com`;
  return new S3Store(endpoint, config.s3Region, config.s3Bucket, config.s3AccessKey, config.s3SecretKey);
}
