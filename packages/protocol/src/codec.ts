/**
 * Binary codec for sealed payloads.
 *
 * Layout (version 1):
 *   u8  version
 *   u8  alg (1 = 1:1 DR, 2 = sender key)
 *   u8  flags (bit0 = has prekey meta)
 *   u8  dh_pub_len + dh_pub
 *   u32 pn, u32 n
 *   if prekey:
 *     u32 registration_id
 *     u32 signed_prekey_id
 *     u32 one_time_prekey_id (0 = none)
 *     u8  eph_len + eph
 *     u8  ik_len + ik
 *   u8  nonce_len + nonce
 *   u32 ct_len + ct
 */

import type { PrekeyWhisperMeta, RatchetHeader, SealedPayload } from "./index.js";

const ALG_DR = 1;
const ALG_SK = 2;

export function encodeSealed(p: SealedPayload): Uint8Array {
  const chunks: Uint8Array[] = [];
  const head = new Uint8Array(3);
  head[0] = p.version;
  head[1] = p.alg.startsWith("senderkey") ? ALG_SK : ALG_DR;
  head[2] = p.prekey ? 1 : 0;
  chunks.push(head);
  chunks.push(tlv(p.header.dhPublic));
  chunks.push(u32(p.header.previousChainLength));
  chunks.push(u32(p.header.messageNumber));
  if (p.prekey) {
    chunks.push(u32(p.prekey.registrationId));
    chunks.push(u32(p.prekey.signedPrekeyId));
    chunks.push(u32(p.prekey.oneTimePrekeyId ?? 0));
    chunks.push(tlv(p.prekey.ephemeralPublic));
    chunks.push(tlv(p.prekey.identityKeyX25519));
  }
  chunks.push(tlv(p.nonce));
  chunks.push(u32(p.ciphertext.length));
  chunks.push(p.ciphertext);
  return concat(chunks);
}

export function decodeSealed(buf: Uint8Array): SealedPayload {
  const r = new Reader(buf);
  const version = r.u8();
  if (version !== 1) {
    throw new Error("unsupported_version");
  }
  const algId = r.u8();
  const flags = r.u8();
  const dhPublic = r.tlv();
  const previousChainLength = r.u32();
  const messageNumber = r.u32();
  let prekey: PrekeyWhisperMeta | undefined;
  if (flags & 1) {
    const registrationId = r.u32();
    const signedPrekeyId = r.u32();
    const opk = r.u32();
    prekey = {
      registrationId,
      signedPrekeyId,
      oneTimePrekeyId: opk === 0 ? undefined : opk,
      ephemeralPublic: r.tlv(),
      identityKeyX25519: r.tlv(),
    };
  }
  const nonce = r.tlv();
  const ctLen = r.u32();
  const ciphertext = r.bytes(ctLen);
  const header: RatchetHeader = { dhPublic, previousChainLength, messageNumber };
  return {
    version: 1,
    alg: algId === ALG_SK ? "senderkey-xchacha20poly1305-v1" : "x3dh-dr-xchacha20poly1305-v1",
    header,
    prekey,
    nonce,
    ciphertext,
  };
}

export function bytesToB64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("odd hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function tlv(data: Uint8Array): Uint8Array {
  if (data.length > 255) throw new Error("tlv too long");
  const out = new Uint8Array(1 + data.length);
  out[0] = data.length;
  out.set(data, 1);
  return out;
}

function u32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  const v = n >>> 0;
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

class Reader {
  constructor(
    private readonly buf: Uint8Array,
    private i = 0,
  ) {}
  u8(): number {
    return this.bytes(1)[0]!;
  }
  u32(): number {
    const b = this.bytes(4);
    return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
  }
  tlv(): Uint8Array {
    const n = this.u8();
    return this.bytes(n);
  }
  bytes(n: number): Uint8Array {
    if (this.i + n > this.buf.length) throw new Error("truncated");
    const s = this.buf.subarray(this.i, this.i + n);
    this.i += n;
    return s;
  }
}
