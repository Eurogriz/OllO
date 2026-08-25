import type { InnerMessage, PrekeyBundle, SealedPayload } from "@ollo/protocol";
import { decodeSealed, encodeSealed, paddingBucket } from "@ollo/protocol";
import {
  type LocalDevice,
  type SessionState,
  acceptSession,
  beginSession,
  createLocalDevice,
  decryptAttachment,
  decryptMessage,
  deserializeSession,
  encryptAttachment,
  encryptFirstMessage,
  encryptMessage,
  generateSignedPrekey,
  safetyNumber,
  serializeIdentity,
  serializeSession,
  deserializeIdentity,
} from "@ollo/crypto";

const STORE_KEY = "ollo.account.v1";

export interface ChatMessage {
  clientId: string;
  threadId: string;
  fromMe: boolean;
  senderUserId: string;
  text?: string;
  sentAt: string;
  status: "pending" | "sent" | "delivered" | "read" | "failed";
  replyTo?: string;
  attachments?: { name: string; mime: string; url?: string; objectId?: string }[];
  voice?: { url: string; durationMs: number };
  reaction?: string;
  edited?: boolean;
  deleted?: boolean;
  expiresAt?: string;
}

export interface Thread {
  id: string;
  kind: "direct" | "group";
  title: string;
  peerUserId?: string;
  groupId?: string;
  last?: string;
  lastAt?: string;
  unread: number;
  disappearingSeconds: number;
}

export interface Account {
  userId: string;
  deviceId: string;
  username: string | null;
  displayName: string;
  about: string;
  access: string;
  refresh: string;
  device: LocalDevice;
  sessions: Record<string, SessionState>;
  messages: Record<string, ChatMessage[]>;
  threads: Thread[];
  contacts: { id: string; username: string | null; display_name: string }[];
  pinned: Record<string, string[]>;
  drafts: Record<string, string>;
  firstSent: Record<string, boolean>;
}

export function sessionKey(userId: string, deviceId: string): string {
  return `${userId}:${deviceId}`;
}

export function loadAccount(): Account | null {
  const raw = localStorage.getItem(STORE_KEY);
  if (!raw) return null;
  try {
    const j = JSON.parse(raw) as Stored;
    const device: LocalDevice = {
      userId: j.userId,
      deviceId: j.deviceId,
      registrationId: j.registrationId,
      identity: deserializeIdentity(j.identity),
      signedPrekey: {
        id: j.signedPrekey.id,
        privateKey: b64u(j.signedPrekey.privateKey),
        publicKey: b64u(j.signedPrekey.publicKey),
        signature: b64u(j.signedPrekey.signature),
      },
      oneTimePrekeys: j.oneTimePrekeys.map((k) => ({
        id: k.id,
        privateKey: b64u(k.privateKey),
        publicKey: b64u(k.publicKey),
      })),
    };
    const sessions: Record<string, SessionState> = {};
    for (const [k, v] of Object.entries(j.sessions)) {
      sessions[k] = deserializeSession(v);
    }
    return {
      userId: j.userId,
      deviceId: j.deviceId,
      username: j.username,
      displayName: j.displayName,
      about: j.about,
      access: j.access,
      refresh: j.refresh,
      device,
      sessions,
      messages: j.messages,
      threads: j.threads,
      contacts: j.contacts,
      pinned: j.pinned,
      drafts: j.drafts,
      firstSent: j.firstSent ?? {},
    };
  } catch {
    return null;
  }
}

export function saveAccount(acc: Account): void {
  const stored: Stored = {
    userId: acc.userId,
    deviceId: acc.deviceId,
    username: acc.username,
    displayName: acc.displayName,
    about: acc.about,
    access: acc.access,
    refresh: acc.refresh,
    registrationId: acc.device.registrationId,
    identity: serializeIdentity(acc.device.identity),
    signedPrekey: {
      id: acc.device.signedPrekey.id,
      privateKey: b64(acc.device.signedPrekey.privateKey),
      publicKey: b64(acc.device.signedPrekey.publicKey),
      signature: b64(acc.device.signedPrekey.signature),
    },
    oneTimePrekeys: acc.device.oneTimePrekeys.map((k) => ({
      id: k.id,
      privateKey: b64(k.privateKey),
      publicKey: b64(k.publicKey),
    })),
    sessions: Object.fromEntries(
      Object.entries(acc.sessions).map(([k, v]) => [k, serializeSession(v)]),
    ),
    messages: acc.messages,
    threads: acc.threads,
    contacts: acc.contacts,
    pinned: acc.pinned,
    drafts: acc.drafts,
    firstSent: acc.firstSent,
  };
  localStorage.setItem(STORE_KEY, JSON.stringify(stored));
}

export function clearAccount(): void {
  localStorage.removeItem(STORE_KEY);
}

export function newDeviceMaterial() {
  return createLocalDevice();
}

export function publicDevicePayload(mat: ReturnType<typeof createLocalDevice>, name: string, platform: "web") {
  return {
    name,
    platform,
    registration_id: mat.registrationId,
    identity_key_x25519: b64(mat.identity.x25519Public),
    identity_key_ed25519: b64(mat.identity.ed25519Public),
    signed_prekey: {
      id: mat.signedPrekey.id,
      public: b64(mat.signedPrekey.publicKey),
      signature: b64(mat.signedPrekey.signature),
    },
    one_time_prekeys: mat.oneTimePrekeys.slice(0, 100).map((k) => ({
      id: k.id,
      public: b64(k.publicKey),
    })),
  };
}

export async function api(path: string, access: string | null, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (access) headers.set("Authorization", `Bearer ${access}`);
  if (init.body && !(init.body instanceof Uint8Array) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(path, { ...init, headers });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const msg = data?.error?.message ?? res.statusText;
    throw new Error(msg);
  }
  return data;
}

export function parseBundle(raw: {
  user_id: string;
  device_id: string;
  registration_id: number;
  identity_key_x25519: string;
  identity_key_ed25519: string;
  signed_prekey: { id: number; public: string; signature: string };
  one_time_prekey?: { id: number; public: string } | null;
}): PrekeyBundle {
  return {
    userId: raw.user_id,
    deviceId: raw.device_id,
    registrationId: raw.registration_id,
    identityKeyX25519: b64u(raw.identity_key_x25519),
    identityKeyEd25519: b64u(raw.identity_key_ed25519),
    signedPrekey: {
      id: raw.signed_prekey.id,
      publicKey: b64u(raw.signed_prekey.public),
      signature: b64u(raw.signed_prekey.signature),
    },
    oneTimePrekey: raw.one_time_prekey
      ? { id: raw.one_time_prekey.id, publicKey: b64u(raw.one_time_prekey.public) }
      : undefined,
  };
}

export async function sealForPeer(
  acc: Account,
  bundle: PrekeyBundle,
  inner: InnerMessage,
): Promise<{ payload: string; bucket: number }> {
  const sk = sessionKey(bundle.userId, bundle.deviceId);
  let sealed: SealedPayload;
  if (!acc.sessions[sk]) {
    const init = beginSession(acc.device, bundle);
    acc.sessions[sk] = init.session;
    sealed = encryptFirstMessage(acc.device, init, inner);
    acc.firstSent[sk] = true;
  } else {
    sealed = encryptMessage(acc.sessions[sk]!, inner);
  }
  const bytes = encodeSealed(sealed);
  return { payload: b64(bytes), bucket: paddingBucket(bytes.length) };
}

export function openEnvelope(
  acc: Account,
  senderUserId: string,
  senderDeviceId: string,
  ciphertextB64: string,
): InnerMessage {
  const sealed = decodeSealed(b64u(ciphertextB64));
  const sk = sessionKey(senderUserId, senderDeviceId);
  if (!acc.sessions[sk]) {
    const { acceptSession } = requireAccept();
    acc.sessions[sk] = acceptSession(acc.device, sealed, senderUserId, senderDeviceId);
  }
  return decryptMessage(acc.sessions[sk]!, sealed);
}

function requireAccept() {
  return { acceptSession: (awaiter as unknown as { acceptSession: typeof import("@ollo/crypto").acceptSession }).acceptSession };
}

// static import used above via function to keep tree simple
import { acceptSession } from "@ollo/crypto";
const awaiter = { acceptSession };

export function computeSafety(acc: Account, theirX: Uint8Array) {
  return safetyNumber(acc.device.identity.x25519Public, theirX);
}

export async function encryptFile(file: File) {
  const buf = new Uint8Array(await file.arrayBuffer());
  return encryptAttachment(buf, { mime: file.type || "application/octet-stream", filename: file.name });
}

export function decryptFile(
  enc: Parameters<typeof decryptAttachment>[0],
  ciphertext: Uint8Array,
) {
  return decryptAttachment(enc, ciphertext);
}

export function rotateLocalPrekey(acc: Account) {
  acc.device.signedPrekey = generateSignedPrekey(acc.device.identity, acc.device.signedPrekey.id + 1);
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64u(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

interface Stored {
  userId: string;
  deviceId: string;
  username: string | null;
  displayName: string;
  about: string;
  access: string;
  refresh: string;
  registrationId: number;
  identity: string;
  signedPrekey: { id: number; privateKey: string; publicKey: string; signature: string };
  oneTimePrekeys: { id: number; privateKey: string; publicKey: string }[];
  sessions: Record<string, ReturnType<typeof serializeSession>>;
  messages: Record<string, ChatMessage[]>;
  threads: Thread[];
  contacts: Account["contacts"];
  pinned: Record<string, string[]>;
  drafts: Record<string, string>;
  firstSent: Record<string, boolean>;
}
