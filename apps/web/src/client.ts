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
  deserializeIdentity,
  deserializeSession,
  encryptAttachment,
  encryptFirstMessage,
  encryptMessage,
  generateOneTimePrekeys,
  generateSignedPrekey,
  safetyNumber,
  serializeIdentity,
  serializeSession,
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
  attachments?: { name: string; mime: string; url?: string; objectId?: string; grant?: string }[];
  voice?: { url: string; durationMs: number };
  reaction?: string;
  edited?: boolean;
  deleted?: boolean;
  expiresAt?: string;
  pinned?: boolean;
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
  archived?: boolean;
  muted?: boolean;
}

export interface OutboxItem {
  id: string;
  peerUserId: string;
  groupId?: string;
  kind: "message" | "receipt" | "typing" | "call" | "control";
  inner: InnerMessage;
  attempts: number;
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
  knownIdentities: Record<string, string>;
  outbox: OutboxItem[];
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
    for (const [k, v] of Object.entries(j.sessions)) sessions[k] = deserializeSession(v);
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
      knownIdentities: j.knownIdentities ?? {},
      outbox: j.outbox ?? [],
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
    sessions: Object.fromEntries(Object.entries(acc.sessions).map(([k, v]) => [k, serializeSession(v)])),
    messages: acc.messages,
    threads: acc.threads,
    contacts: acc.contacts,
    pinned: acc.pinned,
    drafts: acc.drafts,
    firstSent: acc.firstSent,
    knownIdentities: acc.knownIdentities,
    outbox: acc.outbox,
  };
  localStorage.setItem(STORE_KEY, JSON.stringify(stored));
}

export function clearAccount(): void {
  localStorage.removeItem(STORE_KEY);
}

export function newDeviceMaterial() {
  return createLocalDevice();
}

export function publicDevicePayload(
  mat: ReturnType<typeof createLocalDevice>,
  name: string,
  platform: "web",
) {
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

export async function refreshSession(acc: Account): Promise<boolean> {
  try {
    const res = await fetch("/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: acc.refresh }),
    });
    if (!res.ok) return false;
    const data = (await res.json()) as { access_token: string; refresh_token: string };
    acc.access = data.access_token;
    acc.refresh = data.refresh_token;
    saveAccount(acc);
    return true;
  } catch {
    return false;
  }
}

export async function api(path: string, access: string | null, init: RequestInit = {}, acc?: Account) {
  const headers = new Headers(init.headers);
  if (access) headers.set("Authorization", `Bearer ${access}`);
  if (init.body && !(init.body instanceof Uint8Array) && !(init.body instanceof ArrayBuffer) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  let res = await fetch(path, { ...init, headers });
  if (res.status === 401 && acc?.refresh) {
    const ok = await refreshSession(acc);
    if (ok) {
      headers.set("Authorization", `Bearer ${acc.access}`);
      res = await fetch(path, { ...init, headers });
    }
  }
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    throw new Error(data?.error?.message ?? res.statusText);
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

export async function sealForExisting(acc: Account, userId: string, deviceId: string, inner: InnerMessage) {
  const sk = sessionKey(userId, deviceId);
  const session = acc.sessions[sk];
  if (!session) return null;
  const sealed = encryptMessage(session, inner);
  const bytes = encodeSealed(sealed);
  return { payload: b64(bytes), bucket: paddingBucket(bytes.length) };
}

export async function sealWithBundle(acc: Account, bundle: PrekeyBundle, inner: InnerMessage) {
  const sk = sessionKey(bundle.userId, bundle.deviceId);
  const fp = b64(bundle.identityKeyX25519);
  const prev = acc.knownIdentities[sk];
  if (prev && prev !== fp) {
    throw new Error("identity_changed");
  }
  acc.knownIdentities[sk] = fp;
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

export async function sendToUser(
  acc: Account,
  peerUserId: string,
  inner: InnerMessage,
  kind: OutboxItem["kind"] = "message",
  groupId?: string,
): Promise<void> {
  const listed = await api(`/v1/keys/${peerUserId}/devices`, acc.access, {}, acc);
  const devices = (listed.devices ?? []) as Array<{ device_id: string }>;
  const envelopes = [];
  for (const d of devices) {
    if (d.device_id === acc.deviceId && peerUserId === acc.userId) continue;
    const existing = await sealForExisting(acc, peerUserId, d.device_id, inner);
    if (existing) {
      envelopes.push({
        recipient_user_id: peerUserId,
        recipient_device_id: d.device_id,
        kind,
        ciphertext: existing.payload,
        padding_bucket: existing.bucket,
        group_id: groupId,
      });
      continue;
    }
    const one = await api(`/v1/keys/${peerUserId}/${d.device_id}`, acc.access, {}, acc);
    const sealed = await sealWithBundle(acc, parseBundle(one.bundle), inner);
    envelopes.push({
      recipient_user_id: peerUserId,
      recipient_device_id: d.device_id,
      kind,
      ciphertext: sealed.payload,
      padding_bucket: sealed.bucket,
      group_id: groupId,
    });
  }
  if (envelopes.length) {
    await api("/v1/envelopes", acc.access, { method: "POST", body: JSON.stringify({ envelopes }) }, acc);
  }
}

export function enqueue(acc: Account, item: Omit<OutboxItem, "id" | "attempts">): void {
  acc.outbox.push({ ...item, id: crypto.randomUUID(), attempts: 0 });
}

export async function flushOutbox(acc: Account): Promise<void> {
  const pending = [...acc.outbox];
  for (const item of pending) {
    try {
      if (item.groupId) {
        const g = await api(`/v1/groups/${item.groupId}`, acc.access, {}, acc);
        for (const m of g.group.members as { user_id: string }[]) {
          await sendToUser(acc, m.user_id, item.inner, item.kind, item.groupId);
        }
      } else {
        await sendToUser(acc, item.peerUserId, item.inner, item.kind);
      }
      acc.outbox = acc.outbox.filter((x) => x.id !== item.id);
    } catch {
      item.attempts += 1;
      if (item.attempts >= 8) acc.outbox = acc.outbox.filter((x) => x.id !== item.id);
    }
  }
  saveAccount(acc);
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
    acc.sessions[sk] = acceptSession(acc.device, sealed, senderUserId, senderDeviceId);
  }
  return decryptMessage(acc.sessions[sk]!, sealed);
}

export function computeSafety(acc: Account, theirX: Uint8Array) {
  return safetyNumber(acc.device.identity.x25519Public, theirX);
}

export async function encryptFile(file: File) {
  const buf = new Uint8Array(await file.arrayBuffer());
  return encryptAttachment(buf, { mime: file.type || "application/octet-stream", filename: file.name });
}

export function decryptFile(enc: Parameters<typeof decryptAttachment>[0], ciphertext: Uint8Array) {
  return decryptAttachment(enc, ciphertext);
}

export async function downloadAndDecrypt(
  acc: Account,
  pointer: {
    objectId: string;
    key: Uint8Array;
    nonce: Uint8Array;
    digest: Uint8Array;
    mime: string;
    filename: string;
    grant?: string;
  },
): Promise<Blob> {
  const q = pointer.grant ? `?grant=${encodeURIComponent(pointer.grant)}` : "";
  const res = await fetch(`/v1/attachments/${pointer.objectId}/data${q}`, {
    headers: { Authorization: `Bearer ${acc.access}` },
  });
  if (!res.ok) throw new Error("download failed");
  const buf = new Uint8Array(await res.arrayBuffer());
  const pt = decryptAttachment(
    {
      ciphertext: buf,
      key: pointer.key,
      nonce: pointer.nonce,
      digest: pointer.digest,
      size: buf.length,
      mime: pointer.mime,
      filename: pointer.filename,
    },
    buf,
  );
  return new Blob([pt], { type: pointer.mime });
}

export async function replenishPrekeys(acc: Account): Promise<void> {
  const depth = await api("/v1/me/prekey-depth", acc.access, {}, acc);
  if ((depth.remaining as number) >= 20) return;
  const start =
    acc.device.oneTimePrekeys.reduce((m, k) => Math.max(m, k.id), 0) + 1;
  const extra = generateOneTimePrekeys(start, 80);
  acc.device.oneTimePrekeys.push(...extra);
  await api(
    "/v1/keys/one-time",
    acc.access,
    {
      method: "POST",
      body: JSON.stringify({
        keys: extra.map((k) => ({ id: k.id, public: b64(k.publicKey) })),
      }),
    },
    acc,
  );
}

export function rotateLocalPrekey(acc: Account) {
  acc.device.signedPrekey = generateSignedPrekey(acc.device.identity, acc.device.signedPrekey.id + 1);
}

export function searchLocal(acc: Account, q: string): ChatMessage[] {
  const needle = q.trim().toLowerCase();
  if (!needle) return [];
  const out: ChatMessage[] = [];
  for (const list of Object.values(acc.messages)) {
    for (const m of list) {
      if (m.text?.toLowerCase().includes(needle)) out.push(m);
    }
  }
  return out.slice(0, 50);
}

export function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64u(s: string): Uint8Array {
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
  knownIdentities: Record<string, string>;
  outbox: OutboxItem[];
}
