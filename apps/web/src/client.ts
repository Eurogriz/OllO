import type { InnerMessage, PrekeyBundle, SealedPayload } from "@ollo/protocol";
import { decodeSealed, encodeSealed, paddingBucket } from "@ollo/protocol";
import {
  noteRemoteIdentity,
  onRefreshRejected,
  onSendFailure,
  planDeviceDrop,
  planKeyFetch,
  planSessionAccept,
  planPrekeyReplenish,
  planRosterPrune,
  afterUnauthorized,
  planSignedPrekeyRotation,
  realtimeHello,
  realtimeUrl,
  rememberEnvelope,
  emptyReplayCache,
  type ReplayCache,
  retainUnexpired,
  planDroppedDevices,
  planHeldSenderKeyFlush,
  planOwnOtherHoldDevices,
  planMembershipApply,
  planMembershipDelta,
  planMembershipSignerNotice,
  planRejectedHashes,
  planOwnSenderKeyRotate,
  planSenderKeyEpochRotate,
  planSenderKeyIngest,
  planSenderKeyPrune,
  planTrustedMembers,
} from "@ollo/shared";
import {
  type LocalDevice,
  type RemoteSenderKey,
  type SenderKeyState,
  type SessionState,
  deviceRosterHash,
  membershipHash,
  signMembership,
  verifyMembership,
  acceptSenderKey,
  acceptSession,
  beginSession,
  createLocalDevice,
  createSenderKey,
  decryptAttachment,
  decryptGroupMessage,
  decryptMessage,
  deserializeIdentity,
  deserializeRemoteSenderKey,
  deserializeSenderKey,
  deserializeSession,
  distributeSenderKey,
  encryptAttachment,
  encryptFirstMessage,
  encryptGroupMessage,
  encryptMessage,
  decodeBackup,
  decodeVault,
  encodeBackup,
  encodeVault,
  fromUtf8,
  generateOneTimePrekeys,
  generateSignedPrekey,
  newVaultKey,
  retainSignedPrekeys,
  openBackup,
  openVault,
  safetyNumber,
  sealBackup,
  sealVault,
  serializeIdentity,
  serializeRemoteSenderKey,
  serializeSenderKey,
  serializeSession,
  utf8,
} from "@ollo/crypto";

export { realtimeHello, realtimeUrl };

const STORE_KEY = "ollo.account.v1";
const VAULT_STORE = "ollo.vault.v1";
const VAULT_KEY_STORE = "ollo.vault.key.v1";
const VAULT_WRAP_STORE = "ollo.vault.wrap.v1";

let memoryVaultKey: Uint8Array | null = null;

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
  senderKeys: Record<string, SenderKeyState>;
  remoteSenderKeys: Record<string, RemoteSenderKey>;
  heldSenderKeys: Record<string, RemoteSenderKey>;
  ownRosterHash?: string;
  signedPrekeyAt?: number;
  replay: ReplayCache;
  memberships: Record<string, LocalGroupMembership>;
  pendingMemberships: Record<string, LocalGroupMembership>;
  rejectedMemberships: Record<string, string[]>;
  droppedDevices: string[];
}

export interface LocalGroupMembership {
  groupId: string;
  epoch: number;
  hash: string;
  members: { userId: string; role: string }[];
  signerUserId: string;
  signerDeviceId: string;
}

export function sessionKey(userId: string, deviceId: string): string {
  return `${userId}:${deviceId}`;
}

/** Drop local ratchet state for devices that left a user's live roster. */
export function pruneSessionsForUser(acc: Account, userId: string, liveDeviceIds: string[]): string[] {
  const dropped = planRosterPrune(Object.keys(acc.sessions), userId, liveDeviceIds);
  for (const k of dropped) {
    delete acc.sessions[k];
    delete acc.knownIdentities[k];
    delete acc.firstSent[k];
    const deviceId = k.slice(userId.length + 1);
    if (deviceId) noteDroppedDevice(acc, userId, deviceId);
  }
  return dropped;
}

export function dropDeviceSessions(acc: Account, userId: string, deviceId: string): string[] {
  const dropped = planDeviceDrop(Object.keys(acc.sessions), userId, deviceId);
  for (const k of dropped) {
    delete acc.sessions[k];
    delete acc.knownIdentities[k];
    delete acc.firstSent[k];
  }
  noteDroppedDevice(acc, userId, deviceId);
  return dropped;
}

function noteDroppedDevice(acc: Account, userId: string, deviceId: string): void {
  if (!acc.droppedDevices) acc.droppedDevices = [];
  acc.droppedDevices = planDroppedDevices(acc.droppedDevices, userId, deviceId);
  pruneSenderKeys(acc, { userId, deviceId });
}

function pruneSenderKeys(acc: Account, filter: { userId?: string; deviceId?: string }): void {
  if (acc.remoteSenderKeys) {
    for (const slot of planSenderKeyPrune(Object.keys(acc.remoteSenderKeys), filter)) {
      delete acc.remoteSenderKeys[slot];
    }
  }
  if (acc.heldSenderKeys) {
    for (const slot of planSenderKeyPrune(Object.keys(acc.heldSenderKeys), filter)) {
      delete acc.heldSenderKeys[slot];
    }
  }
}

function quarantineSenderDevice(acc: Account, userId: string, deviceId: string): void {
  if (!acc.remoteSenderKeys) acc.remoteSenderKeys = {};
  if (!acc.heldSenderKeys) acc.heldSenderKeys = {};
  for (const slot of planSenderKeyPrune(Object.keys(acc.remoteSenderKeys), { userId, deviceId })) {
    const k = acc.remoteSenderKeys[slot];
    if (k) acc.heldSenderKeys[slot] = k;
    delete acc.remoteSenderKeys[slot];
  }
}

function pendingHoldDevices(acc: Account): string[] {
  return planOwnOtherHoldDevices({
    localUserId: acc.userId,
    localDeviceId: acc.deviceId,
    pending: Object.values(acc.pendingMemberships ?? {}).map((p) => ({
      signerUserId: p.signerUserId,
      signerDeviceId: p.signerDeviceId,
    })),
  });
}

/** Record a transport envelope id before decrypting. Drop means skip the body. */
export function noteEnvelope(acc: Account, envelopeId: string): "accept" | "drop" {
  if (!acc.replay) acc.replay = emptyReplayCache();
  return rememberEnvelope(acc.replay, envelopeId);
}

function wireMembership(
  signed: { epoch: number; members: { userId: string; role: string }[]; signature: Uint8Array },
  signerUserId: string,
  signerDeviceId: string,
) {
  return {
    epoch: signed.epoch,
    members: signed.members.map((m) => ({ user_id: m.userId, role: m.role })),
    signer_user_id: signerUserId,
    signer_device_id: signerDeviceId,
    signature: b64(signed.signature),
  };
}

export function rememberMembership(
  acc: Account,
  next: LocalGroupMembership,
): "accept" | "confirm" | "unchanged" | "stale" | "drop" | "rejected" {
  if (!acc.memberships) acc.memberships = {};
  if (!acc.pendingMemberships) acc.pendingMemberships = {};
  if (!acc.rejectedMemberships) acc.rejectedMemberships = {};
  const local = acc.memberships[next.groupId];
  const signerRole = next.members.find((m) => m.userId === next.signerUserId)?.role ?? "";
  const decision = planMembershipApply({
    local: local ? { epoch: local.epoch, hash: local.hash } : undefined,
    incomingEpoch: next.epoch,
    incomingHash: next.hash,
    signatureValid: true,
    signerRole,
    signerUserId: next.signerUserId,
    localMembers: local?.members,
    incomingMembers: next.members,
    rejectedHashes: acc.rejectedMemberships[next.groupId],
    localDeviceId: acc.deviceId,
    signerDeviceId: next.signerDeviceId,
  });
  if (decision === "accept") {
    const removed = local ? planMembershipDelta(local.members, next.members).removed : [];
    acc.memberships[next.groupId] = next;
    delete acc.pendingMemberships[next.groupId];
    flushHeldSenderKeys(acc, next.groupId, next.members.map((m) => m.userId));
    for (const uid of removed) pruneSenderKeys(acc, { userId: uid });
  }
  if (decision === "confirm") {
    acc.pendingMemberships[next.groupId] = next;
    const notice = planMembershipSignerNotice({
      localUserId: acc.userId,
      localDeviceId: acc.deviceId,
      signerUserId: next.signerUserId,
      signerDeviceId: next.signerDeviceId,
    });
    if (notice === "own-other-device") {
      quarantineSenderDevice(acc, next.signerUserId, next.signerDeviceId);
    }
  }
  if (decision === "rejected") delete acc.pendingMemberships[next.groupId];
  return decision;
}

/** Apply a confirmed roster. Caller must distribute sender keys to `added` only after this. */
export function confirmPendingMembership(
  acc: Account,
  groupId: string,
): { applied: LocalGroupMembership; added: string[] } | null {
  if (!acc.memberships) acc.memberships = {};
  if (!acc.pendingMemberships) acc.pendingMemberships = {};
  const pending = acc.pendingMemberships[groupId];
  if (!pending) return null;
  const local = acc.memberships[groupId];
  const delta = planMembershipDelta(local?.members ?? [], pending.members);
  acc.memberships[groupId] = pending;
  delete acc.pendingMemberships[groupId];
  flushHeldSenderKeys(acc, groupId, pending.members.map((m) => m.userId));
  for (const uid of delta.removed) pruneSenderKeys(acc, { userId: uid });
  return { applied: pending, added: delta.added };
}

export function rejectPendingMembership(acc: Account, groupId: string): boolean {
  if (!acc.rejectedMemberships) acc.rejectedMemberships = {};
  const pending = acc.pendingMemberships?.[groupId];
  if (pending?.hash) {
    acc.rejectedMemberships[groupId] = planRejectedHashes(acc.rejectedMemberships[groupId] ?? [], pending.hash);
  }
  if (acc.pendingMemberships) delete acc.pendingMemberships[groupId];
  let hostile = false;
  if (pending) {
    const notice = planMembershipSignerNotice({
      localUserId: acc.userId,
      localDeviceId: acc.deviceId,
      signerUserId: pending.signerUserId,
      signerDeviceId: pending.signerDeviceId,
    });
    if (notice === "own-other-device") {
      noteDroppedDevice(acc, pending.signerUserId, pending.signerDeviceId);
      hostile = true;
    }
  }
  const local = acc.memberships?.[groupId];
  flushHeldSenderKeys(acc, groupId, (local?.members ?? []).map((m) => m.userId));
  return hostile;
}

function senderKeySlot(k: { groupId: string; userId: string; deviceId: string; epoch: number }): string {
  return `${k.groupId}:${k.userId}:${k.deviceId}:${k.epoch}`;
}

function flushHeldSenderKeys(acc: Account, groupId: string, trustedUserIds: string[]): void {
  if (!acc.heldSenderKeys) acc.heldSenderKeys = {};
  if (!acc.remoteSenderKeys) acc.remoteSenderKeys = {};
  const prefix = `${groupId}:`;
  const held = Object.entries(acc.heldSenderKeys)
    .filter(([slot]) => slot.startsWith(prefix))
    .map(([slot, k]) => ({ slot, userId: k.userId }));
  const plan = planHeldSenderKeyFlush(held, trustedUserIds);
  for (const slot of plan.install) {
    const k = acc.heldSenderKeys[slot];
    if (k) acc.remoteSenderKeys[slot] = k;
    delete acc.heldSenderKeys[slot];
  }
  for (const slot of plan.discard) delete acc.heldSenderKeys[slot];
}

export function pendingMembershipNotice(
  acc: Account,
  groupId: string,
): { added: string[]; roleChanged: string[]; signerDeviceId: string; signerNotice: ReturnType<typeof planMembershipSignerNotice> } | null {
  const pending = acc.pendingMemberships?.[groupId];
  if (!pending) return null;
  const local = acc.memberships?.[groupId];
  const delta = planMembershipDelta(local?.members ?? [], pending.members);
  return {
    added: delta.added,
    roleChanged: delta.roleChanged,
    signerDeviceId: pending.signerDeviceId,
    signerNotice: planMembershipSignerNotice({
      localUserId: acc.userId,
      localDeviceId: acc.deviceId,
      signerUserId: pending.signerUserId,
      signerDeviceId: pending.signerDeviceId,
    }),
  };
}

export async function createSignedGroup(
  acc: Account,
  memberIds: string[],
): Promise<{ id: string; epoch: number; memberIds: string[] }> {
  const id = crypto.randomUUID();
  const unique = [...new Set([acc.userId, ...memberIds])];
  const members = unique.map((userId) => ({
    userId,
    role: (userId === acc.userId ? "admin" : "member") as "admin" | "member",
  }));
  const signed = signMembership({ groupId: id, epoch: 1, members }, acc.device.identity);
  await api(
    "/v1/groups",
    acc.access,
    {
      method: "POST",
      body: JSON.stringify({
        id,
        member_ids: memberIds,
        membership: wireMembership(signed, acc.userId, acc.deviceId),
      }),
    },
    acc,
  );
  rememberMembership(acc, {
    groupId: id,
    epoch: 1,
    hash: signed.hash,
    members: signed.members,
    signerUserId: acc.userId,
    signerDeviceId: acc.deviceId,
  });
  return { id, epoch: 1, memberIds: unique };
}

async function trustedGroupMembers(acc: Account, groupId: string, serverRows: { user_id: string }[], membership: {
  epoch: number;
  members: { user_id: string; role: string }[];
  signer_user_id: string;
  signer_device_id: string;
  signature: string;
} | null): Promise<string[]> {
  if (!membership) throw new Error("unsigned_membership");
  const members = membership.members.map((m) => ({ userId: m.user_id, role: m.role }));
  const ed = await resolveSenderEd25519(acc, membership.signer_user_id, membership.signer_device_id);
  const valid = verifyMembership({
    groupId,
    epoch: membership.epoch,
    members,
    signerEd25519: ed,
    signature: b64u(membership.signature),
  });
  if (!valid) throw new Error("unsigned_membership");
  const hash = membershipHash(groupId, membership.epoch, members);
  const decision = rememberMembership(acc, {
    groupId,
    epoch: membership.epoch,
    hash,
    members,
    signerUserId: membership.signer_user_id,
    signerDeviceId: membership.signer_device_id,
  });
  if (decision === "drop" || decision === "stale") throw new Error("unsigned_membership");
  if (decision === "confirm" || decision === "rejected") {
    const localIds = (acc.memberships[groupId]?.members ?? []).map((m) => m.userId);
    return planTrustedMembers(
      localIds,
      serverRows.map((m) => m.user_id),
    ).trusted;
  }
  const plan = planTrustedMembers(
    members.map((m) => m.userId),
    serverRows.map((m) => m.user_id),
  );
  if (plan.extra.length) throw new Error("unsigned_member");
  return plan.trusted;
}

/** Fetch and apply the signed roster without sending. Confirm UI can show before a send. */
export async function syncGroupMembership(acc: Account, groupId: string) {
  const g = await api(`/v1/groups/${groupId}`, acc.access, {}, acc);
  await trustedGroupMembers(
    acc,
    groupId,
    (g.group.members ?? []) as { user_id: string }[],
    (g.group.membership ?? null) as {
      epoch: number;
      members: { user_id: string; role: string }[];
      signer_user_id: string;
      signer_device_id: string;
      signature: string;
    } | null,
  );
}

export function vaultPinEnabled(): boolean {
  return Boolean(localStorage.getItem(VAULT_WRAP_STORE));
}

export function vaultLocked(): boolean {
  return Boolean(localStorage.getItem(VAULT_WRAP_STORE) && !memoryVaultKey);
}

export function unlockVault(pin: string): boolean {
  const wrap = localStorage.getItem(VAULT_WRAP_STORE);
  if (!wrap) return false;
  try {
    memoryVaultKey = openBackup(pin, decodeBackup(wrap));
    return memoryVaultKey.length === 32;
  } catch {
    return false;
  }
}

export function wrapVaultWithPin(pin: string): void {
  const key = ensureVaultKey();
  localStorage.setItem(VAULT_WRAP_STORE, encodeBackup(sealBackup(pin, key)));
  localStorage.removeItem(VAULT_KEY_STORE);
}

export function unwrapVaultPin(): void {
  const key = ensureVaultKey();
  localStorage.setItem(VAULT_KEY_STORE, b64(key));
  localStorage.removeItem(VAULT_WRAP_STORE);
}

function ensureVaultKey(): Uint8Array {
  if (memoryVaultKey) return memoryVaultKey;
  const raw = localStorage.getItem(VAULT_KEY_STORE);
  if (raw) {
    memoryVaultKey = b64u(raw);
    return memoryVaultKey;
  }
  memoryVaultKey = newVaultKey();
  if (!localStorage.getItem(VAULT_WRAP_STORE)) {
    localStorage.setItem(VAULT_KEY_STORE, b64(memoryVaultKey));
  }
  return memoryVaultKey;
}

export function loadAccount(): Account | null {
  if (vaultLocked()) return null;
  const sealed = localStorage.getItem(VAULT_STORE);
  if (sealed) {
    try {
      const pt = openVault(ensureVaultKey(), decodeVault(sealed));
      return gcExpired(accountFromStored(JSON.parse(fromUtf8(pt)) as Stored));
    } catch {
      return null;
    }
  }
  const raw = localStorage.getItem(STORE_KEY);
  if (!raw) return null;
  try {
    const acc = gcExpired(accountFromStored(JSON.parse(raw) as Stored));
    saveAccount(acc);
    localStorage.removeItem(STORE_KEY);
    return acc;
  } catch {
    return null;
  }
}

function gcExpired(acc: Account): Account {
  for (const tid of Object.keys(acc.messages)) {
    acc.messages[tid] = retainUnexpired(acc.messages[tid] ?? []);
  }
  return acc;
}

function accountFromStored(j: Stored): Account {
  const device: LocalDevice = {
    userId: j.userId,
    deviceId: j.deviceId,
    registrationId: j.registrationId,
    identity: deserializeIdentity(j.identity),
    signedPrekey: deserSpk(j.signedPrekey),
    previousSignedPrekeys: (j.previousSignedPrekeys ?? []).map(deserSpk),
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
    senderKeys: Object.fromEntries(
      Object.entries(j.senderKeys ?? {}).map(([k, v]) => [k, deserializeSenderKey(v)]),
    ),
    remoteSenderKeys: Object.fromEntries(
      Object.entries(j.remoteSenderKeys ?? {}).map(([k, v]) => [k, deserializeRemoteSenderKey(v)]),
    ),
    heldSenderKeys: Object.fromEntries(
      Object.entries(j.heldSenderKeys ?? {}).map(([k, v]) => [k, deserializeRemoteSenderKey(v)]),
    ),
    ownRosterHash: j.ownRosterHash,
    signedPrekeyAt: j.signedPrekeyAt,
    replay: j.replay?.ids ? { ids: [...j.replay.ids] } : emptyReplayCache(),
    memberships: j.memberships ?? {},
    pendingMemberships: j.pendingMemberships ?? {},
    rejectedMemberships: j.rejectedMemberships ?? {},
    droppedDevices: j.droppedDevices ?? [],
  };
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
    signedPrekey: serSpk(acc.device.signedPrekey),
    previousSignedPrekeys: (acc.device.previousSignedPrekeys ?? []).map(serSpk),
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
    senderKeys: Object.fromEntries(
      Object.entries(acc.senderKeys ?? {}).map(([k, v]) => [k, serializeSenderKey(v)]),
    ),
    remoteSenderKeys: Object.fromEntries(
      Object.entries(acc.remoteSenderKeys ?? {}).map(([k, v]) => [k, serializeRemoteSenderKey(v)]),
    ),
    heldSenderKeys: Object.fromEntries(
      Object.entries(acc.heldSenderKeys ?? {}).map(([k, v]) => [k, serializeRemoteSenderKey(v)]),
    ),
    ownRosterHash: acc.ownRosterHash,
    signedPrekeyAt: acc.signedPrekeyAt,
    replay: acc.replay ?? emptyReplayCache(),
    memberships: acc.memberships ?? {},
    pendingMemberships: acc.pendingMemberships ?? {},
    rejectedMemberships: acc.rejectedMemberships ?? {},
    droppedDevices: acc.droppedDevices ?? [],
  };
  const sealed = sealVault(ensureVaultKey(), utf8(JSON.stringify(stored)));
  localStorage.setItem(VAULT_STORE, encodeVault(sealed));
  localStorage.removeItem(STORE_KEY);
}

export function clearAccount(): void {
  localStorage.removeItem(STORE_KEY);
  localStorage.removeItem(VAULT_STORE);
  localStorage.removeItem(VAULT_KEY_STORE);
  localStorage.removeItem(VAULT_WRAP_STORE);
  memoryVaultKey = null;
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
    if (!res.ok) {
      if (afterUnauthorized(false) === "wipe" || onRefreshRejected() === "wipe") clearAccount();
      return false;
    }
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
  if (
    planSessionAccept({
      userId: bundle.userId,
      deviceId: bundle.deviceId,
      droppedDevices: acc.droppedDevices,
    }) === "drop"
  ) {
    throw new Error("dropped_device");
  }
  const sk = sessionKey(bundle.userId, bundle.deviceId);
  const fp = b64(bundle.identityKeyX25519);
  if (noteRemoteIdentity(acc.knownIdentities[sk], fp) === "changed") {
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
  pruneSessionsForUser(
    acc,
    peerUserId,
    devices.map((d) => d.device_id),
  );
  const envelopes = [];
  for (const d of devices) {
    if (
      planSessionAccept({
        userId: peerUserId,
        deviceId: d.device_id,
        droppedDevices: acc.droppedDevices,
      }) === "drop"
    ) {
      continue;
    }
    const plan = planKeyFetch({
      localUserId: acc.userId,
      localDeviceId: acc.deviceId,
      targetUserId: peerUserId,
      targetDeviceId: d.device_id,
      hasSession: Boolean(acc.sessions[sessionKey(peerUserId, d.device_id)]),
    });
    if (plan === "skip-self") continue;
    if (plan === "use-session") {
      const existing = await sealForExisting(acc, peerUserId, d.device_id, inner);
      if (!existing) continue;
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
        await sendToGroup(acc, item.groupId, item.inner, item.kind);
      } else {
        await sendToUser(acc, item.peerUserId, item.inner, item.kind);
        if (item.peerUserId !== acc.userId) {
          await sendToUser(acc, acc.userId, item.inner, item.kind);
        }
      }
      acc.outbox = acc.outbox.filter((x) => x.id !== item.id);
    } catch {
      const next = onSendFailure({ id: item.id, status: "pending", attempts: item.attempts });
      item.attempts = next.attempts;
      if (next.status === "failed") acc.outbox = acc.outbox.filter((x) => x.id !== item.id);
    }
  }
  saveAccount(acc);
}

export function openEnvelope(
  acc: Account,
  senderUserId: string,
  senderDeviceId: string,
  ciphertextB64: string,
  groupId?: string,
): InnerMessage {
  if (
    planSessionAccept({
      userId: senderUserId,
      deviceId: senderDeviceId,
      droppedDevices: acc.droppedDevices,
    }) === "drop"
  ) {
    delete acc.sessions[sessionKey(senderUserId, senderDeviceId)];
    throw new Error("dropped_device");
  }
  const sealed = decodeSealed(b64u(ciphertextB64));
  if (sealed.alg.startsWith("senderkey") && groupId) {
    const epoch = sealed.header.previousChainLength;
    const key = `${groupId}:${senderUserId}:${senderDeviceId}:${epoch}`;
    const rk = acc.remoteSenderKeys?.[key];
    if (!rk) throw new Error("missing sender key");
    return decryptGroupMessage(rk, sealed);
  }
  const sk = sessionKey(senderUserId, senderDeviceId);
  if (!acc.sessions[sk]) {
    acc.sessions[sk] = acceptSession(acc.device, sealed, senderUserId, senderDeviceId);
  }
  return decryptMessage(acc.sessions[sk]!, sealed);
}

function bytesZero(b: Uint8Array): boolean {
  return b.every((x) => x === 0);
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export async function resolveSenderEd25519(
  acc: Account,
  senderUserId: string,
  senderDeviceId: string,
): Promise<Uint8Array> {
  if (senderUserId === acc.userId && senderDeviceId === acc.deviceId) {
    return acc.device.identity.ed25519Public;
  }
  const sk = sessionKey(senderUserId, senderDeviceId);
  const session = acc.sessions[sk];
  if (session && !bytesZero(session.remoteIdentityEd25519)) {
    return session.remoteIdentityEd25519;
  }
  const listed = await api(`/v1/keys/${senderUserId}/devices`, acc.access, {}, acc);
  const devices = (listed.devices ?? []) as Array<{
    device_id: string;
    identity_key_x25519: string;
    identity_key_ed25519: string;
  }>;
  const row = devices.find((d) => d.device_id === senderDeviceId);
  if (!row) throw new Error("unknown sender device");
  const ed = b64u(row.identity_key_ed25519);
  const x = b64u(row.identity_key_x25519);
  if (session) {
    if (!bytesEq(session.remoteIdentityX25519, x)) {
      throw new Error("identity_changed");
    }
    session.remoteIdentityEd25519 = ed;
  }
  return ed;
}

export function ingestSenderKey(
  acc: Account,
  inner: InnerMessage,
  senderUserId: string,
  senderDeviceId: string,
  senderIdentityEd25519: Uint8Array,
): void {
  if (!inner.senderKey) return;
  const sig = inner.senderKey.identitySignature;
  if (!sig || sig.length === 0) throw new Error("sender key missing identity signature");
  const remote = acceptSenderKey({
    dist: inner.senderKey,
    identitySignature: sig,
    senderIdentityEd25519,
    userId: senderUserId,
    deviceId: senderDeviceId,
  });
  const trusted = (acc.memberships?.[remote.groupId]?.members ?? []).map((m) => m.userId);
  const pending = (acc.pendingMemberships?.[remote.groupId]?.members ?? []).map((m) => m.userId);
  const decision = planSenderKeyIngest({
    trustedUserIds: trusted,
    pendingUserIds: pending,
    senderUserId,
    senderDeviceId,
    droppedDevices: acc.droppedDevices,
    holdDevices: pendingHoldDevices(acc),
  });
  if (decision === "drop") return;
  const slot = senderKeySlot(remote);
  if (decision === "hold") {
    if (!acc.heldSenderKeys) acc.heldSenderKeys = {};
    acc.heldSenderKeys[slot] = remote;
    return;
  }
  if (!acc.remoteSenderKeys) acc.remoteSenderKeys = {};
  acc.remoteSenderKeys[slot] = remote;
}

export function ensureOwnSenderKey(acc: Account, groupId: string, epoch: number): SenderKeyState {
  if (!acc.senderKeys) acc.senderKeys = {};
  const k = `${groupId}:${epoch}`;
  const existing = acc.senderKeys[k];
  if (existing) return existing;
  const created = createSenderKey(groupId, epoch);
  acc.senderKeys[k] = created;
  return created;
}

export async function rotateSenderKeysAfterDeviceDrop(acc: Account): Promise<void> {
  const groups = Object.values(acc.memberships ?? {}).map((m) => ({
    groupId: m.groupId,
    epoch: m.epoch,
    role: m.members.find((row) => row.userId === acc.userId)?.role ?? "",
  }));
  for (const plan of planSenderKeyEpochRotate(groups)) {
    const local = acc.memberships[plan.groupId];
    if (!local) continue;
    const members = local.members.filter(
      (m) => m.userId && (m.role === "admin" || m.role === "moderator" || m.role === "member"),
    ) as { userId: string; role: "admin" | "moderator" | "member" }[];
    if (!members.length) continue;
    const signed = signMembership({ groupId: plan.groupId, epoch: plan.nextEpoch, members }, acc.device.identity);
    await api(
      `/v1/groups/${plan.groupId}/epoch`,
      acc.access,
      { method: "POST", body: JSON.stringify({ membership: wireMembership(signed, acc.userId, acc.deviceId) }) },
      acc,
    );
    rememberMembership(acc, {
      groupId: plan.groupId,
      epoch: plan.nextEpoch,
      hash: signed.hash,
      members: signed.members,
      signerUserId: acc.userId,
      signerDeviceId: acc.deviceId,
    });
    await distributeOwnSenderKey(
      acc,
      plan.groupId,
      plan.nextEpoch,
      signed.members.map((m) => m.userId),
    );
  }
  for (const plan of planOwnSenderKeyRotate(groups)) {
    const local = acc.memberships[plan.groupId];
    if (!local) continue;
    if (acc.senderKeys) delete acc.senderKeys[`${plan.groupId}:${plan.epoch}`];
    await distributeOwnSenderKey(
      acc,
      plan.groupId,
      plan.epoch,
      local.members.map((m) => m.userId),
    );
  }
}

export async function distributeOwnSenderKey(
  acc: Account,
  groupId: string,
  epoch: number,
  memberIds: string[],
): Promise<void> {
  const state = ensureOwnSenderKey(acc, groupId, epoch);
  const dist = distributeSenderKey(state, acc.device.identity);
  const inner: InnerMessage = {
    version: 1,
    type: "sender_key_distribute",
    clientId: crypto.randomUUID(),
    sentAt: new Date().toISOString(),
    threadId: groupId,
    senderKey: {
      groupId: dist.groupId,
      epoch: dist.epoch,
      chainId: dist.chainId,
      chainKey: dist.chainKey,
      iteration: dist.iteration,
      signingKey: dist.signingKey,
      identitySignature: dist.identitySignature,
    },
  };
  for (const uid of memberIds) {
    if (uid === acc.userId) continue;
    await sendToUser(acc, uid, inner, "control", groupId);
  }
}

export async function sendToGroup(
  acc: Account,
  groupId: string,
  inner: InnerMessage,
  kind: OutboxItem["kind"] = "message",
): Promise<void> {
  const g = await api(`/v1/groups/${groupId}`, acc.access, {}, acc);
  const epoch = Number(g.group.epoch ?? 1);
  const members = await trustedGroupMembers(
    acc,
    groupId,
    (g.group.members ?? []) as { user_id: string }[],
    (g.group.membership ?? null) as {
      epoch: number;
      members: { user_id: string; role: string }[];
      signer_user_id: string;
      signer_device_id: string;
      signature: string;
    } | null,
  );
  const keyId = `${groupId}:${epoch}`;
  const existed = Boolean(acc.senderKeys?.[keyId]);
  if (!existed) {
    await distributeOwnSenderKey(acc, groupId, epoch, members);
  }
  const state = ensureOwnSenderKey(acc, groupId, epoch);
  const sealed = encryptGroupMessage(state, inner);
  const bytes = encodeSealed(sealed);
  await api(
    `/v1/groups/${groupId}/fanout`,
    acc.access,
    {
      method: "POST",
      body: JSON.stringify({
        kind,
        ciphertext: b64(bytes),
        padding_bucket: paddingBucket(bytes.length),
        ttl_seconds: inner.ttlSeconds,
      }),
    },
    acc,
  );
}

export async function syncToOwnDevices(
  acc: Account,
  inner: InnerMessage,
  kind: OutboxItem["kind"] = "message",
): Promise<void> {
  await sendToUser(acc, acc.userId, inner, kind);
}

export function computeSafety(acc: Account, theirX: Uint8Array) {
  return safetyNumber(acc.device.identity.x25519Public, theirX);
}

export function noteOwnRoster(
  acc: Account,
  devices: { deviceId: string; identityX25519: Uint8Array }[],
): "new" | "unchanged" | "changed" {
  const next = deviceRosterHash(devices);
  const prev = acc.ownRosterHash;
  if (!prev) {
    acc.ownRosterHash = next;
    return "new";
  }
  if (prev === next) return "unchanged";
  return "changed";
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
  return new Blob([new Uint8Array(pt)], { type: pointer.mime });
}

export async function replenishPrekeys(acc: Account): Promise<void> {
  const depth = await api("/v1/me/prekey-depth", acc.access, {}, acc);
  const start =
    acc.device.oneTimePrekeys.reduce((m, k) => Math.max(m, k.id), 0) + 1;
  const plan = planPrekeyReplenish(Number(depth.remaining ?? 0), start);
  if (!plan) return;
  const extra = generateOneTimePrekeys(plan.startId, plan.count);
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
  const next = generateSignedPrekey(acc.device.identity, acc.device.signedPrekey.id + 1);
  acc.device.previousSignedPrekeys = retainSignedPrekeys(
    acc.device.signedPrekey,
    acc.device.previousSignedPrekeys ?? [],
  );
  acc.device.signedPrekey = next;
}

/** Upload a new signed prekey only after the weekly planner fires. */
export async function maybeRotateSignedPrekey(acc: Account, now = Date.now()): Promise<boolean> {
  const plan = planSignedPrekeyRotation({
    currentId: acc.device.signedPrekey.id,
    createdAtMs: acc.signedPrekeyAt,
    now,
  });
  if (!plan) {
    if (acc.signedPrekeyAt == null) {
      acc.signedPrekeyAt = now;
      saveAccount(acc);
    }
    return false;
  }
  const next = generateSignedPrekey(acc.device.identity, plan.nextId);
  await api(
    "/v1/keys/signed-prekey",
    acc.access,
    {
      method: "PUT",
      body: JSON.stringify({
        id: next.id,
        public: b64(next.publicKey),
        signature: b64(next.signature),
      }),
    },
    acc,
  );
  acc.device.previousSignedPrekeys = retainSignedPrekeys(
    acc.device.signedPrekey,
    acc.device.previousSignedPrekeys ?? [],
  );
  acc.device.signedPrekey = next;
  acc.signedPrekeyAt = now;
  saveAccount(acc);
  return true;
}

export function backupPlaintext(acc: Account): Uint8Array {
  const stored: Stored = {
    userId: acc.userId,
    deviceId: acc.deviceId,
    username: acc.username,
    displayName: acc.displayName,
    about: acc.about,
    access: "",
    refresh: "",
    registrationId: acc.device.registrationId,
    identity: serializeIdentity(acc.device.identity),
    signedPrekey: serSpk(acc.device.signedPrekey),
    previousSignedPrekeys: (acc.device.previousSignedPrekeys ?? []).map(serSpk),
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
    outbox: [],
    senderKeys: Object.fromEntries(
      Object.entries(acc.senderKeys ?? {}).map(([k, v]) => [k, serializeSenderKey(v)]),
    ),
    remoteSenderKeys: Object.fromEntries(
      Object.entries(acc.remoteSenderKeys ?? {}).map(([k, v]) => [k, serializeRemoteSenderKey(v)]),
    ),
    heldSenderKeys: Object.fromEntries(
      Object.entries(acc.heldSenderKeys ?? {}).map(([k, v]) => [k, serializeRemoteSenderKey(v)]),
    ),
    replay: emptyReplayCache(),
    memberships: acc.memberships ?? {},
    pendingMemberships: acc.pendingMemberships ?? {},
    rejectedMemberships: acc.rejectedMemberships ?? {},
    droppedDevices: acc.droppedDevices ?? [],
  };
  return utf8(JSON.stringify(stored));
}

export function createBackupFile(acc: Account, passphrase: string): string {
  return encodeBackup(sealBackup(passphrase, backupPlaintext(acc)));
}

export function materialFromBackup(raw: string, passphrase: string): ReturnType<typeof createLocalDevice> & {
  identity: Account["device"]["identity"];
} {
  const stored = JSON.parse(fromUtf8(openBackup(passphrase, decodeBackup(raw)))) as Stored;
  return {
    registrationId: stored.registrationId,
    identity: deserializeIdentity(stored.identity),
    signedPrekey: deserSpk(stored.signedPrekey),
    previousSignedPrekeys: (stored.previousSignedPrekeys ?? []).map(deserSpk),
    oneTimePrekeys: stored.oneTimePrekeys.map((k) => ({
      id: k.id,
      privateKey: b64u(k.privateKey),
      publicKey: b64u(k.publicKey),
    })),
  };
}

export function mergeBackupHistory(acc: Account, raw: string, passphrase: string): void {
  const stored = JSON.parse(fromUtf8(openBackup(passphrase, decodeBackup(raw)))) as Stored;
  acc.messages = { ...stored.messages, ...acc.messages };
  acc.threads = stored.threads.length ? stored.threads : acc.threads;
  acc.contacts = stored.contacts.length ? stored.contacts : acc.contacts;
  acc.knownIdentities = { ...stored.knownIdentities, ...acc.knownIdentities };
  acc.pinned = { ...stored.pinned, ...acc.pinned };
  acc.memberships = { ...(stored.memberships ?? {}), ...acc.memberships };
  acc.pendingMemberships = { ...(stored.pendingMemberships ?? {}), ...(acc.pendingMemberships ?? {}) };
  const rejected: Record<string, string[]> = { ...(acc.rejectedMemberships ?? {}) };
  for (const [gid, hashes] of Object.entries(stored.rejectedMemberships ?? {})) {
    let cur = rejected[gid] ?? [];
    for (const h of hashes) cur = planRejectedHashes(cur, h);
    rejected[gid] = cur;
  }
  acc.rejectedMemberships = rejected;
  let dropped = [...(acc.droppedDevices ?? [])];
  for (const d of stored.droppedDevices ?? []) {
    const [uid, did] = d.split(":");
    if (uid && did) dropped = planDroppedDevices(dropped, uid, did);
  }
  acc.droppedDevices = dropped;
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

type StoredSpk = { id: number; privateKey: string; publicKey: string; signature: string };

function serSpk(k: { id: number; privateKey: Uint8Array; publicKey: Uint8Array; signature: Uint8Array }): StoredSpk {
  return {
    id: k.id,
    privateKey: b64(k.privateKey),
    publicKey: b64(k.publicKey),
    signature: b64(k.signature),
  };
}

function deserSpk(k: StoredSpk) {
  return {
    id: k.id,
    privateKey: b64u(k.privateKey),
    publicKey: b64u(k.publicKey),
    signature: b64u(k.signature),
  };
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
  signedPrekey: StoredSpk;
  previousSignedPrekeys?: StoredSpk[];
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
  senderKeys?: Record<string, string>;
  remoteSenderKeys?: Record<string, string>;
  heldSenderKeys?: Record<string, string>;
  ownRosterHash?: string;
  signedPrekeyAt?: number;
  replay?: ReplayCache;
  memberships?: Record<string, LocalGroupMembership>;
  pendingMemberships?: Record<string, LocalGroupMembership>;
  rejectedMemberships?: Record<string, string[]>;
  droppedDevices?: string[];
}
