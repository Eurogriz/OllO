import type { WebSocket } from "ws";
import { log } from "../observability/logger.js";
import { getRedis, publishBus, PUSH_CHANNEL, subscribeBus } from "../redis.js";
import { randomToken } from "../security/crypto-utils.js";

/** Cross-process presence TTL. Local maps still drive this-process WS push. */
export const PRESENCE_TTL_SECONDS = 90;

/** Skip our own PUBLISH so local deliver is not doubled. */
export const HUB_INSTANCE = randomToken(8);

export interface SocketClient {
  deviceId: string;
  userId: string;
  ws: WebSocket;
  resume: string;
}

const byDevice = new Map<string, Set<SocketClient>>();
const byUser = new Map<string, Set<string>>();

export function attach(client: SocketClient): void {
  const set = byDevice.get(client.deviceId) ?? new Set();
  set.add(client);
  byDevice.set(client.deviceId, set);
  const devices = byUser.get(client.userId) ?? new Set();
  devices.add(client.deviceId);
  byUser.set(client.userId, devices);
  void touchPresence(client.userId, client.deviceId);
}

export async function touchPresence(userId: string, deviceId: string): Promise<void> {
  try {
    const r = await getRedis();
    await r.setEx(`presence:user:${userId}`, PRESENCE_TTL_SECONDS, deviceId);
    await r.setEx(`presence:device:${deviceId}`, PRESENCE_TTL_SECONDS, userId);
  } catch {
    /* local maps still apply */
  }
}

export async function presenceSeen(userId: string): Promise<boolean> {
  if (isOnline(userId)) return true;
  try {
    const r = await getRedis();
    return (await r.get(`presence:user:${userId}`)) != null;
  } catch {
    return false;
  }
}

export function detach(client: SocketClient): Promise<void> {
  const set = byDevice.get(client.deviceId);
  if (set) {
    set.delete(client);
    if (set.size === 0) byDevice.delete(client.deviceId);
  }
  if (!byDevice.has(client.deviceId)) {
    byUser.get(client.userId)?.delete(client.deviceId);
    return clearDevicePresence(client.userId, client.deviceId);
  }
  return Promise.resolve();
}

async function clearDevicePresence(userId: string, deviceId: string): Promise<void> {
  try {
    const r = await getRedis();
    await r.del(`presence:device:${deviceId}`);
    if (!isOnline(userId)) await r.del(`presence:user:${userId}`);
  } catch {
    /* TTL still expires the key */
  }
}

export function isOnline(userId: string): boolean {
  return (byUser.get(userId)?.size ?? 0) > 0;
}

/** Push skip must be per device: another online device must not mute this one. */
export function isDeviceOnline(deviceId: string): boolean {
  const set = byDevice.get(deviceId);
  if (!set) return false;
  for (const c of set) {
    if (c.ws.readyState === 1) return true;
  }
  return false;
}

/** True if this process holds a live socket or Redis has a presence:device key. */
export async function devicePresenceSeen(deviceId: string): Promise<boolean> {
  if (isDeviceOnline(deviceId)) return true;
  try {
    const r = await getRedis();
    return (await r.get(`presence:device:${deviceId}`)) != null;
  } catch {
    return false;
  }
}

export function pushToUser(userId: string, frame: unknown): number {
  const devices = byUser.get(userId);
  if (!devices) return 0;
  let n = 0;
  for (const deviceId of devices) n += pushToDevice(deviceId, frame);
  return n;
}

export function deliverLocal(deviceId: string, frame: unknown): number {
  const set = byDevice.get(deviceId);
  if (!set) return 0;
  const data = JSON.stringify(frame);
  let n = 0;
  for (const c of set) {
    try {
      if (c.ws.readyState === 1) {
        c.ws.send(data);
        n += 1;
      }
    } catch {
      log.warn("ws send failed", { deviceId });
    }
  }
  return n;
}

export function pushToDevice(deviceId: string, frame: unknown): number {
  const n = deliverLocal(deviceId, frame);
  void publishPush(deviceId, frame);
  return n;
}

async function publishPush(deviceId: string, frame: unknown): Promise<void> {
  try {
    await publishBus(PUSH_CHANNEL, JSON.stringify({ origin: HUB_INSTANCE, deviceId, frame }));
  } catch {
    /* local deliver already ran */
  }
}

function onPushBus(raw: string): void {
  try {
    const msg = JSON.parse(raw) as { origin?: unknown; deviceId?: unknown; frame?: unknown };
    if (msg.origin === HUB_INSTANCE) return;
    if (typeof msg.deviceId === "string") deliverLocal(msg.deviceId, msg.frame);
  } catch {
    /* drop malformed bus frames */
  }
}

export async function startHubFanout(): Promise<() => void> {
  return subscribeBus(PUSH_CHANNEL, onPushBus);
}

export function connectionCount(): number {
  let n = 0;
  for (const s of byDevice.values()) n += s.size;
  return n;
}

/** Close every socket for a revoked device so a stolen JWT cannot stay online. */
export function dropDevice(deviceId: string): number {
  const set = byDevice.get(deviceId);
  if (!set) return 0;
  const copy = [...set];
  for (const c of copy) {
    try {
      if (c.ws.readyState === 1) c.ws.close();
    } catch {
      /* already gone */
    }
    detach(c);
  }
  return copy.length;
}

export function dropUser(userId: string): number {
  const devices = [...(byUser.get(userId) ?? [])];
  let n = 0;
  for (const id of devices) n += dropDevice(id);
  return n;
}

export function resetHub(): void {
  byDevice.clear();
  byUser.clear();
}
