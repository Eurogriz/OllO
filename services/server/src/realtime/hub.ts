import type { WebSocket } from "ws";
import { log } from "../observability/logger.js";

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
}

export function detach(client: SocketClient): void {
  const set = byDevice.get(client.deviceId);
  if (set) {
    set.delete(client);
    if (set.size === 0) byDevice.delete(client.deviceId);
  }
  if (!byDevice.has(client.deviceId)) {
    byUser.get(client.userId)?.delete(client.deviceId);
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

export function pushToUser(userId: string, frame: unknown): number {
  const devices = byUser.get(userId);
  if (!devices) return 0;
  let n = 0;
  for (const deviceId of devices) n += pushToDevice(deviceId, frame);
  return n;
}

export function pushToDevice(deviceId: string, frame: unknown): number {
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
    } catch (err) {
      log.warn("ws send failed", { deviceId });
    }
  }
  return n;
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
