import { createHmac } from "node:crypto";
import { config } from "../config.js";

export interface IceServer {
  urls: string | string[];
  username?: string;
  credential?: string;
}

/**
 * coturn REST (time-limited) credentials.
 * username = "<expiry>:<userId>", password = base64(HMAC-SHA1(secret, username)).
 * Static long-lived TURN passwords are never returned in production.
 */
export function iceServersFor(userId: string, ttlSeconds = 3600): IceServer[] {
  const stun: IceServer[] = config.stunUrls.map((urls) => ({ urls }));
  if (!config.turnUrls.length) return stun;

  if (config.turnSecret) {
    const expiry = Math.floor(Date.now() / 1000) + ttlSeconds;
    const username = `${expiry}:${userId}`;
    const credential = createHmac("sha1", config.turnSecret).update(username).digest("base64");
    return [
      ...stun,
      ...config.turnUrls.map((urls) => ({ urls, username, credential })),
    ];
  }

  if (!config.isProd && config.turnUsername && config.turnPassword) {
    return [
      ...stun,
      ...config.turnUrls.map((urls) => ({
        urls,
        username: config.turnUsername,
        credential: config.turnPassword,
      })),
    ];
  }

  return stun;
}
