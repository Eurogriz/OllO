/**
 * OllO wire protocol — versioned types shared by clients and the server.
 *
 * The server is only allowed to parse ServerEnvelope / public identity
 * material. Inner payloads are opaque ciphertext after the client AEAD.
 */

export const PROTOCOL_VERSION = 1 as const;
export const PRODUCT = "ollo" as const;

export type Platform = "android" | "ios" | "web" | "desktop";

export type EnvelopeKind =
  | "message"
  | "receipt"
  | "typing"
  | "call"
  | "control";

export type InnerMessageType =
  | "text"
  | "attachment"
  | "attachments"
  | "voice"
  | "sticker"
  | "gif"
  | "reaction"
  | "reply"
  | "forward"
  | "edit"
  | "delete"
  | "pin"
  | "receipt_delivery"
  | "receipt_read"
  | "typing"
  | "call_signal"
  | "sender_key_distribute"
  | "group_state"
  | "disappearing_timer"
  | "profile_key"
  | "sync";

export interface PublicIdentity {
  userId: string;
  deviceId: string;
  identityKeyX25519: Uint8Array;
  identityKeyEd25519: Uint8Array;
}

export interface SignedPrekey {
  id: number;
  publicKey: Uint8Array;
  signature: Uint8Array;
}

export interface OneTimePrekey {
  id: number;
  publicKey: Uint8Array;
}

export interface PrekeyBundle {
  userId: string;
  deviceId: string;
  registrationId: number;
  identityKeyX25519: Uint8Array;
  identityKeyEd25519: Uint8Array;
  signedPrekey: SignedPrekey;
  oneTimePrekey?: OneTimePrekey;
}

/** Header that travels next to ciphertext. Not content, but not secret either. */
export interface RatchetHeader {
  dhPublic: Uint8Array;
  previousChainLength: number;
  messageNumber: number;
}

export interface PrekeyWhisperMeta {
  registrationId: number;
  signedPrekeyId: number;
  oneTimePrekeyId?: number;
  ephemeralPublic: Uint8Array;
  identityKeyX25519: Uint8Array;
}

/**
 * Client-sealed blob the server stores and forwards.
 * `body` = serialize(header, optional prekey meta, aead nonce, aead ct).
 */
export interface SealedPayload {
  version: typeof PROTOCOL_VERSION;
  alg: "x3dh-dr-xchacha20poly1305-v1" | "senderkey-xchacha20poly1305-v1";
  header: RatchetHeader;
  prekey?: PrekeyWhisperMeta;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

/** What the server is allowed to see. */
export interface ServerEnvelope {
  id: string;
  senderUserId: string;
  senderDeviceId: string;
  recipientUserId: string;
  recipientDeviceId: string;
  groupId?: string;
  kind: EnvelopeKind;
  payload: Uint8Array;
  paddingBucket: number;
  createdAt: string;
  expiresAt?: string;
}

export interface InnerMessage {
  version: typeof PROTOCOL_VERSION;
  type: InnerMessageType;
  clientId: string;
  sentAt: string;
  expiresAt?: string;
  ttlSeconds?: number;
  threadId: string;
  replyToClientId?: string;
  mentions?: string[];
  editOf?: string;
  deleteFor?: "me" | "everyone";
  forwardedFrom?: { userId: string; sentAt: string };
  reaction?: { targetClientId: string; emoji: string; remove?: boolean };
  text?: string;
  attachments?: AttachmentPointer[];
  voice?: AttachmentPointer & { durationMs: number; waveform?: number[] };
  sticker?: { packId: string; stickerId: string };
  gif?: { urlCipher?: never; attachment: AttachmentPointer };
  call?: CallSignal;
  senderKey?: SenderKeyDistribution;
  groupState?: GroupStateUpdate;
  disappearingTimerSeconds?: number;
  receipt?: { targetClientId: string; at: string };
}

export interface AttachmentPointer {
  objectId: string;
  key: Uint8Array;
  nonce: Uint8Array;
  digest: Uint8Array;
  size: number;
  mime: string;
  filename: string;
  width?: number;
  height?: number;
  durationMs?: number;
  thumbnail?: {
    key: Uint8Array;
    nonce: Uint8Array;
    digest: Uint8Array;
    objectId: string;
    size: number;
  };
  grant?: string;
}

export interface SenderKeyDistribution {
  groupId: string;
  epoch: number;
  chainId: string;
  chainKey: Uint8Array;
  iteration: number;
  signingKey: Uint8Array;
}

export interface GroupStateUpdate {
  groupId: string;
  epoch: number;
  name?: string;
  about?: string;
  avatarObjectId?: string;
  disappearingSeconds?: number;
  signedByDeviceId: string;
  signature: Uint8Array;
}

export type CallSignalType =
  | "offer"
  | "answer"
  | "ice"
  | "hangup"
  | "reject"
  | "busy"
  | "renegotiate";

export interface CallSignal {
  callId: string;
  media: "audio" | "video";
  signalType: CallSignalType;
  sdp?: string;
  ice?: { candidate: string; sdpMid?: string; sdpMLineIndex?: number };
  sframeKey?: Uint8Array;
}

export const PADDING_BUCKETS = [256, 512, 1024, 4096, 16384, 65536] as const;

export function paddingBucket(size: number): number {
  for (const b of PADDING_BUCKETS) {
    if (size <= b) return b;
  }
  return Math.ceil(size / 65536) * 65536;
}

export type ApiErrorCode =
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "validation"
  | "otp_invalid"
  | "otp_expired"
  | "registration_lock"
  | "device_revoked"
  | "prekeys_exhausted"
  | "payload_too_large"
  | "unsupported_version"
  | "internal";

export interface ApiErrorBody {
  error: {
    code: ApiErrorCode;
    message: string;
    request_id: string;
  };
}

export * from "./codec.js";
export * from "./ids.js";
