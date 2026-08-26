import {
  ED25519_PUBLIC_LEN,
  ED25519_SIGNATURE_LEN,
  X25519_PUBLIC_LEN,
  planPublicKeyAccept,
} from "@ollo/shared";
import { ApiError } from "../http.js";

export { ED25519_PUBLIC_LEN, ED25519_SIGNATURE_LEN, X25519_PUBLIC_LEN };

export function requirePublicBytes(b64: string, expected: number, label: string): Buffer {
  const buf = Buffer.from(b64, "base64");
  if (planPublicKeyAccept(new Uint8Array(buf), expected) !== "accept") {
    throw new ApiError("validation", `${label} is not valid public key material`);
  }
  return buf;
}
