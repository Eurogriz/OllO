import Foundation

/// Account address is the long-term identity Ed25519 public key, not a phone.
/// Private key never appears in this encoding.
public enum IdentityAddress {
    public static let prefix = "ollo:user:v1:"
    public static let authProofDomain = "ollo-auth-v1"

    public static func encode(_ ed25519Public: Data) -> String {
        guard ed25519Public.count == 32, ed25519Public.contains(where: { $0 != 0 }) else { return "" }
        return prefix + b64url(ed25519Public)
    }

    public static func parse(_ raw: String) -> Data? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return nil }
        let payload = s.hasPrefix(prefix) ? String(s.dropFirst(prefix.count)) : s
        guard let bytes = b64urlDecode(payload), bytes.count == 32, bytes.contains(where: { $0 != 0 }) else {
            return nil
        }
        return bytes
    }

    /// Canonical bytes signed to prove possession of the identity Ed25519 key.
    public static func authProof(challengeId: String, nonce: String) -> Data {
        if challengeId.isEmpty || nonce.isEmpty { return Data() }
        var out = Data(authProofDomain.utf8)
        out.append(0)
        out.append(Data(challengeId.utf8))
        out.append(0)
        out.append(Data(nonce.utf8))
        return out
    }

    private static func b64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    private static func b64urlDecode(_ raw: String) -> Data? {
        var t = raw.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let pad = (4 - t.count % 4) % 4
        if pad > 0 { t += String(repeating: "=", count: pad) }
        return Data(base64Encoded: t)
    }
}
