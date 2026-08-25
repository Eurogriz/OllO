import CryptoKit
import Foundation

/// AES-256-GCM wrap matching Android `AesGcmWrap`.
/// AAD `ollo-wrap-v1`. Layout: 12-byte nonce || ciphertext || 16-byte tag.
public enum AesGcmWrap {
    public static let aad = Data("ollo-wrap-v1".utf8)

    public static func seal(key: Data, plaintext: Data, nonce: Data? = nil) throws -> Data {
        guard key.count == 32 else { throw WrapError.badKey }
        let symmetric = SymmetricKey(data: key)
        let n: AES.GCM.Nonce
        if let nonce {
            n = try AES.GCM.Nonce(data: nonce)
        } else {
            n = AES.GCM.Nonce()
        }
        let box = try AES.GCM.seal(plaintext, using: symmetric, nonce: n, authenticating: aad)
        guard let combined = box.combined else { throw WrapError.sealFailed }
        return combined
    }

    public static func open(key: Data, blob: Data) throws -> Data {
        guard key.count == 32 else { throw WrapError.badKey }
        let symmetric = SymmetricKey(data: key)
        let box = try AES.GCM.SealedBox(combined: blob)
        return try AES.GCM.open(box, using: symmetric, authenticating: aad)
    }

    public enum WrapError: Error {
        case badKey
        case sealFailed
    }
}
