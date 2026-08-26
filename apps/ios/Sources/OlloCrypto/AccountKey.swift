import CryptoKit
import Foundation

/// Long-term **account** identity. Real Ed25519 (CryptoKit), not a
/// LibSignalClient `IdentityKeyPair`. libsignal identity is XEdDSA and will
/// not verify on the server (`@noble/curves` Ed25519). Mixing the two is a
/// release blocker.
public struct AccountKey: Sendable {
    public let privateKey: Curve25519.Signing.PrivateKey
    public var publicKey: Data { privateKey.publicKey.rawRepresentation }

    public init() {
        self.privateKey = Curve25519.Signing.PrivateKey()
    }

    public init(privateKey: Curve25519.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    public init(rawPrivateKey: Data) throws {
        self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
    }

    public func sign(message: Data) throws -> Data {
        try privateKey.signature(for: message)
    }

    public func verify(message: Data, signature: Data) -> Bool {
        privateKey.publicKey.isValidSignature(signature, for: message)
    }

    public func publicB64() -> String {
        publicKey.base64EncodedString()
    }
}
