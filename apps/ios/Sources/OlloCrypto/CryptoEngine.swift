import Foundation

/// Production builds must back this protocol with official libsignal.
/// Do not implement a homegrown Double Ratchet here.
public protocol CryptoEngine: Sendable {
    func generateIdentity() throws -> IdentityMaterial
    func processPrekeyBundle(_ remote: Data) throws -> String
    func encrypt(sessionId: String, plaintext: Data) throws -> Data
    func decrypt(sessionId: String, payload: Data) throws -> Data
    func safetyNumber(local: Data, remote: Data) -> String
}

public struct IdentityMaterial: Sendable {
    public var identityX25519: Data
    public var identityEd25519: Data
    public var signedPrekey: Data
    public var signature: Data
    public var oneTimePrekeys: [Data]

    public init(
        identityX25519: Data,
        identityEd25519: Data,
        signedPrekey: Data,
        signature: Data,
        oneTimePrekeys: [Data]
    ) {
        self.identityX25519 = identityX25519
        self.identityEd25519 = identityEd25519
        self.signedPrekey = signedPrekey
        self.signature = signature
        self.oneTimePrekeys = oneTimePrekeys
    }
}

/// Fails closed until a libsignal-backed engine is bound. Shipping this
/// type as the production engine is a release blocker.
public struct UnboundCryptoEngine: CryptoEngine {
    public init() {}

    public func generateIdentity() throws -> IdentityMaterial {
        throw EngineError.unbound
    }

    public func processPrekeyBundle(_ remote: Data) throws -> String {
        throw EngineError.unbound
    }

    public func encrypt(sessionId: String, plaintext: Data) throws -> Data {
        throw EngineError.unbound
    }

    public func decrypt(sessionId: String, payload: Data) throws -> Data {
        throw EngineError.unbound
    }

    public func safetyNumber(local: Data, remote: Data) -> String {
        SafetyNumber.of(identityA: local, identityB: remote).digits
    }

    public enum EngineError: Error {
        case unbound
    }
}
