import CryptoKit
import Foundation
import LibSignalClient

/// Official LibSignalClient for **device** sessions.
///
/// Account proofs stay on `AccountKey` (CryptoKit Ed25519). libsignal
/// identity is XEdDSA and must not sign `ollo-auth-v1` or the published
/// `signed_prekey.signature` that the server verifies with noble Ed25519.
///
/// Published `identity_key_x25519` is the libsignal identity with the 0x05
/// prefix stripped (OllO directory is 32 bytes). SessionBuilder needs the
/// XEdDSA signature of the signed prekey; that lives in `signed_prekey.xeddsa`
/// and is ignored by the server.
///
/// This is not a Signal-level security claim.
public final class LibsignalEngine: CryptoEngine, @unchecked Sendable {
    public static let djbType: UInt8 = 0x05

    private let identity: IdentityKeyPair
    private let registrationId: UInt32
    private let deviceEd25519: Curve25519.Signing.PrivateKey
    private let store: InMemorySignalProtocolStore
    private var sessions: [String: ProtocolAddress] = [:]
    private let lock = NSLock()

    public init() throws {
        let identity = IdentityKeyPair.generate()
        let registrationId = UInt32.random(in: 1...16_383)
        self.identity = identity
        self.registrationId = registrationId
        self.deviceEd25519 = Curve25519.Signing.PrivateKey()
        self.store = try InMemorySignalProtocolStore(identity: identity, registrationId: registrationId)
    }

    public func generateIdentity() throws -> IdentityMaterial {
        let signed = try SignedPreKeyRecord.generate(id: 1, signedBy: identity)
        try store.storeSignedPreKey(signed.id, record: signed)
        var oneTime: [PreKeyRecord] = []
        for i in 1...100 {
            let rec = try PreKeyRecord.generate(id: UInt32(i))
            try store.storePreKey(rec.id, record: rec)
            oneTime.append(rec)
        }
        let spkPub = try Self.stripDjb(signed.publicKey.serialize())
        let edSig = try deviceEd25519.signature(for: spkPub)
        return IdentityMaterial(
            identityX25519: try Self.stripDjb(identity.identityKey.serialize()),
            identityEd25519: deviceEd25519.publicKey.rawRepresentation,
            signedPrekey: spkPub,
            signature: edSig,
            oneTimePrekeys: try oneTime.map { try Self.stripDjb($0.publicKey.serialize()) }
        )
    }

    public func deviceRegistrationJson(name: String, platform: String) throws -> String {
        let signed = try SignedPreKeyRecord.generate(id: 1, signedBy: identity)
        try store.storeSignedPreKey(signed.id, record: signed)
        var opks: [[String: Any]] = []
        for i in 1...100 {
            let rec = try PreKeyRecord.generate(id: UInt32(i))
            try store.storePreKey(rec.id, record: rec)
            opks.append([
                "id": rec.id,
                "public": try Self.stripDjb(rec.publicKey.serialize()).base64EncodedString(),
            ])
        }
        let spkPub = try Self.stripDjb(signed.publicKey.serialize())
        let edSig = try deviceEd25519.signature(for: spkPub)
        let body: [String: Any] = [
            "name": name,
            "platform": platform,
            "registration_id": registrationId,
            "identity_key_x25519": try Self.stripDjb(identity.identityKey.serialize()).base64EncodedString(),
            "identity_key_ed25519": deviceEd25519.publicKey.rawRepresentation.base64EncodedString(),
            "signed_prekey": [
                "id": signed.id,
                "public": spkPub.base64EncodedString(),
                "signature": edSig.base64EncodedString(),
                "xeddsa": signed.signature.base64EncodedString(),
            ],
            "one_time_prekeys": opks,
        ]
        let data = try JSONSerialization.data(withJSONObject: body)
        guard let json = String(data: data, encoding: .utf8) else { throw CryptoEngineError.unbound }
        return json
    }

    public func processPrekeyBundle(_ remote: Data) throws -> String {
        guard let json = try JSONSerialization.jsonObject(with: remote) as? [String: Any] else {
            throw CryptoEngineError.unbound
        }
        guard let userId = json["user_id"] as? String,
              let deviceId = json["device_id"] as? String,
              let registration = json["registration_id"] as? Int,
              let identityB64 = json["identity_key_x25519"] as? String,
              let spk = json["signed_prekey"] as? [String: Any],
              let spkId = spk["id"] as? Int,
              let spkPubB64 = spk["public"] as? String
        else {
            throw CryptoEngineError.unbound
        }
        let xeddsaB64 = (spk["xeddsa"] as? String) ?? (json["xeddsa"] as? String)
        guard let xeddsaB64, let xeddsa = Data(base64Encoded: xeddsaB64) else {
            throw CryptoEngineError.unbound
        }
        let address = try ProtocolAddress(name: "\(userId):\(deviceId)", deviceId: 1)
        let identityKey = try IdentityKey(bytes: Self.prefixDjb(Self.b64(identityB64)))
        let preKey: (UInt32, PublicKey)? = {
            guard let opk = json["one_time_prekey"] as? [String: Any],
                  let id = opk["id"] as? Int,
                  let pub = opk["public"] as? String
            else { return nil }
            return (UInt32(id), try? PublicKey(Self.prefixDjb(Self.b64(pub))))
        }()
        let bundle = try PreKeyBundle(
            registrationId: UInt32(registration),
            deviceId: 1,
            prekeyId: preKey?.0,
            prekey: preKey?.1,
            signedPrekeyId: UInt32(spkId),
            signedPrekey: PublicKey(Self.prefixDjb(Self.b64(spkPubB64))),
            signedPrekeySignature: xeddsa,
            identity: identityKey
        )
        try processPreKeyBundle(bundle, for: address, sessionStore: store, identityStore: store)
        let handle = UUID().uuidString
        lock.lock()
        sessions[handle] = address
        lock.unlock()
        return handle
    }

    public func encrypt(sessionId: String, plaintext: Data) throws -> Data {
        lock.lock()
        let address = sessions[sessionId]
        lock.unlock()
        guard let address else { throw CryptoEngineError.unbound }
        let cipher = try SessionCipher(store, remoteAddress: address)
        return try cipher.encrypt(plaintext).serialize()
    }

    public func decrypt(sessionId: String, payload: Data) throws -> Data {
        lock.lock()
        let address = sessions[sessionId]
        lock.unlock()
        guard let address else { throw CryptoEngineError.unbound }
        let cipher = try SessionCipher(store, remoteAddress: address)
        if let pre = try? PreKeySignalMessage(bytes: payload) {
            return try cipher.decrypt(message: pre)
        }
        return try cipher.decrypt(message: try SignalMessage(bytes: payload))
    }

    public func safetyNumber(local: Data, remote: Data) -> String {
        SafetyNumber.of(identityA: local, identityB: remote).digits
    }

    /// Device Ed25519 (CryptoKit). Account proofs must use `AccountKey.sign`.
    public func sign(message: Data) throws -> Data {
        try deviceEd25519.signature(for: message)
    }

    public static func stripDjb(_ serialized: Data) throws -> Data {
        guard serialized.count == 33, serialized.first == djbType else {
            throw CryptoEngineError.unbound
        }
        return serialized.dropFirst()
    }

    public static func prefixDjb(_ raw32: Data) -> Data {
        var out = Data([djbType])
        out.append(raw32)
        return out
    }

    private static func b64(_ s: String) -> Data {
        Data(base64Encoded: s) ?? Data()
    }
}
