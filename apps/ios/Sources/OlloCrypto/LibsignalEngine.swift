import CryptoKit
import Foundation
import LibSignalClient

/// Official LibSignalClient 0.58 for **device** sessions.
///
/// Account proofs stay on `AccountKey` (CryptoKit Ed25519). libsignal
/// identity is XEdDSA and must not sign `ollo-auth-v1` or the published
/// `signed_prekey.signature` that the server verifies with noble Ed25519.
///
/// Real 0.58 APIs: `PrivateKey.generate`, `identity.privateKey.generateSignature`,
/// `PreKeyRecord(id:privateKey:)`, `SignedPreKeyRecord(id:timestamp:privateKey:signature:)`,
/// `signalEncrypt` / `signalDecrypt` / `signalDecryptPreKey` + `NullContext()`.
/// There is no `SessionCipher`, `SignedPreKeyRecord.generate`, or
/// `PreKeyRecord.generate`.
///
/// Identity, prekeys, and session records are written into `ProtocolStore`
/// when one is bound so a process restart does not remint or drop ratchets.
///
/// This is not a Signal-level security claim.
public final class LibsignalEngine: CryptoEngine, @unchecked Sendable {
    public static let djbType: UInt8 = 0x05

    private let identity: IdentityKeyPair
    private let registrationId: UInt32
    private let deviceEd25519: Curve25519.Signing.PrivateKey
    private let store: InMemorySignalProtocolStore
    private let proto: ProtocolStore?
    private var sessions: [String: ProtocolAddress] = [:]
    private var published: PublishedKeys?
    private let lock = NSLock()
    private let ctx = NullContext()

    public convenience init() throws {
        try self.init(store: nil)
    }

    public init(store proto: ProtocolStore?) throws {
        if let proto,
           let record = try proto.loadLocalIdentity(),
           let reg = try proto.registrationId(),
           let seed = try proto.loadIdentityField("device_ed25519_seed")
        {
            self.identity = try IdentityKeyPair(bytes: record)
            self.registrationId = UInt32(reg)
            self.deviceEd25519 = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            self.store = InMemorySignalProtocolStore(identity: self.identity, registrationId: self.registrationId)
            self.proto = proto
            try Self.restoreSessions(into: self.store, proto: proto, context: NullContext())
            return
        }
        let identity = IdentityKeyPair.generate()
        let registrationId = UInt32.random(in: 1...16_383)
        let device = Curve25519.Signing.PrivateKey()
        self.identity = identity
        self.registrationId = registrationId
        self.deviceEd25519 = device
        self.store = InMemorySignalProtocolStore(identity: identity, registrationId: registrationId)
        self.proto = proto
        try proto?.storeLocalIdentity(
            record: identity.serialize(),
            registrationId: Int(registrationId),
            extras: [
                "device_ed25519_seed": device.rawRepresentation,
                "device_ed25519_public": device.publicKey.rawRepresentation,
            ]
        )
    }

    public func generateIdentity() throws -> IdentityMaterial {
        try mintIfNeeded().material
    }

    public func deviceRegistrationJson(name: String, platform: String) throws -> String {
        let pub = try mintIfNeeded()
        var opks: [[String: Any]] = []
        for (id, publicKey) in pub.oneTime {
            opks.append([
                "id": id,
                "public": publicKey.base64EncodedString(),
            ])
        }
        let body: [String: Any] = [
            "name": name,
            "platform": platform,
            "registration_id": registrationId,
            "identity_key_x25519": try Self.stripDjb(identity.identityKey.serialize()).base64EncodedString(),
            "identity_key_ed25519": deviceEd25519.publicKey.rawRepresentation.base64EncodedString(),
            "signed_prekey": [
                "id": pub.signedId,
                "public": pub.spkPub.base64EncodedString(),
                "signature": pub.edSig.base64EncodedString(),
                "xeddsa": pub.xeddsa.base64EncodedString(),
            ],
            "one_time_prekeys": opks,
        ]
        let data = try JSONSerialization.data(withJSONObject: body)
        guard let json = String(data: data, encoding: .utf8) else { throw CryptoEngineError.unbound }
        return json
    }

    public func existingSession(userId: String, deviceId: String) -> String? {
        guard let address = try? ProtocolAddress(name: "\(userId):\(deviceId)", deviceId: 1),
              let rec = try? store.loadSession(for: address, context: ctx),
              rec != nil
        else { return nil }
        return remember(address)
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
        let address = try ProtocolAddress(name: "\(userId):\(deviceId)", deviceId: 1)
        if try store.loadSession(for: address, context: ctx) != nil {
            return remember(address)
        }
        let xeddsaB64 = (spk["xeddsa"] as? String) ?? (json["xeddsa"] as? String)
        guard let xeddsaB64, let xeddsa = Data(base64Encoded: xeddsaB64) else {
            throw CryptoEngineError.unbound
        }
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
        try processPreKeyBundle(
            bundle,
            for: address,
            sessionStore: store,
            identityStore: store,
            context: ctx
        )
        try persistSession(address)
        _ = try proto?.sessions.noteRemoteIdentity(
            SessionDirectory.Address(userId: userId, deviceId: deviceId),
            identityX25519: try Self.stripDjb(identityKey.serialize())
        )
        return remember(address)
    }

    public func encrypt(sessionId: String, plaintext: Data) throws -> Data {
        lock.lock()
        let address = sessions[sessionId]
        lock.unlock()
        guard let address else { throw CryptoEngineError.unbound }
        let cipher = try signalEncrypt(
            message: plaintext,
            for: address,
            sessionStore: store,
            identityStore: store,
            context: ctx
        )
        try persistSession(address)
        return cipher.serialize()
    }

    public func decrypt(sessionId: String, payload: Data) throws -> Data {
        lock.lock()
        let address = sessions[sessionId]
        lock.unlock()
        guard let address else { throw CryptoEngineError.unbound }
        let out: Data
        if let pre = try? PreKeySignalMessage(bytes: payload) {
            out = try signalDecryptPreKey(
                message: pre,
                from: address,
                sessionStore: store,
                identityStore: store,
                preKeyStore: store,
                signedPreKeyStore: store,
                kyberPreKeyStore: store,
                context: ctx
            )
        } else {
            out = try signalDecrypt(
                message: try SignalMessage(bytes: payload),
                from: address,
                sessionStore: store,
                identityStore: store,
                context: ctx
            )
        }
        try persistSession(address)
        return out
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
        return Data(serialized.dropFirst())
    }

    public static func prefixDjb(_ raw32: Data) -> Data {
        var out = Data([djbType])
        out.append(raw32)
        return out
    }

    private func mintIfNeeded() throws -> PublishedKeys {
        lock.lock()
        defer { lock.unlock() }
        if let published { return published }
        if let restored = try restorePublished() {
            published = restored
            return restored
        }
        let spkPriv = PrivateKey.generate()
        let xeddsa = identity.privateKey.generateSignature(message: spkPriv.publicKey.serialize())
        let signed = try SignedPreKeyRecord(
            id: 1,
            timestamp: UInt64(Date().timeIntervalSince1970 * 1000),
            privateKey: spkPriv,
            signature: xeddsa
        )
        try store.storeSignedPreKey(signed, id: signed.id, context: ctx)
        var oneTime: [(UInt32, Data)] = []
        for i in 1...100 {
            let rec = try PreKeyRecord(id: UInt32(i), privateKey: PrivateKey.generate())
            try store.storePreKey(rec, id: rec.id, context: ctx)
            try proto?.storePreKey(id: Int(rec.id), record: rec.serialize())
            oneTime.append((rec.id, try Self.stripDjb(try rec.publicKey().serialize())))
        }
        let spkPub = try Self.stripDjb(try signed.publicKey().serialize())
        let edSig = try deviceEd25519.signature(for: spkPub)
        try proto?.storeSignedPreKey(id: Int(signed.id), record: signed.serialize())
        try proto?.pruneSignedPreKeys(currentId: Int(signed.id))
        try proto?.storeLocalIdentity(
            record: identity.serialize(),
            registrationId: Int(registrationId),
            extras: [
                "device_ed25519_seed": deviceEd25519.rawRepresentation,
                "device_ed25519_public": deviceEd25519.publicKey.rawRepresentation,
                "spk_ed25519_sig": edSig,
            ]
        )
        let next = PublishedKeys(
            signedId: signed.id,
            spkPub: spkPub,
            edSig: edSig,
            xeddsa: signed.signature,
            oneTime: oneTime,
            material: IdentityMaterial(
                identityX25519: try Self.stripDjb(identity.identityKey.serialize()),
                identityEd25519: deviceEd25519.publicKey.rawRepresentation,
                signedPrekey: spkPub,
                signature: edSig,
                oneTimePrekeys: oneTime.map(\.1)
            )
        )
        published = next
        return next
    }

    private func restorePublished() throws -> PublishedKeys? {
        guard let proto else { return nil }
        let ids = try proto.signedPreKeyIds()
        guard let currentId = ids.max(), let raw = try proto.loadSignedPreKey(id: currentId) else {
            return nil
        }
        let signed = try SignedPreKeyRecord(bytes: raw)
        try store.storeSignedPreKey(signed, id: signed.id, context: ctx)
        var oneTime: [(UInt32, Data)] = []
        for id in try proto.preKeyIds() {
            guard let recRaw = try proto.loadPreKey(id: id) else { continue }
            let rec = try PreKeyRecord(bytes: recRaw)
            try store.storePreKey(rec, id: rec.id, context: ctx)
            oneTime.append((rec.id, try Self.stripDjb(try rec.publicKey().serialize())))
        }
        let spkPub = try Self.stripDjb(try signed.publicKey().serialize())
        guard let edSig = try proto.loadIdentityField("spk_ed25519_sig") else { return nil }
        return PublishedKeys(
            signedId: signed.id,
            spkPub: spkPub,
            edSig: edSig,
            xeddsa: signed.signature,
            oneTime: oneTime,
            material: IdentityMaterial(
                identityX25519: try Self.stripDjb(identity.identityKey.serialize()),
                identityEd25519: deviceEd25519.publicKey.rawRepresentation,
                signedPrekey: spkPub,
                signature: edSig,
                oneTimePrekeys: oneTime.map(\.1)
            )
        )
    }

    private func persistSession(_ address: ProtocolAddress) throws {
        guard let proto, let rec = try store.loadSession(for: address, context: ctx) else { return }
        let parts = address.name.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2 else { return }
        try proto.sessions.saveSession(
            SessionDirectory.Address(userId: String(parts[0]), deviceId: String(parts[1])),
            record: rec.serialize()
        )
    }

    private func remember(_ address: ProtocolAddress) -> String {
        let handle = UUID().uuidString
        lock.lock()
        sessions[handle] = address
        lock.unlock()
        return handle
    }

    private static func restoreSessions(
        into store: InMemorySignalProtocolStore,
        proto: ProtocolStore,
        context: StoreContext
    ) throws {
        for key in try proto.sessions.sessionKeys() {
            let parts = key.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2,
                  let raw = try proto.sessions.loadSession(
                    SessionDirectory.Address(userId: String(parts[0]), deviceId: String(parts[1]))
                  )
            else { continue }
            let address = try ProtocolAddress(name: key, deviceId: 1)
            try store.storeSession(try SessionRecord(bytes: raw), for: address, context: context)
        }
    }

    private static func b64(_ s: String) -> Data {
        Data(base64Encoded: s) ?? Data()
    }

    private struct PublishedKeys {
        var signedId: UInt32
        var spkPub: Data
        var edSig: Data
        var xeddsa: Data
        var oneTime: [(UInt32, Data)]
        var material: IdentityMaterial
    }
}
