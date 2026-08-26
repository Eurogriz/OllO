import Foundation
import OlloCrypto
import OlloStorage

/// Process-lifetime session host. Protocol blobs live under Application Support
/// and are wrapped by a Keychain key (`ollo.vault.wrap.v1`). Tokens restore
/// from `SessionController`. Registration still requires a bound libsignal
/// engine — this host never invents `registration_id` or prekey ids.
final class SessionHost {
    let proto: ProtocolStore
    let sessions: SessionController
    let engine: CryptoEngine

    init(proto: ProtocolStore, sessions: SessionController, engine: CryptoEngine) {
        self.proto = proto
        self.sessions = sessions
        self.engine = engine
    }

    func launch() throws -> EnvelopePlanner.SessionLaunch {
        try sessions.launch()
    }

    func loadInbox() throws -> ThreadIndex {
        try proto.loadThreads()
    }

    func wipe() {
        sessions.wipe()
    }

    /// Fail closed before burning an OTP. A bound engine emits the official
    /// device JSON; `UnboundCryptoEngine` throws.
    func requireRegistration(name: String, platform: String) throws -> String {
        try engine.deviceRegistrationJson(name: name, platform: platform)
    }

    static func open(
        store: IdentityStore,
        wrapKey: Data,
        engine: CryptoEngine = UnboundCryptoEngine()
    ) throws -> SessionHost {
        guard wrapKey.count == 32 else { throw SessionHostError.wrapUnavailable }
        let proto = ProtocolStore(store: store, wrapKey: wrapKey)
        return SessionHost(proto: proto, sessions: SessionController(proto: proto), engine: engine)
    }

    static func open(engine: CryptoEngine = UnboundCryptoEngine()) throws -> SessionHost {
        let root = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("ollo-proto", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let wrap = try IdentityVault(directory: root).wrappingKey()
        return try open(store: IdentityStore(directory: root), wrapKey: wrap, engine: engine)
    }
}

enum SessionHostError: Error {
    case wrapUnavailable
}
