import Foundation
import OlloCrypto
import OlloNetwork
import OlloStorage

/// Process-lifetime session host. Protocol blobs live under Application Support
/// and are wrapped by a Keychain key (`ollo.vault.wrap.v1`). Tokens restore
/// from `SessionController`. Registration still requires a bound libsignal
/// engine — this host never invents `registration_id` or prekey ids.
final class SessionHost {
    let proto: ProtocolStore
    let sessions: SessionController
    let engine: CryptoEngine
    let auth: AuthRepository

    init(
        proto: ProtocolStore,
        sessions: SessionController,
        engine: CryptoEngine,
        auth: AuthRepository
    ) {
        self.proto = proto
        self.sessions = sessions
        self.engine = engine
        self.auth = auth
    }

    func launch() throws -> EnvelopePlanner.SessionLaunch {
        try sessions.launch()
    }

    func loadInbox() throws -> ThreadIndex {
        try proto.loadThreads()
    }

    func wipe() {
        auth.logout()
    }

    /// Fail closed before burning an OTP. A bound engine emits the official
    /// device JSON; `UnboundCryptoEngine` throws.
    func requireRegistration(name: String, platform: String) throws -> String {
        try engine.deviceRegistrationJson(name: name, platform: platform)
    }

    func signIn() async throws {
        if try launch() == .signedIn { return }
        _ = try await auth.signInWithKey(engine: engine, account: AccountKey(), name: "iPhone", platform: "ios")
    }

    static func open(
        store: IdentityStore,
        wrapKey: Data,
        engine: CryptoEngine = UnboundCryptoEngine(),
        baseURL: URL = OlloAPI.baseURL,
        urlSession: URLSession = .shared
    ) throws -> SessionHost {
        guard wrapKey.count == 32 else { throw SessionHostError.wrapUnavailable }
        let proto = ProtocolStore(store: store, wrapKey: wrapKey)
        let sessions = SessionController(proto: proto)
        return SessionHost(
            proto: proto,
            sessions: sessions,
            engine: engine,
            auth: AuthRepository.connected(baseURL: baseURL, sessions: sessions, urlSession: urlSession)
        )
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
