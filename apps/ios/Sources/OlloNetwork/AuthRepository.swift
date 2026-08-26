import Foundation
import OlloCrypto

/// Twin of Android `AuthRepository`. Tokens live in `SessionController`.
/// `deviceJson` is produced only by a bound engine.
public final class AuthRepository: @unchecked Sendable {
    public let client: OlloClient
    private let sessions: SessionController?

    public init(client: OlloClient, sessions: SessionController? = nil) {
        self.client = client
        self.sessions = sessions
    }

    public func requestOtp(phone: String) async throws -> (challengeId: String, devOtp: String?) {
        let raw = try await client.requestOTP(phone: phone)
        return try AuthPayload.parseOtpChallenge(raw)
    }

    public func verify(
        challengeId: String,
        otp: String,
        accountEd25519: String,
        deviceJson: String,
        registrationLock: String? = nil
    ) async throws -> AuthSession {
        let body = try AuthPayload.verifyBody(
            challengeId: challengeId,
            otp: otp,
            accountEd25519: accountEd25519,
            deviceJson: deviceJson,
            registrationLock: registrationLock
        )
        let raw = try await client.verifyOTP(body: body)
        let session = try AuthPayload.parseSession(raw)
        try sessions?.save(
            SessionSecrets(
                userId: session.userId,
                deviceId: session.deviceId,
                access: session.access,
                refresh: session.refresh
            )
        )
        return session
    }

    /// Fail closed before burning an OTP: unbound engines throw here.
    public func signIn(
        engine: CryptoEngine,
        account: AccountKey,
        phone: String,
        otp: String,
        name: String,
        platform: String,
        registrationLock: String? = nil
    ) async throws -> AuthSession {
        let deviceJson = try engine.deviceRegistrationJson(name: name, platform: platform)
        let challenge = try await requestOtp(phone: phone)
        return try await verify(
            challengeId: challenge.challengeId,
            otp: otp,
            accountEd25519: account.publicB64(),
            deviceJson: deviceJson,
            registrationLock: registrationLock
        )
    }

    /// Primary registration: prove possession of the account Ed25519 key.
    public func signInWithKey(
        engine: CryptoEngine,
        account: AccountKey,
        name: String,
        platform: String,
        registrationLock: String? = nil
    ) async throws -> AuthSession {
        let deviceJson = try engine.deviceRegistrationJson(name: name, platform: platform)
        let raw = try await client.authChallenge()
        let challenge = try AuthPayload.parseAuthChallenge(raw)
        let proof = IdentityAddress.authProof(challengeId: challenge.challengeId, nonce: challenge.nonce)
        let signature = try account.sign(message: proof).base64EncodedString()
        let body = try AuthPayload.registerKeyBody(
            challengeId: challenge.challengeId,
            accountEd25519: account.publicB64(),
            signature: signature,
            deviceJson: deviceJson,
            registrationLock: registrationLock
        )
        let sessionRaw = try await client.registerKey(body: body)
        let session = try AuthPayload.parseSession(sessionRaw)
        try sessions?.save(
            SessionSecrets(
                userId: session.userId,
                deviceId: session.deviceId,
                access: session.access,
                refresh: session.refresh
            )
        )
        return session
    }

    public func logout() {
        sessions?.wipe()
    }

    /// Authenticated client: 401 retries once via refresh, then wipes the
    /// protocol store. [deviceJson] is still produced only by a bound engine.
    public static func connected(
        baseURL: URL,
        sessions: SessionController,
        urlSession: URLSession = .shared
    ) -> AuthRepository {
        let holder = ClientHolder()
        let client = OlloClient(
            baseURL: baseURL,
            session: urlSession,
            token: { sessions.access() },
            refreshTokens: {
                guard let token = sessions.refresh() else { return false }
                guard let client = holder.client else { return false }
                do {
                    let raw = try await client.refreshSession(token)
                    let pair = try AuthPayload.parseRefresh(raw)
                    return try sessions.applyRefresh(access: pair.access, refresh: pair.refresh)
                } catch {
                    return false
                }
            },
            onWipe: { sessions.wipe() }
        )
        holder.client = client
        return AuthRepository(client: client, sessions: sessions)
    }
}

private final class ClientHolder: @unchecked Sendable {
    var client: OlloClient?
}
