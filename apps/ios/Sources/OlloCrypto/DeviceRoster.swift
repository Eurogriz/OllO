import CryptoKit
import Foundation

/// Hash of the live device roster. Includes device ids so a restored extra
/// device with the same identity keys is still visible. Matches
/// `packages/crypto/src/safety.ts` `deviceRosterHash`.
public enum DeviceRoster {
    public struct Device: Sendable {
        public var deviceId: String
        public var identityX25519: Data

        public init(deviceId: String, identityX25519: Data) {
            self.deviceId = deviceId
            self.identityX25519 = identityX25519
        }
    }

    public enum Decision: String, Sendable {
        case new
        case unchanged
        case changed
    }

    public static func hash(_ devices: [Device]) -> String {
        let sorted = devices.sorted { $0.deviceId < $1.deviceId }
        var out = Data("ollo-roster-v1".utf8)
        for d in sorted {
            out.append(Data(d.deviceId.utf8))
            out.append(0)
            out.append(d.identityX25519)
            out.append(0)
        }
        return SHA256.hash(data: out).map { String(format: "%02x", $0) }.joined()
    }

    public static func note(previous: String?, next: String) -> Decision {
        guard let previous else { return .new }
        return previous == next ? .unchanged : .changed
    }
}
