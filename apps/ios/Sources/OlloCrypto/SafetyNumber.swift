import CryptoKit
import Foundation

/// Safety number matching `packages/crypto/src/safety.ts`.
public enum SafetyNumber {
    public struct Result: Equatable, Sendable {
        public var digits: String
        public var grouped: String
        public var hex: String
        public var qr: String
    }

    public static func of(identityA: Data, identityB: Data) -> Result {
        let ordered: (Data, Data) = compare(identityA, identityB) <= 0
            ? (identityA, identityB)
            : (identityB, identityA)
        let digest = sha256(Data("ollo-safety-v1".utf8) + ordered.0 + ordered.1)
        let digest2 = sha256(Data("ollo-safety-v1-b".utf8) + ordered.0 + ordered.1)
        var digits = ""
        digits.reserveCapacity(60)
        for i in 0..<30 { digits.append(String(Int(digest[i]) % 10)) }
        for i in 0..<30 { digits.append(String(Int(digest2[i]) % 10)) }
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        let grouped = stride(from: 0, to: 60, by: 5).map {
            String(digits[digits.index(digits.startIndex, offsetBy: $0)..<digits.index(digits.startIndex, offsetBy: $0 + 5)])
        }.joined(separator: " ")
        return Result(digits: digits, grouped: grouped, hex: hex, qr: "ollo:safety:v1:\(hex)")
    }

    private static func sha256(_ data: Data) -> [UInt8] {
        Array(SHA256.hash(data: data))
    }

    private static func compare(_ a: Data, _ b: Data) -> Int {
        let n = min(a.count, b.count)
        for i in 0..<n {
            if a[i] != b[i] { return a[i] < b[i] ? -1 : 1 }
        }
        return a.count - b.count
    }
}
