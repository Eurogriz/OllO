import Foundation

/// Length-prefixed map used for opaque libsignal records.
/// Magic `OLM1`. Not a ratchet — only a container. Must match Android `BlobMap`.
public enum BlobMap {
    private static let magic: [UInt8] = [0x4F, 0x4C, 0x4D, 0x31]

    public static func encode(_ map: [String: Data]) throws -> Data {
        var out = Data(magic)
        out.append(u32(UInt32(map.count)))
        for (k, v) in map {
            let key = Data(k.utf8)
            guard key.count <= UInt16.max else { throw BlobError.badKey }
            out.append(u16(UInt16(key.count)))
            out.append(key)
            out.append(u32(UInt32(v.count)))
            out.append(v)
        }
        return out
    }

    public static func decode(_ bytes: Data) throws -> [String: Data] {
        guard bytes.count >= 8 else { throw BlobError.tooShort }
        var i = bytes.startIndex
        let mag = [UInt8](bytes[i..<(i + 4)])
        i += 4
        guard mag == magic else { throw BlobError.badMagic }
        let n = Int(try readU32(bytes, &i))
        guard n >= 0 && n <= 100_000 else { throw BlobError.badCount }
        var map: [String: Data] = [:]
        map.reserveCapacity(n)
        for _ in 0..<n {
            let klen = Int(try readU16(bytes, &i))
            guard bytes.distance(from: i, to: bytes.endIndex) >= klen else { throw BlobError.tooShort }
            let keyData = bytes[i..<(i + klen)]
            i += klen
            let vlen = Int(try readU32(bytes, &i))
            guard vlen >= 0 && vlen <= 8 * 1024 * 1024 else { throw BlobError.valueTooLarge }
            guard bytes.distance(from: i, to: bytes.endIndex) >= vlen else { throw BlobError.tooShort }
            let value = bytes[i..<(i + vlen)]
            i += vlen
            guard let key = String(data: Data(keyData), encoding: .utf8) else { throw BlobError.badKey }
            map[key] = Data(value)
        }
        return map
    }

    public enum BlobError: Error {
        case tooShort
        case badMagic
        case badCount
        case badKey
        case valueTooLarge
    }

    private static func u16(_ n: UInt16) -> Data {
        Data([UInt8(n >> 8), UInt8(n & 0xFF)])
    }

    private static func u32(_ n: UInt32) -> Data {
        Data([
            UInt8((n >> 24) & 0xFF),
            UInt8((n >> 16) & 0xFF),
            UInt8((n >> 8) & 0xFF),
            UInt8(n & 0xFF),
        ])
    }

    private static func readU16(_ bytes: Data, _ i: inout Data.Index) throws -> UInt16 {
        guard bytes.distance(from: i, to: bytes.endIndex) >= 2 else { throw BlobError.tooShort }
        let hi = UInt16(bytes[i])
        let lo = UInt16(bytes[i + 1])
        i += 2
        return (hi << 8) | lo
    }

    private static func readU32(_ bytes: Data, _ i: inout Data.Index) throws -> UInt32 {
        guard bytes.distance(from: i, to: bytes.endIndex) >= 4 else { throw BlobError.tooShort }
        let b0 = UInt32(bytes[i])
        let b1 = UInt32(bytes[i + 1])
        let b2 = UInt32(bytes[i + 2])
        let b3 = UInt32(bytes[i + 3])
        i += 4
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }
}
