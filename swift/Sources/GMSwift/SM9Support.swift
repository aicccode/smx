// SM9 的辅助算法：H1/H2、KDF、随机数、SM4 模式的填充、恒定时间比较。

import Foundation

#if canImport(Security)
    import Security
#endif

enum SM9Limits {
    /// 随机数和重试循环的次数上限，达到上限只可能是随机源出了问题
    static let maximumAttempts = 128
    /// 密钥交换与密钥封装的密钥长度范围（字节）
    static let keyLengths = 1...(1 << 20)
    /// KDF 计数器是32位
    static let maximumKDFBytes: UInt64 = 0xFFFF_FFFF * 32
    static let macKeyLength = 32
    static let sm4KeyLength = 16
}

enum SM9Support {
    // MARK: - 哈希

    /// H(tag, Z) = (Ha mod (N-1)) + 1，Ha = SM3(tag||Z||1) || SM3(tag||Z||2) 的前8字节（共320位）
    static func hashToRange(tag: UInt8, parts: [[UInt8]]) -> BigInt256 {
        var prefix = SM3Core()
        prefix.update(byte: tag)
        for part in parts {
            prefix.update(part)
        }
        var first = prefix
        first.update([0, 0, 0, 1])
        var second = prefix
        second.update([0, 0, 0, 2])
        var a = first.finalize()
        var b = second.finalize()
        defer {
            secureWipe(&a)
            secureWipe(&b)
        }
        // Ha 的高64位是 a[0..<8]，低256位是 a[8..<32] || b[0..<8]
        var high: UInt64 = 0
        for index in 0..<8 {
            high = (high &<< 8) | UInt64(a[index])
        }
        var low = Array(a[8..<32])
        low.append(contentsOf: b[0..<8])
        defer { secureWipe(&low) }
        let reduced = SM9Scalar.reduceModNMinus1(high: high, low: BigInt256.fromBEBytes(low))
        return reduced.add(BigInt256.one).0
    }

    static func h1(_ parts: [UInt8]...) -> BigInt256 {
        return hashToRange(tag: 0x01, parts: parts)
    }

    static func h2(_ parts: [UInt8]...) -> BigInt256 {
        return hashToRange(tag: 0x02, parts: parts)
    }

    /// KDF(Z, klen)：SM3(Z || ct)，ct 是从1开始的32位大端计数器。调用方保证 klen 不超过上限。
    static func kdf(_ parts: [[UInt8]], length: Int) -> [UInt8] {
        var prefix = SM3Core()
        for part in parts {
            prefix.update(part)
        }
        var output = [UInt8]()
        output.reserveCapacity(length + 32)
        var counter: UInt32 = 1
        while output.count < length {
            var core = prefix
            core.update([
                UInt8(truncatingIfNeeded: counter >> 24), UInt8(truncatingIfNeeded: counter >> 16),
                UInt8(truncatingIfNeeded: counter >> 8), UInt8(truncatingIfNeeded: counter),
            ])
            var block = core.finalize()
            output.append(contentsOf: block)
            secureWipe(&block)
            counter &+= 1
        }
        let extra = output.count - length
        if extra > 0 {
            output.withUnsafeMutableBytes { raw in
                secureWipe(UnsafeMutableRawBufferPointer(rebasing: raw[length...]))
            }
            output.removeLast(extra)
        }
        return output
    }

    static func sm3(_ parts: [UInt8]...) -> [UInt8] {
        var core = SM3Core()
        for part in parts {
            core.update(part)
        }
        return core.finalize()
    }

    // MARK: - 随机数

    /// 操作系统 CSPRNG（与 SM2 相同）。Apple 平台失败时抛错；其它平台标准库在随机源失败时直接中止进程。
    private static func fillRandom(_ buffer: UnsafeMutableRawBufferPointer) throws {
        #if canImport(Security)
            guard let base = buffer.baseAddress,
                SecRandomCopyBytes(kSecRandomDefault, buffer.count, base) == errSecSuccess
            else {
                throw SM9Error.randomFailure("System random generator failed")
            }
        #else
            var generator = SystemRandomNumberGenerator()
            var offset = 0
            while offset + 8 <= buffer.count {
                buffer.storeBytes(of: generator.next() as UInt64, toByteOffset: offset, as: UInt64.self)
                offset += 8
            }
        #endif
    }

    /// 拒绝采样，均匀分布在 [1, N-1]
    static func randomScalar() throws -> BigInt256 {
        for _ in 0..<SM9Limits.maximumAttempts {
            let candidate = try withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 32) { bytes -> BigInt256 in
                let raw = UnsafeMutableRawBufferPointer(bytes)
                defer { secureWipe(raw) }
                try fillRandom(raw)
                guard let base = bytes.baseAddress else {
                    return BigInt256.zero
                }
                return BigInt256.fromBEPointer(UnsafePointer(base))
            }
            if SM9Scalar.validMask(candidate) != 0 {
                return candidate
            }
        }
        throw SM9Error.randomFailure("Too many rejected values")
    }

    // MARK: - 解析

    /// 严格解析标量：恰好64个十六进制字符（大小写均可），取值在 [1, N-1]。不按标量的值分支。
    static func parseScalar(_ hex: String) -> BigInt256? {
        guard let k = BigInt256(hex: hex), SM9Scalar.validMask(k) != 0 else {
            return nil
        }
        return k
    }

    // MARK: - 字节运算

    static func xor(_ a: [UInt8], _ b: ArraySlice<UInt8>) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: a.count)
        var index = 0
        var other = b.startIndex
        while index < a.count {
            out[index] = a[index] ^ b[other]
            index += 1
            other += 1
        }
        return out
    }

    static func pkcs7Pad(_ data: [UInt8]) -> [UInt8] {
        let padding = 16 - data.count % 16
        return data + [UInt8](repeating: UInt8(padding), count: padding)
    }
}

/// 比较时间只取决于长度
@inline(never)
func sm9ConstantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
    if lhs.count != rhs.count {
        return false
    }
    var difference: UInt8 = 0
    for index in 0..<lhs.count {
        difference |= lhs[index] ^ rhs[index]
    }
    return opaqueMask(UInt64(difference)) == 0
}

@inline(never)
func sm9ConstantTimeIsAllZero<C: Collection>(_ bytes: C) -> Bool where C.Element == UInt8 {
    var accumulated: UInt8 = 0
    for byte in bytes {
        accumulated |= byte
    }
    return opaqueMask(UInt64(accumulated)) == 0
}

/// 错误信息不包含任何密钥或明文内容
public enum SM9Error: Error, Equatable {
    case invalidInput(String)
    case invalidKey(String)
    case decryptionFailed(String)
    case randomFailure(String)
}
