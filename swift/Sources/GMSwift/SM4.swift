// SM4 分组密码（GB/T 32907），CBC 模式 + PKCS#7 填充。
//
// 安全说明（使用前请阅读）：
// - CBC 只提供机密性，不提供完整性。攻击者可以修改密文而不被发现；需要完整性时必须另外做 MAC 或签名。
// - IV 在 setKey 时固定，之后每次 encrypt 都复用同一个 IV，相同明文得到相同密文。
//   调用方必须为每条消息设置新的随机 IV。这是现有接口的形状，无法在库内部解决。
// - 密钥和 IV 必须恰好16字节，其余长度一律失败（不再做哈希或截断）。
// - 不含依赖秘密数据的查表或分支（S 盒是布尔电路，见 SM4SBox.swift）；Swift 无法保证恒定时间，
//   这是源码层面能做到的上限。没有硬件路径：AES-NI/GFNI/NEON 需要 unsafeFlags 或 C 目标，本包都不使用。

import Foundation

/// SM4 的失败类型。所有解密失败（十六进制、长度、填充、UTF-8）都是同一个 decryptionFailed，无法用来区分原因。
public enum SM4Error: Error {
    case invalidKeyOrIV
    case keyNotSet
    case decryptionFailed
}

private let sm4FK: (UInt32, UInt32, UInt32, UInt32) = (0xA3B1_BAC6, 0x56AA_3350, 0x677D_9197, 0xB270_22DC)

private let sm4CK: [UInt32] = [
    0x0007_0E15, 0x1C23_2A31, 0x383F_464D, 0x545B_6269,
    0x7077_7E85, 0x8C93_9AA1, 0xA8AF_B6BD, 0xC4CB_D2D9,
    0xE0E7_EEF5, 0xFC03_0A11, 0x181F_262D, 0x343B_4249,
    0x5057_5E65, 0x6C73_7A81, 0x888F_969D, 0xA4AB_B2B9,
    0xC0C7_CED5, 0xDCE3_EAF1, 0xF8FF_060D, 0x141B_2229,
    0x3037_3E45, 0x4C53_5A61, 0x686F_767D, 0x848B_9299,
    0xA0A7_AEB5, 0xBCC3_CAD1, 0xD8DF_E6ED, 0xF4FB_0209,
    0x1017_1E25, 0x2C33_3A41, 0x484F_565D, 0x646B_7279,
]

@inline(__always)
private func rotl(_ x: UInt32, _ count: UInt32) -> UInt32 {
    return (x &<< count) | (x &>> (32 &- count))
}

@inline(__always)
private func loadBE(_ pointer: UnsafePointer<UInt8>) -> UInt32 {
    return UInt32(bigEndian: UnsafeRawPointer(pointer).loadUnaligned(as: UInt32.self))
}

@inline(__always)
private func storeBE(_ value: UInt32, _ pointer: UnsafeMutablePointer<UInt8>) {
    UnsafeMutableRawPointer(pointer).storeBytes(of: value.bigEndian, as: UInt32.self)
}

/// 同时对64位字里的两个32位值做循环左移
@inline(__always)
private func rotlPair(_ x: UInt64, _ count: UInt64) -> UInt64 {
    let lowBits = (UInt64(1) &<< count) &- 1
    let carried = lowBits | (lowBits &<< 32)
    return ((x &<< count) & ~carried) | ((x &>> (32 &- count)) & carried)
}

/// 32轮加密一个分组（输入输出都是大端字）。
@inline(__always)
private func encryptWords(
    _ a: UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, roundKeys rk: UnsafePointer<UInt32>
) -> (UInt32, UInt32, UInt32, UInt32) {
    @inline(__always)
    func f(_ v: UInt32) -> UInt32 {
        let s = sm4SubstituteBytes(v)
        return s ^ rotl(s, 2) ^ rotl(s, 10) ^ rotl(s, 18) ^ rotl(s, 24)
    }

    var (x0, x1, x2, x3) = (a, b, c, d)
    var index = 0
    for _ in 0..<8 {
        x0 ^= f(x1 ^ x2 ^ x3 ^ rk[index])
        x1 ^= f(x2 ^ x3 ^ x0 ^ rk[index &+ 1])
        x2 ^= f(x3 ^ x0 ^ x1 ^ rk[index &+ 2])
        x3 ^= f(x0 ^ x1 ^ x2 ^ rk[index &+ 3])
        index &+= 4
    }
    return (x3, x2, x1, x0)
}

/// 32轮解密两个分组。每个字的高32位属于一个分组，低32位属于另一个，只有解密可以这样并行。
@inline(__always)
private func decryptPairs(
    _ a: UInt64, _ b: UInt64, _ c: UInt64, _ d: UInt64, roundKeys rk: UnsafePointer<UInt32>
) -> (UInt64, UInt64, UInt64, UInt64) {
    @inline(__always)
    func f(_ v: UInt64) -> UInt64 {
        let s = sm4SubstituteBytes(v)
        return s ^ rotlPair(s, 2) ^ rotlPair(s, 10) ^ rotlPair(s, 18) ^ rotlPair(s, 24)
    }
    @inline(__always)
    func key(_ index: Int) -> UInt64 {
        let value = UInt64(rk[index])
        return value | (value &<< 32)
    }

    var (x0, x1, x2, x3) = (a, b, c, d)
    var index = 31
    for _ in 0..<8 {
        x0 ^= f(x1 ^ x2 ^ x3 ^ key(index))
        x1 ^= f(x2 ^ x3 ^ x0 ^ key(index &- 1))
        x2 ^= f(x3 ^ x0 ^ x1 ^ key(index &- 2))
        x3 ^= f(x0 ^ x1 ^ x2 ^ key(index &- 3))
        index &-= 4
    }
    return (x3, x2, x1, x0)
}

/// 不可变的密钥状态。替换时旧状态的引用计数归零才清除，正在使用它的线程不受影响。
private final class SM4KeyState {
    private(set) var roundKeys: [UInt32]
    private(set) var iv: [UInt8]

    /// key、iv 必须已确认恰好16字节
    init(key: [UInt8], iv: [UInt8]) {
        self.iv = iv
        var k0 = SM4KeyState.word(key, 0) ^ sm4FK.0
        var k1 = SM4KeyState.word(key, 4) ^ sm4FK.1
        var k2 = SM4KeyState.word(key, 8) ^ sm4FK.2
        var k3 = SM4KeyState.word(key, 12) ^ sm4FK.3
        var keys = [UInt32](repeating: 0, count: 32)
        for round in 0..<32 {
            let v = k1 ^ k2 ^ k3 ^ sm4CK[round]
            let s = sm4SubstituteBytes(v)
            let next = k0 ^ s ^ rotl(s, 13) ^ rotl(s, 23)
            keys[round] = next
            (k0, k1, k2, k3) = (k1, k2, k3, next)
        }
        self.roundKeys = keys
    }

    private static func word(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        return bytes.withUnsafeBufferPointer { buffer in
            guard let base = buffer.baseAddress else {
                return 0
            }
            return loadBE(base + offset)
        }
    }

    deinit {
        secureWipe(&roundKeys)
        secureWipe(&iv)
    }
}

public func getSM4() -> Sm4Impl {
    return Sm4Impl()
}

/// SM4-CBC。可以在多个线程间共享：setKey 与 encrypt/decrypt 并发时，每次运算使用其开始时的完整密钥状态。
///
/// 原有的 encrypt/decrypt 无法抛错：失败时返回空字符串，这和“解密得到空明文”无法区分。
/// 需要区分时请使用 setKeyChecked/encryptChecked/decryptChecked。
public final class Sm4Impl: @unchecked Sendable {
    private let lock = NSLock()
    private var state: SM4KeyState?

    private func currentState() throws -> SM4KeyState {
        lock.lock()
        defer { lock.unlock() }
        guard let state = state else {
            throw SM4Error.keyNotSet
        }
        return state
    }

    private func replaceState(_ newState: SM4KeyState?) {
        lock.lock()
        defer { lock.unlock() }
        state = newState
    }

    /// 设置密钥和 IV。hex 为 true 时都必须是32个十六进制字符，为 false 时其 UTF-8 编码都必须恰好16字节。
    /// 不合法时清除已有密钥并返回 self，之后的 encrypt/decrypt 都失败。
    public func setKey(key: String, iv: String, hex: Bool) -> Sm4Impl {
        return (try? setKeyChecked(key: key, iv: iv, hex: hex)) ?? self
    }

    /// 同 setKey，不合法时抛出 SM4Error.invalidKeyOrIV（已有密钥同样被清除）。
    @discardableResult
    public func setKeyChecked(key: String, iv: String, hex: Bool) throws -> Sm4Impl {
        // 先检查长度，超长的字符串不做解码
        let expected = hex ? 32 : 16
        guard key.utf8.count == expected, iv.utf8.count == expected else {
            replaceState(nil)
            throw SM4Error.invalidKeyOrIV
        }
        var keyBytes = hex ? (Hex.decodeStrict(key) ?? []) : Array(key.utf8)
        defer { secureWipe(&keyBytes) }
        let ivBytes = hex ? (Hex.decodeStrict(iv) ?? []) : Array(iv.utf8)
        try setKeyBytes(keyBytes: keyBytes, ivBytes: ivBytes)
        return self
    }

    func setKeyBytes(keyBytes: [UInt8], ivBytes: [UInt8]) throws {
        guard keyBytes.count == 16, ivBytes.count == 16 else {
            replaceState(nil)
            throw SM4Error.invalidKeyOrIV
        }
        replaceState(SM4KeyState(key: keyBytes, iv: ivBytes))
    }

    /// 返回小写十六进制密文。未设置有效密钥时返回空字符串。
    public func encrypt(text: String) -> String {
        return (try? encryptChecked(text: text)) ?? ""
    }

    /// 失败时返回空字符串（见类型说明）。
    public func decrypt(text: String) -> String {
        return (try? decryptChecked(text: text)) ?? ""
    }

    public func encryptChecked(text: String) throws -> String {
        let key = try currentState()
        var plain = Array(text.utf8)
        defer { secureWipe(&plain) }
        return Hex.encode(Sm4Impl.encryptCBC(plain, roundKeys: key.roundKeys, iv: key.iv))
    }

    /// 所有失败都抛出同一个 SM4Error.decryptionFailed。密文必须是小写十六进制（encrypt 的输出形式）。
    ///
    /// 不管填充是否合法，都对同样多的字节做同样的 UTF-8 校验之后才判断结果，否则失败的快慢就是填充预言机。
    /// 成功路径还要构造字符串，所以成功和失败的耗时不同，但成功本身就是可观察的结果。
    /// 明文不一定是文本时用 decryptBytesChecked。
    public func decryptChecked(text: String) throws -> String {
        var plain = try decryptedBuffer(text: text)
        defer { secureWipe(&plain) }
        guard let result = Sm4Impl.finishStringDecrypt(&plain, utf8Check: utf8InvalidMask) else {
            throw SM4Error.decryptionFailed
        }
        return result
    }

    /// 返回明文字节，没有 UTF-8 步骤。所有失败都抛出同一个 SM4Error.decryptionFailed。
    public func decryptBytesChecked(text: String) throws -> [UInt8] {
        var plain = try decryptedBuffer(text: text)
        let invalid = plain.withUnsafeBufferPointer { buffer -> UInt32 in
            guard let base = buffer.baseAddress else {
                return 1
            }
            return pkcs7InvalidMask(base, count: buffer.count)
        }
        if invalid != 0 {
            secureWipe(&plain)
            throw SM4Error.decryptionFailed
        }
        plain.removeLast(Int(plain[plain.count - 1]))
        return plain
    }

    private func decryptedBuffer(text: String) throws -> [UInt8] {
        let key = try currentState()
        guard let cipher = Hex.decodeCanonical(text),
            let plain = Sm4Impl.decryptCBC(cipher, roundKeys: key.roundKeys, iv: key.iv)
        else {
            throw SM4Error.decryptionFailed
        }
        return plain
    }

    /// 校验填充和 UTF-8（总是两者都做，且 UTF-8 校验覆盖整个缓冲区），都通过才去除填充并构造字符串。
    /// 合法的 PKCS#7 填充字节都是 ASCII，所以校验整个缓冲区与只校验明文部分的结论相同。
    /// utf8Check 是参数，测试可以确认填充错误时它同样运行。
    static func finishStringDecrypt(
        _ data: inout [UInt8], utf8Check: (UnsafePointer<UInt8>, Int) -> UInt32
    ) -> String? {
        let invalid = data.withUnsafeBufferPointer { buffer -> UInt32 in
            guard let base = buffer.baseAddress else {
                return 1
            }
            let padding = pkcs7InvalidMask(base, count: buffer.count)
            let text = utf8Check(base, buffer.count)
            return padding | text
        }
        if invalid != 0 {
            return nil
        }
        return String(decoding: data.dropLast(Int(data[data.count - 1])), as: UTF8.self)
    }

    // MARK: - 内部接口（测试使用）

    /// 无填充地加密一个分组
    func encryptBlock(_ block: [UInt8]) -> [UInt8]? {
        guard block.count == 16, let key = try? currentState() else {
            return nil
        }
        var output = block
        key.roundKeys.withUnsafeBufferPointer { keys in
            output.withUnsafeMutableBufferPointer { buffer in
                guard let rk = keys.baseAddress, let base = buffer.baseAddress else {
                    return
                }
                let (c0, c1, c2, c3) = encryptWords(
                    loadBE(UnsafePointer(base)), loadBE(UnsafePointer(base + 4)), loadBE(UnsafePointer(base + 8)),
                    loadBE(UnsafePointer(base + 12)), roundKeys: rk
                )
                storeBE(c0, base)
                storeBE(c1, base + 4)
                storeBE(c2, base + 8)
                storeBE(c3, base + 12)
            }
        }
        return output
    }

    var roundKeys: [UInt32]? {
        return (try? currentState())?.roundKeys
    }

    var iv: [UInt8]? {
        return (try? currentState())?.iv
    }

    // MARK: - CBC

    private static func encryptCBC(_ input: [UInt8], roundKeys: [UInt32], iv: [UInt8]) -> [UInt8] {
        let padding = 16 - input.count % 16
        var data = input
        data.append(contentsOf: repeatElement(UInt8(padding), count: padding))
        let blocks = data.count / 16

        roundKeys.withUnsafeBufferPointer { keys in
            iv.withUnsafeBufferPointer { ivBytes in
                data.withUnsafeMutableBufferPointer { buffer in
                    guard let rk = keys.baseAddress, let ivBase = ivBytes.baseAddress, var block = buffer.baseAddress
                    else {
                        return
                    }
                    var c0 = loadBE(ivBase)
                    var c1 = loadBE(ivBase + 4)
                    var c2 = loadBE(ivBase + 8)
                    var c3 = loadBE(ivBase + 12)
                    for _ in 0..<blocks {
                        (c0, c1, c2, c3) = encryptWords(
                            loadBE(UnsafePointer(block)) ^ c0, loadBE(UnsafePointer(block + 4)) ^ c1,
                            loadBE(UnsafePointer(block + 8)) ^ c2, loadBE(UnsafePointer(block + 12)) ^ c3,
                            roundKeys: rk
                        )
                        storeBE(c0, block)
                        storeBE(c1, block + 4)
                        storeBE(c2, block + 8)
                        storeBE(c3, block + 12)
                        block += 16
                    }
                }
            }
        }
        return data
    }

    /// 解密，不处理填充。只有长度不合法时返回 nil（长度是公开的）。
    private static func decryptCBC(_ cipher: [UInt8], roundKeys: [UInt32], iv: [UInt8]) -> [UInt8]? {
        guard !cipher.isEmpty, cipher.count % 16 == 0 else {
            return nil
        }
        var data = cipher
        let total = data.count / 16

        roundKeys.withUnsafeBufferPointer { keys in
            iv.withUnsafeBufferPointer { ivBytes in
                data.withUnsafeMutableBufferPointer { buffer in
                    guard let keyBase = keys.baseAddress, let ivBase = ivBytes.baseAddress,
                        let base = buffer.baseAddress
                    else {
                        return
                    }
                    // 前一个密文分组的4个字
                    var p0 = loadBE(ivBase)
                    var p1 = loadBE(ivBase + 4)
                    var p2 = loadBE(ivBase + 8)
                    var p3 = loadBE(ivBase + 12)
                    var index = 0
                    while index < total {
                        // 每次解密两个分组；最后只剩一个时另一半输入为 0，结果被丢弃
                        let first = UnsafePointer(base + index * 16)
                        let hasSecond = index + 1 < total
                        let second = first + 16
                        let (c0, c1, c2, c3) = (
                            loadBE(first), loadBE(first + 4), loadBE(first + 8), loadBE(first + 12)
                        )
                        let d0 = hasSecond ? loadBE(second) : 0
                        let d1 = hasSecond ? loadBE(second + 4) : 0
                        let d2 = hasSecond ? loadBE(second + 8) : 0
                        let d3 = hasSecond ? loadBE(second + 12) : 0
                        let (o0, o1, o2, o3) = decryptPairs(
                            UInt64(c0) &<< 32 | UInt64(d0), UInt64(c1) &<< 32 | UInt64(d1),
                            UInt64(c2) &<< 32 | UInt64(d2), UInt64(c3) &<< 32 | UInt64(d3),
                            roundKeys: keyBase
                        )
                        let target = base + index * 16
                        storeBE(UInt32(truncatingIfNeeded: o0 &>> 32) ^ p0, target)
                        storeBE(UInt32(truncatingIfNeeded: o1 &>> 32) ^ p1, target + 4)
                        storeBE(UInt32(truncatingIfNeeded: o2 &>> 32) ^ p2, target + 8)
                        storeBE(UInt32(truncatingIfNeeded: o3 &>> 32) ^ p3, target + 12)
                        (p0, p1, p2, p3) = (c0, c1, c2, c3)
                        if hasSecond {
                            let next = target + 16
                            storeBE(UInt32(truncatingIfNeeded: o0) ^ p0, next)
                            storeBE(UInt32(truncatingIfNeeded: o1) ^ p1, next + 4)
                            storeBE(UInt32(truncatingIfNeeded: o2) ^ p2, next + 8)
                            storeBE(UInt32(truncatingIfNeeded: o3) ^ p3, next + 12)
                            (p0, p1, p2, p3) = (d0, d1, d2, d3)
                        }
                        index += 2
                    }
                }
            }
        }

        return data
    }
}

// MARK: - ECB（只供 SM9 加密的 SM4 模式使用）

/// SM4-ECB 加密或解密 data（长度必须是16的倍数，调用方保证），key 恰好16字节。不处理填充。
func sm4ECB(key: [UInt8], data: [UInt8], decrypt: Bool) -> [UInt8] {
    precondition(key.count == 16 && data.count % 16 == 0)
    let state = SM4KeyState(key: key, iv: [UInt8](repeating: 0, count: 16))
    // SM4 decryption is the same round function with the round keys reversed.
    var keys = decrypt ? Array(state.roundKeys.reversed()) : state.roundKeys
    defer { secureWipe(&keys) }
    var output = data
    keys.withUnsafeBufferPointer { keyBuffer in
        output.withUnsafeMutableBufferPointer { buffer in
            guard let rk = keyBuffer.baseAddress, var block = buffer.baseAddress else {
                return
            }
            for _ in 0..<(data.count / 16) {
                let (c0, c1, c2, c3) = encryptWords(
                    loadBE(UnsafePointer(block)), loadBE(UnsafePointer(block + 4)),
                    loadBE(UnsafePointer(block + 8)), loadBE(UnsafePointer(block + 12)), roundKeys: rk)
                storeBE(c0, block)
                storeBE(c1, block + 4)
                storeBE(c2, block + 8)
                storeBE(c3, block + 12)
                block += 16
            }
        }
    }
    return output
}

/// 恒定流程的 PKCS#7 检查：合法时返回 0，否则返回非 0。count 必须是不小于16的整数。
/// 总是检查最后16个字节，不提前退出，也不按数据分支。
@inline(never)
func pkcs7InvalidMask(_ bytes: UnsafePointer<UInt8>, count: Int) -> UInt32 {
    let last = bytes + (count &- 1)
    let pad = UInt32(last.pointee)
    var bad: UInt32 = (pad &- 1) >> 31  // pad == 0
    bad |= (16 &- pad) >> 31  // pad > 16
    var offset: UInt32 = 0
    while offset < 16 {
        // offset < pad 时掩码全 1
        let inPadding = 0 &- ((offset &- pad) >> 31)
        bad |= (UInt32((last - Int(offset)).pointee) ^ pad) & inPadding
        offset &+= 1
    }
    return bad
}

extension Sm4Impl: CustomReflectable, CustomStringConvertible {
    /// 不通过反射暴露密钥状态
    public var customMirror: Mirror {
        return Mirror(self, children: [])
    }

    public var description: String {
        return "Sm4Impl(<redacted>)"
    }
}
