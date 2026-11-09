// SM4 分组密码（GB/T 32907），CBC 模式 + PKCS#7 填充。
//
// 安全说明（使用前请阅读）：
// - CBC 只提供机密性，不提供完整性。攻击者可以修改密文而不被发现；需要完整性时必须另外做 MAC 或签名。
// - IV 在 setKey 时固定，之后每次 encrypt 都复用同一个 IV，相同明文得到相同密文。
//   调用方必须为每条消息设置新的随机 IV。这是现有接口的形状，无法在库内部解决。
// - 密钥和 IV 必须恰好16字节，其余长度一律失败（不再做哈希或截断）。
// - 本分支的 SM4 为高性能版本，使用查表（T 表：S 盒与线性变换合并，与 OpenSSL、BouncyCastle 的做法相同），
//   表的下标依赖密钥和数据，因此不抵抗缓存时序攻击：能在同一台机器上观察缓存时序的攻击者可能恢复密钥。
//   需要抵抗缓存时序攻击时请使用仓库的 security 分支，那里的 S 盒是布尔电路，不含依赖秘密数据的查表。

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

/// GB/T 32907 的 S 盒
let sm4SBox: [UInt8] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]

/// 4张 T 表连续存放，第 i 张（i = 0 对应最高字节）在 [256 * i, 256 * i + 256)：
/// T_i[x] = linear(S(x) << (24 - 8i))。一轮的 S 盒和线性变换合并为4次查表。
private func sm4MakeTables(_ linear: (UInt32) -> UInt32) -> [UInt32] {
    var tables = [UInt32](repeating: 0, count: 1024)
    for x in 0..<256 {
        let value = linear(UInt32(sm4SBox[x]))
        tables[x] = rotl(value, 24)
        tables[256 + x] = rotl(value, 16)
        tables[512 + x] = rotl(value, 8)
        tables[768 + x] = value
    }
    return tables
}

/// 轮函数用的表，L(B) = B ^ (B <<< 2) ^ (B <<< 10) ^ (B <<< 18) ^ (B <<< 24)
let sm4RoundTables: [UInt32] = sm4MakeTables { $0 ^ rotl($0, 2) ^ rotl($0, 10) ^ rotl($0, 18) ^ rotl($0, 24) }

/// 密钥扩展用的表，L'(B) = B ^ (B <<< 13) ^ (B <<< 23)
let sm4KeyTables: [UInt32] = sm4MakeTables { $0 ^ rotl($0, 13) ^ rotl($0, 23) }

/// 查表计算 L(S(x))（或 L'(S(x))，取决于 table）
@inline(__always)
private func sm4Lookup(_ x: UInt32, _ table: UnsafePointer<UInt32>) -> UInt32 {
    return table[Int(x &>> 24)] ^ table[256 &+ Int((x &>> 16) & 0xFF)]
        ^ table[512 &+ Int((x &>> 8) & 0xFF)] ^ table[768 &+ Int(x & 0xFF)]
}

/// 32轮处理一个分组（输入输出都是大端字）。用加密轮密钥即加密，用逆序轮密钥即解密。
@inline(__always)
private func cryptWords(
    _ a: UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32, roundKeys rk: UnsafePointer<UInt32>,
    table: UnsafePointer<UInt32>
) -> (UInt32, UInt32, UInt32, UInt32) {
    var (x0, x1, x2, x3) = (a, b, c, d)
    var index = 0
    for _ in 0..<8 {
        x0 ^= sm4Lookup(x1 ^ x2 ^ x3 ^ rk[index], table)
        x1 ^= sm4Lookup(x2 ^ x3 ^ x0 ^ rk[index &+ 1], table)
        x2 ^= sm4Lookup(x3 ^ x0 ^ x1 ^ rk[index &+ 2], table)
        x3 ^= sm4Lookup(x0 ^ x1 ^ x2 ^ rk[index &+ 3], table)
        index &+= 4
    }
    return (x3, x2, x1, x0)
}

/// 交错处理两个互不依赖的分组（只用于解密），让两条查表依赖链并行
@inline(__always)
private func cryptWords2(
    _ a: (UInt32, UInt32, UInt32, UInt32), _ b: (UInt32, UInt32, UInt32, UInt32),
    roundKeys rk: UnsafePointer<UInt32>, table: UnsafePointer<UInt32>
) -> ((UInt32, UInt32, UInt32, UInt32), (UInt32, UInt32, UInt32, UInt32)) {
    var (x0, x1, x2, x3) = a
    var (y0, y1, y2, y3) = b
    var index = 0
    for _ in 0..<8 {
        var k = rk[index]
        x0 ^= sm4Lookup(x1 ^ x2 ^ x3 ^ k, table)
        y0 ^= sm4Lookup(y1 ^ y2 ^ y3 ^ k, table)
        k = rk[index &+ 1]
        x1 ^= sm4Lookup(x2 ^ x3 ^ x0 ^ k, table)
        y1 ^= sm4Lookup(y2 ^ y3 ^ y0 ^ k, table)
        k = rk[index &+ 2]
        x2 ^= sm4Lookup(x3 ^ x0 ^ x1 ^ k, table)
        y2 ^= sm4Lookup(y3 ^ y0 ^ y1 ^ k, table)
        k = rk[index &+ 3]
        x3 ^= sm4Lookup(x0 ^ x1 ^ x2 ^ k, table)
        y3 ^= sm4Lookup(y0 ^ y1 ^ y2 ^ k, table)
        index &+= 4
    }
    return ((x3, x2, x1, x0), (y3, y2, y1, y0))
}

/// 不可变的密钥状态。替换时旧状态的引用计数归零才清除，正在使用它的线程不受影响。
private final class SM4KeyState {
    private(set) var roundKeys: [UInt32]
    /// 逆序的轮密钥，解密用
    private(set) var decryptKeys: [UInt32]
    private(set) var iv: [UInt8]

    /// key、iv 必须已确认恰好16字节
    init(key: [UInt8], iv: [UInt8]) {
        self.iv = iv
        var k0 = SM4KeyState.word(key, 0) ^ sm4FK.0
        var k1 = SM4KeyState.word(key, 4) ^ sm4FK.1
        var k2 = SM4KeyState.word(key, 8) ^ sm4FK.2
        var k3 = SM4KeyState.word(key, 12) ^ sm4FK.3
        var keys = [UInt32](repeating: 0, count: 32)
        sm4KeyTables.withUnsafeBufferPointer { tables in
            guard let table = tables.baseAddress else {
                return
            }
            for round in 0..<32 {
                let next = k0 ^ sm4Lookup(k1 ^ k2 ^ k3 ^ sm4CK[round], table)
                keys[round] = next
                (k0, k1, k2, k3) = (k1, k2, k3, next)
            }
        }
        self.roundKeys = keys
        self.decryptKeys = keys.reversed()
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
        secureWipe(&decryptKeys)
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
            let plain = Sm4Impl.decryptCBC(cipher, decryptKeys: key.decryptKeys, iv: key.iv)
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
            sm4RoundTables.withUnsafeBufferPointer { tables in
                output.withUnsafeMutableBufferPointer { buffer in
                    guard let rk = keys.baseAddress, let table = tables.baseAddress, let base = buffer.baseAddress
                    else {
                        return
                    }
                    let (c0, c1, c2, c3) = cryptWords(
                        loadBE(UnsafePointer(base)), loadBE(UnsafePointer(base + 4)),
                        loadBE(UnsafePointer(base + 8)), loadBE(UnsafePointer(base + 12)), roundKeys: rk, table: table
                    )
                    storeBE(c0, base)
                    storeBE(c1, base + 4)
                    storeBE(c2, base + 8)
                    storeBE(c3, base + 12)
                }
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
            sm4RoundTables.withUnsafeBufferPointer { tables in
                iv.withUnsafeBufferPointer { ivBytes in
                    data.withUnsafeMutableBufferPointer { buffer in
                        guard let rk = keys.baseAddress, let table = tables.baseAddress,
                            let ivBase = ivBytes.baseAddress, var block = buffer.baseAddress
                        else {
                            return
                        }
                        var c0 = loadBE(ivBase)
                        var c1 = loadBE(ivBase + 4)
                        var c2 = loadBE(ivBase + 8)
                        var c3 = loadBE(ivBase + 12)
                        for _ in 0..<blocks {
                            (c0, c1, c2, c3) = cryptWords(
                                loadBE(UnsafePointer(block)) ^ c0, loadBE(UnsafePointer(block + 4)) ^ c1,
                                loadBE(UnsafePointer(block + 8)) ^ c2, loadBE(UnsafePointer(block + 12)) ^ c3,
                                roundKeys: rk, table: table
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
        }
        return data
    }

    /// 解密，不处理填充。只有长度不合法时返回 nil（长度是公开的）。
    private static func decryptCBC(_ cipher: [UInt8], decryptKeys: [UInt32], iv: [UInt8]) -> [UInt8]? {
        guard !cipher.isEmpty, cipher.count % 16 == 0 else {
            return nil
        }
        var data = cipher
        let blocks = data.count / 16

        decryptKeys.withUnsafeBufferPointer { keys in
            sm4RoundTables.withUnsafeBufferPointer { tables in
                iv.withUnsafeBufferPointer { ivBytes in
                    data.withUnsafeMutableBufferPointer { buffer in
                        guard let rk = keys.baseAddress, let table = tables.baseAddress,
                            let ivBase = ivBytes.baseAddress, var block = buffer.baseAddress
                        else {
                            return
                        }
                        // 前一个密文分组的4个字
                        var p0 = loadBE(ivBase)
                        var p1 = loadBE(ivBase + 4)
                        var p2 = loadBE(ivBase + 8)
                        var p3 = loadBE(ivBase + 12)
                        var remaining = blocks
                        while remaining >= 2 {
                            let c = (
                                loadBE(UnsafePointer(block)), loadBE(UnsafePointer(block + 4)),
                                loadBE(UnsafePointer(block + 8)), loadBE(UnsafePointer(block + 12))
                            )
                            let d = (
                                loadBE(UnsafePointer(block + 16)), loadBE(UnsafePointer(block + 20)),
                                loadBE(UnsafePointer(block + 24)), loadBE(UnsafePointer(block + 28))
                            )
                            let (o, q) = cryptWords2(c, d, roundKeys: rk, table: table)
                            storeBE(o.0 ^ p0, block)
                            storeBE(o.1 ^ p1, block + 4)
                            storeBE(o.2 ^ p2, block + 8)
                            storeBE(o.3 ^ p3, block + 12)
                            storeBE(q.0 ^ c.0, block + 16)
                            storeBE(q.1 ^ c.1, block + 20)
                            storeBE(q.2 ^ c.2, block + 24)
                            storeBE(q.3 ^ c.3, block + 28)
                            (p0, p1, p2, p3) = d
                            block += 32
                            remaining -= 2
                        }
                        if remaining == 1 {
                            let c0 = loadBE(UnsafePointer(block))
                            let c1 = loadBE(UnsafePointer(block + 4))
                            let c2 = loadBE(UnsafePointer(block + 8))
                            let c3 = loadBE(UnsafePointer(block + 12))
                            let (o0, o1, o2, o3) = cryptWords(c0, c1, c2, c3, roundKeys: rk, table: table)
                            storeBE(o0 ^ p0, block)
                            storeBE(o1 ^ p1, block + 4)
                            storeBE(o2 ^ p2, block + 8)
                            storeBE(o3 ^ p3, block + 12)
                        }
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
    var output = data
    let keys = decrypt ? state.decryptKeys : state.roundKeys
    keys.withUnsafeBufferPointer { keyBuffer in
        sm4RoundTables.withUnsafeBufferPointer { tables in
            output.withUnsafeMutableBufferPointer { buffer in
                guard let rk = keyBuffer.baseAddress, let table = tables.baseAddress, var block = buffer.baseAddress
                else {
                    return
                }
                for _ in 0..<(data.count / 16) {
                    let (c0, c1, c2, c3) = cryptWords(
                        loadBE(UnsafePointer(block)), loadBE(UnsafePointer(block + 4)),
                        loadBE(UnsafePointer(block + 8)), loadBE(UnsafePointer(block + 12)), roundKeys: rk,
                        table: table)
                    storeBE(c0, block)
                    storeBE(c1, block + 4)
                    storeBE(c2, block + 8)
                    storeBE(c3, block + 12)
                    block += 16
                }
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
