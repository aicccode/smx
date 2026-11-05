// SM4 分组密码（GB/T 32907），CBC 模式 + PKCS#7 填充。
//
// 缓存时序说明：轮函数用下标依赖秘密数据的 T 表（4 张 256 项，共 4KB）。原实现查的是 256 字节 S 盒，
// 同样依赖秘密下标；T 表把可观察的缓存足迹放大到 4KB。Swift 没有可在不加编译参数的情况下使用的
// AES-NI/GFNI 通路，也没有运行时 CPU 检测，所以这里没有硬件路径。运行在与攻击者共享缓存的环境时需要留意。

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

private let sm4SBox: [UInt8] = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
]

/// T 表：T0..T3 依次存放，每张256项。T(b) = L(S(b)) 再循环移位对齐字节位置。首次使用时生成，只读。
private struct SM4Tables: @unchecked Sendable {
    let pointer: UnsafePointer<UInt32>

    static let shared: SM4Tables = {
        let table = UnsafeMutablePointer<UInt32>.allocate(capacity: 4 * 256)
        for input in 0..<256 {
            let s = UInt32(sm4SBox[input])
            var value = s ^ rotl(s, 2) ^ rotl(s, 10) ^ rotl(s, 18) ^ rotl(s, 24)
            for tableIndex in stride(from: 3, through: 0, by: -1) {
                table[tableIndex * 256 + input] = value
                value = rotl(value, 8)
            }
        }
        return SM4Tables(pointer: UnsafePointer(table))
    }()
}

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

/// 32轮加/解密一个分组（输入输出都是大端字）。step 为 +1 加密，-1 解密，rk 指向第一个使用的轮密钥。
@inline(__always)
private func cryptWords(
    _ a: UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32,
    roundKeys rk: UnsafePointer<UInt32>, step: Int, table t: UnsafePointer<UInt32>
) -> (UInt32, UInt32, UInt32, UInt32) {
    @inline(__always)
    func f(_ v: UInt32) -> UInt32 {
        return t[Int(truncatingIfNeeded: v &>> 24)]
            ^ t[256 &+ Int(truncatingIfNeeded: (v &>> 16) & 0xFF)]
            ^ t[512 &+ Int(truncatingIfNeeded: (v &>> 8) & 0xFF)]
            ^ t[768 &+ Int(truncatingIfNeeded: v & 0xFF)]
    }

    var (x0, x1, x2, x3) = (a, b, c, d)
    var key = rk
    for _ in 0..<8 {
        x0 ^= f(x1 ^ x2 ^ x3 ^ key[0])
        x1 ^= f(x2 ^ x3 ^ x0 ^ key[step])
        x2 ^= f(x3 ^ x0 ^ x1 ^ key[2 &* step])
        x3 ^= f(x0 ^ x1 ^ x2 ^ key[3 &* step])
        key += 4 &* step
    }
    return (x3, x2, x1, x0)
}

public func getSM4() -> Sm4Impl {
    return Sm4Impl()
}

public final class Sm4Impl {
    private(set) var roundKeys = [UInt32](repeating: 0, count: 32)
    private(set) var iv = [UInt8](repeating: 0, count: 16)

    public func setKey(key: String, iv: String, hex: Bool) -> Sm4Impl {
        if hex {
            setKeyBytes(keyBytes: decodeHex(key), ivBytes: decodeHex(iv))
        } else {
            setKeyString(keyString: key, ivString: iv)
        }
        return self
    }

    func setKeyBytes(keyBytes: [UInt8], ivBytes: [UInt8]) {
        initKey(key: keyBytes, iv: ivBytes)
    }

    /// 长度不是16字节的字符串：取其 SM3 大写十六进制串的前16个字符的 ASCII 码作为字节（既有行为）
    private func deriveBytes(_ text: String) -> [UInt8] {
        let bytes = Array(text.utf8)
        if bytes.count == 16 {
            return bytes
        }
        return Array(getSM3().update(text).finalize().getHash().utf8.prefix(16))
    }

    func setKeyString(keyString: String, ivString: String) {
        initKey(key: deriveBytes(keyString), iv: deriveBytes(ivString))
    }

    func initKey(key: [UInt8], iv: [UInt8]) {
        // 不足4个字的部分按0处理；超过16字节中多余的完整字会触发越界陷阱（既有行为）
        var words: (UInt32, UInt32, UInt32, UInt32) = (0, 0, 0, 0)
        for index in 0..<(key.count / 4) {
            precondition(index < 4, "SM4 key too long")
            let word =
                UInt32(key[index * 4]) &<< 24 | UInt32(key[index * 4 + 1]) &<< 16
                | UInt32(key[index * 4 + 2]) &<< 8 | UInt32(key[index * 4 + 3])
            switch index {
            case 0: words.0 = word
            case 1: words.1 = word
            case 2: words.2 = word
            default: words.3 = word
            }
        }

        var k0 = words.0 ^ sm4FK.0
        var k1 = words.1 ^ sm4FK.1
        var k2 = words.2 ^ sm4FK.2
        var k3 = words.3 ^ sm4FK.3
        sm4SBox.withUnsafeBufferPointer { sbox in
            sm4CK.withUnsafeBufferPointer { ck in
                roundKeys.withUnsafeMutableBufferPointer { rk in
                    for round in 0..<32 {
                        let v = k1 ^ k2 ^ k3 ^ ck[round]
                        let s =
                            UInt32(sbox[Int(truncatingIfNeeded: v &>> 24)]) &<< 24
                            | UInt32(sbox[Int(truncatingIfNeeded: (v &>> 16) & 0xFF)]) &<< 16
                            | UInt32(sbox[Int(truncatingIfNeeded: (v &>> 8) & 0xFF)]) &<< 8
                            | UInt32(sbox[Int(truncatingIfNeeded: v & 0xFF)])
                        let next = k0 ^ s ^ rotl(s, 13) ^ rotl(s, 23)
                        rk[round] = next
                        (k0, k1, k2, k3) = (k1, k2, k3, next)
                    }
                }
            }
        }
        self.iv = Array(iv[0..<16])
    }

    public func encrypt(text: String) -> String {
        return doCrypt(input: Array(text.utf8), cbcIV: iv, encrypt: true)
    }

    public func decrypt(text: String) -> String {
        return doCrypt(input: decodeHex(text), cbcIV: iv, encrypt: false)
    }

    /// CBC 加密（附加 PKCS#7 填充，返回小写十六进制）或解密（宽松去填充，返回 UTF-8 字符串）
    func doCrypt(input: [UInt8], cbcIV: [UInt8], encrypt: Bool) -> String {
        precondition(cbcIV.count >= 16, "SM4 IV too short")
        if encrypt {
            let padding = 16 - input.count % 16
            let total = input.count + padding
            let output = [UInt8](unsafeUninitializedCapacity: total) { buffer, initialized in
                guard let base = buffer.baseAddress else {
                    return
                }
                input.withUnsafeBufferPointer { source in
                    if let start = source.baseAddress {
                        base.initialize(from: start, count: source.count)
                    }
                }
                (base + input.count).initialize(repeating: UInt8(padding), count: padding)
                encryptCBC(base, count: total, iv: cbcIV)
                initialized = total
            }
            return Hex.encode(output)
        }

        var output = input
        let length = input.count / 16 * 16
        output.removeLast(input.count - length)
        output.withUnsafeMutableBufferPointer { buffer in
            if let base = buffer.baseAddress {
                decryptCBC(base, count: length, iv: cbcIV)
            }
        }
        // 严格检查PKCS#7填充，不合法时原样返回全部数据（既有行为）。空输入在这里触发越界陷阱（既有行为）。
        let pad = Int(output[output.count - 1])
        if pad > 0 && pad <= 16 && output[(output.count - pad)...].allSatisfy({ Int($0) == pad }) {
            output.removeLast(pad)
        }
        return String(decoding: output, as: UTF8.self)
    }

    private func encryptCBC(_ data: UnsafeMutablePointer<UInt8>, count: Int, iv: [UInt8]) {
        let table = SM4Tables.shared.pointer
        roundKeys.withUnsafeBufferPointer { keys in
            iv.withUnsafeBufferPointer { ivBytes in
                guard let rk = keys.baseAddress, let ivBase = ivBytes.baseAddress else {
                    return
                }
                var c0 = loadBE(ivBase)
                var c1 = loadBE(ivBase + 4)
                var c2 = loadBE(ivBase + 8)
                var c3 = loadBE(ivBase + 12)
                var block = data
                for _ in 0..<(count / 16) {
                    (c0, c1, c2, c3) = cryptWords(
                        loadBE(UnsafePointer(block)) ^ c0, loadBE(UnsafePointer(block + 4)) ^ c1,
                        loadBE(UnsafePointer(block + 8)) ^ c2, loadBE(UnsafePointer(block + 12)) ^ c3,
                        roundKeys: rk, step: 1, table: table
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

    private func decryptCBC(_ data: UnsafeMutablePointer<UInt8>, count: Int, iv: [UInt8]) {
        let table = SM4Tables.shared.pointer
        roundKeys.withUnsafeBufferPointer { keys in
            iv.withUnsafeBufferPointer { ivBytes in
                guard let rk = keys.baseAddress, let ivBase = ivBytes.baseAddress else {
                    return
                }
                var p0 = loadBE(ivBase)
                var p1 = loadBE(ivBase + 4)
                var p2 = loadBE(ivBase + 8)
                var p3 = loadBE(ivBase + 12)
                var block = data
                for _ in 0..<(count / 16) {
                    let (i0, i1, i2, i3) = (
                        loadBE(UnsafePointer(block)), loadBE(UnsafePointer(block + 4)),
                        loadBE(UnsafePointer(block + 8)),
                        loadBE(UnsafePointer(block + 12))
                    )
                    let (o0, o1, o2, o3) = cryptWords(i0, i1, i2, i3, roundKeys: rk + 31, step: -1, table: table)
                    storeBE(o0 ^ p0, block)
                    storeBE(o1 ^ p1, block + 4)
                    storeBE(o2 ^ p2, block + 8)
                    storeBE(o3 ^ p3, block + 12)
                    (p0, p1, p2, p3) = (i0, i1, i2, i3)
                    block += 16
                }
            }
        }
    }

    /// 十六进制解码。奇数长度返回空数组；遇到无法解析的片段时返回已解析部分（既有行为）。
    func decodeHex(_ hex: String) -> [UInt8] {
        if let bytes = Hex.decodeStrict(hex) {
            return bytes
        }
        var bytes = [UInt8]()
        let length = hex.count
        if length & 1 != 0 {
            return bytes
        }
        bytes.reserveCapacity(length / 2)
        var index = hex.startIndex
        for _ in 0..<(length / 2) {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                return bytes
            }
            bytes.append(byte)
            index = nextIndex
        }
        return bytes
    }
}
