// SM2椭圆曲线公钥密码算法实现：加解密、签名验签、密钥交换

import Foundation

#if canImport(Security)
    import Security
#endif

// MARK: - 限制

private enum SM2Limits {
    /// 随机数和重试循环的次数上限。合法范围覆盖了约 1 - 2^-32 的取值，达到上限只可能是随机源出了问题。
    static let maximumAttempts = 128
    /// ENTL 是16位比特长度
    static let maximumUserIdBytes = 8191
    /// 密钥交换协商的密钥长度范围
    static let keyExchangeLengths = 1...(1 << 20)
    /// KDF 计数器是32位
    static let maximumKDFBytes: UInt64 = 0xFFFF_FFFF * 32
}

// MARK: - SM2密钥交换参数

/// 密钥交换的结果。ka/kb 和 v 都是秘密，不会出现在 print/dump 的输出里。
public final class SM2KeySwapParams: CustomReflectable, CustomStringConvertible {
    public var sa: String?
    public var sb: String?
    public var ka: String?
    public var kb: String?
    public var v: ECPoint?
    public var za: [UInt8]?
    public var zb: [UInt8]?
    public var success: Bool = false
    public var message: String?

    public var customMirror: Mirror {
        return Mirror(self, children: [])
    }

    public var description: String {
        return "SM2KeySwapParams(success: \(success), message: \(message ?? "nil"))"
    }

    fileprivate static func failure(_ message: String) -> SM2KeySwapParams {
        let result = SM2KeySwapParams()
        result.message = message
        return result
    }
}

// MARK: - SM2主类

public final class SM2 {

    // MARK: - 密钥对生成

    /// 生成私钥在 [1, n-2] 内的密钥对。这个接口无法抛错：操作系统随机源失败时两个字符串都为空，
    /// 而空字符串不是合法的公钥或私钥，后续调用都会干净地失败。
    public static func genKeyPair() -> (privateKey: String, publicKey: String) {
        guard let privateKey = try? randomScalar(belowNMinus1: true) else {
            return ("", "")
        }
        return (privateKey.toHex(), ECPoint.multiplyGenerator(privateKey).toHexEncoded())
    }

    // MARK: - 加密

    public static func encrypt(_ plaintext: String, publicKey: String) throws -> String {
        var message = Array(plaintext.utf8)
        defer { secureWipe(&message) }
        if message.isEmpty {
            throw SM2Error.invalidInput("Plaintext cannot be empty")
        }
        if UInt64(message.count) > SM2Limits.maximumKDFBytes {
            throw SM2Error.invalidInput("Plaintext too long")
        }

        let pubPoint = ECPoint.fromHexEncoded(publicKey)
        if !pubPoint.isValidPublicKey {
            throw SM2Error.invalidKey("Invalid public key")
        }

        for _ in 0..<SM2Limits.maximumAttempts {
            let k = try randomScalar(belowNMinus1: false)

            // C1 = [k]G
            let c1 = ECPoint.multiplyGenerator(k)

            // P2 = [k]PB
            let p2 = pubPoint.multiply(k)
            if p2.isInfinity {
                continue
            }

            // KDF
            var keyPrefix = SM3Core()
            keyPrefix.update(p2.x.value)
            keyPrefix.update(p2.y.value)
            var key = kdf(keylen: message.count, prefix: keyPrefix)
            defer { secureWipe(&key) }

            if constantTimeIsAllZero(key) {
                continue
            }

            // C3 = SM3(x2 || M || y2)
            var digest = SM3Core()
            digest.update(p2.x.value)
            digest.update(message)
            digest.update(p2.y.value)
            let c3 = digest.finalize()

            // 输出 C1 || C3 || C2，C2 = M XOR t
            let c1Encoded = c1.toEncoded()
            var output = [UInt8]()
            output.reserveCapacity(c1Encoded.count + c3.count + message.count)
            output.append(contentsOf: c1Encoded)
            output.append(contentsOf: c3)
            output.append(contentsOf: xorBytes(message, key))
            return Hex.encode(output)
        }
        throw SM2Error.randomFailure("Too many rejected values")
    }

    // MARK: - 解密

    /// 密文是 C1 || C3 || C2 的十六进制（大小写均可），C2 不能为空。
    public static func decrypt(_ ciphertext: String, privateKey: String) throws -> String {
        guard let bytes = Hex.decodeStrict(ciphertext) else {
            throw SM2Error.invalidInput("Invalid ciphertext encoding")
        }
        // 65 字节 C1 + 32 字节 C3 + 至少 1 字节 C2
        guard bytes.count >= 98 else {
            throw SM2Error.invalidInput("Ciphertext too short")
        }
        let c1 = ECPoint.fromEncoded(Array(bytes[0..<65]))
        if !c1.isValidPublicKey {
            throw SM2Error.invalidInput("Invalid C1 point")
        }
        guard let d = parsePrivateKey(privateKey) else {
            throw SM2Error.invalidKey("Invalid private key")
        }

        // P2 = [d]C1
        let p2 = c1.multiply(d)
        if p2.isInfinity {
            throw SM2Error.decryptionFailed("Decryption verification failed")
        }

        // KDF，M = C2 XOR t
        let c2 = bytes[97...]
        var keyPrefix = SM3Core()
        keyPrefix.update(p2.x.value)
        keyPrefix.update(p2.y.value)
        var key = kdf(keylen: c2.count, prefix: keyPrefix)
        defer { secureWipe(&key) }
        let keyIsZero = constantTimeIsAllZero(key)
        var message = xorBytes(Array(c2), key)
        defer { secureWipe(&message) }

        // 验证 C3。无论 KDF 是否全 0 都完整计算，错误信息也相同。
        var digest = SM3Core()
        digest.update(p2.x.value)
        digest.update(message)
        digest.update(p2.y.value)
        let matches = constantTimeEquals(digest.finalize(), Array(bytes[65..<97]))

        if keyIsZero || !matches {
            throw SM2Error.decryptionFailed("Decryption verification failed")
        }

        guard let plaintext = strictUTF8String(message) else {
            throw SM2Error.decryptionFailed("UTF-8 decode error")
        }
        return plaintext
    }

    // MARK: - 签名

    public static func sign(userId: String, message: String, privateKey: String) throws -> String {
        guard let d = parsePrivateKey(privateKey) else {
            throw SM2Error.invalidKey("Invalid private key")
        }
        guard userId.utf8.count <= SM2Limits.maximumUserIdBytes else {
            throw SM2Error.invalidInput("User ID too long")
        }
        let publicKey = ECPoint.multiplyGenerator(d)
        let e = messageDigest(userId: userId, message: message, publicKey: publicKey)

        for _ in 0..<SM2Limits.maximumAttempts {
            let k = try randomScalar(belowNMinus1: false)
            if let (r, s) = signDigest(e: e, d: d, k: k) {
                return "\(r.toHexLower())h\(s.toHexLower())"
            }
        }
        throw SM2Error.randomFailure("Too many rejected values")
    }

    /// 用给定的随机数计算签名；这组 k 不可用时返回 nil。要求 d 在 [1, n-2]，k 在 [1, n-1]。
    static func signDigest(e: BigInt256, d: BigInt256, k: BigInt256) -> (r: BigInt256, s: BigInt256)? {
        let n = SM2Curve.n

        // (x1, y1) = [k]G
        let point = ECPoint.multiplyGenerator(k)

        // r = (e + x1) mod n。e < 2^256，x1 < p < 2n，都先完全约减。
        let r = reduceModN(e).modAdd(reduceModN(point.x.toBigInt()), n)

        // r == 0 或 r + k == n 时换一个 k
        let (rk, _) = r.add(k)
        let rejected = r.isZeroMask | BigInt256.equalMask(rk, n)
        if rejected != 0 {
            return nil
        }

        // s = ((1 + d)^-1 * (k - r*d)) mod n
        let dPlus1Inverse = d.add(BigInt256.one).0.modInverse(n)
        let s = k.modSub(r.modMul(d, n), n).modMul(dPlus1Inverse, n)
        return s.isZero ? nil : (r, s)
    }

    /// value < 2n 时的完全约减。e 可以是任意256位值：2^256 < 2n。
    private static func reduceModN(_ value: BigInt256) -> BigInt256 {
        let (reduced, borrow) = value.subtractingWithBorrow(SM2Curve.n)
        return BigInt256.select(zeroMask(borrow), reduced, value)
    }

    // MARK: - 验签

    /// 签名格式是 r + "h" + s，r、s 都是恰好64个十六进制字符。任何不合法的输入都返回 false。
    public static func verify(userId: String, signature: String, message: String, publicKey: String) -> Bool {
        guard let (r, s) = parseSignature(signature) else {
            return false
        }

        if r.isZero || r >= SM2Curve.n || s.isZero || s >= SM2Curve.n {
            return false
        }
        if userId.utf8.count > SM2Limits.maximumUserIdBytes {
            return false
        }

        let pubPoint = ECPoint.fromHexEncoded(publicKey)
        if !pubPoint.isValidPublicKey {
            return false
        }

        let e = messageDigest(userId: userId, message: message, publicKey: pubPoint)

        // t = (r + s) mod n
        let t = r.modAdd(s, SM2Curve.n)
        if t.isZero {
            return false
        }

        // (x1, y1) = [s]G + [t]PA，全部是公开数据，使用可变时间的 wNAF 双标量乘法
        let point = JacobianPoint.multiplyPublicPair(
            generatorScalar: s, pointScalar: t, point: pubPoint.toJacobian())
        if point.isInfinity {
            return false
        }

        return signatureMatches(point: point, r: r, e: e)
    }

    private static func parseSignature(_ signature: String) -> (BigInt256, BigInt256)? {
        var copy = signature
        return copy.withUTF8 { utf8 -> (BigInt256, BigInt256)? in
            guard utf8.count == 129, utf8[64] == UInt8(ascii: "h") else {
                return nil
            }
            let rPart = String(decoding: UnsafeBufferPointer(rebasing: utf8[0..<64]), as: UTF8.self)
            let sPart = String(decoding: UnsafeBufferPointer(rebasing: utf8[65...]), as: UTF8.self)
            guard let r = BigInt256(hex: rPart), let s = BigInt256(hex: sPart) else {
                return nil
            }
            return (r, s)
        }
    }

    /// 判断 r == (e + x1) mod n，其中 x1 = X/Z^2，无需求逆。x1 在 [0, p) 内而 p < 2n，
    /// 所以 x1 只可能是 c = (r - e) mod n 或 c + n（后者要求小于 p）。
    static func signatureMatches(point: JacobianPoint, r: BigInt256, e: BigInt256) -> Bool {
        let n = SM2Curve.n
        let candidate = r.modSub(reduceModN(e), n)
        if point.affineXEquals(candidate) {
            return true
        }
        let (shifted, carry) = candidate.addingWithCarry(n)
        return carry == 0 && shifted < SM2Curve.p && point.affineXEquals(shifted)
    }

    // MARK: - 密钥交换协议

    private static let invalidKeyExchangeInput = "协商失败，输入参数不合法"

    /// 所有点、私钥、长度和用户 ID 都通过校验才返回 true。
    private static func keyExchangeInputsValid(
        byteLen: Int, points: [ECPoint], scalars: [BigInt256], ids: [String]
    ) -> Bool {
        var scalarsValid: UInt64 = .max
        for scalar in scalars {
            scalarsValid &= validPrivateKeyMask(scalar)
        }
        return SM2Limits.keyExchangeLengths.contains(byteLen) && scalarsValid != 0
            && points.allSatisfy { $0.isValidPublicKey }
            && ids.allSatisfy { $0.utf8.count <= SM2Limits.maximumUserIdBytes }
    }

    // swift-format-ignore: AlwaysUseLowerCamelCase
    public static func getSb(
        byteLen: Int,
        pA: ECPoint, Ra: ECPoint,
        pB: ECPoint, dB: BigInt256, Rb: ECPoint, rb: BigInt256,
        IDa: String, IDb: String
    ) -> SM2KeySwapParams {
        guard
            keyExchangeInputsValid(
                byteLen: byteLen, points: [pA, Ra, pB, Rb], scalars: [dB, rb], ids: [IDa, IDb])
        else {
            return SM2KeySwapParams.failure(invalidKeyExchangeInput)
        }

        let result = SM2KeySwapParams()

        // tb = (dB + x2_ * rb) mod n，x2_ = 2^w + (x2 & (2^w - 1))
        let tb = calcT(n: SM2Curve.n, r: rb, d: dB, xBar: calcX(Rb.x.toBigInt()))

        // V = [tb](PA + [x1_]RA)
        let v = calcPoint(t: tb, xBar: calcX(Ra.x.toBigInt()), p: pA, r: Ra)
        if v.isInfinity {
            return SM2KeySwapParams.failure("协商失败，V点是无穷远点")
        }

        let za = userSM3Z(userId: IDa, publicKey: pA)
        let zb = userSM3Z(userId: IDb, publicKey: pB)

        var kb = kdfKeySwap(keylen: byteLen, vu: v, za: za, zb: zb)
        defer { secureWipe(&kb) }
        let sb = createS(tag: 0x02, vu: v, za: za, zb: zb, ra: Ra, rb: Rb)

        result.sb = Hex.encode(sb)
        result.kb = Hex.encode(kb)
        result.v = v
        result.za = za
        result.zb = zb
        result.success = true

        return result
    }

    // swift-format-ignore: AlwaysUseLowerCamelCase
    public static func getSa(
        byteLen: Int,
        pB: ECPoint, Rb: ECPoint,
        pA: ECPoint, dA: BigInt256, Ra: ECPoint, ra: BigInt256,
        IDa: String, IDb: String,
        Sb: [UInt8]
    ) -> SM2KeySwapParams {
        guard
            keyExchangeInputsValid(
                byteLen: byteLen, points: [pB, Rb, pA, Ra], scalars: [dA, ra], ids: [IDa, IDb])
        else {
            return SM2KeySwapParams.failure(invalidKeyExchangeInput)
        }

        let result = SM2KeySwapParams()

        // ta = (dA + x1_ * ra) mod n，x1_ = 2^w + (x1 & (2^w - 1))
        let ta = calcT(n: SM2Curve.n, r: ra, d: dA, xBar: calcX(Ra.x.toBigInt()))

        // U = [ta](PB + [x2_]RB)
        let u = calcPoint(t: ta, xBar: calcX(Rb.x.toBigInt()), p: pB, r: Rb)
        if u.isInfinity {
            return SM2KeySwapParams.failure("协商失败，U点是无穷远点")
        }

        let za = userSM3Z(userId: IDa, publicKey: pA)
        let zb = userSM3Z(userId: IDb, publicKey: pB)

        var ka = kdfKeySwap(keylen: byteLen, vu: u, za: za, zb: zb)
        defer { secureWipe(&ka) }
        let s1 = createS(tag: 0x02, vu: u, za: za, zb: zb, ra: Ra, rb: Rb)

        // constantTimeEquals 对长度不同（包括空）的 Sb 返回 false
        if !constantTimeEquals(s1, Sb) {
            return SM2KeySwapParams.failure("协商失败，B用户验证值与A侧计算值不相等")
        }

        let sa = createS(tag: 0x03, vu: u, za: za, zb: zb, ra: Ra, rb: Rb)

        result.sa = Hex.encode(sa)
        result.ka = Hex.encode(ka)
        result.success = true

        return result
    }

    // swift-format-ignore: AlwaysUseLowerCamelCase
    public static func checkSa(V: ECPoint, Za: [UInt8], Zb: [UInt8], Ra: ECPoint, Rb: ECPoint, Sa: [UInt8]) -> Bool {
        guard V.isValidPublicKey, Ra.isValidPublicKey, Rb.isValidPublicKey, Za.count == 32, Zb.count == 32 else {
            return false
        }
        return constantTimeEquals(createS(tag: 0x03, vu: V, za: Za, zb: Zb, ra: Ra, rb: Rb), Sa)
    }

    // MARK: - 辅助方法

    static func decodePoint(_ hex: String) -> ECPoint {
        return ECPoint.fromHexEncoded(hex)
    }

    static func getPublicKey(_ privateKey: BigInt256) -> ECPoint {
        return ECPoint.multiplyGenerator(privateKey)
    }

    // MARK: - 私钥与随机数

    /// d 在 [1, n-2] 内时返回全 1，否则返回 0。不依赖 d 的值分支。
    static func validPrivateKeyMask(_ d: BigInt256) -> UInt64 {
        let nMinus1 = SM2Curve.n.subtractingWithBorrow(BigInt256.one).difference
        let belowLimit = 0 &- d.subtractingWithBorrow(nMinus1).borrow
        return belowLimit & ~d.isZeroMask
    }

    /// 严格解析私钥：恰好64个十六进制字符，取值在 [1, n-2] 内。解析和范围判断都不依赖私钥的值分支。
    static func parsePrivateKey(_ hex: String) -> BigInt256? {
        guard let d = BigInt256(hex: hex), validPrivateKeyMask(d) != 0 else {
            return nil
        }
        return d
    }

    /// 操作系统 CSPRNG 产生32字节写入 buffer。
    /// Apple 平台的 SecRandomCopyBytes 失败时抛错；其它平台使用标准库的 SystemRandomNumberGenerator
    /// （Linux 的 getrandom/urandom、Windows 的 BCrypt），标准库在随机源失败时直接中止进程，不会返回弱随机数。
    private static func fillRandom(_ buffer: UnsafeMutableRawBufferPointer) throws {
        #if canImport(Security)
            guard let base = buffer.baseAddress,
                SecRandomCopyBytes(kSecRandomDefault, buffer.count, base) == errSecSuccess
            else {
                throw SM2Error.randomFailure("System random generator failed")
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

    /// 拒绝采样：均匀分布在 [1, n-1]（belowNMinus1 为 true 时是 [1, n-2]），没有取模偏差。
    private static func randomScalar(belowNMinus1: Bool) throws -> BigInt256 {
        let n = SM2Curve.n
        let limit = belowNMinus1 ? n.subtractingWithBorrow(BigInt256.one).difference : n
        for _ in 0..<SM2Limits.maximumAttempts {
            let candidate = try withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 32) { bytes -> BigInt256 in
                let raw = UnsafeMutableRawBufferPointer(bytes)
                defer { secureWipe(raw) }
                try fillRandom(raw)
                return raw.withMemoryRebound(to: UInt8.self) { typed in
                    guard let base = typed.baseAddress else {
                        return BigInt256.zero
                    }
                    return BigInt256.fromBEPointer(UnsafePointer(base))
                }
            }
            let inRange = (0 &- candidate.subtractingWithBorrow(limit).borrow) & ~candidate.isZeroMask
            if inRange != 0 {
                return candidate
            }
        }
        throw SM2Error.randomFailure("Too many rejected values")
    }

    // MARK: - 内部辅助方法

    /// e = SM3(Z || M)
    static func messageDigest(userId: String, message: String, publicKey: ECPoint) -> BigInt256 {
        var digest = SM3Core()
        digest.update(userSM3Z(userId: userId, publicKey: publicKey))
        digest.update(message)
        return BigInt256.fromBEBytes(digest.finalize())
    }

    /// KDF：prefix 是已吸收全部前缀数据的 SM3 状态，每个计数器值从它复制一份，不重复压缩前缀。
    /// keylen 由调用方限制在 SM2Limits.maximumKDFBytes 以内（消息已在内存中，或者已检查 byteLen）。
    private static func kdf(keylen: Int, prefix: SM3Core) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: keylen)
        result.withUnsafeMutableBufferPointer { output in
            withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 32) { hash in
                guard let base = output.baseAddress, let hashBase = hash.baseAddress else {
                    return
                }
                defer { secureWipe(UnsafeMutableRawBufferPointer(hash)) }
                var counter: UInt32 = 1
                var start = 0
                while start < keylen {
                    var core = prefix
                    var bigEndian = counter.bigEndian
                    withUnsafeBytes(of: &bigEndian) { core.update($0.bindMemory(to: UInt8.self)) }
                    if keylen - start >= 32 {
                        core.finalize(into: base + start)
                        start += 32
                    } else {
                        core.finalize(into: hashBase)
                        (base + start).update(from: hashBase, count: keylen - start)
                        start = keylen
                    }
                    counter &+= 1
                }
            }
        }
        return result
    }

    private static func kdfKeySwap(keylen: Int, vu: ECPoint, za: [UInt8], zb: [UInt8]) -> [UInt8] {
        var prefix = SM3Core()
        prefix.update(vu.x.value)
        prefix.update(vu.y.value)
        prefix.update(za)
        prefix.update(zb)
        return kdf(keylen: keylen, prefix: prefix)
    }

    /// 调用方必须已检查 userId 不超过 8191 字节，这里的 ENTL 不会回绕。
    private static func userSM3Z(userId: String, publicKey: ECPoint) -> [UInt8] {
        var digest = SM3Core()

        // ENTL (2字节)
        let entl = UInt16(truncatingIfNeeded: userId.utf8.count &* 8)
        digest.update(byte: UInt8(truncatingIfNeeded: entl >> 8))
        digest.update(byte: UInt8(truncatingIfNeeded: entl))

        digest.update(userId)
        digest.update(SM2Curve.a)
        digest.update(SM2Curve.b)
        digest.update(SM2Curve.gx)
        digest.update(SM2Curve.gy)
        digest.update(publicKey.x.value)
        digest.update(publicKey.y.value)
        return digest.finalize()
    }

    /// x_ = 2^127 + (x & (2^127 - 1))
    private static func calcX(_ x: BigInt256) -> BigInt256 {
        return BigInt256(x.l0, x.l1 | (UInt64(1) << 63), 0, 0)
    }

    private static func calcT(n: BigInt256, r: BigInt256, d: BigInt256, xBar: BigInt256) -> BigInt256 {
        return d.modAdd(xBar.modMul(r, n), n)
    }

    /// [t](P + [x_]R)：x_ 由公开点 R 算出，可以用可变时间；t 是秘密，用恒定时间。P、R 都已校验。
    private static func calcPoint(t: BigInt256, xBar: BigInt256, p: ECPoint, r: ECPoint) -> ECPoint {
        return p.add(r.multiplyPublic(xBar)).multiply(t)
    }

    private static func createS(
        tag: UInt8, vu: ECPoint, za: [UInt8], zb: [UInt8], ra: ECPoint, rb: ECPoint
    ) -> [UInt8] {
        // 第一个哈希
        var inner = SM3Core()
        inner.update(vu.x.value)
        inner.update(za)
        inner.update(zb)
        inner.update(ra.x.value)
        inner.update(ra.y.value)
        inner.update(rb.x.value)
        inner.update(rb.y.value)

        // 第二个哈希
        var outer = SM3Core()
        outer.update(byte: tag)
        outer.update(vu.y.value)
        outer.update(inner.finalize())
        return outer.finalize()
    }
}

// MARK: - 错误类型

/// 错误信息不包含任何密钥或明文内容。
public enum SM2Error: Error {
    case invalidInput(String)
    case invalidKey(String)
    case decryptionFailed(String)
    case randomFailure(String)
}

// MARK: - 辅助函数

/// 按字节异或，长度取 data 与 key 中较短者（调用方保证等长）
private func xorBytes(_ data: [UInt8], _ key: [UInt8]) -> [UInt8] {
    let count = min(data.count, key.count)
    return [UInt8](unsafeUninitializedCapacity: count) { buffer, initialized in
        data.withUnsafeBufferPointer { input in
            key.withUnsafeBufferPointer { stream in
                for index in 0..<count {
                    buffer[index] = input[index] ^ stream[index]
                }
            }
        }
        initialized = count
    }
}

/// 比较时间只取决于长度。不内联，以便 Tools/check_constant_time.py 检查编译结果。
@inline(never)
private func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
    if lhs.count != rhs.count {
        return false
    }
    var difference: UInt8 = 0
    for index in 0..<lhs.count {
        difference |= lhs[index] ^ rhs[index]
    }
    return difference == 0
}

@inline(never)
private func constantTimeIsAllZero(_ bytes: [UInt8]) -> Bool {
    var accumulated: UInt8 = 0
    for byte in bytes {
        accumulated |= byte
    }
    return accumulated == 0
}
