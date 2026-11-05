// SM2椭圆曲线公钥密码算法实现：加解密、签名验签、密钥交换

import Foundation

#if canImport(Security)
    import Security
#endif

// MARK: - SM2密钥交换参数

public final class SM2KeySwapParams {
    public var sa: String?
    public var sb: String?
    public var ka: String?
    public var kb: String?
    public var v: ECPoint?
    public var za: [UInt8]?
    public var zb: [UInt8]?
    public var success: Bool = false
    public var message: String?
}

// MARK: - SM2主类

public final class SM2 {

    // MARK: - 密钥对生成

    public static func genKeyPair() -> (privateKey: String, publicKey: String) {
        while true {
            let privateKey = randomBigInt()

            if privateKey.isZero || privateKey >= SM2Curve.n {
                continue
            }

            let publicKey = ECPoint.multiplyGenerator(privateKey)

            let priHex = privateKey.toHex()
            let pubHex = publicKey.toHexEncoded()

            if priHex.count == 64 && pubHex.count == 130 {
                return (priHex, pubHex)
            }
        }
    }

    // MARK: - 加密

    public static func encrypt(_ plaintext: String, publicKey: String) throws -> String {
        let message = Array(plaintext.utf8)
        if message.isEmpty {
            throw SM2Error.invalidInput("Plaintext cannot be empty")
        }

        let pubPoint = ECPoint.fromHexEncoded(publicKey)
        if !pubPoint.isOnCurve() {
            throw SM2Error.invalidKey("Invalid public key")
        }

        while true {
            let k = randomBigInt()
            if k.isZero || k >= SM2Curve.n {
                continue
            }

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
            let key = kdf(keylen: message.count, prefix: keyPrefix)

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
    }

    // MARK: - 解密

    public static func decrypt(_ ciphertext: String, privateKey: String) throws -> String {
        // 规范输入一次解码，否则走按字符的原有路径（错误信息和对非常规输入的处理保持不变）
        if let bytes = Hex.decodeStrict(ciphertext), bytes.count >= 97 {
            let c1 = ECPoint.fromEncoded(Array(bytes[0..<65]))
            return try decrypt(
                c1: c1, c3: { Array(bytes[65..<97]) }, c2: { Array(bytes[97...]) }, privateKey: privateKey)
        }

        if ciphertext.count < 130 + 64 {
            throw SM2Error.invalidInput("Ciphertext too short")
        }

        // 解析 C1 || C3 || C2
        let c1Hex = String(ciphertext.prefix(130))
        let c3Hex = String(ciphertext.dropFirst(130).prefix(64))
        let c2Hex = String(ciphertext.dropFirst(194))

        return try decrypt(
            c1: ECPoint.fromHexEncoded(c1Hex),
            c3: { try hexToBytes(c3Hex) },
            c2: { try hexToBytes(c2Hex) },
            privateKey: privateKey
        )
    }

    private static func decrypt(
        c1: ECPoint, c3 decodeC3: () throws -> [UInt8], c2 decodeC2: () throws -> [UInt8], privateKey: String
    ) throws -> String {
        if !c1.isOnCurve() {
            throw SM2Error.invalidInput("Invalid C1 point")
        }

        let c3 = try decodeC3()
        let c2 = try decodeC2()

        let d = BigInt256.fromHex(privateKey)

        // P2 = [d]C1
        let p2 = c1.multiply(d)
        if p2.isInfinity {
            throw SM2Error.decryptionFailed("Invalid decryption")
        }

        // KDF，M = C2 XOR t
        var keyPrefix = SM3Core()
        keyPrefix.update(p2.x.value)
        keyPrefix.update(p2.y.value)
        let message = xorBytes(c2, kdf(keylen: c2.count, prefix: keyPrefix))

        // 验证 C3
        var digest = SM3Core()
        digest.update(p2.x.value)
        digest.update(message)
        digest.update(p2.y.value)

        if !constantTimeEquals(digest.finalize(), c3) {
            throw SM2Error.decryptionFailed("Decryption verification failed")
        }

        guard let plaintext = String(bytes: message, encoding: .utf8) else {
            throw SM2Error.decryptionFailed("UTF-8 decode error")
        }

        return plaintext
    }

    // MARK: - 签名

    public static func sign(userId: String, message: String, privateKey: String) throws -> String {
        let d = BigInt256.fromHex(privateKey)
        let publicKey = ECPoint.multiplyGenerator(d)
        let e = messageDigest(userId: userId, message: message, publicKey: publicKey)

        while true {
            let k = randomBigInt()
            if k.isZero || k >= SM2Curve.n {
                continue
            }

            // (x1, y1) = [k]G
            let x1 = ECPoint.multiplyGenerator(k).x.toBigInt()

            // r = (e + x1) mod n
            let r = e.modAdd(x1, SM2Curve.n)
            if r.isZero {
                continue
            }

            // 检查 r + k != n
            let (rk, _) = r.add(k)
            if rk == SM2Curve.n {
                continue
            }

            // s = ((1 + d)^-1 * (k - r*d)) mod n
            let (dPlus1, _) = d.add(BigInt256.one)
            let dPlus1Inverse = dPlus1.modInverse(SM2Curve.n)
            let rd = r.modMul(d, SM2Curve.n)
            let s = k.modSub(rd, SM2Curve.n).modMul(dPlus1Inverse, SM2Curve.n)

            if s.isZero {
                continue
            }

            return "\(r.toHexLower())h\(s.toHexLower())"
        }
    }

    // MARK: - 验签

    public static func verify(userId: String, signature: String, message: String, publicKey: String) -> Bool {
        let parts = signature.split(separator: "h")
        if parts.count != 2 {
            return false
        }

        let r = BigInt256.fromHex(String(parts[0]))
        let s = BigInt256.fromHex(String(parts[1]))

        if r.isZero || r >= SM2Curve.n {
            return false
        }
        if s.isZero || s >= SM2Curve.n {
            return false
        }

        let pubPoint = ECPoint.fromHexEncoded(publicKey)
        if !pubPoint.isOnCurve() {
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

    /// 判断 r == e.modAdd(x1, n)，其中 x1 = X/Z^2，无需求逆。
    ///
    /// modAdd 在和小于 n 时返回 e + x1，否则返回 (e + x1 - n) mod 2^256，
    /// 所以 x1 只可能是 r - e 或 (r + n - e) mod 2^256。每个候选值先用 modAdd 本身确认，
    /// 再与点比较，这样对 e >= n、x1 >= n 这些边界的判定与直接计算完全一致。
    static func signatureMatches(point: JacobianPoint, r: BigInt256, e: BigInt256) -> Bool {
        let n = SM2Curve.n
        let (direct, borrow) = r.subtractingWithBorrow(e)
        if borrow == 0 && e.modAdd(direct, n) == r && point.affineXEquals(direct) {
            return true
        }
        let wrapped = r.add(n).0.sub(e).0
        return wrapped < SM2Curve.p && e.modAdd(wrapped, n) == r && point.affineXEquals(wrapped)
    }

    // MARK: - 密钥交换协议

    // swift-format-ignore: AlwaysUseLowerCamelCase
    public static func getSb(
        byteLen: Int,
        pA: ECPoint, Ra: ECPoint,
        pB: ECPoint, dB: BigInt256, Rb: ECPoint, rb: BigInt256,
        IDa: String, IDb: String
    ) -> SM2KeySwapParams {
        let result = SM2KeySwapParams()

        // x2_ = 2^w + (x2 & (2^w - 1))
        let x2Bar = calcX(Rb.x.toBigInt())

        // tb = (dB + x2_ * rb) mod n
        let tb = calcT(n: SM2Curve.n, r: rb, d: dB, xBar: x2Bar)

        // 验证 Ra 在曲线上
        if !Ra.isOnCurve() {
            result.message = "协商失败，A用户随机公钥不是椭圆曲线倍点"
            return result
        }

        // x1_ = 2^w + (x1 & (2^w - 1))
        let x1Bar = calcX(Ra.x.toBigInt())

        // V = [tb](PA + [x1_]RA)
        let v = calcPoint(t: tb, xBar: x1Bar, p: pA, r: Ra)
        if v.isInfinity {
            result.message = "协商失败，V点是无穷远点"
            return result
        }

        let za = userSM3Z(userId: IDa, publicKey: pA)
        let zb = userSM3Z(userId: IDb, publicKey: pB)

        let kb = kdfKeySwap(keylen: byteLen, vu: v, za: za, zb: zb)
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
        let result = SM2KeySwapParams()

        // x1_ = 2^w + (x1 & (2^w - 1))
        let x1Bar = calcX(Ra.x.toBigInt())

        // ta = (dA + x1_ * ra) mod n
        let ta = calcT(n: SM2Curve.n, r: ra, d: dA, xBar: x1Bar)

        // 验证 Rb 在曲线上
        if !Rb.isOnCurve() {
            result.message = "协商失败，B用户随机公钥不是椭圆曲线倍点"
            return result
        }

        // x2_ = 2^w + (x2 & (2^w - 1))
        let x2Bar = calcX(Rb.x.toBigInt())

        // U = [ta](PB + [x2_]RB)
        let u = calcPoint(t: ta, xBar: x2Bar, p: pB, r: Rb)
        if u.isInfinity {
            result.message = "协商失败，U点是无穷远点"
            return result
        }

        let za = userSM3Z(userId: IDa, publicKey: pA)
        let zb = userSM3Z(userId: IDb, publicKey: pB)

        let ka = kdfKeySwap(keylen: byteLen, vu: u, za: za, zb: zb)
        let s1 = createS(tag: 0x02, vu: u, za: za, zb: zb, ra: Ra, rb: Rb)

        if !constantTimeEquals(s1, Sb) {
            result.message = "协商失败，B用户验证值与A侧计算值不相等"
            return result
        }

        let sa = createS(tag: 0x03, vu: u, za: za, zb: zb, ra: Ra, rb: Rb)

        result.sa = Hex.encode(sa)
        result.ka = Hex.encode(ka)
        result.success = true

        return result
    }

    // swift-format-ignore: AlwaysUseLowerCamelCase
    public static func checkSa(V: ECPoint, Za: [UInt8], Zb: [UInt8], Ra: ECPoint, Rb: ECPoint, Sa: [UInt8]) -> Bool {
        return constantTimeEquals(createS(tag: 0x03, vu: V, za: Za, zb: Zb, ra: Ra, rb: Rb), Sa)
    }

    // MARK: - 辅助方法

    static func decodePoint(_ hex: String) -> ECPoint {
        return ECPoint.fromHexEncoded(hex)
    }

    static func getPublicKey(_ privateKey: BigInt256) -> ECPoint {
        return ECPoint.multiplyGenerator(privateKey)
    }

    // MARK: - 内部辅助方法

    private static func randomBigInt() -> BigInt256 {
        var bytes = [UInt8](repeating: 0, count: 32)
        #if canImport(Security)
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        #else
            for i in 0..<32 {
                bytes[i] = UInt8.random(in: 0...255)
            }
        #endif
        return BigInt256.fromBEBytes(bytes)
    }

    /// e = SM3(Z || M)
    private static func messageDigest(userId: String, message: String, publicKey: ECPoint) -> BigInt256 {
        var digest = SM3Core()
        digest.update(userSM3Z(userId: userId, publicKey: publicKey))
        digest.update(message)
        return BigInt256.fromBEBytes(digest.finalize())
    }

    /// KDF：prefix 是已吸收全部前缀数据的 SM3 状态，每个计数器值从它复制一份，不重复压缩前缀。
    private static func kdf(keylen: Int, prefix: SM3Core) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: keylen)
        let blocks = (keylen + 31) / 32
        result.withUnsafeMutableBufferPointer { output in
            withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 32) { hash in
                guard let base = output.baseAddress, let hashBase = hash.baseAddress else {
                    return
                }
                var counter: UInt32 = 1
                for index in 0..<blocks {
                    var core = prefix
                    var bigEndian = counter.bigEndian
                    withUnsafeBytes(of: &bigEndian) { core.update($0.bindMemory(to: UInt8.self)) }
                    let start = index * 32
                    if keylen - start >= 32 {
                        core.finalize(into: base + start)
                    } else {
                        core.finalize(into: hashBase)
                        (base + start).update(from: hashBase, count: keylen - start)
                    }
                    counter += 1
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

    private static func userSM3Z(userId: String, publicKey: ECPoint) -> [UInt8] {
        var digest = SM3Core()

        // ENTL (2字节)，ID 超过 8191 字节时触发溢出陷阱（既有行为）
        let entl = UInt16(userId.utf8.count * 8)
        digest.update(byte: UInt8(entl >> 8))
        digest.update(byte: UInt8(entl & 0xFF))

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

    /// [t](P + [x_]R)：x_ 由公开点 R 算出，可以用可变时间；t 是秘密，用恒定时间。R 已校验在曲线上。
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

enum SM2Error: Error {
    case invalidInput(String)
    case invalidKey(String)
    case decryptionFailed(String)
}

// MARK: - 辅助函数

/// 按字节异或，长度取 data 的长度（调用方保证 key 不短于 data）
private func xorBytes(_ data: [UInt8], _ key: [UInt8]) -> [UInt8] {
    precondition(key.count >= data.count)
    return [UInt8](unsafeUninitializedCapacity: data.count) { buffer, initialized in
        data.withUnsafeBufferPointer { input in
            key.withUnsafeBufferPointer { stream in
                for index in 0..<input.count {
                    buffer[index] = input[index] ^ stream[index]
                }
            }
        }
        initialized = data.count
    }
}

/// 比较时间只取决于长度
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

private func constantTimeIsAllZero(_ bytes: [UInt8]) -> Bool {
    return bytes.reduce(0, |) == 0
}

private func hexToBytes(_ hex: String) throws -> [UInt8] {
    if hex.count % 2 != 0 {
        throw SM2Error.invalidInput("Invalid hex string length")
    }
    if let bytes = Hex.decodeStrict(hex) {
        return bytes
    }
    var bytes = [UInt8]()
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
            throw SM2Error.invalidInput("Invalid hex character")
        }
        bytes.append(byte)
        index = nextIndex
    }
    return bytes
}
