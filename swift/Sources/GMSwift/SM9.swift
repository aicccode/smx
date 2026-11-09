// SM9 标识密码算法（GB/T 38635）：主密钥与用户密钥生成、签名验签、密钥封装、加解密。密钥交换见 SM9KeyExchange.swift。
//
// 接口风格与 SM2 相同：十六进制字符串输入输出（输出一律小写），失败抛 SM9Error，验签只返回 Bool。
// - 主私钥、用户私钥、主公钥：十六进制，大小写均可，长度精确，必须是合法值
//   （标量在 [1, N-1]；点在曲线上、坐标小于 q、不是无穷远点，G2 点还要在子群里）。
// - 签名、密文：只接受小写十六进制（每个值只有一种字符串）。
// - 用户标识是字节串，字符串接口用 UTF-8；允许空标识。
// 秘密标量（主私钥、r、l、t2）只经过固定窗口 + 全表扫描的标量乘法和 GT 幂运算。

import Foundation

/// SM9 加密的对称部分。密文不记录模式，解密时要传入同样的模式。
public enum SM9EncryptionMode {
    /// 基于 KDF 的序列密码（默认）
    case stream
    /// SM4-ECB + PKCS#7（GB/T 38635.5 示例使用的模式）
    case sm4
}

public final class SM9 {
    public static let hidSign: UInt8 = 0x01
    public static let hidExchange: UInt8 = 0x02
    public static let hidEncrypt: UInt8 = 0x03

    // MARK: - 签名主密钥与用户密钥

    /// 生成签名主密钥对：主私钥 ks（64个十六进制字符）和主公钥 Ppub-s = [ks]P2（G2 点，258个十六进制字符）
    public static func genSignMasterKey() throws -> (masterPrivateKey: String, masterPublicKey: String) {
        let ks = try SM9Support.randomScalar()
        return (ks.toHexLower(), signMasterPublicPoint(ks))
    }

    /// 由签名主私钥计算主公钥
    public static func signMasterPublicKey(_ masterPrivateKey: String) throws -> String {
        guard let ks = SM9Support.parseScalar(masterPrivateKey) else {
            throw SM9Error.invalidKey("Invalid master private key")
        }
        return signMasterPublicPoint(ks)
    }

    private static func signMasterPublicPoint(_ ks: BigInt256) -> String {
        let point = SM9G2.multiplySecret(SM9Points.p2.jacobian, ks).toAffine()
        return Hex.encode(point.map(SM9Points.encodeG2) ?? [])
    }

    /// 签名用户私钥 ds = [ks / (H1(ID||hid) + ks)]P1（G1 点）
    public static func genSignUserKey(masterPrivateKey: String, userId: String, hid: UInt8 = hidSign) throws -> String {
        return try genSignUserKey(masterPrivateKey: masterPrivateKey, userId: Array(userId.utf8), hid: hid)
    }

    public static func genSignUserKey(masterPrivateKey: String, userId: [UInt8], hid: UInt8 = hidSign) throws
        -> String
    {
        let t2 = try userKeyScalar(masterPrivateKey, userId: userId, hid: hid)
        let point = SM9G1.multiplySecret(SM9Points.p1.jacobian, t2).toAffine()
        return Hex.encode(point.map(SM9Points.encodeG1) ?? [])
    }

    // MARK: - 加密主密钥与用户密钥

    /// 生成加密主密钥对：主私钥 ke 和主公钥 Ppub-e = [ke]P1（G1 点，130个十六进制字符）
    public static func genEncMasterKey() throws -> (masterPrivateKey: String, masterPublicKey: String) {
        let ke = try SM9Support.randomScalar()
        return (ke.toHexLower(), encMasterPublicPoint(ke))
    }

    public static func encMasterPublicKey(_ masterPrivateKey: String) throws -> String {
        guard let ke = SM9Support.parseScalar(masterPrivateKey) else {
            throw SM9Error.invalidKey("Invalid master private key")
        }
        return encMasterPublicPoint(ke)
    }

    private static func encMasterPublicPoint(_ ke: BigInt256) -> String {
        let point = SM9G1.multiplySecret(SM9Points.p1.jacobian, ke).toAffine()
        return Hex.encode(point.map(SM9Points.encodeG1) ?? [])
    }

    /// 加密（以及密钥封装、密钥交换）用户私钥 de = [ke / (H1(ID||hid) + ke)]P2（G2 点）。
    /// 密钥交换的用户私钥用 hid = hidExchange 生成。
    public static func genEncUserKey(masterPrivateKey: String, userId: String, hid: UInt8 = hidEncrypt) throws -> String
    {
        return try genEncUserKey(masterPrivateKey: masterPrivateKey, userId: Array(userId.utf8), hid: hid)
    }

    public static func genEncUserKey(masterPrivateKey: String, userId: [UInt8], hid: UInt8 = hidEncrypt) throws
        -> String
    {
        let t2 = try userKeyScalar(masterPrivateKey, userId: userId, hid: hid)
        let point = SM9G2.multiplySecret(SM9Points.p2.jacobian, t2).toAffine()
        return Hex.encode(point.map(SM9Points.encodeG2) ?? [])
    }

    /// t2 = s * (H1(ID||hid) + s)^-1 mod N；t1 = 0 时报错
    private static func userKeyScalar(_ masterPrivateKey: String, userId: [UInt8], hid: UInt8) throws -> BigInt256 {
        guard let s = SM9Support.parseScalar(masterPrivateKey) else {
            throw SM9Error.invalidKey("Invalid master private key")
        }
        let t1 = SM9Scalar.add(SM9Support.h1(userId, [hid]), s)
        if t1.isZero {
            throw SM9Error.invalidInput("Cannot derive a key for this identity, generate a new master key")
        }
        return SM9Scalar.mul(s, SM9Scalar.inverse(t1))
    }

    // MARK: - 签名

    public static func sign(_ message: String, userPrivateKey: String, masterPublicKey: String) throws -> String {
        return try sign(Array(message.utf8), userPrivateKey: userPrivateKey, masterPublicKey: masterPublicKey)
    }

    /// 签名 h || S（97字节，194个小写十六进制字符）
    public static func sign(_ message: [UInt8], userPrivateKey: String, masterPublicKey: String) throws -> String {
        guard let ds = SM9Points.decodeG1Hex(userPrivateKey) else {
            throw SM9Error.invalidKey("Invalid user private key")
        }
        guard let ppubS = SM9Points.decodeG2Hex(masterPublicKey) else {
            throw SM9Error.invalidKey("Invalid master public key")
        }
        let g = SM9MasterPairingCache.shared.signBase(ppubS)
        for _ in 0..<SM9Limits.maximumAttempts {
            let r = try SM9Support.randomScalar()
            if let signature = signWithRandom(message, ds: ds, g: g, r: r) {
                return signature
            }
        }
        throw SM9Error.randomFailure("Too many rejected values")
    }

    /// 测试入口：用给定的 r（[1, N-1]）签名，l = 0 时返回 nil。ppubS 是签名主公钥的十六进制。
    static func signWithRandom(_ message: [UInt8], userPrivateKey: String, masterPublicKey: String, r: BigInt256)
        -> String?
    {
        guard let ds = SM9Points.decodeG1Hex(userPrivateKey), let ppubS = SM9Points.decodeG2Hex(masterPublicKey),
            SM9Scalar.validMask(r) != 0
        else {
            return nil
        }
        return signWithRandom(message, ds: ds, g: SM9MasterPairingCache.shared.signBase(ppubS), r: r)
    }

    private static func signWithRandom(_ message: [UInt8], ds: SM9Affine<SM9Fp>, g: SM9Fp12, r: BigInt256) -> String? {
        let w = SM9Pairing.powSecret(g, r)
        var wBytes = w.toBytes()
        defer { secureWipe(&wBytes) }
        let h = SM9Support.h2(message, wBytes)
        let l = SM9Scalar.sub(r, h)
        if l.isZero {
            return nil
        }
        guard let s = SM9G1.multiplySecret(ds.jacobian, l).toAffine() else {
            return nil
        }
        return Hex.encode(h.toBEBytes() + SM9Points.encodeG1(s))
    }

    // MARK: - 验签

    public static func verify(
        _ message: String, signature: String, userId: String, masterPublicKey: String, hid: UInt8 = hidSign
    ) -> Bool {
        return verify(
            Array(message.utf8), signature: signature, userId: Array(userId.utf8), masterPublicKey: masterPublicKey,
            hid: hid)
    }

    public static func verify(
        _ message: [UInt8], signature: String, userId: String, masterPublicKey: String, hid: UInt8 = hidSign
    ) -> Bool {
        return verify(
            message, signature: signature, userId: Array(userId.utf8), masterPublicKey: masterPublicKey, hid: hid)
    }

    /// 任何不合法的输入都返回 false。全部是公开数据。
    public static func verify(
        _ message: [UInt8], signature: String, userId: [UInt8], masterPublicKey: String, hid: UInt8 = hidSign
    ) -> Bool {
        guard signature.utf8.count == 194, let bytes = Hex.decodeCanonical(signature) else {
            return false
        }
        let h = BigInt256.fromBEBytes(Array(bytes[0..<32]))
        guard SM9Scalar.validMask(h) != 0, let s = SM9Points.decodeG1(Array(bytes[32...])),
            let ppubS = SM9Points.decodeG2Hex(masterPublicKey)
        else {
            return false
        }
        let g = SM9MasterPairingCache.shared.signBase(ppubS)
        let t = SM9Pairing.powSecret(g, h)
        let h1 = SM9Support.h1(userId, [hid])
        let p = SM9G2.multiplyPublic(SM9Points.p2.jacobian, h1).addPublic(ppubS.jacobian)
        let u = SM9Pairing.pairing(s, p.toAffine())
        let w = u.mul(t)
        return SM9Support.h2(message, w.toBytes()) == h
    }

    // MARK: - 公共部分

    /// Q = [H1(ID||hid)]P1 + Ppub-e。无穷远时返回 nil（只有恶意构造的主公钥才会这样）。
    static func identityPoint(_ userId: [UInt8], hid: UInt8, ppubE: SM9Affine<SM9Fp>) -> SM9G1? {
        let h1 = SM9Support.h1(userId, [hid])
        let q = SM9G1.multiplyPublic(SM9Points.p1.jacobian, h1).addPublic(ppubE.jacobian)
        return q.isInfinity ? nil : q
    }

    /// 解析加密主公钥，计算 Q 和 g = e(Ppub-e, P2)
    private static func encryptionContext(
        userId: [UInt8], masterPublicKey: String, hid: UInt8
    ) throws -> (q: SM9G1, g: SM9Fp12) {
        guard let ppubE = SM9Points.decodeG1Hex(masterPublicKey) else {
            throw SM9Error.invalidKey("Invalid master public key")
        }
        guard let q = identityPoint(userId, hid: hid, ppubE: ppubE) else {
            throw SM9Error.invalidKey("Invalid master public key")
        }
        return (q, SM9MasterPairingCache.shared.encryptBase(ppubE))
    }

    /// C = [r]Q 与 w = g^r 的编码。C 为无穷远时返回 nil。
    private static func randomizedPoint(q: SM9G1, g: SM9Fp12, r: BigInt256) -> (c: SM9Affine<SM9Fp>, w: [UInt8])? {
        guard let c = SM9G1.multiplySecret(q, r).toAffine() else {
            return nil
        }
        return (c, SM9Pairing.powSecret(g, r).toBytes())
    }

    // MARK: - 密钥封装

    /// 返回 (K, C)：K 是 keyLength 字节的密钥，C 是 G1 点（130个十六进制字符）。keyLength 在 [1, 1 MiB]。
    public static func encapsulate(
        userId: String, masterPublicKey: String, keyLength: Int, hid: UInt8 = hidEncrypt
    ) throws -> (key: String, ciphertext: String) {
        guard SM9Limits.keyLengths.contains(keyLength) else {
            throw SM9Error.invalidInput("Invalid key length")
        }
        let id = Array(userId.utf8)
        let context = try encryptionContext(userId: id, masterPublicKey: masterPublicKey, hid: hid)
        for _ in 0..<SM9Limits.maximumAttempts {
            let r = try SM9Support.randomScalar()
            if let result = encapsulate(id, context: context, keyLength: keyLength, r: r) {
                return result
            }
        }
        throw SM9Error.randomFailure("Too many rejected values")
    }

    /// 测试入口：用给定的 r 封装
    static func encapsulateWithRandom(
        userId: [UInt8], masterPublicKey: String, keyLength: Int, hid: UInt8, r: BigInt256
    ) throws -> (key: String, ciphertext: String)? {
        let context = try encryptionContext(userId: userId, masterPublicKey: masterPublicKey, hid: hid)
        return encapsulate(userId, context: context, keyLength: keyLength, r: r)
    }

    private static func encapsulate(
        _ userId: [UInt8], context: (q: SM9G1, g: SM9Fp12), keyLength: Int, r: BigInt256
    ) -> (key: String, ciphertext: String)? {
        guard let randomized = randomizedPoint(q: context.q, g: context.g, r: r) else {
            return nil
        }
        let c = randomized.c
        var w = randomized.w
        defer { secureWipe(&w) }
        var key = SM9Support.kdf([SM9Points.xyG1(c), w, userId], length: keyLength)
        defer { secureWipe(&key) }
        if sm9ConstantTimeIsAllZero(key) {
            return nil
        }
        return (Hex.encode(key), Hex.encode(SM9Points.encodeG1(c)))
    }

    /// 解封装。C 必须是小写十六进制的合法 G1 点；所有失败都是同一个错误。
    public static func decapsulate(
        _ ciphertext: String, userId: String, userPrivateKey: String, keyLength: Int
    ) throws -> String {
        guard SM9Limits.keyLengths.contains(keyLength) else {
            throw SM9Error.invalidInput("Invalid key length")
        }
        guard let de = SM9Points.decodeG2Hex(userPrivateKey) else {
            throw SM9Error.invalidKey("Invalid user private key")
        }
        guard ciphertext.utf8.count == 130, let bytes = Hex.decodeCanonical(ciphertext),
            let c = SM9Points.decodeG1(bytes)
        else {
            throw SM9Error.decryptionFailed("Decapsulation failed")
        }
        var w = SM9Pairing.pairing(c, de).toBytes()
        defer { secureWipe(&w) }
        var key = SM9Support.kdf([SM9Points.xyG1(c), w, Array(userId.utf8)], length: keyLength)
        defer { secureWipe(&key) }
        if sm9ConstantTimeIsAllZero(key) {
            throw SM9Error.decryptionFailed("Decapsulation failed")
        }
        return Hex.encode(key)
    }

    // MARK: - 加密

    public static func encrypt(
        _ plaintext: String, userId: String, masterPublicKey: String, hid: UInt8 = hidEncrypt,
        mode: SM9EncryptionMode = .stream
    ) throws -> String {
        var message = Array(plaintext.utf8)
        defer { secureWipe(&message) }
        return try encrypt(message, userId: userId, masterPublicKey: masterPublicKey, hid: hid, mode: mode)
    }

    /// 密文 C1 || C3 || C2（C1 是带 04 前缀的 G1 点），小写十六进制。明文不能为空。
    public static func encrypt(
        _ plaintext: [UInt8], userId: String, masterPublicKey: String, hid: UInt8 = hidEncrypt,
        mode: SM9EncryptionMode = .stream
    ) throws -> String {
        if plaintext.isEmpty {
            throw SM9Error.invalidInput("Plaintext cannot be empty")
        }
        if UInt64(plaintext.count) + 48 > SM9Limits.maximumKDFBytes {
            throw SM9Error.invalidInput("Plaintext too long")
        }
        let id = Array(userId.utf8)
        let context = try encryptionContext(userId: id, masterPublicKey: masterPublicKey, hid: hid)
        for _ in 0..<SM9Limits.maximumAttempts {
            let r = try SM9Support.randomScalar()
            if let cipher = encrypt(plaintext, userId: id, context: context, mode: mode, r: r) {
                return cipher
            }
        }
        throw SM9Error.randomFailure("Too many rejected values")
    }

    /// 测试入口：用给定的 r 加密
    static func encryptWithRandom(
        _ plaintext: [UInt8], userId: [UInt8], masterPublicKey: String, hid: UInt8, mode: SM9EncryptionMode,
        r: BigInt256
    ) throws -> String? {
        let context = try encryptionContext(userId: userId, masterPublicKey: masterPublicKey, hid: hid)
        return encrypt(plaintext, userId: userId, context: context, mode: mode, r: r)
    }

    private static func encrypt(
        _ plaintext: [UInt8], userId: [UInt8], context: (q: SM9G1, g: SM9Fp12), mode: SM9EncryptionMode, r: BigInt256
    ) -> String? {
        guard let randomized = randomizedPoint(q: context.q, g: context.g, r: r) else {
            return nil
        }
        let c1 = randomized.c
        var w = randomized.w
        defer { secureWipe(&w) }
        let k1Length = mode == .stream ? plaintext.count : SM9Limits.sm4KeyLength
        var key = SM9Support.kdf([SM9Points.xyG1(c1), w, userId], length: k1Length + SM9Limits.macKeyLength)
        defer { secureWipe(&key) }
        var k1 = Array(key[0..<k1Length])
        defer { secureWipe(&k1) }
        if sm9ConstantTimeIsAllZero(k1) {
            return nil
        }
        let c2: [UInt8]
        switch mode {
        case .stream:
            c2 = SM9Support.xor(plaintext, key[0..<k1Length])
        case .sm4:
            var padded = SM9Support.pkcs7Pad(plaintext)
            defer { secureWipe(&padded) }
            c2 = sm4ECB(key: k1, data: padded, decrypt: false)
        }
        let c3 = SM9Support.sm3(c2, Array(key[k1Length...]))
        return Hex.encode(SM9Points.encodeG1(c1) + c3 + c2)
    }

    // MARK: - 解密

    private static let decryptionFailure = SM9Error.decryptionFailed("Decryption failed")

    /// 解密为字节。密文必须是 encrypt 输出的小写十六进制，mode 与加密时相同。
    /// 先在恒定时间内比较 C3，再解密和去填充；所有失败（格式、C1、MAC、填充）都是同一个错误。
    public static func decrypt(
        _ ciphertext: String, userId: String, userPrivateKey: String, mode: SM9EncryptionMode = .stream
    ) throws -> [UInt8] {
        guard let de = SM9Points.decodeG2Hex(userPrivateKey) else {
            throw SM9Error.invalidKey("Invalid user private key")
        }
        guard let bytes = Hex.decodeCanonical(ciphertext), bytes.count > 97 else {
            throw decryptionFailure
        }
        let c2 = Array(bytes[97...])
        if mode == .sm4 && c2.count % 16 != 0 {
            throw decryptionFailure
        }
        guard let c1 = SM9Points.decodeG1(Array(bytes[0..<65])) else {
            throw decryptionFailure
        }
        var w = SM9Pairing.pairing(c1, de).toBytes()
        defer { secureWipe(&w) }
        let k1Length = mode == .stream ? c2.count : SM9Limits.sm4KeyLength
        var key = SM9Support.kdf(
            [SM9Points.xyG1(c1), w, Array(userId.utf8)], length: k1Length + SM9Limits.macKeyLength)
        defer { secureWipe(&key) }
        var k1 = Array(key[0..<k1Length])
        defer { secureWipe(&k1) }
        let keyIsZero = sm9ConstantTimeIsAllZero(k1)
        let macMatches = sm9ConstantTimeEquals(SM9Support.sm3(c2, Array(key[k1Length...])), Array(bytes[65..<97]))
        if keyIsZero || !macMatches {
            throw decryptionFailure
        }
        switch mode {
        case .stream:
            return SM9Support.xor(c2, key[0..<k1Length])
        case .sm4:
            var plain = sm4ECB(key: k1, data: c2, decrypt: true)
            let invalid = plain.withUnsafeBufferPointer { buffer -> UInt32 in
                guard let base = buffer.baseAddress else {
                    return 1
                }
                return pkcs7InvalidMask(base, count: buffer.count)
            }
            // C3 has already been checked, so a ciphertext of an empty message (one full
            // padding block) is authentic and decrypts to empty bytes, as in every other
            // language of this repository.
            if invalid != 0 {
                secureWipe(&plain)
                throw decryptionFailure
            }
            plain.removeLast(Int(plain[plain.count - 1]))
            return plain
        }
    }

    /// 解密并按严格 UTF-8 解码
    public static func decryptString(
        _ ciphertext: String, userId: String, userPrivateKey: String, mode: SM9EncryptionMode = .stream
    ) throws -> String {
        var plain = try decrypt(ciphertext, userId: userId, userPrivateKey: userPrivateKey, mode: mode)
        defer { secureWipe(&plain) }
        guard let text = strictUTF8String(plain) else {
            throw decryptionFailure
        }
        return text
    }
}
