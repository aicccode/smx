import XCTest

@testable import GMSwift

/// SM3、SM4 以及 SM2 高层流程的差分和边界测试
final class SymmetricDifferentialTests: XCTestCase {

    // MARK: - SM4 参考实现（只用 S 盒，逐轮计算）

    private let sbox = sm4ReferenceSBox

    private func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 {
        return (x << n) | (x >> (32 - n))
    }

    private func tau(_ a: UInt32) -> UInt32 {
        var out: UInt32 = 0
        for shift in stride(from: 24, through: 0, by: -8) {
            out |= UInt32(sbox[Int((a >> UInt32(shift)) & 0xFF)]) << UInt32(shift)
        }
        return out
    }

    private func word(_ bytes: ArraySlice<UInt8>) -> UInt32 {
        var value: UInt32 = 0
        for byte in bytes {
            value = (value << 8) | UInt32(byte)
        }
        return value
    }

    /// CK[i] 的第 j 字节 = (4i + j) * 7 mod 256
    private func ck(_ round: Int) -> UInt32 {
        var value: UInt32 = 0
        for j in 0..<4 {
            value = (value << 8) | UInt32((4 * round + j) * 7 % 256)
        }
        return value
    }

    private func referenceKeySchedule(_ key: [UInt8]) -> [UInt32] {
        let fk: [UInt32] = [0xA3B1_BAC6, 0x56AA_3350, 0x677D_9197, 0xB270_22DC]
        var k = [UInt32]()
        for i in 0..<4 {
            k.append(word(key[(i * 4)..<(i * 4 + 4)]) ^ fk[i])
        }
        var rk = [UInt32]()
        for i in 0..<32 {
            let t = tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck(i))
            let next: UInt32 = k[i] ^ t ^ rotl(t, 13) ^ rotl(t, 23)
            k.append(next)
            rk.append(next)
        }
        return rk
    }

    private func referenceBlock(_ block: [UInt8], _ rk: [UInt32]) -> [UInt8] {
        var x = [UInt32]()
        for i in 0..<4 {
            x.append(word(block[(i * 4)..<(i * 4 + 4)]))
        }
        for i in 0..<32 {
            let t = tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i])
            let linear: UInt32 = t ^ rotl(t, 2) ^ rotl(t, 10) ^ rotl(t, 18) ^ rotl(t, 24)
            x.append(x[i] ^ linear)
        }
        var out = [UInt8]()
        for w in [x[35], x[34], x[33], x[32]] {
            out += [UInt8(w >> 24), UInt8((w >> 16) & 0xFF), UInt8((w >> 8) & 0xFF), UInt8(w & 0xFF)]
        }
        return out
    }

    private func referenceCBCEncrypt(_ message: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        let rk = referenceKeySchedule(key)
        let pad = 16 - message.count % 16
        let padded = message + [UInt8](repeating: UInt8(pad), count: pad)
        var previous = iv
        var out = [UInt8]()
        for offset in stride(from: 0, to: padded.count, by: 16) {
            previous = referenceBlock(zip(padded[offset..<(offset + 16)], previous).map { $0 ^ $1 }, rk)
            out += previous
        }
        return out
    }

    func testSM4MatchesReference() {
        var rng = TestRandom(seed: 0xB1)
        for length in [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 257, 1024] {
            for _ in 0..<3 {
                let key = rng.bytes(16)
                let iv = rng.bytes(16)
                let message = rng.bytes(length).map { $0 & 0x7F }
                let sm4 = getSM4().setKey(key: Hex.encode(key), iv: Hex.encode(iv), hex: true)
                XCTAssertEqual(sm4.roundKeys, referenceKeySchedule(key))
                let expected = Hex.encode(referenceCBCEncrypt(message, key: key, iv: iv))
                let text = String(decoding: message, as: UTF8.self)
                XCTAssertEqual(sm4.encrypt(text: text), expected)
                XCTAssertEqual(sm4.decrypt(text: expected), text)
                XCTAssertEqual(sm4.decrypt(text: expected.uppercased()), text)
            }
        }
    }

    /// 既有行为：长度不是16字节的字符串密钥取 SM3 大写十六进制的前16个 ASCII 字符
    func testSM4StringKeyDerivation() {
        let hash = getSM3().update("short").finalize().getHash()
        let sm4 = getSM4().setKey(key: "short", iv: "1234567890abcdef", hex: false)
        XCTAssertEqual(sm4.roundKeys, referenceKeySchedule(Array(hash.utf8.prefix(16))))
        XCTAssertEqual(sm4.iv, Array("1234567890abcdef".utf8))
    }

    /// 既有行为：去填充宽松，非法填充时原样返回；末尾不足一个分组的数据被忽略
    func testSM4LenientDecrypt() {
        let sm4 = getSM4().setKey(
            key: "0123456789abcdeffedcba9876543210", iv: "00000000000000000000000000000000", hex: true)
        let cipher = sm4.encrypt(text: "0123456789abcdef")
        XCTAssertEqual(sm4.decrypt(text: cipher + "00"), "0123456789abcdef")
        // 只取第一个分组：明文就是 16 字节消息本身，最后一字节 'f' 不是合法填充
        XCTAssertEqual(sm4.decrypt(text: String(cipher.prefix(32))), "0123456789abcdef")
        XCTAssertEqual(sm4.decodeHex("abc"), [])
        XCTAssertEqual(sm4.decodeHex("abzz12"), [0xAB])
        XCTAssertEqual(sm4.decodeHex("+f-0"), [0x0F, 0x00])
    }

    func testSM4ShortKeyIsZeroPadded() {
        let sm4 = getSM4()
        sm4.setKeyBytes(keyBytes: [1, 2, 3, 4, 5, 6, 7, 8], ivBytes: [UInt8](repeating: 0, count: 16))
        XCTAssertEqual(sm4.roundKeys, referenceKeySchedule([1, 2, 3, 4, 5, 6, 7, 8] + [UInt8](repeating: 0, count: 8)))
    }

    // MARK: - SM3

    /// 任意切分方式和分组边界
    func testSM3StreamingMatchesOneShot() {
        var rng = TestRandom(seed: 0xB2)
        for length in [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 1000, 4097] {
            let data = rng.bytes(length)
            let oneShot = SM3().update(data).finalize().getHash()
            for chunk in [1, 3, 31, 63, 64, 65, 200] {
                let sm3 = SM3()
                var offset = 0
                while offset < length {
                    let end = min(length, offset + chunk)
                    _ = sm3.update(Array(data[offset..<end]))
                    offset = end
                }
                XCTAssertEqual(sm3.finalize().getHash(), oneShot, "length \(length) chunk \(chunk)")
            }
            var core = SM3Core()
            core.update(data)
            XCTAssertEqual(Hex.encode(core.finalize(), gap: Hex.uppercaseGap), oneShot)
        }
    }

    func testSM3PaddingBoundariesCaptured() {
        // 输出来自提交 3397c6d 的实现
        let vectors: [(Int, String)] = sm3CapturedVectors
        for (length, expected) in vectors {
            let data = (0..<length).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) }
            XCTAssertEqual(SM3().update(data).finalize().getHash(), expected, "length \(length)")
        }
    }

    func testSM3StateAfterFinalizeMatchesHistoricalBehaviour() {
        let sm3 = SM3()
        XCTAssertEqual(sm3.getHash(), "")
        XCTAssertEqual(sm3.getHashBytes(), [])
        _ = sm3.update("abc").finalize()
        let first = sm3.getHash()
        _ = sm3.update([1, 2, 3])
        XCTAssertEqual(sm3.getHash(), first, "update must not change the stored hash")
        _ = sm3.finalize()
        XCTAssertEqual(sm3.getHash(), sm3AfterFinalizeCaptured.0)
        _ = sm3.finalize()
        XCTAssertEqual(sm3.getHash(), sm3AfterFinalizeCaptured.1)
    }

    // MARK: - SM2 高层流程

    func testEncryptDecryptAcrossKDFBoundaries() throws {
        let (privateKey, publicKey) = SM2.genKeyPair()
        for length in [1, 31, 32, 33, 63, 64, 65, 1000] {
            let message = String(repeating: "x", count: length)
            let cipher = try SM2.encrypt(message, publicKey: publicKey)
            XCTAssertEqual(cipher.count, 130 + 64 + 2 * length)
            XCTAssertEqual(try SM2.decrypt(cipher, privateKey: privateKey), message)
            XCTAssertEqual(try SM2.decrypt(cipher.uppercased(), privateKey: privateKey), message)
        }
    }

    /// KDF 与按标准逐块计算的结果一致：C3 校验通过，且密文用独立算出的密钥流可以解开
    func testKDFAgainstNaiveConstruction() throws {
        let privateHex = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
        let publicKey = SM2.getPublicKey(BigInt256.fromHex(privateHex)).toHexEncoded()
        let message = String(repeating: "z", count: 100)
        let cipher = try SM2.encrypt(message, publicKey: publicKey)
        let c1 = ECPoint.fromHexEncoded(String(cipher.prefix(130)))
        let p2 = c1.multiply(BigInt256.fromHex(privateHex))
        let c2 = Hex.decodeStrict(String(cipher.dropFirst(194))) ?? []

        var stream = [UInt8]()
        var counter: UInt32 = 1
        while stream.count < c2.count {
            let bytes = (0..<4).map { UInt8((counter >> UInt32(24 - $0 * 8)) & 0xFF) }
            stream += SM3().update(p2.x.toBEBytes() + p2.y.toBEBytes() + bytes).finalize().getHashBytes()
            counter += 1
        }
        XCTAssertEqual(String(decoding: zip(c2, stream).map { $0 ^ $1 }, as: UTF8.self), message)

        let c3 = SM3().update(p2.x.toBEBytes() + Array(message.utf8) + p2.y.toBEBytes()).finalize().getHashBytes()
        XCTAssertEqual(Hex.encode(c3), String(cipher.dropFirst(130).prefix(64)))
    }

    func testDecryptRejectsTamperedOrMalformedInput() throws {
        let (privateKey, publicKey) = SM2.genKeyPair()
        let cipher = try SM2.encrypt("hello", publicKey: publicKey)

        func message(_ input: String) -> String {
            do {
                return "ok: \(try SM2.decrypt(input, privateKey: privateKey))"
            } catch {
                return "\(error)"
            }
        }
        XCTAssertEqual(message("00"), #"invalidInput("Ciphertext too short")"#)
        XCTAssertEqual(message(String(cipher.dropLast())), #"invalidInput("Invalid hex string length")"#)
        XCTAssertEqual(
            message(String(cipher.dropLast(2)) + "00"), #"decryptionFailed("Decryption verification failed")"#)
        XCTAssertEqual(
            message(String(cipher.prefix(130)) + String(repeating: "0", count: 64) + "zz"),
            #"invalidInput("Invalid hex character")"#)
        XCTAssertEqual(message("04" + String(repeating: "1", count: 192)), #"invalidInput("Invalid C1 point")"#)
    }

    func testSignatureChecks() throws {
        let (privateKey, publicKey) = SM2.genKeyPair()
        let id = "ALICE123@YAHOO.COM"
        let signature = try SM2.sign(userId: id, message: "m", privateKey: privateKey)
        func check(_ sig: String, _ msg: String = "m", _ key: String? = nil) -> Bool {
            return SM2.verify(userId: id, signature: sig, message: msg, publicKey: key ?? publicKey)
        }
        XCTAssertTrue(check(signature))
        XCTAssertFalse(check(signature, "n"))
        XCTAssertFalse(check("abc"))
        XCTAssertFalse(check("0h0"))
        XCTAssertFalse(check("1h0"))
        XCTAssertFalse(check("0h1"))
        let n = SM2Curve.n.toHexLower()
        XCTAssertFalse(check("\(n)h1"), "r = n")
        XCTAssertFalse(check("1h\(n)"), "s = n")
        XCTAssertFalse(check(signature, "m", "04" + String(repeating: "1", count: 128)), "not on curve")
        // r + s = n
        XCTAssertFalse(check("1h" + SM2Curve.n.sub(.one).0.toHexLower()), "t = 0")
    }

    func testKeyExchangeConfirmationRejectsWrongValues() {
        let idA = "ALICE123@YAHOO.COM"
        let idB = "BILL456@YAHOO.COM"
        let dA = BigInt256.fromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
        let ra = BigInt256.fromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")
        let dB = BigInt256.fromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")
        let rb = BigInt256.fromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")
        let pA = SM2.getPublicKey(dA)
        let pointRa = SM2.getPublicKey(ra)
        let pB = SM2.getPublicKey(dB)
        let pointRb = SM2.getPublicKey(rb)

        let b = SM2.getSb(byteLen: 16, pA: pA, Ra: pointRa, pB: pB, dB: dB, Rb: pointRb, rb: rb, IDa: idA, IDb: idB)
        let wrong = SM2.getSa(
            byteLen: 16, pB: pB, Rb: pointRb, pA: pA, dA: dA, Ra: pointRa, ra: ra, IDa: idA, IDb: idB,
            Sb: [UInt8](repeating: 0, count: 32))
        XCTAssertFalse(wrong.success)
        let shortValue = SM2.getSa(
            byteLen: 16, pB: pB, Rb: pointRb, pA: pA, dA: dA, Ra: pointRa, ra: ra, IDa: idA, IDb: idB, Sb: [1])
        XCTAssertFalse(shortValue.success)
        if let v = b.v, let za = b.za, let zb = b.zb {
            XCTAssertFalse(
                SM2.checkSa(V: v, Za: za, Zb: zb, Ra: pointRa, Rb: pointRb, Sa: [UInt8](repeating: 0, count: 32)))
            XCTAssertFalse(SM2.checkSa(V: v, Za: za, Zb: zb, Ra: pointRa, Rb: pointRb, Sa: []))
        } else {
            XCTFail("expected V, Za and Zb")
        }

        let offCurve = ECPoint.fromHex(xHex: "1", yHex: "1")
        XCTAssertFalse(
            SM2.getSb(byteLen: 16, pA: pA, Ra: offCurve, pB: pB, dB: dB, Rb: pointRb, rb: rb, IDa: idA, IDb: idB)
                .success)
    }
}
