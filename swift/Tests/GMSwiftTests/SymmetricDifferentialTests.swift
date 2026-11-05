import Foundation
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

    func testSM4SBoxCircuitMatchesStandardOnAllInputs() {
        for value in 0..<256 {
            let byte = UInt64(value)
            let expected = UInt64(sbox[value])
            // 每个字节位置都试一次，其余字节输入 0，S(0) = 0xD6
            for position in 0..<8 {
                let shift = UInt64(position * 8)
                let filler = 0xD6D6_D6D6_D6D6_D6D6 & ~(UInt64(0xFF) << shift)
                XCTAssertEqual(sm4SubstituteBytes(byte << shift), expected << shift | filler)
                if position < 4 {
                    let narrow = UInt32(byte << shift)
                    XCTAssertEqual(sm4SubstituteBytes(narrow), UInt32(truncatingIfNeeded: expected << shift | filler))
                }
            }
            // 同一个输入填满所有字节
            XCTAssertEqual(sm4SubstituteBytes(byte &* 0x0101_0101_0101_0101), expected &* 0x0101_0101_0101_0101)
        }
    }

    func testSM4RejectsKeysAndIVsOfOtherLengths() {
        let goodKey = String(repeating: "ab", count: 16)
        for length in [0, 1, 15, 17, 24, 32] {
            let hex = String(repeating: "ab", count: length)
            XCTAssertThrowsError(try getSM4().setKeyChecked(key: hex, iv: goodKey, hex: true), "key \(length)")
            XCTAssertThrowsError(try getSM4().setKeyChecked(key: goodKey, iv: hex, hex: true), "iv \(length)")
            let text = String(repeating: "a", count: length)
            XCTAssertThrowsError(try getSM4().setKeyChecked(key: text, iv: "0123456789abcdef", hex: false))
            XCTAssertThrowsError(try getSM4().setKeyChecked(key: "0123456789abcdef", iv: text, hex: false))
        }
        for bad in ["zz" + String(repeating: "ab", count: 15), "+f" + String(repeating: "ab", count: 15), "é"] {
            XCTAssertThrowsError(try getSM4().setKeyChecked(key: bad, iv: goodKey, hex: true))
        }
        // 16 字节的 UTF-8：按字节算，不是按字符算
        XCTAssertNoThrow(
            try getSM4().setKeyChecked(key: "国密国密国a", iv: "0123456789abcdef", hex: false).encryptChecked(text: "x"))
    }

    func testSM4FailedSetKeyClearsThePreviousKey() {
        let good = String(repeating: "ab", count: 16)
        let sm4 = getSM4().setKey(key: good, iv: good, hex: true)
        XCTAssertFalse(sm4.encrypt(text: "x").isEmpty)
        _ = sm4.setKey(key: "short", iv: good, hex: true)
        XCTAssertEqual(sm4.encrypt(text: "x"), "")
        XCTAssertNil(sm4.roundKeys)
    }

    /// 曾经静默地用全 0 轮密钥加密
    func testSM4WithoutKeyFails() {
        let sm4 = getSM4()
        XCTAssertEqual(sm4.encrypt(text: "x"), "")
        XCTAssertEqual(sm4.decrypt(text: "00"), "")
        XCTAssertThrowsError(try sm4.encryptChecked(text: "x"))
        XCTAssertThrowsError(try sm4.decryptChecked(text: "00"))
    }

    /// 曾经把 decrypt("") 变成越界陷阱，把非法填充原样返回
    func testSM4DecryptFailuresAreUniform() throws {
        let key = [UInt8](0..<16)
        let iv = [UInt8](16..<32)
        let sm4 = try getSM4().setKeyChecked(key: Hex.encode(key), iv: Hex.encode(iv), hex: true)
        let cipher = try sm4.encryptChecked(text: "0123456789abcdef")
        let cases = [
            "", "0", "zz", "é", String(cipher.dropLast(2)), cipher + "00", String(repeating: "00", count: 1),
            "+f" + String(cipher.dropFirst(2)), String(cipher.prefix(32)), String(repeating: "ff", count: 48),
        ]
        for text in cases {
            XCTAssertEqual(sm4.decrypt(text: text), "", text)
            XCTAssertThrowsError(try sm4.decryptChecked(text: text), text) { error in
                XCTAssertEqual(error as? SM4Error, SM4Error.decryptionFailed)
            }
        }
    }

    /// 填充合法但不是 UTF-8：曾经被静默替换成 U+FFFD
    func testSM4DecryptRejectsInvalidUTF8() throws {
        let key = [UInt8](0..<16)
        let iv = [UInt8](16..<32)
        let sm4 = try getSM4().setKeyChecked(key: Hex.encode(key), iv: Hex.encode(iv), hex: true)
        for bad in [[0xFF], [0xC0, 0x80], [0xE4, 0xB8], [0xED, 0xA0, 0x80]] as [[UInt8]] {
            let cipher = Hex.encode(referenceCBCEncrypt(bad, key: key, iv: iv))
            XCTAssertThrowsError(try sm4.decryptChecked(text: cipher))
        }
        // 明文里真实的 U+FFFD 和 NUL 不受影响
        for text in ["\u{FFFD}", "a\0b"] {
            XCTAssertEqual(try sm4.decryptChecked(text: try sm4.encryptChecked(text: text)), text)
        }
    }

    /// 所有填充边界，并行解密的分组数覆盖 1 到 9
    func testSM4DecryptEveryLength() throws {
        var rng = TestRandom(seed: 0xB3)
        let key = rng.bytes(16)
        let iv = rng.bytes(16)
        let sm4 = try getSM4().setKeyChecked(key: Hex.encode(key), iv: Hex.encode(iv), hex: true)
        for length in 0..<150 {
            let text = String(decoding: rng.bytes(length).map { $0 & 0x7F }, as: UTF8.self)
            let cipher = Hex.encode(referenceCBCEncrypt(Array(text.utf8), key: key, iv: iv))
            XCTAssertEqual(try sm4.decryptChecked(text: cipher), text)
        }
    }

    /// setKey 与 encrypt/decrypt 并发：结果必须来自某一个完整的密钥，不能崩溃或混合
    func testSM4ConcurrentUse() {
        let first = String(repeating: "11", count: 16)
        let second = String(repeating: "22", count: 16)
        let sm4 = getSM4().setKey(key: first, iv: first, hex: true)
        let expectedFirst = getSM4().setKey(key: first, iv: first, hex: true).encrypt(text: "msg")
        let expectedSecond = getSM4().setKey(key: second, iv: second, hex: true).encrypt(text: "msg")
        let lock = NSLock()
        var unexpected = 0
        DispatchQueue.concurrentPerform(iterations: 8) { worker in
            for round in 0..<200 {
                if worker == 0 {
                    _ = sm4.setKey(key: round % 2 == 0 ? second : first, iv: round % 2 == 0 ? second : first, hex: true)
                } else {
                    let cipher = sm4.encrypt(text: "msg")
                    if cipher != expectedFirst && cipher != expectedSecond {
                        lock.lock()
                        unexpected += 1
                        lock.unlock()
                    }
                }
            }
        }
        XCTAssertEqual(unexpected, 0)
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

    /// 结束之后对象不再改变。曾经的实现在结束后继续累积状态，再次 finalize 得到非标准的值。
    func testSM3ReuseAfterFinalizeIsInert() {
        let sm3 = SM3()
        XCTAssertEqual(sm3.getHash(), "")
        XCTAssertEqual(sm3.getHashBytes(), [])
        _ = sm3.update("abc").finalize()
        let first = sm3.getHash()
        _ = sm3.update([1, 2, 3]).update("more")
        XCTAssertEqual(sm3.getHash(), first)
        _ = sm3.finalize()
        XCTAssertEqual(sm3.getHash(), first)
    }

    /// 2^61 - 1 字节是上限：恰好到达时可以结束，超过时不回绕、不产生摘要
    func testSM3LengthLimit() {
        let limit = SM3Core.maximumByteCount
        var atLimit = SM3Core(testingByteCount: limit - 1)
        atLimit.update([1])
        XCTAssertFalse(atLimit.isOverLimit)
        XCTAssertEqual(atLimit.finalize().count, 32)

        var over = SM3Core(testingByteCount: limit)
        over.update([1])
        XCTAssertTrue(over.isOverLimit)
        XCTAssertEqual(over.finalize(), [])

        var wrap = SM3Core(testingByteCount: .max)
        wrap.update([1])
        XCTAssertTrue(wrap.isOverLimit)
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
        XCTAssertEqual(message(String(cipher.dropLast())), #"invalidInput("Invalid ciphertext encoding")"#)
        XCTAssertEqual(
            message(String(cipher.dropLast(2)) + "00"), #"decryptionFailed("Decryption verification failed")"#)
        XCTAssertEqual(
            message(String(cipher.prefix(130)) + String(repeating: "0", count: 64) + "zz"),
            #"invalidInput("Invalid ciphertext encoding")"#)
        XCTAssertEqual(message("04" + String(repeating: "1", count: 194)), #"invalidInput("Invalid C1 point")"#)
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

        let offCurve = ECPoint(x: FpElement(.one), y: FpElement(.one))
        XCTAssertFalse(
            SM2.getSb(byteLen: 16, pA: pA, Ra: offCurve, pB: pB, dB: dB, Rb: pointRb, rb: rb, IDa: idA, IDb: idB)
                .success)
    }
}
