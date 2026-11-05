import Foundation
import XCTest

@testable import GMSwift

/// 共享向量 testvectors/security-vectors.json（独立于本库生成，只读）以及入口校验。
final class SecurityVectorTests: XCTestCase {
    private static let vectors: [String: Any] = {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("testvectors/security-vectors.json")
        guard let data = try? Data(contentsOf: url),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return [:]
        }
        return object
    }()

    private var sm2: [String: Any] { return SecurityVectorTests.vectors["sm2"] as? [String: Any] ?? [:] }
    private var sm3: [String: Any] { return SecurityVectorTests.vectors["sm3"] as? [String: Any] ?? [:] }
    private var sm4: [String: Any] { return SecurityVectorTests.vectors["sm4"] as? [String: Any] ?? [:] }

    private func text(_ table: [String: Any], _ key: String) -> String {
        guard let value = table[key] as? String else {
            XCTFail("missing vector \(key)")
            return ""
        }
        return value
    }

    private func cases(_ table: [String: Any], _ key: String) -> [[String: String]] {
        guard let value = table[key] as? [[String: String]], !value.isEmpty else {
            XCTFail("missing vector list \(key)")
            return []
        }
        return value
    }

    private func numbers(_ table: [String: Any], _ key: String) -> [Int] {
        guard let value = table[key] as? [Int], !value.isEmpty else {
            XCTFail("missing vector list \(key)")
            return []
        }
        return value
    }

    private let exchangeD = BigInt256.fromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
    private let exchangeR = BigInt256.fromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")
    private let exchangeDB = BigInt256.fromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")
    private let exchangeRB = BigInt256.fromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")

    // MARK: - SM2 正向

    func testSM2ValidVectors() throws {
        let privateKey = text(sm2, "private_key")
        let publicKey = text(sm2, "public_key")
        let userId = text(sm2, "user_id")
        let message = text(sm2, "message")
        let r = text(sm2, "r")
        let s = text(sm2, "s")

        XCTAssertEqual(SM2.getPublicKey(BigInt256.fromHex(privateKey)).toHexEncoded(), publicKey)
        XCTAssertTrue(SM2.verify(userId: userId, signature: "\(r)h\(s)", message: message, publicKey: publicKey))
        XCTAssertEqual(try SM2.decrypt(text(sm2, "ciphertext"), privateKey: privateKey), text(sm2, "plaintext"))

        // 用向量给定的随机数重算签名
        guard let d = SM2.parsePrivateKey(privateKey), let k = BigInt256(hex: text(sm2, "nonce_k")) else {
            return XCTFail("vector scalars must parse")
        }
        let e = SM2.messageDigest(userId: userId, message: message, publicKey: SM2.getPublicKey(d))
        let signature = SM2.signDigest(e: e, d: d, k: k)
        XCTAssertEqual(signature?.r.toHexLower(), r)
        XCTAssertEqual(signature?.s.toHexLower(), s)

        let round = try SM2.sign(userId: userId, message: message, privateKey: privateKey)
        XCTAssertTrue(SM2.verify(userId: userId, signature: round, message: message, publicKey: publicKey))
    }

    func testLargestValidPrivateKey() throws {
        let key = text(sm2, "n_minus_2_is_max_valid_private_key")
        XCTAssertEqual(key, SM2Curve.n.sub(BigInt256(2, 0, 0, 0)).0.toHexLower())
        let publicKey = SM2.getPublicKey(BigInt256.fromHex(key)).toHexEncoded()
        let signature = try SM2.sign(userId: "id", message: "m", privateKey: key)
        XCTAssertTrue(SM2.verify(userId: "id", signature: signature, message: "m", publicKey: publicKey))
        XCTAssertEqual(try SM2.decrypt(try SM2.encrypt("m", publicKey: publicKey), privateKey: key), "m")
    }

    // MARK: - SM2 非法输入

    func testInvalidPublicKeys() {
        let id = text(sm2, "user_id")
        let message = text(sm2, "message")
        let signature = "\(text(sm2, "r"))h\(text(sm2, "s"))"
        for vector in cases(sm2, "invalid_public_keys") {
            let name = vector["name"] ?? "?"
            let value = vector["value"] ?? ""
            XCTAssertThrowsError(try SM2.encrypt("x", publicKey: value), name)
            XCTAssertFalse(SM2.verify(userId: id, signature: signature, message: message, publicKey: value), name)
            XCTAssertTrue(ECPoint.fromHexEncoded(value).isInfinity, name)
            let bytes = Hex.decodeStrict(value)
            if let bytes = bytes {
                XCTAssertTrue(ECPoint.fromEncoded(bytes).isInfinity, name)
            }
            // 同一个无效点作为密钥交换的任一方
            assertExchangeRejects(point: ECPoint.fromHexEncoded(value), name)
        }
    }

    func testInvalidPrivateKeys() {
        let publicKey = text(sm2, "public_key")
        let cipher = text(sm2, "ciphertext")
        for vector in cases(sm2, "invalid_private_keys") {
            let name = vector["name"] ?? "?"
            let value = vector["value"] ?? ""
            XCTAssertThrowsError(try SM2.sign(userId: "id", message: "m", privateKey: value), name)
            XCTAssertThrowsError(try SM2.decrypt(cipher, privateKey: value), name)
            XCTAssertNil(SM2.parsePrivateKey(value), name)
        }
        XCTAssertFalse(publicKey.isEmpty)
        // 宽松解析接口得到的值同样被密钥交换拒绝
        for value in [SM2Curve.n, SM2Curve.n.sub(.one).0, BigInt256.zero, BigInt256(.max, .max, .max, .max)] {
            assertExchangeRejects(scalar: value)
        }
    }

    func testInvalidSignatures() {
        let id = text(sm2, "user_id")
        let message = text(sm2, "message")
        let publicKey = text(sm2, "public_key")
        for vector in cases(sm2, "invalid_signatures") {
            let signature = "\(vector["r"] ?? "")h\(vector["s"] ?? "")"
            XCTAssertFalse(
                SM2.verify(userId: id, signature: signature, message: message, publicKey: publicKey),
                vector["name"] ?? "?")
        }
        let good = "\(text(sm2, "r"))h\(text(sm2, "s"))"
        for bad in ["", "h", good + "h", "h" + good, good + "00", "\(text(sm2, "r"))H\(text(sm2, "s"))"] {
            XCTAssertFalse(SM2.verify(userId: id, signature: bad, message: message, publicKey: publicKey), bad)
        }
    }

    func testInvalidCiphertexts() {
        let privateKey = text(sm2, "private_key")
        for vector in cases(sm2, "invalid_ciphertexts") {
            XCTAssertThrowsError(try SM2.decrypt(vector["value"] ?? "", privateKey: privateKey), vector["name"] ?? "?")
        }
    }

    func testUserIdLengthLimit() throws {
        let privateKey = text(sm2, "private_key")
        let publicKey = text(sm2, "public_key")
        let valid = String(repeating: "a", count: try XCTUnwrap(sm2["user_id_max_bytes"] as? Int))
        let invalid = String(repeating: "a", count: try XCTUnwrap(sm2["user_id_first_invalid_bytes"] as? Int))

        let signature = try SM2.sign(userId: valid, message: "m", privateKey: privateKey)
        XCTAssertTrue(SM2.verify(userId: valid, signature: signature, message: "m", publicKey: publicKey))
        XCTAssertThrowsError(try SM2.sign(userId: invalid, message: "m", privateKey: privateKey))
        XCTAssertFalse(SM2.verify(userId: invalid, signature: signature, message: "m", publicKey: publicKey))
        // ENTL 不能回绕：65536 比特正好回到 0
        XCTAssertThrowsError(
            try SM2.sign(userId: String(repeating: "a", count: 16384), message: "m", privateKey: privateKey))

        let (pA, ra, pB, rb) = exchangePoints()
        let longId = SM2.getSb(
            byteLen: 16, pA: pA, Ra: ra, pB: pB, dB: exchangeDB, Rb: rb, rb: exchangeRB, IDa: invalid, IDb: "b")
        XCTAssertFalse(longId.success)
        XCTAssertTrue(
            SM2.getSb(byteLen: 16, pA: pA, Ra: ra, pB: pB, dB: exchangeDB, Rb: rb, rb: exchangeRB, IDa: valid, IDb: "b")
                .success)
    }

    // MARK: - 密钥交换

    private func exchangePoints() -> (ECPoint, ECPoint, ECPoint, ECPoint) {
        return (
            SM2.getPublicKey(exchangeD), SM2.getPublicKey(exchangeR), SM2.getPublicKey(exchangeDB),
            SM2.getPublicKey(exchangeRB)
        )
    }

    private func assertExchangeRejects(point bad: ECPoint, _ name: String, line: UInt = #line) {
        let (pA, ra, pB, rb) = exchangePoints()
        let sb = [UInt8](repeating: 0, count: 32)
        let sbCalls = [
            (bad, ra, pB, rb), (pA, bad, pB, rb), (pA, ra, bad, rb), (pA, ra, pB, bad),
        ]
        for (a, b, c, d) in sbCalls {
            let result = SM2.getSb(
                byteLen: 16, pA: a, Ra: b, pB: c, dB: exchangeDB, Rb: d, rb: exchangeRB, IDa: "a", IDb: "b")
            XCTAssertFalse(result.success, name, line: line)
            XCTAssertNil(result.kb, name, line: line)
            let other = SM2.getSa(
                byteLen: 16, pB: c, Rb: d, pA: a, dA: exchangeD, Ra: b, ra: exchangeR, IDa: "a", IDb: "b", Sb: sb)
            XCTAssertFalse(other.success, name, line: line)
            XCTAssertNil(other.ka, name, line: line)
        }
        XCTAssertFalse(SM2.checkSa(V: bad, Za: sb, Zb: sb, Ra: ra, Rb: rb, Sa: sb), name, line: line)
        XCTAssertFalse(SM2.checkSa(V: pA, Za: sb, Zb: sb, Ra: bad, Rb: rb, Sa: sb), name, line: line)
        XCTAssertFalse(SM2.checkSa(V: pA, Za: sb, Zb: sb, Ra: ra, Rb: bad, Sa: sb), name, line: line)
    }

    private func assertExchangeRejects(scalar: BigInt256, line: UInt = #line) {
        let (pA, ra, pB, rb) = exchangePoints()
        let sb = [UInt8](repeating: 0, count: 32)
        XCTAssertFalse(
            SM2.getSb(byteLen: 16, pA: pA, Ra: ra, pB: pB, dB: scalar, Rb: rb, rb: exchangeRB, IDa: "a", IDb: "b")
                .success,
            line: line)
        XCTAssertFalse(
            SM2.getSb(byteLen: 16, pA: pA, Ra: ra, pB: pB, dB: exchangeDB, Rb: rb, rb: scalar, IDa: "a", IDb: "b")
                .success,
            line: line)
        XCTAssertFalse(
            SM2.getSa(
                byteLen: 16, pB: pB, Rb: rb, pA: pA, dA: scalar, Ra: ra, ra: exchangeR, IDa: "a", IDb: "b", Sb: sb
            )
            .success, line: line)
        XCTAssertFalse(
            SM2.getSa(
                byteLen: 16, pB: pB, Rb: rb, pA: pA, dA: exchangeD, Ra: ra, ra: scalar, IDa: "a", IDb: "b", Sb: sb
            )
            .success, line: line)
    }

    func testKeyExchangeLengthBounds() {
        let (pA, ra, pB, rb) = exchangePoints()
        for length in [Int.min, -1, 0, (1 << 20) + 1, 1 << 40, Int.max] {
            XCTAssertFalse(
                SM2.getSb(
                    byteLen: length, pA: pA, Ra: ra, pB: pB, dB: exchangeDB, Rb: rb, rb: exchangeRB, IDa: "a", IDb: "b"
                )
                .success, "\(length)")
            XCTAssertFalse(
                SM2.getSa(
                    byteLen: length, pB: pB, Rb: rb, pA: pA, dA: exchangeD, Ra: ra, ra: exchangeR, IDa: "a", IDb: "b",
                    Sb: [UInt8](repeating: 0, count: 32)
                ).success, "\(length)")
        }
        for length in [1, 32, 1 << 20] {
            let b = SM2.getSb(
                byteLen: length, pA: pA, Ra: ra, pB: pB, dB: exchangeDB, Rb: rb, rb: exchangeRB, IDa: "a", IDb: "b")
            XCTAssertTrue(b.success, "\(length)")
            XCTAssertEqual(b.kb?.utf8.count, length * 2)
        }
    }

    func testKeyExchangeConfirmationValues() throws {
        let (pA, ra, pB, rb) = exchangePoints()
        let b = SM2.getSb(
            byteLen: 16, pA: pA, Ra: ra, pB: pB, dB: exchangeDB, Rb: rb, rb: exchangeRB, IDa: "a", IDb: "b")
        let sb = try XCTUnwrap(Hex.decodeStrict(try XCTUnwrap(b.sb)))
        let exchange: ([UInt8]) -> SM2KeySwapParams = {
            SM2.getSa(
                byteLen: 16, pB: pB, Rb: rb, pA: pA, dA: self.exchangeD, Ra: ra, ra: self.exchangeR, IDa: "a", IDb: "b",
                Sb: $0)
        }
        XCTAssertTrue(exchange(sb).success)
        XCTAssertFalse(exchange([]).success, "empty Sb")
        XCTAssertFalse(exchange(Array(sb.dropLast())).success, "short Sb")
        XCTAssertFalse(exchange(sb + [0]).success, "long Sb")

        let v = try XCTUnwrap(b.v)
        let za = try XCTUnwrap(b.za)
        let zb = try XCTUnwrap(b.zb)
        let sa = try XCTUnwrap(Hex.decodeStrict(try XCTUnwrap(exchange(sb).sa)))
        XCTAssertTrue(SM2.checkSa(V: v, Za: za, Zb: zb, Ra: ra, Rb: rb, Sa: sa))
        XCTAssertFalse(SM2.checkSa(V: v, Za: za, Zb: zb, Ra: ra, Rb: rb, Sa: []))
        XCTAssertFalse(SM2.checkSa(V: v, Za: [], Zb: zb, Ra: ra, Rb: rb, Sa: sa))
    }

    /// PA = -[x_]RA 让和点成为无穷远点，协商必须失败（V 为无穷远）
    func testKeyExchangeRejectsInfinitySum() {
        let (_, ra, pB, rb) = exchangePoints()
        let xBar = BigInt256(ra.x.value.l0, ra.x.value.l1 | (UInt64(1) << 63), 0, 0)
        let cancelling = ra.multiply(xBar).negate()
        let result = SM2.getSb(
            byteLen: 16, pA: cancelling, Ra: ra, pB: pB, dB: exchangeDB, Rb: rb, rb: exchangeRB, IDa: "a", IDb: "b")
        XCTAssertFalse(result.success)
        XCTAssertNotNil(result.message)
    }

    /// x、y 是公开可写的：解析之后被改成 >= p 或离开曲线的点，入口也必须拒绝
    func testMutatedPublicPointsAreRejected() {
        let (pA, ra, pB, rb) = exchangePoints()
        let mutated = ECPoint(x: pA.x, y: pA.y)
        mutated.x.value = mutated.x.value.add(SM2Curve.p).0
        assertExchangeRejects(point: mutated, "x + p")
        let moved = ECPoint(x: pA.x, y: pA.y)
        moved.y.value = moved.y.value.add(.one).0
        assertExchangeRejects(point: moved, "y + 1")
        XCTAssertFalse(
            SM2.getSb(
                byteLen: 16, pA: mutated, Ra: ra, pB: pB, dB: exchangeDB, Rb: rb, rb: exchangeRB, IDa: "a", IDb: "b"
            )
            .success)
    }

    func testPointParsingIsStrict() {
        let g = ECPoint.generator().toHexEncoded()
        XCTAssertFalse(ECPoint.fromHexEncoded(g).isInfinity)
        XCTAssertFalse(ECPoint.fromHexEncoded(g.uppercased()).isInfinity)
        let rest = String(g.dropFirst(2))
        let malformed: [String] = ["0x\(g)", " \(g)", "\(g) ", "\(g)\n", "\r\n\(g)", rest, "03\(rest)"]
        for bad in malformed {
            XCTAssertTrue(ECPoint.fromHexEncoded(bad).isInfinity, bad)
        }
        XCTAssertTrue(ECPoint.fromEncoded([]).isInfinity)
        XCTAssertTrue(ECPoint.fromEncoded([4]).isInfinity)
        XCTAssertTrue(ECPoint.fromEncoded([UInt8](repeating: 4, count: 65)).isInfinity)
        XCTAssertTrue(ECPoint.fromHex(xHex: "1", yHex: "1").isInfinity)
        XCTAssertTrue(ECPoint.fromHex(xHex: "", yHex: "").isInfinity)
        XCTAssertTrue(ECPoint.fromHex(xHex: SM2Curve.p.toHex(), yHex: SM2Curve.gy.toHex()).isInfinity)
        XCTAssertEqual(ECPoint.fromHex(xHex: SM2Curve.gx.toHex(), yHex: SM2Curve.gy.toHex()), ECPoint.generator())
    }

    func testValidPrivateKeyRange() {
        let n = SM2Curve.n
        XCTAssertEqual(SM2.validPrivateKeyMask(.zero), 0)
        XCTAssertEqual(SM2.validPrivateKeyMask(.one), .max)
        XCTAssertEqual(SM2.validPrivateKeyMask(n.sub(BigInt256(2, 0, 0, 0)).0), .max)
        XCTAssertEqual(SM2.validPrivateKeyMask(n.sub(.one).0), 0)
        XCTAssertEqual(SM2.validPrivateKeyMask(n), 0)
        XCTAssertEqual(SM2.validPrivateKeyMask(n.add(.one).0), 0)
        XCTAssertEqual(SM2.validPrivateKeyMask(BigInt256(.max, .max, .max, .max)), 0)
        XCTAssertEqual(SM2.validPrivateKeyMask(BigInt256(0, 0, 0, 1)), .max)
    }

    func testGeneratedKeysAreInRangeAndDistinct() {
        var seen = Set<String>()
        for _ in 0..<50 {
            let (privateKey, publicKey) = SM2.genKeyPair()
            XCTAssertNotNil(SM2.parsePrivateKey(privateKey))
            XCTAssertFalse(ECPoint.fromHexEncoded(publicKey).isInfinity)
            XCTAssertTrue(seen.insert(privateKey).inserted)
        }
    }

    /// 同一消息的两次签名必须用不同的随机数
    func testSignaturesDoNotRepeatNonces() throws {
        let key = text(sm2, "private_key")
        var seen = Set<String>()
        for _ in 0..<20 {
            let signature = try SM2.sign(userId: "id", message: "m", privateKey: key)
            XCTAssertTrue(seen.insert(String(signature.prefix(64))).inserted)
        }
    }

    func testSecretsAreNotPrinted() throws {
        let secret = BigInt256.fromHex(text(sm2, "private_key"))
        let marker = secret.toHex().lowercased()
        var dumped = ""
        dump(secret, to: &dumped)
        let reflected = String(reflecting: secret)
        let element = "\(FpElement(secret))"
        XCTAssertEqual(Mirror(reflecting: secret).children.count, 0)
        let outputs: [String] = ["\(secret)", reflected, dumped, element]
        for output in outputs {
            XCTAssertFalse(output.lowercased().contains(marker))
            XCTAssertFalse(output.contains(String(secret.l0)))
        }

        let cipherKey = "0123456789abcdeffedcba9876543210"
        let sm4Object = getSM4().setKey(key: cipherKey, iv: cipherKey, hex: true)
        var sm4Dump = ""
        dump(sm4Object, to: &sm4Dump)
        let rk0 = sm4Object.roundKeys?.first.map { String($0) } ?? "missing"
        XCTAssertFalse(sm4Dump.contains(rk0))
        XCTAssertEqual(Mirror(reflecting: sm4Object).children.count, 0)

        let (pA, ra, pB, rb) = exchangePoints()
        let result = SM2.getSb(
            byteLen: 16, pA: pA, Ra: ra, pB: pB, dB: exchangeDB, Rb: rb, rb: exchangeRB, IDa: "a", IDb: "b")
        let kb = try XCTUnwrap(result.kb)
        var resultDump = ""
        dump(result, to: &resultDump)
        XCTAssertFalse(resultDump.contains(kb))
        XCTAssertFalse("\(result)".contains(kb))
        do {
            _ = try SM2.decrypt(text(sm2, "ciphertext"), privateKey: "zz" + marker.dropFirst(2))
            XCTFail("must throw")
        } catch {
            XCTAssertFalse("\(error)".contains(marker.dropFirst(2)))
        }
    }

    // MARK: - SM3

    /// 跨过 2^32 比特（512 MiB）和 2^33 比特的长度字段。调试构建太慢，只在 release 构建运行。
    func testSM3LargeInputs() throws {
        #if DEBUG
            throw XCTSkip("run with: swift test -c release")
        #else
            let chunk = [UInt8](repeating: 0, count: 1 << 20)
            var core = SM3Core()
            for _ in 0..<512 {
                core.update(chunk)
            }
            var at512 = core
            XCTAssertEqual(Hex.encode(at512.finalize()), text(sm3, "zeros_512_mib"))
            for _ in 512..<1024 {
                core.update(chunk)
            }
            XCTAssertEqual(Hex.encode(core.finalize()), text(sm3, "zeros_1024_mib"))
        #endif
    }

    // MARK: - SM4

    private func keyed() throws -> Sm4Impl {
        return try getSM4().setKeyChecked(key: text(sm4, "key"), iv: text(sm4, "iv"), hex: true)
    }

    func testSM4ValidVectors() throws {
        let cipher = try keyed()
        XCTAssertEqual(
            try cipher.encryptChecked(text: text(sm4, "valid_padded_plaintext")), text(sm4, "valid_padded_ciphertext"))
        XCTAssertEqual(
            try cipher.decryptChecked(text: text(sm4, "valid_padded_ciphertext")), text(sm4, "valid_padded_plaintext"))
        XCTAssertEqual(try cipher.decryptChecked(text: text(sm4, "valid_full_padding_block_ciphertext")), "")
        XCTAssertEqual(try cipher.encryptChecked(text: ""), text(sm4, "valid_full_padding_block_ciphertext"))
    }

    func testSM4InvalidKeyAndIVLengths() throws {
        let key = text(sm4, "key")
        let iv = text(sm4, "iv")
        for length in numbers(sm4, "invalid_key_lengths_bytes") {
            let hex = String(repeating: "00", count: length)
            XCTAssertThrowsError(try getSM4().setKeyChecked(key: hex, iv: iv, hex: true), "\(length)")
            XCTAssertEqual(getSM4().setKey(key: hex, iv: iv, hex: true).encrypt(text: "x"), "")
        }
        for length in numbers(sm4, "invalid_iv_lengths_bytes") {
            let hex = String(repeating: "00", count: length)
            XCTAssertThrowsError(try getSM4().setKeyChecked(key: key, iv: hex, hex: true), "\(length)")
            XCTAssertEqual(getSM4().setKey(key: key, iv: hex, hex: true).encrypt(text: "x"), "")
        }
    }

    func testSM4InvalidPaddingAndLengthsGiveOneError() throws {
        let cipher = try keyed()
        var inputs = cases(sm4, "invalid_paddings").map { $0["value"] ?? "" }
        inputs += numbers(sm4, "invalid_ciphertext_lengths_bytes").map { String(repeating: "00", count: $0) }
        for input in inputs {
            XCTAssertEqual(cipher.decrypt(text: input), "", input)
            XCTAssertThrowsError(try cipher.decryptChecked(text: input), input) { error in
                XCTAssertEqual(error as? SM4Error, SM4Error.decryptionFailed)
            }
        }
    }
}
