import Foundation
import XCTest

@testable import GMSwift

/// 共享向量 testvectors/sm9-vectors.json（由独立的 testvectors/sm9_ref.py 生成）以及 SM9 的往返、篡改、校验测试。
final class SM9Tests: XCTestCase {
    private static let vectors: [String: Any] = {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("testvectors/sm9-vectors.json")
        guard let data = try? Data(contentsOf: url),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return [:]
        }
        return object
    }()

    private func table(_ path: String...) -> [String: Any] {
        var current: Any = SM9Tests.vectors
        for key in path {
            guard let next = (current as? [String: Any])?[key] else {
                XCTFail("missing vector table \(path)")
                return [:]
            }
            current = next
        }
        return current as? [String: Any] ?? [:]
    }

    private func list(_ table: [String: Any], _ key: String) -> [[String: Any]] {
        guard let value = table[key] as? [[String: Any]], !value.isEmpty else {
            XCTFail("missing vector list \(key)")
            return []
        }
        return value
    }

    private func str(_ table: [String: Any], _ key: String) -> String {
        guard let value = table[key] as? String else {
            XCTFail("missing vector \(key)")
            return ""
        }
        return value
    }

    private func int(_ table: [String: Any], _ key: String) -> Int {
        guard let value = table[key] as? Int else {
            XCTFail("missing vector \(key)")
            return 0
        }
        return value
    }

    private func bytes(_ table: [String: Any], _ key: String) -> [UInt8] {
        guard let value = Hex.decodeStrict(str(table, key)) else {
            XCTFail("bad hex \(key)")
            return []
        }
        return value
    }

    private func scalar(_ table: [String: Any], _ key: String) -> BigInt256 {
        guard let value = BigInt256(hex: str(table, key)) else {
            XCTFail("bad scalar \(key)")
            return .zero
        }
        return value
    }

    private var extra: [String: Any] { return table("extra") }

    // MARK: - 参数与底层运算

    func testParameters() {
        let params = table("params")
        XCTAssertEqual(SM9Params.q.toHexLower(), str(params, "q"))
        XCTAssertEqual(SM9Params.n.toHexLower(), str(params, "n"))
        XCTAssertEqual(String(SM9Params.t, radix: 16), str(params, "t"))
        XCTAssertEqual(Hex.encode(SM9Points.encodeG1(SM9Points.p1)), str(params, "P1"))
        XCTAssertEqual(Hex.encode(SM9Points.encodeG2(SM9Points.p2)), str(params, "P2"))
        XCTAssertTrue(SM9Points.p1.isOnCurve)
        XCTAssertTrue(SM9Points.p2.isOnCurve)
        XCTAssertTrue(SM9G1.multiplyPublic(SM9Points.p1.jacobian, SM9Params.n).isInfinity)
        XCTAssertTrue(SM9G2.multiplyPublic(SM9Points.p2.jacobian, SM9Params.n).isInfinity)
    }

    private func randomFp() -> SM9Fp {
        var value = BigInt256(.random(in: 0...UInt64.max), .random(in: 0...UInt64.max), .random(in: 0...UInt64.max), 0)
        value.l3 = .random(in: 0..<0xB640_0000_0000_0000)
        return SM9Fp(canonical: value)
    }

    private func randomFp12() -> SM9Fp12 {
        func fp2() -> SM9Fp2 { return SM9Fp2(randomFp(), randomFp()) }
        return SM9Fp12(SM9Fp4(fp2(), fp2()), SM9Fp4(fp2(), fp2()), SM9Fp4(fp2(), fp2()))
    }

    private func randomScalar() -> BigInt256 {
        return (try? SM9Support.randomScalar()) ?? .one
    }

    func testFieldArithmetic() {
        for _ in 0..<20 {
            let a = randomFp()
            let b = randomFp()
            XCTAssertEqual(SM9Fp(canonical: a.canonical).m, a.m)
            XCTAssertTrue(a.mul(a.inverse()) == SM9Fp.one || a.isZero)
            XCTAssertTrue(a.add(b).sub(b) == a)
            XCTAssertTrue(a.add(a.neg()).isZero)
            XCTAssertTrue(a.square() == a.mul(a))
            let product = SM9Fp(canonical: a.canonical.modMul(b.canonical, SM9Params.q))
            XCTAssertTrue(product == a.mul(b))
            let x = SM9Fp2(a, b)
            XCTAssertTrue(x.mul(x.inverse()) == SM9Fp2.one)
            XCTAssertTrue(x.square() == x.mul(x))
            let f = randomFp12()
            XCTAssertTrue(f.mul(f.inverse()) == SM9Fp12.one)
            XCTAssertTrue(f.square() == f.mul(f))
            XCTAssertTrue(f.frobenius(1).frobenius(1) == f.frobenius(2))
            XCTAssertTrue(f.frobenius(2).frobenius(1) == f.frobenius(3))
            XCTAssertTrue(f.frobenius(3).frobenius(3) == f.conjugate())
            // q 次 Frobenius 等于 q 次幂
            XCTAssertTrue(f.frobenius(1) == f.powPublic(SM9Params.q))
        }
        XCTAssertTrue(SM9Fp.zero.inverse().isZero)
    }

    func testScalarArithmetic() {
        for _ in 0..<20 {
            let a = randomScalar()
            let b = randomScalar()
            XCTAssertEqual(SM9Scalar.mul(a, b), a.modMul(b, SM9Params.n))
            XCTAssertEqual(SM9Scalar.mul(a, SM9Scalar.inverse(a)), .one)
            let high = UInt64.random(in: 0...UInt64.max)
            // 与通用的逐位约减对照
            let wide: Wide512 = (a.l0, a.l1, a.l2, a.l3, high, 0, 0, 0)
            XCTAssertEqual(
                SM9Scalar.reduceModNMinus1(high: high, low: a), BigInt256.modReduce512(wide, SM9Params.nMinus1))
        }
    }

    func testCyclotomicSquareAndGTPower() {
        let g = SM9Pairing.pairing(SM9Points.p1, SM9Points.p2)
        XCTAssertFalse(g.isOne)
        XCTAssertTrue(g.cyclotomicSquare() == g.square())
        XCTAssertTrue(g.powPublic(SM9Params.n).isOne)
        XCTAssertTrue(g.conjugate().mul(g).isOne)
        for k in [BigInt256.one, BigInt256(2, 0, 0, 0), BigInt256(31, 0, 0, 0), SM9Params.nMinus1, randomScalar()] {
            XCTAssertTrue(SM9Pairing.powSecret(g, k) == g.powPublic(k))
        }
    }

    func testPairingBilinearity() {
        let a = randomScalar()
        let b = randomScalar()
        let pa = SM9G1.multiplySecret(SM9Points.p1.jacobian, a).toAffine()
        let qb = SM9G2.multiplySecret(SM9Points.p2.jacobian, b).toAffine()
        let lhs = SM9Pairing.pairing(pa, qb)
        let rhs = SM9Pairing.pairing(SM9Points.p1, SM9Points.p2).powPublic(SM9Scalar.mul(a, b))
        XCTAssertTrue(lhs == rhs)
        XCTAssertTrue(SM9Pairing.pairing(nil, SM9Points.p2).isOne)
        XCTAssertTrue(SM9Pairing.pairing(SM9Points.p1, nil).isOne)
    }

    func testScalarMultiplicationAgrees() {
        let scalars = [BigInt256.one, BigInt256(16, 0, 0, 0), SM9Params.nMinus1, randomScalar(), randomScalar()]
        for k in scalars {
            let g1 = SM9G1.multiplySecret(SM9Points.p1.jacobian, k)
            XCTAssertTrue(g1.equalsPublic(SM9G1.multiplyPublic(SM9Points.p1.jacobian, k)))
            let g2 = SM9G2.multiplySecret(SM9Points.p2.jacobian, k)
            XCTAssertTrue(g2.equalsPublic(SM9G2.multiplyPublic(SM9Points.p2.jacobian, k)))
        }
        XCTAssertTrue(SM9G1.multiplySecret(SM9Points.p1.jacobian, .zero).isInfinity)
        XCTAssertTrue(SM9G1.multiplySecret(SM9Points.p1.jacobian, SM9Params.n).isInfinity)
        // 2^256 - 1 的 wNAF 需要进位
        let all = BigInt256(.max, .max, .max, .max)
        XCTAssertTrue(
            SM9G1.multiplyPublic(SM9Points.p1.jacobian, all).equalsPublic(
                SM9G1.multiplySecret(SM9Points.p1.jacobian, all)))
    }

    func testSubgroupCheckMatchesOrder() {
        var points = [SM9Points.p2]
        for entry in list(table("invalid_points"), "g2") where str(entry, "name") == "not_in_subgroup" {
            guard let bytes = Hex.decodeStrict(str(entry, "value")) else {
                XCTFail("bad vector")
                continue
            }
            let x = SM9Fp2(
                SM9Fp(canonical: BigInt256.fromBEBytes(Array(bytes[33..<65]))),
                SM9Fp(canonical: BigInt256.fromBEBytes(Array(bytes[1..<33]))))
            let y = SM9Fp2(
                SM9Fp(canonical: BigInt256.fromBEBytes(Array(bytes[97..<129]))),
                SM9Fp(canonical: BigInt256.fromBEBytes(Array(bytes[65..<97]))))
            let point = SM9Affine(x: x, y: y)
            XCTAssertTrue(point.isOnCurve)
            XCTAssertFalse(SM9Points.isInG2(point))
            points.append(point)
        }
        XCTAssertEqual(points.count, 2)
        if let random = SM9G2.multiplySecret(SM9Points.p2.jacobian, randomScalar()).toAffine() {
            points.append(random)
        }
        for point in points {
            XCTAssertEqual(SM9Points.isInG2(point), SM9G2.multiplyPublic(point.jacobian, SM9Params.n).isInfinity)
        }
    }

    // MARK: - GB/T 38635.5 的标准示例

    func testStandardSign() throws {
        let v = table("standard", "sign")
        let master = str(v, "master_private_key")
        XCTAssertEqual(try SM9.signMasterPublicKey(master), str(v, "master_public_key"))
        let userKey = try SM9.genSignUserKey(
            masterPrivateKey: master, userId: str(v, "user_id"), hid: UInt8(int(v, "hid")))
        XCTAssertEqual(userKey, str(v, "user_private_key"))
        guard let ppubS = SM9Points.decodeG2Hex(str(v, "master_public_key")) else {
            return XCTFail("master public key")
        }
        XCTAssertEqual(Hex.encode(SM9Pairing.pairing(SM9Points.p1, ppubS).toBytes()), str(v, "pairing_g"))
        let message = Array(str(v, "message").utf8)
        let signature = SM9.signWithRandom(
            message, userPrivateKey: userKey, masterPublicKey: str(v, "master_public_key"), r: scalar(v, "r"))
        XCTAssertEqual(signature, str(v, "signature"))
        XCTAssertTrue(
            SM9.verify(
                message, signature: str(v, "signature"), userId: str(v, "user_id"),
                masterPublicKey: str(v, "master_public_key")))
    }

    private func checkExchange(_ v: [String: Any], masterPublicKey: String, hid: UInt8) {
        let idA = str(v, "id_a")
        let idB = str(v, "id_b")
        let keyLength = int(v, "key_len")
        let ra = try? SM9.exchangeInitWithRandom(
            peerId: Array(idB.utf8), masterPublicKey: masterPublicKey, hid: hid, r: scalar(v, "r_a"))
        let rb = try? SM9.exchangeInitWithRandom(
            peerId: Array(idA.utf8), masterPublicKey: masterPublicKey, hid: hid, r: scalar(v, "r_b"))
        XCTAssertEqual(ra, str(v, "R_a"))
        XCTAssertEqual(rb, str(v, "R_b"))
        let b = SM9.exchangeRespond(
            keyLength: keyLength, idA: idA, idB: idB, masterPublicKey: masterPublicKey,
            userPrivateKeyB: str(v, "user_private_key_b"), randomPrivateB: str(v, "r_b"),
            randomPointB: str(v, "R_b"), randomPointA: str(v, "R_a"))
        XCTAssertTrue(b.success, b.message ?? "")
        XCTAssertEqual(b.sharedKey, str(v, "shared_key"))
        XCTAssertEqual(b.sb, str(v, "s_b"))
        XCTAssertEqual(b.s2, str(v, "s_a"))
        let a = SM9.exchangeConfirm(
            keyLength: keyLength, idA: idA, idB: idB, masterPublicKey: masterPublicKey,
            userPrivateKeyA: str(v, "user_private_key_a"), randomPrivateA: str(v, "r_a"),
            randomPointA: str(v, "R_a"), randomPointB: str(v, "R_b"), sb: str(v, "s_b"))
        XCTAssertTrue(a.success, a.message ?? "")
        XCTAssertEqual(a.sharedKey, str(v, "shared_key"))
        XCTAssertEqual(a.sa, str(v, "s_a"))
        XCTAssertTrue(SM9.exchangeCheck(s2: b.s2 ?? "", sa: a.sa ?? "x"))
    }

    func testStandardExchange() throws {
        let v = table("standard", "exchange")
        let master = str(v, "master_private_key")
        let hid = UInt8(int(v, "hid"))
        XCTAssertEqual(try SM9.encMasterPublicKey(master), str(v, "master_public_key"))
        XCTAssertEqual(
            try SM9.genEncUserKey(masterPrivateKey: master, userId: str(v, "id_a"), hid: hid),
            str(v, "user_private_key_a"))
        XCTAssertEqual(
            try SM9.genEncUserKey(masterPrivateKey: master, userId: str(v, "id_b"), hid: hid),
            str(v, "user_private_key_b"))
        checkExchange(v, masterPublicKey: str(v, "master_public_key"), hid: hid)
    }

    func testStandardEncapsulate() throws {
        let v = table("standard", "encapsulate")
        let master = str(v, "master_private_key")
        let hid = UInt8(int(v, "hid"))
        XCTAssertEqual(try SM9.encMasterPublicKey(master), str(v, "master_public_key"))
        XCTAssertEqual(
            try SM9.genEncUserKey(masterPrivateKey: master, userId: str(v, "user_id"), hid: hid),
            str(v, "user_private_key"))
        checkEncapsulate(v, masterPublicKey: str(v, "master_public_key"), hid: hid)
    }

    private func checkEncapsulate(_ v: [String: Any], masterPublicKey: String, hid: UInt8) {
        let id = str(v, "user_id")
        let result = try? SM9.encapsulateWithRandom(
            userId: Array(id.utf8), masterPublicKey: masterPublicKey, keyLength: int(v, "key_len"), hid: hid,
            r: scalar(v, "r"))
        XCTAssertEqual(result?.key, str(v, "key"))
        XCTAssertEqual(result?.ciphertext, str(v, "ciphertext"))
        XCTAssertEqual(
            try? SM9.decapsulate(
                str(v, "ciphertext"), userId: id, userPrivateKey: str(v, "user_private_key"),
                keyLength: int(v, "key_len")),
            str(v, "key"))
    }

    func testStandardEncrypt() throws {
        let v = table("standard", "encrypt")
        let master = str(v, "master_private_key")
        let hid = UInt8(int(v, "hid"))
        XCTAssertEqual(
            try SM9.genEncUserKey(masterPrivateKey: master, userId: str(v, "user_id"), hid: hid),
            str(v, "user_private_key"))
        checkEncrypt(v, plaintext: Array(str(v, "plaintext").utf8), masterPublicKey: str(v, "master_public_key"), hid: hid)
    }

    private func checkEncrypt(_ v: [String: Any], plaintext: [UInt8], masterPublicKey: String, hid: UInt8) {
        let id = str(v, "user_id")
        let userKey = str(v, "user_private_key")
        for (mode, key) in [(SM9EncryptionMode.stream, "ciphertext_stream"), (.sm4, "ciphertext_sm4")] {
            let cipher = try? SM9.encryptWithRandom(
                plaintext, userId: Array(id.utf8), masterPublicKey: masterPublicKey, hid: hid, mode: mode,
                r: scalar(v, "r"))
            XCTAssertEqual(cipher, str(v, key), key)
            XCTAssertEqual(try? SM9.decrypt(str(v, key), userId: id, userPrivateKey: userKey, mode: mode), plaintext)
        }
    }

    // MARK: - 额外向量

    func testExtraMasterKeys() throws {
        XCTAssertEqual(
            try SM9.signMasterPublicKey(str(extra, "sign_master_private_key")), str(extra, "sign_master_public_key"))
        XCTAssertEqual(
            try SM9.encMasterPublicKey(str(extra, "enc_master_private_key")), str(extra, "enc_master_public_key"))
        let max = str(table(), "max_valid_master_private_key")
        XCTAssertNoThrow(try SM9.signMasterPublicKey(max))
        XCTAssertNoThrow(try SM9.encMasterPublicKey(max))
    }

    private func table() -> [String: Any] { return SM9Tests.vectors }

    func testExtraSign() throws {
        let master = str(extra, "sign_master_private_key")
        let ppub = str(extra, "sign_master_public_key")
        for v in list(extra, "sign") {
            let id = str(v, "user_id")
            let userKey = try SM9.genSignUserKey(masterPrivateKey: master, userId: id)
            XCTAssertEqual(userKey, str(v, "user_private_key"))
            let message = bytes(v, "message_hex")
            XCTAssertEqual(
                SM9.signWithRandom(message, userPrivateKey: userKey, masterPublicKey: ppub, r: scalar(v, "r")),
                str(v, "signature"))
            XCTAssertTrue(SM9.verify(message, signature: str(v, "signature"), userId: id, masterPublicKey: ppub))
        }
    }

    func testExtraEncrypt() throws {
        let master = str(extra, "enc_master_private_key")
        let ppub = str(extra, "enc_master_public_key")
        for v in list(extra, "encrypt") {
            XCTAssertEqual(
                try SM9.genEncUserKey(masterPrivateKey: master, userId: str(v, "user_id")), str(v, "user_private_key"))
            checkEncrypt(v, plaintext: bytes(v, "plaintext_hex"), masterPublicKey: ppub, hid: SM9.hidEncrypt)
        }
    }

    func testExtraEncapsulate() throws {
        let master = str(extra, "enc_master_private_key")
        let ppub = str(extra, "enc_master_public_key")
        for v in list(extra, "encapsulate") {
            XCTAssertEqual(
                try SM9.genEncUserKey(masterPrivateKey: master, userId: str(v, "user_id")), str(v, "user_private_key"))
            checkEncapsulate(v, masterPublicKey: ppub, hid: SM9.hidEncrypt)
        }
    }

    func testExtraExchange() throws {
        let master = str(extra, "enc_master_private_key")
        let ppub = str(extra, "enc_master_public_key")
        for v in list(extra, "exchange") {
            XCTAssertEqual(
                try SM9.genEncUserKey(masterPrivateKey: master, userId: str(v, "id_a"), hid: SM9.hidExchange),
                str(v, "user_private_key_a"))
            XCTAssertEqual(
                try SM9.genEncUserKey(masterPrivateKey: master, userId: str(v, "id_b"), hid: SM9.hidExchange),
                str(v, "user_private_key_b"))
            checkExchange(v, masterPublicKey: ppub, hid: SM9.hidExchange)
        }
    }

    // MARK: - 非法输入

    func testInvalidPointsRejected() throws {
        let invalid = table("invalid_points")
        let signMaster = str(extra, "sign_master_private_key")
        let signPub = str(extra, "sign_master_public_key")
        let encPub = str(extra, "enc_master_public_key")
        let encMaster = str(extra, "enc_master_private_key")
        let signKey = try SM9.genSignUserKey(masterPrivateKey: signMaster, userId: "Alice")
        let encKey = try SM9.genEncUserKey(masterPrivateKey: encMaster, userId: "Bob")
        let exchangeKey = try SM9.genEncUserKey(masterPrivateKey: encMaster, userId: "Bob", hid: SM9.hidExchange)
        let signature = try SM9.sign("m", userPrivateKey: signKey, masterPublicKey: signPub)
        let (rB, pointB) = try SM9.exchangeInit(peerId: "Alice", masterPublicKey: encPub)
        let (_, pointA) = try SM9.exchangeInit(peerId: "Bob", masterPublicKey: encPub)

        let g1 = list(invalid, "g1")
        XCTAssertEqual(g1.count, 10)
        for entry in g1 {
            let value = str(entry, "value")
            let name = str(entry, "name")
            XCTAssertNil(SM9Points.decodeG1Hex(value), name)
            XCTAssertThrowsError(try SM9.encrypt("x", userId: "Bob", masterPublicKey: value), name)
            XCTAssertThrowsError(try SM9.encapsulate(userId: "Bob", masterPublicKey: value, keyLength: 16), name)
            XCTAssertThrowsError(try SM9.exchangeInit(peerId: "Bob", masterPublicKey: value), name)
            XCTAssertThrowsError(try SM9.sign("m", userPrivateKey: value, masterPublicKey: signPub), name)
            XCTAssertThrowsError(
                try SM9.decapsulate(value.lowercased(), userId: "Bob", userPrivateKey: encKey, keyLength: 16), name)
            // 签名里的 S 和密文里的 C1
            let lower = value.lowercased()
            if lower.utf8.count == 130 {
                let forged = String(signature.prefix(64)) + lower
                XCTAssertFalse(SM9.verify("m", signature: forged, userId: "Alice", masterPublicKey: signPub), name)
                let cipher = try SM9.encrypt("x", userId: "Bob", masterPublicKey: encPub)
                let tampered = lower + String(cipher.dropFirst(130))
                XCTAssertThrowsError(try SM9.decrypt(tampered, userId: "Bob", userPrivateKey: encKey), name)
            }
            XCTAssertFalse(
                SM9.exchangeRespond(
                    keyLength: 16, idA: "Alice", idB: "Bob", masterPublicKey: encPub, userPrivateKeyB: exchangeKey,
                    randomPrivateB: rB, randomPointB: pointB, randomPointA: value
                ).success, name)
            XCTAssertFalse(
                SM9.exchangeRespond(
                    keyLength: 16, idA: "Alice", idB: "Bob", masterPublicKey: value, userPrivateKeyB: exchangeKey,
                    randomPrivateB: rB, randomPointB: pointB, randomPointA: pointA
                ).success, name)
        }

        let g2 = list(invalid, "g2")
        XCTAssertEqual(g2.count, 8)
        for entry in g2 {
            let value = str(entry, "value")
            let name = str(entry, "name")
            XCTAssertNil(SM9Points.decodeG2Hex(value), name)
            XCTAssertThrowsError(try SM9.sign("m", userPrivateKey: signKey, masterPublicKey: value), name)
            XCTAssertFalse(SM9.verify("m", signature: signature, userId: "Alice", masterPublicKey: value), name)
            let cipher = try SM9.encrypt("x", userId: "Bob", masterPublicKey: encPub)
            XCTAssertThrowsError(try SM9.decrypt(cipher, userId: "Bob", userPrivateKey: value), name)
            XCTAssertFalse(
                SM9.exchangeRespond(
                    keyLength: 16, idA: "Alice", idB: "Bob", masterPublicKey: encPub, userPrivateKeyB: value,
                    randomPrivateB: rB, randomPointB: pointB, randomPointA: pointA
                ).success, name)
        }
    }

    func testInvalidScalarsRejected() throws {
        let scalars = SM9Tests.vectors["invalid_scalars"] as? [[String: Any]] ?? []
        XCTAssertEqual(scalars.count, 6)
        let encPub = str(extra, "enc_master_public_key")
        let encMaster = str(extra, "enc_master_private_key")
        let exchangeKey = try SM9.genEncUserKey(masterPrivateKey: encMaster, userId: "Bob", hid: SM9.hidExchange)
        let (_, pointB) = try SM9.exchangeInit(peerId: "Alice", masterPublicKey: encPub)
        let (_, pointA) = try SM9.exchangeInit(peerId: "Bob", masterPublicKey: encPub)
        for entry in scalars {
            let value = str(entry, "value")
            let name = str(entry, "name")
            XCTAssertNil(SM9Support.parseScalar(value), name)
            XCTAssertThrowsError(try SM9.signMasterPublicKey(value), name)
            XCTAssertThrowsError(try SM9.encMasterPublicKey(value), name)
            XCTAssertThrowsError(try SM9.genSignUserKey(masterPrivateKey: value, userId: "a"), name)
            XCTAssertThrowsError(try SM9.genEncUserKey(masterPrivateKey: value, userId: "a"), name)
            XCTAssertFalse(
                SM9.exchangeRespond(
                    keyLength: 16, idA: "Alice", idB: "Bob", masterPublicKey: encPub, userPrivateKeyB: exchangeKey,
                    randomPrivateB: value, randomPointB: pointB, randomPointA: pointA
                ).success, name)
        }
        // 主私钥大小写都接受
        let upper = str(extra, "sign_master_private_key").uppercased()
        XCTAssertEqual(try SM9.signMasterPublicKey(upper), str(extra, "sign_master_public_key"))
    }

    /// t1 = H1(ID||hid) + ks = 0 时无法生成用户私钥
    func testUserKeyT1Zero() {
        let h1 = SM9Support.h1(Array("Alice".utf8), [SM9.hidSign])
        let ks = SM9Params.n.subtractingWithBorrow(h1).difference
        XCTAssertThrowsError(try SM9.genSignUserKey(masterPrivateKey: ks.toHexLower(), userId: "Alice"))
        XCTAssertNoThrow(try SM9.genSignUserKey(masterPrivateKey: ks.toHexLower(), userId: "Alice", hid: 2))
    }

    // MARK: - 往返与篡改

    func testSignRoundTripAndTamper() throws {
        let (master, pub) = try SM9.genSignMasterKey()
        XCTAssertEqual(master.utf8.count, 64)
        XCTAssertEqual(pub.utf8.count, 258)
        XCTAssertEqual(try SM9.signMasterPublicKey(master), pub)
        let key = try SM9.genSignUserKey(masterPrivateKey: master, userId: "张三")
        for message in ["", "hello", String(repeating: "国", count: 100)] {
            let signature = try SM9.sign(message, userPrivateKey: key, masterPublicKey: pub)
            XCTAssertEqual(signature.utf8.count, 194)
            XCTAssertTrue(SM9.verify(message, signature: signature, userId: "张三", masterPublicKey: pub))
            XCTAssertFalse(SM9.verify(message + "x", signature: signature, userId: "张三", masterPublicKey: pub))
            XCTAssertFalse(SM9.verify(message, signature: signature, userId: "李四", masterPublicKey: pub))
            XCTAssertFalse(
                SM9.verify(message, signature: signature, userId: "张三", masterPublicKey: pub, hid: SM9.hidEncrypt))
            XCTAssertFalse(
                SM9.verify(message, signature: signature.uppercased(), userId: "张三", masterPublicKey: pub))
            XCTAssertTrue(
                SM9.verify(message, signature: signature, userId: "张三", masterPublicKey: pub.uppercased()))
            for position in [0, 31, 63, 64, 65, 66, 100, 129, 130, 193] {
                XCTAssertFalse(
                    SM9.verify(
                        message, signature: flipHex(signature, at: position), userId: "张三", masterPublicKey: pub),
                    "position \(position)")
            }
            XCTAssertFalse(SM9.verify(message, signature: signature + "00", userId: "张三", masterPublicKey: pub))
            XCTAssertFalse(
                SM9.verify(message, signature: String(signature.dropLast(2)), userId: "张三", masterPublicKey: pub))
        }
        // h = 0 和 h = N
        let signature = try SM9.sign("m", userPrivateKey: key, masterPublicKey: pub)
        let tail = String(signature.dropFirst(64))
        XCTAssertFalse(
            SM9.verify("m", signature: String(repeating: "0", count: 64) + tail, userId: "张三", masterPublicKey: pub))
        XCTAssertFalse(
            SM9.verify("m", signature: SM9Params.n.toHexLower() + tail, userId: "张三", masterPublicKey: pub))
        // 别的主密钥
        let (_, otherPub) = try SM9.genSignMasterKey()
        XCTAssertFalse(SM9.verify("m", signature: signature, userId: "张三", masterPublicKey: otherPub))
        // 签名私钥不能用加密主公钥那样的 G1 主公钥
        XCTAssertThrowsError(try SM9.sign("m", userPrivateKey: key, masterPublicKey: key))
    }

    private func flipHex(_ hex: String, at position: Int) -> String {
        var chars = Array(hex.utf8)
        chars[position] = chars[position] == UInt8(ascii: "0") ? UInt8(ascii: "1") : UInt8(ascii: "0")
        return String(decoding: chars, as: UTF8.self)
    }

    func testEncryptRoundTripAndTamper() throws {
        let (master, pub) = try SM9.genEncMasterKey()
        XCTAssertEqual(pub.utf8.count, 130)
        XCTAssertEqual(try SM9.encMasterPublicKey(master), pub)
        let key = try SM9.genEncUserKey(masterPrivateKey: master, userId: "Bob")
        let otherKey = try SM9.genEncUserKey(masterPrivateKey: master, userId: "Carol")
        for mode in [SM9EncryptionMode.stream, .sm4] {
            for text in ["a", "Chinese IBE standard", String(repeating: "0123456789abcdef", count: 4), "国密SM9"] {
                let cipher = try SM9.encrypt(text, userId: "Bob", masterPublicKey: pub, mode: mode)
                XCTAssertEqual(try SM9.decryptString(cipher, userId: "Bob", userPrivateKey: key, mode: mode), text)
                XCTAssertThrowsError(try SM9.decrypt(cipher, userId: "Carol", userPrivateKey: key, mode: mode))
                XCTAssertThrowsError(try SM9.decrypt(cipher, userId: "Bob", userPrivateKey: otherKey, mode: mode))
                // 密文不记录模式。C2 恰好16字节时两种模式的 K2 都是 KDF 输出的第16到48字节，MAC 同样通过，
                // 只是得到的明文不同（规范的性质）；其它长度用错模式一定失败。
                let wrongMode = try? SM9.decrypt(
                    cipher, userId: "Bob", userPrivateKey: key, mode: mode == .sm4 ? .stream : .sm4)
                if cipher.utf8.count == 194 + 32 {
                    XCTAssertNotEqual(wrongMode, Array(text.utf8))
                } else {
                    XCTAssertNil(wrongMode)
                }
                XCTAssertThrowsError(
                    try SM9.decrypt(cipher.uppercased(), userId: "Bob", userPrivateKey: key, mode: mode))
                XCTAssertEqual(
                    try SM9.decryptString(cipher, userId: "Bob", userPrivateKey: key.uppercased(), mode: mode), text)
                let length = cipher.utf8.count
                for position in [0, 2, 70, 129, 130, 150, 193, 194, length - 1] {
                    XCTAssertThrowsError(
                        try SM9.decrypt(flipHex(cipher, at: position), userId: "Bob", userPrivateKey: key, mode: mode),
                        "position \(position)")
                }
                XCTAssertThrowsError(try SM9.decrypt(cipher + "00", userId: "Bob", userPrivateKey: key, mode: mode))
                XCTAssertThrowsError(
                    try SM9.decrypt(String(cipher.prefix(194)), userId: "Bob", userPrivateKey: key, mode: mode))
            }
            XCTAssertThrowsError(try SM9.encrypt("", userId: "Bob", masterPublicKey: pub, mode: mode))
            XCTAssertThrowsError(try SM9.encrypt([UInt8](), userId: "Bob", masterPublicKey: pub, mode: mode))
        }
        // 每个错误都相同
        let cipher = try SM9.encrypt("x", userId: "Bob", masterPublicKey: pub)
        var errors = [SM9Error]()
        for bad in [flipHex(cipher, at: 140), flipHex(cipher, at: 195), "zz", cipher.uppercased()] {
            do {
                _ = try SM9.decrypt(bad, userId: "Bob", userPrivateKey: key)
            } catch let error as SM9Error {
                errors.append(error)
            }
        }
        XCTAssertEqual(errors.count, 4)
        XCTAssertEqual(Set(errors.map { "\($0)" }).count, 1)
        // 二进制明文
        let binary: [UInt8] = [0, 255, 128, 0]
        let binaryCipher = try SM9.encrypt(binary, userId: "Bob", masterPublicKey: pub, mode: .sm4)
        XCTAssertEqual(try SM9.decrypt(binaryCipher, userId: "Bob", userPrivateKey: key, mode: .sm4), binary)
        XCTAssertThrowsError(try SM9.decryptString(binaryCipher, userId: "Bob", userPrivateKey: key, mode: .sm4))
    }

    func testEncapsulateRoundTrip() throws {
        let (master, pub) = try SM9.genEncMasterKey()
        let key = try SM9.genEncUserKey(masterPrivateKey: master, userId: "Bob")
        for length in [1, 16, 32, 33, 100] {
            let (shared, cipher) = try SM9.encapsulate(userId: "Bob", masterPublicKey: pub, keyLength: length)
            XCTAssertEqual(shared.utf8.count, 2 * length)
            XCTAssertEqual(try SM9.decapsulate(cipher, userId: "Bob", userPrivateKey: key, keyLength: length), shared)
            XCTAssertNotEqual(
                try? SM9.decapsulate(cipher, userId: "Bobb", userPrivateKey: key, keyLength: length), shared)
            XCTAssertThrowsError(
                try SM9.decapsulate(cipher.uppercased(), userId: "Bob", userPrivateKey: key, keyLength: length))
            XCTAssertThrowsError(
                try SM9.decapsulate(flipHex(cipher, at: 80), userId: "Bob", userPrivateKey: key, keyLength: length))
        }
        for bad in [0, -1, (1 << 20) + 1] {
            XCTAssertThrowsError(try SM9.encapsulate(userId: "Bob", masterPublicKey: pub, keyLength: bad))
            XCTAssertThrowsError(try SM9.decapsulate(pub, userId: "Bob", userPrivateKey: key, keyLength: bad))
        }
    }

    func testExchangeRoundTripAndMismatch() throws {
        let (master, pub) = try SM9.genEncMasterKey()
        let keyA = try SM9.genEncUserKey(masterPrivateKey: master, userId: "Alice", hid: SM9.hidExchange)
        let keyB = try SM9.genEncUserKey(masterPrivateKey: master, userId: "Bob", hid: SM9.hidExchange)
        let (rA, pointA) = try SM9.exchangeInit(peerId: "Bob", masterPublicKey: pub)
        let (rB, pointB) = try SM9.exchangeInit(peerId: "Alice", masterPublicKey: pub)

        func respond(idA: String = "Alice", keyLength: Int = 32, key: String? = nil) -> SM9KeyExchangeResult {
            return SM9.exchangeRespond(
                keyLength: keyLength, idA: idA, idB: "Bob", masterPublicKey: pub, userPrivateKeyB: key ?? keyB,
                randomPrivateB: rB, randomPointB: pointB, randomPointA: pointA)
        }
        func confirm(_ sb: String, idA: String = "Alice", keyLength: Int = 32) -> SM9KeyExchangeResult {
            return SM9.exchangeConfirm(
                keyLength: keyLength, idA: idA, idB: "Bob", masterPublicKey: pub, userPrivateKeyA: keyA,
                randomPrivateA: rA, randomPointA: pointA, randomPointB: pointB, sb: sb)
        }

        let b = respond()
        XCTAssertTrue(b.success)
        let a = confirm(b.sb ?? "")
        XCTAssertTrue(a.success)
        XCTAssertEqual(a.sharedKey, b.sharedKey)
        XCTAssertEqual(a.sharedKey?.utf8.count, 64)
        XCTAssertTrue(SM9.exchangeCheck(s2: b.s2 ?? "", sa: a.sa ?? ""))
        XCTAssertFalse(SM9.exchangeCheck(s2: b.s2 ?? "", sa: flipHex(a.sa ?? "", at: 5)))
        XCTAssertFalse(SM9.exchangeCheck(s2: b.s2 ?? "", sa: (a.sa ?? "").uppercased()))
        XCTAssertFalse(SM9.exchangeCheck(s2: b.s2 ?? "", sa: ""))
        XCTAssertFalse(SM9.exchangeCheck(s2: "", sa: ""))

        // S_B 被篡改、大写、为空
        for bad in [flipHex(b.sb ?? "", at: 0), (b.sb ?? "").uppercased(), "", "00"] {
            let failed = confirm(bad)
            XCTAssertFalse(failed.success)
            XCTAssertNil(failed.sharedKey)
        }
        // 双方对 ID_A 的理解不一致：B 的 S_B 在 A 那里通不过
        let mismatched = respond(idA: "Alicia")
        XCTAssertTrue(mismatched.success)
        XCTAssertFalse(confirm(mismatched.sb ?? "").success)
        // 用错私钥（hid = 3 生成的）
        let wrongKey = try SM9.genEncUserKey(masterPrivateKey: master, userId: "Bob")
        let wrong = respond(key: wrongKey)
        XCTAssertTrue(wrong.success)
        XCTAssertFalse(confirm(wrong.sb ?? "").success)
        // 长度
        for bad in [0, -5, (1 << 20) + 1] {
            XCTAssertFalse(respond(keyLength: bad).success)
            XCTAssertFalse(confirm(b.sb ?? "", keyLength: bad).success)
        }
        // 结果对象不泄露密钥
        XCTAssertFalse("\(a)".contains(a.sharedKey ?? "-"))
        var dumped = ""
        dump(a, to: &dumped)
        XCTAssertFalse(dumped.contains(a.sharedKey ?? "-"))
    }

    func testHashToRange() {
        // 结果总在 [1, N-1]
        for index in 0..<50 {
            let h = SM9Support.h1([UInt8(index)], [1])
            XCTAssertNotEqual(SM9Scalar.validMask(h), 0)
        }
        XCTAssertEqual(SM9Support.kdf([[1, 2, 3]], length: 0), [])
        XCTAssertEqual(SM9Support.kdf([[1, 2, 3]], length: 33).count, 33)
        XCTAssertEqual(Array(SM9Support.kdf([[1, 2, 3]], length: 64).prefix(33)), SM9Support.kdf([[1, 2, 3]], length: 33))
    }
}
