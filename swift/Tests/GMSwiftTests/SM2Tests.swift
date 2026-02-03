import XCTest
@testable import GMSwift

final class SM2Tests: XCTestCase {

    func testKeyPairGeneration() {
        let (pri, pub) = SM2.genKeyPair()
        XCTAssertEqual(pri.count, 64)
        XCTAssertEqual(pub.count, 130)
        XCTAssertTrue(pub.hasPrefix("04"))
    }

    func testEncryptDecrypt() throws {
        let (pri, pub) = SM2.genKeyPair()
        let message = "encryption standard"

        let encrypted = try SM2.encrypt(message, publicKey: pub)
        let decrypted = try SM2.decrypt(encrypted, privateKey: pri)

        XCTAssertEqual(decrypted, message)
    }

    func testEncryptDecryptChinese() throws {
        let (pri, pub) = SM2.genKeyPair()
        let message = "SM2国密算法加密测试"

        let encrypted = try SM2.encrypt(message, publicKey: pub)
        let decrypted = try SM2.decrypt(encrypted, privateKey: pri)

        XCTAssertEqual(decrypted, message)
    }

    func testSignVerify() throws {
        let (pri, pub) = SM2.genKeyPair()
        let userId = "ALICE123@YAHOO.COM"
        let message = "encryption standard"

        let signature = try SM2.sign(userId: userId, message: message, privateKey: pri)
        let valid = SM2.verify(userId: userId, signature: signature, message: message, publicKey: pub)

        XCTAssertTrue(valid)
    }

    func testSignVerifyWrongMessage() throws {
        let (pri, pub) = SM2.genKeyPair()
        let userId = "ALICE123@YAHOO.COM"
        let message = "encryption standard"

        let signature = try SM2.sign(userId: userId, message: message, privateKey: pri)
        let valid = SM2.verify(userId: userId, signature: signature, message: "wrong message", publicKey: pub)

        XCTAssertFalse(valid)
    }

    func testKeyExchange() throws {
        let idA = "ALICE123@YAHOO.COM"
        let idB = "BILL456@YAHOO.COM"

        // A的密钥对
        let dA = BigInt256.fromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
        let pA = SM2.getPublicKey(dA)

        // A的随机密钥对
        let ra = BigInt256.fromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")
        let Ra = SM2.getPublicKey(ra)

        // B的密钥对
        let dB = BigInt256.fromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")
        let pB = SM2.getPublicKey(dB)

        // B的随机密钥对
        let rb = BigInt256.fromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")
        let Rb = SM2.getPublicKey(rb)

        // B计算Sb和Kb
        let resultB = SM2.getSb(byteLen: 16, pA: pA, Ra: Ra, pB: pB, dB: dB, Rb: Rb, rb: rb, IDa: idA, IDb: idB)
        XCTAssertTrue(resultB.success, resultB.message ?? "Unknown error")

        // A计算Sa和Ka
        let sbBytes = try hexToBytes(resultB.sb!)
        let resultA = SM2.getSa(byteLen: 16, pB: pB, Rb: Rb, pA: pA, dA: dA, Ra: Ra, ra: ra, IDa: idA, IDb: idB, Sb: sbBytes)
        XCTAssertTrue(resultA.success, resultA.message ?? "Unknown error")

        // 验证Ka == Kb
        XCTAssertEqual(resultA.ka, resultB.kb)

        // B验证Sa
        let saBytes = try hexToBytes(resultA.sa!)
        let check = SM2.checkSa(V: resultB.v!, Za: resultB.za!, Zb: resultB.zb!, Ra: Ra, Rb: Rb, Sa: saBytes)
        XCTAssertTrue(check)
    }

    func testPointOnCurve() {
        let g = ECPoint.generator()
        XCTAssertTrue(g.isOnCurve())
    }

    func testPointAdd() {
        let g = ECPoint.generator()
        let g2 = g.add(g)
        XCTAssertTrue(g2.isOnCurve())
        let g3 = g2.add(g)
        XCTAssertTrue(g3.isOnCurve())
    }

    func testPointTwice() {
        let g = ECPoint.generator()
        let g2a = g.twice()
        let g2b = g.add(g)
        XCTAssertEqual(g2a, g2b)
    }

    func testPointMultiply() {
        let g = ECPoint.generator()
        let k = BigInt256.fromHex("3")
        let p = g.multiply(k)
        XCTAssertTrue(p.isOnCurve())

        let g2 = g.twice()
        let g3 = g2.add(g)
        XCTAssertEqual(p, g3)
    }

    func testBigIntFromHex() {
        let n = BigInt256.fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
        XCTAssertEqual(n.toHex(), "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
    }

    func testBigIntAdd() {
        let a = BigInt256.fromHex("1")
        let b = BigInt256.fromHex("2")
        let (c, _) = a.add(b)
        XCTAssertEqual(c.toHex(), "0000000000000000000000000000000000000000000000000000000000000003")
    }

    func testBigIntSub() {
        let a = BigInt256.fromHex("5")
        let b = BigInt256.fromHex("3")
        let (c, _) = a.sub(b)
        XCTAssertEqual(c.toHex(), "0000000000000000000000000000000000000000000000000000000000000002")
    }

    func testBigIntMul() {
        let a = BigInt256.fromHex("3")
        let b = BigInt256.fromHex("4")
        let c = a.modMul(b, SM2_P)
        XCTAssertEqual(c.toHex(), "000000000000000000000000000000000000000000000000000000000000000C")
    }

    func testBigIntModInverse() {
        let a = BigInt256.fromHex("3")
        let p = BigInt256.fromHex("7")
        let inv = a.modInverse(p)
        let product = a.modMul(inv, p)
        XCTAssertTrue(product.isOne)
    }

    private func hexToBytes(_ hex: String) throws -> [UInt8] {
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            if let byte = UInt8(hex[index..<nextIndex], radix: 16) {
                bytes.append(byte)
            }
            index = nextIndex
        }
        return bytes
    }
}
