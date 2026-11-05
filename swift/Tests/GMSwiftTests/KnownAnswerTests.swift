import XCTest

@testable import GMSwift

/// Standard vectors (GB/T 32905 SM3, GB/T 32907 SM4, GB/T 32918 SM2 sample key) and outputs captured from the
/// pre-optimization code at commit 3397c6d. Written and run against that code before any optimization.
final class KnownAnswerTests: XCTestCase {
    private func unhex(_ hex: String) -> [UInt8] {
        let utf8 = Array(hex.utf8)
        return stride(from: 0, to: utf8.count, by: 2).map {
            UInt8(String(decoding: utf8[$0..<($0 + 2)], as: UTF8.self), radix: 16)!
        }
    }

    // MARK: - SM3

    func testSM3StandardVectors() {
        XCTAssertEqual(
            SM3().update("abc").finalize().getHash(),
            "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0")
        XCTAssertEqual(
            SM3().update(String(repeating: "abcd", count: 16)).finalize().getHash(),
            "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732")
    }

    func testSM3HashBytesMatchHex() {
        let sm3 = SM3().update("abc").finalize()
        XCTAssertEqual(sm3.getHashBytes(), unhex(sm3.getHash()))
    }

    // MARK: - SM4

    private let sm4Key = "0123456789ABCDEFFEDCBA9876543210"

    /// The CBC path with a zero IV gives the raw block cipher for the first block.
    private func encryptBlock(_ sm4: Sm4Impl, _ block: [UInt8]) -> [UInt8] {
        let hex = sm4.doCrypt(input: block, cbcIV: [UInt8](repeating: 0, count: 16), encrypt: true)
        return unhex(String(hex.prefix(32)))
    }

    func testSM4StandardVector() {
        let key = unhex(sm4Key)
        let sm4 = Sm4Impl()
        sm4.setKeyBytes(keyBytes: key, ivBytes: [UInt8](repeating: 0, count: 16))
        XCTAssertEqual(encryptBlock(sm4, key), unhex("681EDF34D206965E86B3E94F536E4246"))
    }

    func testSM4MillionIterationVector() {
        let key = unhex(sm4Key)
        let sm4 = Sm4Impl()
        sm4.setKeyBytes(keyBytes: key, ivBytes: [UInt8](repeating: 0, count: 16))
        var block = key
        for _ in 0..<1_000_000 {
            block = encryptBlock(sm4, block)
        }
        XCTAssertEqual(block, unhex("595298C7C6FD271F0402F804C33D3F66"))
    }

    func testSM4CapturedCBC() {
        let sm4 = Sm4Impl().setKey(
            key: "0123456789abcdeffedcba9876543210", iv: "fedcba98765432100123456789abcdef", hex: true)
        let text = "The quick brown fox jumps over the lazy dog"
        let cipher = sm4.encrypt(text: text)
        XCTAssertEqual(
            cipher, "289db110150af984935cdc485af7075065c16de7466162239ebaedf5c777aab1f9853adcb819040985bc6a3ca49f074e")
        XCTAssertEqual(sm4.decrypt(text: cipher), text)
    }

    // MARK: - SM2

    private let sampleKey = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
    private let samplePublic =
        "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
        + "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
    private let aliceId = "ALICE123@YAHOO.COM"

    func testSM2SampleKeyAndStandardSignature() {
        XCTAssertEqual(SM2.getPublicKey(BigInt256.fromHex(sampleKey)).toHexEncoded(), samplePublic)
        let standard =
            "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3h"
            + "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"
        XCTAssertTrue(
            SM2.verify(
                userId: "1234567812345678", signature: standard, message: "message digest", publicKey: samplePublic))
        XCTAssertFalse(
            SM2.verify(
                userId: "1234567812345678", signature: standard, message: "message digesu", publicKey: samplePublic))
        XCTAssertFalse(
            SM2.verify(userId: aliceId, signature: standard, message: "message digest", publicKey: samplePublic))
    }

    func testSM2CapturedScalarMultiples() {
        let vectors: [(String, String)] = [
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "0456cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd5231b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3"
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                "04a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6"
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000010",
                "0435648233f554ae51bbce44ef5db3e419ea133cd248a93e2555645bbc8704fb6804d7ac60f6d975ef6117bca9ce885dd6154b1870a6a651664411a9a30eca2046"
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000021",
                "04a1aa7f4a428089084624f85fe9b7cb83451641e8455eedb66d69b1bd07837dc93d420dee447499cfeb15fccc636948306e67fd81941c6a60c3c8bd75b5fe25de"
            ),
            (
                "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122",
                "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c743c8c95c0b098863a642311c9496deac2f56788239d5b8c0fd20cd1adec60f5f"
            ),
            (
                "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54121",
                "0456cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52ce481818337e760997aca31f07150e429217b3e6d093718f9087f2c568f5dc3c"
            ),
            ("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", "00"),
            (
                "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54124",
                "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
            ),
            (
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "04b3217d884bc175e6ba6b360eb0e6d4396eaea725c3d66e87bfa5beb6c0d3456ba5199445c54b56602aa60025e1907bfd26b30e867db6c58a034263ae4a2e27c2"
            ),
        ]
        for (scalar, expected) in vectors {
            let k = BigInt256.fromHex(scalar)
            XCTAssertEqual(SM2.getPublicKey(k).toHexEncoded(), expected, scalar)
            XCTAssertEqual(ECPoint.generator().multiply(k).toHexEncoded(), expected, scalar)
        }
    }

    /// Off-curve points reach the scalar multiplication through getSb/getSa, which do not validate pA/pB.
    func testSM2CapturedOffCurveMultiples() {
        let point = ECPoint.fromHex(xHex: "1", yHex: "1")
        XCTAssertEqual(
            point.multiply(BigInt256.fromHex("5")).toHexEncoded(),
            "043d8930bf8f513faac16606ed161c3cbc9a81771334bebc125ad6b5ad6b5ad6b6ec84eb6a69eb7656422f506c7b052e83d63caf66992eafd6706a8e407757a45d"
        )
        XCTAssertEqual(
            point.multiply(BigInt256.fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"))
                .toHexEncoded(),
            "0425f80622cbd80a894fdcbed01cd933bbf70767fef81f89bc4d37729b96e9baa3d16824e7c9b95f5a4e45869e71aa216e1154e1021e5bd085aa857b302dc7b7d8"
        )
    }

    func testSM2CapturedSignatures() {
        let vectors = [
            (
                "4903456119de9585dd5fd4f9666c35dcdedd3ff3df7a76c6580f399cd861d674h78634d1c9e541d1d370f0fd7e83fa33343a0b1effd1641fb99b6b0d2bc88fa24",
                "message digest"
            ),
            (
                "874abcd48f1b008f3dc51c89a0cfd7f1032a4ebcb283405a2e0f3e0265982cc0hc78ce7677eca3d0db725cfa4b2b0ed6854a2fe6f77ddc8c2804701e96332eac6",
                "message digest"
            ),
            (
                "ba072e403829b8d3fb4298ef1bde71fe93f8307b757b12d0c567830e53c0fc27h199bedf9eb88a98dd955b21e810358e90de1377b30ef2d734135eda9e02abc1e",
                "SM2国密算法加密测试"
            ),
        ]
        for (signature, message) in vectors {
            XCTAssertTrue(SM2.verify(userId: aliceId, signature: signature, message: message, publicKey: samplePublic))
            XCTAssertFalse(
                SM2.verify(userId: "BILL456@YAHOO.COM", signature: signature, message: message, publicKey: samplePublic)
            )
        }
    }

    func testSM2CapturedCiphertexts() throws {
        let vectors = [
            (
                "04bb87a773f07dc14c6d1c66fe6536112d597cfe339860090195a5daaff680fd0b29669667e6723eb9bec0dc3f3e82d9077c404fcd5b84e4a4e02eecfedc68676b8ac1998ccf9ff44693d67be9b55a7ca59565bd72523c49acbcce0cebe6983ea8399598aa46326efb5fe62adb5b1a",
                "message digest"
            ),
            (
                "0436131c23393acfec55bd99c2e5c59fbe88ae84fe6fd548e1ba02f83cf868bd010c6f3ea6baa99264c197efe1f0110e00b185517a3e0466645c297a1fb7f300c7d64316ed6da12172d2e156fe54f7ccbd772b8d39c66aa529d731d4509b1debf6f4392e6a46d377df7549dd6fdcde",
                "message digest"
            ),
            (
                "04239adc0c75c83031a3440e5c8a78bdb3d89822f4c66c5db5e2044c29db16b51613fad484ee5a8b8554db0c068042ecfdffd1e8dbd5d0d79862771413dab18e21b603b531f8c669febb43d30fb4f08fdcaf0f9aa4299baeb42c77ef2784424b62535f62ead7b74465bd716bcc708a56e27960a21b7af9497d2f278d",
                "SM2国密算法加密测试"
            ),
        ]
        for (cipher, message) in vectors {
            XCTAssertEqual(try SM2.decrypt(cipher, privateKey: sampleKey), message)
        }
    }

    func testSM2CapturedKeyExchange() {
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

        let b = SM2.getSb(byteLen: 48, pA: pA, Ra: pointRa, pB: pB, dB: dB, Rb: pointRb, rb: rb, IDa: idA, IDb: idB)
        XCTAssertEqual(b.sb, "b93374ade30a74e12ddb40e4c03d0c6fcf61badbf2c2c5cc39a91201d9228e2e")
        XCTAssertEqual(
            b.kb, "f02f9068ad13e14f2b2602e0dfb2504ff5fabef8555364b7374436e8566d02aa5704021bc20a93dbefc42d1978da9b68")
        XCTAssertEqual(
            b.v?.toHexEncoded(),
            "04588d82da2f0e75a042aab58a707c725e203d1bf1cb8eff56e37af32c24665267e85d7572801c598eeebc061347821a568895aef6fb8448fbef16845cfcc2e6f4"
        )

        let a = SM2.getSa(
            byteLen: 48, pB: pB, Rb: pointRb, pA: pA, dA: dA, Ra: pointRa, ra: ra, IDa: idA, IDb: idB,
            Sb: unhex(b.sb ?? ""))
        XCTAssertEqual(a.sa, "daefca6c32f53c48444d4ef35f98471e5d1cd1e3b5b8e3322dede310306689f6")
        XCTAssertEqual(a.ka, b.kb)
    }
}
