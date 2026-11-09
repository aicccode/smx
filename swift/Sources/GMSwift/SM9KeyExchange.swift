// SM9 密钥交换（GB/T 38635.3）。发起方 A（ID_A）与响应方 B（ID_B），双方的用户私钥用 hid = 0x02 生成。
//
//   exchangeInit（双方各调一次）：R = [r]Q_peer，r 保密
//   B: exchangeRespond -> SK_B、S_B（发给 A）、S_2（留着核对 A 的 S_A）
//   A: exchangeConfirm  -> 核对 S_B 后才给出 SK_A，以及 S_A（发给 B）
//   B: exchangeCheck(S_2, S_A)，恒定时间比较

import Foundation

/// 密钥交换的结果。sharedKey 是秘密，不会出现在 print/dump 的输出里。
public final class SM9KeyExchangeResult: CustomReflectable, CustomStringConvertible {
    public internal(set) var success = false
    public internal(set) var message: String?
    /// 协商出的密钥（小写十六进制）
    public internal(set) var sharedKey: String?
    /// 响应方发给发起方的确认值 S_B（exchangeRespond）
    public internal(set) var sb: String?
    /// 响应方期望收到的 S_A（exchangeRespond），交给 exchangeCheck
    public internal(set) var s2: String?
    /// 发起方发给响应方的确认值 S_A（exchangeConfirm）
    public internal(set) var sa: String?

    public var customMirror: Mirror {
        return Mirror(self, children: [])
    }

    public var description: String {
        return "SM9KeyExchangeResult(success: \(success), message: \(message ?? "nil"))"
    }

    fileprivate static func failure(_ message: String) -> SM9KeyExchangeResult {
        let result = SM9KeyExchangeResult()
        result.message = message
        return result
    }
}

extension SM9 {
    private static let invalidExchangeInput = "协商失败，输入参数不合法"

    /// 生成临时密钥：r 随机，R = [r]Q_peer，Q_peer = [H1(ID_peer||hid)]P1 + Ppub-e。
    /// 返回 (r, R)，r（64个十六进制字符）是秘密，R 是 G1 点。
    public static func exchangeInit(
        peerId: String, masterPublicKey: String, hid: UInt8 = hidExchange
    ) throws -> (randomPrivate: String, randomPoint: String) {
        let r = try SM9Support.randomScalar()
        guard let point = try exchangeInitWithRandom(peerId: Array(peerId.utf8), masterPublicKey: masterPublicKey, hid: hid, r: r)
        else {
            throw SM9Error.invalidKey("Invalid master public key")
        }
        return (r.toHexLower(), point)
    }

    /// 测试入口：用给定的 r 计算 R
    static func exchangeInitWithRandom(
        peerId: [UInt8], masterPublicKey: String, hid: UInt8, r: BigInt256
    ) throws -> String? {
        guard let ppubE = SM9Points.decodeG1Hex(masterPublicKey),
            let q = identityPoint(peerId, hid: hid, ppubE: ppubE)
        else {
            throw SM9Error.invalidKey("Invalid master public key")
        }
        return SM9G1.multiplySecret(q, r).toAffine().map { Hex.encode(SM9Points.encodeG1($0)) }
    }

    /// 双方共同的输入校验
    private struct ExchangeInputs {
        let ppubE: SM9Affine<SM9Fp>
        let de: SM9Affine<SM9Fp2>
        let r: BigInt256
        let ra: SM9Affine<SM9Fp>
        let rb: SM9Affine<SM9Fp>
    }

    private static func parseExchange(
        keyLength: Int, masterPublicKey: String, userPrivateKey: String, randomPrivate: String,
        randomPointA: String, randomPointB: String
    ) -> ExchangeInputs? {
        guard SM9Limits.keyLengths.contains(keyLength),
            let ppubE = SM9Points.decodeG1Hex(masterPublicKey),
            let de = SM9Points.decodeG2Hex(userPrivateKey),
            let r = SM9Support.parseScalar(randomPrivate),
            let ra = SM9Points.decodeG1Hex(randomPointA),
            let rb = SM9Points.decodeG1Hex(randomPointB)
        else {
            return nil
        }
        return ExchangeInputs(ppubE: ppubE, de: de, r: r, ra: ra, rb: rb)
    }

    /// SK = KDF(ID_A||ID_B||R_A||R_B||g1||g2||g3, klen)；inner = SM3(g2||g3||ID_A||ID_B||R_A||R_B)
    private static func exchangeValues(
        keyLength: Int, idA: [UInt8], idB: [UInt8], inputs: ExchangeInputs, g1: [UInt8], g2: [UInt8], g3: [UInt8]
    ) -> (key: [UInt8], inner: [UInt8]) {
        let ra = SM9Points.xyG1(inputs.ra)
        let rb = SM9Points.xyG1(inputs.rb)
        let key = SM9Support.kdf([idA, idB, ra, rb, g1, g2, g3], length: keyLength)
        let inner = SM9Support.sm3(g2, g3, idA, idB, ra, rb)
        return (key, inner)
    }

    /// 响应方 B：校验 R_A，计算 SK_B、S_B 和期望的 S_2。
    public static func exchangeRespond(
        keyLength: Int, idA: String, idB: String, masterPublicKey: String, userPrivateKeyB: String,
        randomPrivateB: String, randomPointB: String, randomPointA: String
    ) -> SM9KeyExchangeResult {
        guard
            let inputs = parseExchange(
                keyLength: keyLength, masterPublicKey: masterPublicKey, userPrivateKey: userPrivateKeyB,
                randomPrivate: randomPrivateB, randomPointA: randomPointA, randomPointB: randomPointB)
        else {
            return SM9KeyExchangeResult.failure(invalidExchangeInput)
        }
        let g1Value = SM9Pairing.pairing(inputs.ra, inputs.de)
        var g1 = g1Value.toBytes()
        var g2 = SM9Pairing.powSecret(SM9MasterPairingCache.shared.encryptBase(inputs.ppubE), inputs.r).toBytes()
        var g3 = SM9Pairing.powSecret(g1Value, inputs.r).toBytes()
        defer {
            secureWipe(&g1)
            secureWipe(&g2)
            secureWipe(&g3)
        }
        var (key, inner) = exchangeValues(
            keyLength: keyLength, idA: Array(idA.utf8), idB: Array(idB.utf8), inputs: inputs, g1: g1, g2: g2, g3: g3)
        defer { secureWipe(&key) }
        let result = SM9KeyExchangeResult()
        result.sharedKey = Hex.encode(key)
        result.sb = Hex.encode(SM9Support.sm3([0x82], g1, inner))
        result.s2 = Hex.encode(SM9Support.sm3([0x83], g1, inner))
        secureWipe(&inner)
        result.success = true
        return result
    }

    /// 发起方 A：校验 R_B，在恒定时间内核对 S_B，通过后给出 SK_A 和 S_A。
    public static func exchangeConfirm(
        keyLength: Int, idA: String, idB: String, masterPublicKey: String, userPrivateKeyA: String,
        randomPrivateA: String, randomPointA: String, randomPointB: String, sb: String
    ) -> SM9KeyExchangeResult {
        guard
            let inputs = parseExchange(
                keyLength: keyLength, masterPublicKey: masterPublicKey, userPrivateKey: userPrivateKeyA,
                randomPrivate: randomPrivateA, randomPointA: randomPointA, randomPointB: randomPointB)
        else {
            return SM9KeyExchangeResult.failure(invalidExchangeInput)
        }
        let received = Hex.decodeCanonical(sb) ?? []
        let g2Value = SM9Pairing.pairing(inputs.rb, inputs.de)
        var g1 = SM9Pairing.powSecret(SM9MasterPairingCache.shared.encryptBase(inputs.ppubE), inputs.r).toBytes()
        var g2 = g2Value.toBytes()
        var g3 = SM9Pairing.powSecret(g2Value, inputs.r).toBytes()
        defer {
            secureWipe(&g1)
            secureWipe(&g2)
            secureWipe(&g3)
        }
        var (key, inner) = exchangeValues(
            keyLength: keyLength, idA: Array(idA.utf8), idB: Array(idB.utf8), inputs: inputs, g1: g1, g2: g2, g3: g3)
        defer {
            secureWipe(&key)
            secureWipe(&inner)
        }
        // sm9ConstantTimeEquals 对长度不同（包括解码失败的空数组）返回 false
        if !sm9ConstantTimeEquals(SM9Support.sm3([0x82], g1, inner), received) {
            return SM9KeyExchangeResult.failure("协商失败，B用户验证值与A侧计算值不相等")
        }
        let result = SM9KeyExchangeResult()
        result.sharedKey = Hex.encode(key)
        result.sa = Hex.encode(SM9Support.sm3([0x83], g1, inner))
        result.success = true
        return result
    }

    /// 响应方核对 S_A == S_2，恒定时间。两者都必须是64个小写十六进制字符。
    public static func exchangeCheck(s2: String, sa: String) -> Bool {
        guard let expected = Hex.decodeCanonical(s2), expected.count == 32, let received = Hex.decodeCanonical(sa)
        else {
            return false
        }
        return sm9ConstantTimeEquals(expected, received)
    }
}
