// 确定性随机畸形输入测试。不属于 Swift 包：与库源码一起编译（见 Fuzz/run.sh）。
// 只断言失败约定：任何公开函数都不能陷入陷阱或挂起，失败必须走正常的返回值或抛错，并检查少量不可伪造的性质。
//
//   Fuzz/run.sh [每个函数的用例数，默认 200000] [种子]
//
// 进程崩溃即为发现问题：最后打印的函数名和种子可以确定性复现。

import Foundation

var failures = 0
/// 走到成功路径的用例数，用来确认变异没有把所有输入都挡在最外层
var accepted = 0

func check(_ condition: @autoclosure () throws -> Bool, _ message: @autoclosure () -> String) rethrows {
    if try !condition() {
        failures += 1
        print("FAIL: \(message())")
    }
}

struct RNG {
    var state: UInt64
    mutating func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }
    mutating func below(_ limit: Int) -> Int {
        return Int(next() % UInt64(limit))
    }
    mutating func bytes(_ count: Int) -> [UInt8] {
        return (0..<count).map { _ in UInt8(truncatingIfNeeded: next() >> 17) }
    }
}

let arguments = CommandLine.arguments
let caseCount = arguments.count > 1 ? Int(arguments[1]) ?? 200_000 : 200_000
let seed = arguments.count > 2 ? UInt64(arguments[2]) ?? 0x5EED_1234_ABCD_EF01 : 0x5EED_1234_ABCD_EF01
var rng = RNG(state: seed | 1)

let hexDigits = Array("0123456789abcdefABCDEF".utf8)
let oddities: [String] = [
    "", "h", "0x", "0X", " ", "\n", "\r\n", "\0", "é", "\u{301}", "\u{1F600}", "\u{FEFF}", "+", "-", "z", "G", "/", ":",
    "@", "`",
    "ff", "00", "04", "\u{FFFD}", "国",
]
let n = "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"
let p = "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"
let edgeValues = [
    n, p, String(repeating: "f", count: 64), String(repeating: "0", count: 64),
    "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122",
    "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121",
    "0000000000000000000000000000000000000000000000000000000000000001",
]

func randomHex(_ length: Int) -> String {
    var output = [UInt8]()
    output.reserveCapacity(length)
    for _ in 0..<length {
        output.append(hexDigits[rng.below(hexDigits.count)])
    }
    return String(decoding: output, as: UTF8.self)
}

/// 对合法样本做一次或多次破坏；约三分之一保持不变，以便走到合法路径的更深处。
func mutate(_ text: String) -> String {
    let choice = rng.below(16)
    var scalars = Array(text.utf8)
    switch choice {
    case 0, 1, 2, 3, 4:
        return text
    case 5:  // 改一个字符
        if !scalars.isEmpty {
            scalars[rng.below(scalars.count)] = hexDigits[rng.below(hexDigits.count)]
        }
    case 6:  // 翻转一位，可能产生非 ASCII 或非法 UTF-8（String(decoding:) 会修复）
        if !scalars.isEmpty {
            scalars[rng.below(scalars.count)] ^= UInt8(1) << UInt8(rng.below(8))
        }
    case 7:  // 截断
        scalars = Array(scalars.prefix(rng.below(scalars.count + 1)))
    case 8:  // 延长
        scalars += Array(randomHex(1 + rng.below(70)).utf8)
    case 9:  // 插入怪字符
        let position = rng.below(scalars.count + 1)
        scalars.insert(contentsOf: Array(oddities[rng.below(oddities.count)].utf8), at: position)
    case 10:
        return text.uppercased()
    case 11:  // 随机十六进制，长度随意
        return randomHex(rng.below(300))
    case 12:  // 随机字节
        return String(decoding: rng.bytes(rng.below(200)), as: UTF8.self)
    case 13:
        return oddities[rng.below(oddities.count)]
    case 14:
        return edgeValues[rng.below(edgeValues.count)]
    default:
        // 偶尔很长
        if rng.below(2000) == 0 {
            return randomHex(100_000 + rng.below(100_000))
        }
        return text + text
    }
    return String(decoding: scalars, as: UTF8.self)
}

func suite(_ name: String, _ count: Int = caseCount, _ body: (Int) throws -> Void) rethrows {
    print("start \(name) cases=\(count)")
    fflush(stdout)
    let start = Date()
    for index in 0..<count {
        try body(index)
    }
    print(String(format: "  done %.1fs accepted=%d", Date().timeIntervalSince(start), accepted))
    accepted = 0
    fflush(stdout)
}

let privateHex = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
let publicHex =
    "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
    + "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
let userId = "1234567812345678"
let signedMessage = "message digest"
let goodSignature =
    "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3h"
    + "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"
let encryptedMessage = "encryption standard"
guard let goodCipher = try? SM2.encrypt(encryptedMessage, publicKey: publicHex) else {
    fatalError("setup")
}

// MARK: - 解析

suite("BigInt256.fromHex") { _ in
    let value = BigInt256.fromHex(mutate(privateHex))
    _ = value < BigInt256.one
    _ = value == BigInt256.zero
}
suite("BigInt256.init?(hex:)") { _ in
    let text = mutate(privateHex)
    if BigInt256(hex: text) != nil {
        check(text.utf8.count == 64, "accepted non-canonical length \(text.debugDescription)")
    }
}
suite("ECPoint.fromHexEncoded + toHexEncoded + toEncoded") { _ in
    let text = mutate(publicHex)
    let point = ECPoint.fromHexEncoded(text)
    if !point.isInfinity {
        check(point.toHexEncoded() == text.lowercased(), "point changed its encoding: \(text.debugDescription)")
    }
    _ = point.toEncoded()
}
suite("ECPoint.fromEncoded") { _ in
    var bytes = ECPoint.fromHexEncoded(publicHex).toEncoded()
    switch rng.below(5) {
    case 0: bytes = rng.bytes(rng.below(130))
    case 1: bytes[rng.below(bytes.count)] ^= UInt8(1) << UInt8(rng.below(8))
    case 2: bytes = Array(bytes.prefix(rng.below(66)))
    case 3: bytes += rng.bytes(1 + rng.below(4))
    default: bytes[0] = UInt8(truncatingIfNeeded: rng.next())
    }
    let point = ECPoint.fromEncoded(bytes)
    if !point.isInfinity {
        check(point.toEncoded() == bytes, "accepted different bytes")
    }
}
suite("ECPoint.fromHex") { _ in
    let x = String(publicHex.dropFirst(2).prefix(64))
    let y = String(publicHex.suffix(64))
    let point = ECPoint.fromHex(xHex: mutate(x), yHex: mutate(y))
    _ = point.isInfinity
    _ = point == ECPoint.generator()
}

// MARK: - SM2

suite("SM2.genKeyPair") { _ in
    let (privateKey, publicKey) = SM2.genKeyPair()
    check(privateKey.utf8.count == 64 && publicKey.utf8.count == 130, "bad keypair shape")
}
suite("SM2.verify") { _ in
    let signature = mutate(goodSignature)
    let key = mutate(publicHex)
    let message = rng.below(5) == 0 ? mutate(signedMessage) : signedMessage
    let id = rng.below(5) == 0 ? mutate(userId) : userId
    if SM2.verify(userId: id, signature: signature, message: message, publicKey: key) {
        accepted += 1
        check(
            signature == goodSignature && message == signedMessage && id == userId,
            "forged: \(signature.debugDescription) \(message.debugDescription)")
    }
}
suite("SM2.sign") { _ in
    let key = mutate(privateHex)
    let id = rng.below(6) == 0 ? mutate(userId) : userId
    if let signature = try? SM2.sign(userId: id, message: mutate(signedMessage), privateKey: key) {
        accepted += 1
        check(signature.utf8.count == 129, "bad signature shape")
    }
}
suite("SM2.encrypt") { _ in
    let key = mutate(publicHex)
    if let cipher = try? SM2.encrypt(mutate(encryptedMessage), publicKey: key) {
        accepted += 1
        check(cipher.utf8.count > 194, "bad ciphertext shape")
    }
}
suite("SM2.decrypt") { _ in
    let cipher = mutate(goodCipher)
    let key = rng.below(4) == 0 ? mutate(privateHex) : privateHex
    if let plain = try? SM2.decrypt(cipher, privateKey: key) {
        accepted += 1
        check(cipher == goodCipher && plain == encryptedMessage, "forged ciphertext accepted")
    }
}

// MARK: - 密钥交换

let dAValue = BigInt256.fromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
let raValue = BigInt256.fromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")
let dBValue = BigInt256.fromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")
let rbValue = BigInt256.fromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")
let pointA = SM2.getPublicKey(dAValue).toHexEncoded()
let pointRa = SM2.getPublicKey(raValue).toHexEncoded()
let pointB = SM2.getPublicKey(dBValue).toHexEncoded()
let pointRb = SM2.getPublicKey(rbValue).toHexEncoded()

func fuzzedPoint(_ hex: String) -> ECPoint {
    if rng.below(3) != 0 {
        return ECPoint.fromHexEncoded(hex)
    }
    return ECPoint.fromHexEncoded(mutate(hex))
}

func fuzzedScalar(_ value: BigInt256) -> BigInt256 {
    if rng.below(3) != 0 {
        return value
    }
    return BigInt256.fromHex(mutate(privateHex))
}

func fuzzedLength() -> Int {
    switch rng.below(12) {
    case 0: return Int(truncatingIfNeeded: rng.next())
    case 1: return -rng.below(100)
    case 2: return rng.below(5000) == 0 ? 1 << 20 : 0
    case 3: return (1 << 20) + 1 + rng.below(100)
    default: return 1 + rng.below(64)
    }
}

func fuzzedId(_ valid: String) -> String {
    if rng.below(6) != 0 {
        return valid
    }
    if rng.below(200) == 0 {
        return String(repeating: "a", count: 8180 + rng.below(30))
    }
    return mutate(valid)
}

let goodExchange = SM2.getSb(
    byteLen: 16,
    pA: ECPoint.fromHexEncoded(pointA), Ra: ECPoint.fromHexEncoded(pointRa),
    pB: ECPoint.fromHexEncoded(pointB), dB: dBValue, Rb: ECPoint.fromHexEncoded(pointRb), rb: rbValue,
    IDa: "ALICE", IDb: "BOB")
let goodSb = Hex.decodeStrict(goodExchange.sb ?? "") ?? []

suite("SM2.getSb") { _ in
    let result = SM2.getSb(
        byteLen: fuzzedLength(),
        pA: fuzzedPoint(pointA), Ra: fuzzedPoint(pointRa),
        pB: fuzzedPoint(pointB), dB: fuzzedScalar(dBValue), Rb: fuzzedPoint(pointRb), rb: fuzzedScalar(rbValue),
        IDa: fuzzedId("ALICE"), IDb: fuzzedId("BOB"))
    check(result.success == (result.kb != nil), "getSb inconsistent result")
    accepted += result.success ? 1 : 0
    _ = "\(result)"
}
suite("SM2.getSa") { _ in
    var sb = goodSb
    switch rng.below(5) {
    case 0: sb = rng.bytes(rng.below(70))
    case 1: sb[rng.below(sb.count)] ^= 1
    default: break
    }
    let result = SM2.getSa(
        byteLen: fuzzedLength(),
        pB: fuzzedPoint(pointB), Rb: fuzzedPoint(pointRb),
        pA: fuzzedPoint(pointA), dA: fuzzedScalar(dAValue), Ra: fuzzedPoint(pointRa), ra: fuzzedScalar(raValue),
        IDa: fuzzedId("ALICE"), IDb: fuzzedId("BOB"), Sb: sb)
    check(result.success == (result.ka != nil), "getSa inconsistent result")
    accepted += result.success ? 1 : 0
    if result.success {
        check(sb == goodSb, "accepted a wrong Sb")
    }
}
suite("SM2.checkSa") { _ in
    var sa = rng.bytes(32)
    if rng.below(4) == 0 {
        sa = rng.bytes(rng.below(70))
    }
    let za = rng.below(3) == 0 ? rng.bytes(rng.below(40)) : goodExchange.za ?? []
    let zb = rng.below(3) == 0 ? rng.bytes(rng.below(40)) : goodExchange.zb ?? []
    let v = goodExchange.v ?? ECPoint.infinityPoint()
    check(
        !SM2.checkSa(
            V: rng.below(3) == 0 ? fuzzedPoint(pointA) : v, Za: za, Zb: zb, Ra: fuzzedPoint(pointRa),
            Rb: fuzzedPoint(pointRb),
            Sa: sa),
        "checkSa accepted random Sa")
}

// MARK: - SM4

let sm4Key = "0123456789abcdeffedcba9876543210"
let sm4Iv = "000102030405060708090a0b0c0d0e0f"
let textKey = "0123456789abcdef"
let shared = getSM4().setKey(key: sm4Key, iv: sm4Iv, hex: true)
let sm4Plain = "hello world, this is more than one block long"
let sm4Good = shared.encrypt(text: sm4Plain)

suite("Sm4Impl.setKey") { _ in
    let useHex = rng.below(2) == 0
    let cipher = getSM4().setKey(
        key: mutate(useHex ? sm4Key : textKey), iv: mutate(useHex ? sm4Iv : textKey),
        hex: rng.below(8) == 0 ? !useHex : useHex)
    _ = cipher.encrypt(text: "x")
    _ = cipher.decrypt(text: "00")
}
suite("Sm4Impl.setKeyChecked") { _ in
    let key = mutate(sm4Key)
    let iv = mutate(sm4Iv)
    if (try? getSM4().setKeyChecked(key: key, iv: iv, hex: true)) != nil {
        check(key.utf8.count == 32 && iv.utf8.count == 32, "accepted a bad key or IV length")
    }
}
suite("Sm4Impl.encrypt") { _ in
    let text = mutate(sm4Plain)
    let cipher = shared.encrypt(text: text)
    check(cipher.utf8.count == (text.utf8.count / 16 + 1) * 32, "bad ciphertext length")
}
suite("Sm4Impl.encryptChecked") { _ in
    let text = mutate(sm4Plain)
    if let cipher = try? shared.encryptChecked(text: text) {
        check(cipher.utf8.count == (text.utf8.count / 16 + 1) * 32, "bad ciphertext length")
    }
}
suite("Sm4Impl.decryptBytesChecked") { _ in
    do {
        accepted += try shared.decryptBytesChecked(text: mutate(sm4Good)).isEmpty ? 0 : 1
    } catch let error as SM4Error {
        check(error == .decryptionFailed, "non-uniform error")
    } catch {
        check(false, "unexpected error type")
    }
}
suite("Sm4Impl.decrypt") { _ in
    _ = shared.decrypt(text: mutate(sm4Good))
}
suite("Sm4Impl.decryptChecked") { _ in
    do {
        _ = try shared.decryptChecked(text: mutate(sm4Good))
    } catch let error as SM4Error {
        check(error == .decryptionFailed, "non-uniform error")
    } catch {
        check(false, "unexpected error type")
    }
}

// MARK: - 往返性质

let propertyCount = max(1, caseCount / 10)

func randomText() -> String {
    var scalars = String.UnicodeScalarView()
    for _ in 0..<(1 + rng.below(80)) {
        let value = rng.below(4) == 0 ? UInt32(0x4E00 + rng.below(0x5000)) : UInt32(32 + rng.below(90))
        if let scalar = Unicode.Scalar(value) {
            scalars.append(scalar)
        }
    }
    return String(scalars)
}

try suite("round trip: SM2 encrypt/decrypt", propertyCount) { _ in
    let (privateKey, publicKey) = SM2.genKeyPair()
    let text = randomText()
    let cipher = try SM2.encrypt(text, publicKey: publicKey)
    try check(try SM2.decrypt(cipher, privateKey: privateKey) == text, "SM2 round trip")
}
try suite("round trip: SM2 sign/verify", propertyCount) { _ in
    let (privateKey, publicKey) = SM2.genKeyPair()
    let text = randomText()
    let id = randomText()
    let signature = try SM2.sign(userId: id, message: text, privateKey: privateKey)
    check(SM2.verify(userId: id, signature: signature, message: text, publicKey: publicKey), "sign/verify")
    check(!SM2.verify(userId: id, signature: signature, message: text + "x", publicKey: publicKey), "wrong message")
}
suite("round trip: key exchange", propertyCount) { _ in
    let (dA, pA) = SM2.genKeyPair()
    let (ra, pointR) = SM2.genKeyPair()
    let (dB, pB) = SM2.genKeyPair()
    let (rb, pointS) = SM2.genKeyPair()
    let length = 1 + rng.below(100)
    let b = SM2.getSb(
        byteLen: length, pA: ECPoint.fromHexEncoded(pA), Ra: ECPoint.fromHexEncoded(pointR),
        pB: ECPoint.fromHexEncoded(pB), dB: BigInt256.fromHex(dB), Rb: ECPoint.fromHexEncoded(pointS),
        rb: BigInt256.fromHex(rb),
        IDa: "a", IDb: "b")
    let a = SM2.getSa(
        byteLen: length, pB: ECPoint.fromHexEncoded(pB), Rb: ECPoint.fromHexEncoded(pointS),
        pA: ECPoint.fromHexEncoded(pA), dA: BigInt256.fromHex(dA), Ra: ECPoint.fromHexEncoded(pointR),
        ra: BigInt256.fromHex(ra),
        IDa: "a", IDb: "b", Sb: Hex.decodeStrict(b.sb ?? "") ?? [])
    check(a.success && b.success && a.ka == b.kb, "key exchange round trip")
}
try suite("round trip: SM4", propertyCount) { _ in
    let cipher = try getSM4().setKeyChecked(key: Hex.encode(rng.bytes(16)), iv: Hex.encode(rng.bytes(16)), hex: true)
    let text = randomText()
    try check(try cipher.decryptChecked(text: try cipher.encryptChecked(text: text)) == text, "SM4 round trip")
}


// MARK: - SM9（每次调用都要做配对，用例数按比例缩小）

let sm9Count = max(20, caseCount / 1000)
guard let sm9SignMaster = try? SM9.genSignMasterKey(), let sm9EncMaster = try? SM9.genEncMasterKey(),
    let sm9SignKey = try? SM9.genSignUserKey(masterPrivateKey: sm9SignMaster.masterPrivateKey, userId: "Alice"),
    let sm9EncKey = try? SM9.genEncUserKey(masterPrivateKey: sm9EncMaster.masterPrivateKey, userId: "Bob"),
    let sm9KeyA = try? SM9.genEncUserKey(
        masterPrivateKey: sm9EncMaster.masterPrivateKey, userId: "Alice", hid: SM9.hidExchange),
    let sm9KeyB = try? SM9.genEncUserKey(
        masterPrivateKey: sm9EncMaster.masterPrivateKey, userId: "Bob", hid: SM9.hidExchange),
    let sm9Signature = try? SM9.sign(
        signedMessage, userPrivateKey: sm9SignKey, masterPublicKey: sm9SignMaster.masterPublicKey),
    let sm9Cipher = try? SM9.encrypt(encryptedMessage, userId: "Bob", masterPublicKey: sm9EncMaster.masterPublicKey),
    let sm9CipherSM4 = try? SM9.encrypt(
        encryptedMessage, userId: "Bob", masterPublicKey: sm9EncMaster.masterPublicKey, mode: .sm4),
    let sm9Kem = try? SM9.encapsulate(userId: "Bob", masterPublicKey: sm9EncMaster.masterPublicKey, keyLength: 32),
    let sm9InitA = try? SM9.exchangeInit(peerId: "Bob", masterPublicKey: sm9EncMaster.masterPublicKey),
    let sm9InitB = try? SM9.exchangeInit(peerId: "Alice", masterPublicKey: sm9EncMaster.masterPublicKey)
else {
    fatalError("SM9 setup")
}
let sm9Respond = SM9.exchangeRespond(
    keyLength: 16, idA: "Alice", idB: "Bob", masterPublicKey: sm9EncMaster.masterPublicKey, userPrivateKeyB: sm9KeyB,
    randomPrivateB: sm9InitB.randomPrivate, randomPointB: sm9InitB.randomPoint, randomPointA: sm9InitA.randomPoint)

suite("SM9 master/user key parsing", sm9Count) { _ in
    let master = mutate(sm9SignMaster.masterPrivateKey)
    if let pub = try? SM9.signMasterPublicKey(master) {
        accepted += 1
        check(pub.utf8.count == 258 && master.utf8.count == 64, "bad sign master public key shape")
    }
    if let key = try? SM9.genEncUserKey(masterPrivateKey: master, userId: mutate("Bob")) {
        check(key.utf8.count == 258, "bad enc user key shape")
    }
}
suite("SM9.verify", sm9Count) { _ in
    let signature = mutate(sm9Signature)
    let key = rng.below(4) == 0 ? mutate(sm9SignMaster.masterPublicKey) : sm9SignMaster.masterPublicKey
    let id = rng.below(5) == 0 ? mutate("Alice") : "Alice"
    if SM9.verify(signedMessage, signature: signature, userId: id, masterPublicKey: key) {
        accepted += 1
        check(signature == sm9Signature && id == "Alice", "SM9 forged signature \(signature.debugDescription)")
    }
}
suite("SM9.sign", sm9Count) { _ in
    let key = mutate(sm9SignKey)
    let pub = rng.below(4) == 0 ? mutate(sm9SignMaster.masterPublicKey) : sm9SignMaster.masterPublicKey
    if let signature = try? SM9.sign(signedMessage, userPrivateKey: key, masterPublicKey: pub) {
        accepted += 1
        check(signature.utf8.count == 194, "bad SM9 signature shape")
    }
}
suite("SM9.encrypt", sm9Count) { _ in
    let pub = mutate(sm9EncMaster.masterPublicKey)
    if let cipher = try? SM9.encrypt(mutate(encryptedMessage), userId: "Bob", masterPublicKey: pub) {
        accepted += 1
        check(cipher.utf8.count > 194, "bad SM9 ciphertext shape")
    }
}
suite("SM9.decrypt", sm9Count) { _ in
    let useSM4 = rng.below(2) == 0
    let good = useSM4 ? sm9CipherSM4 : sm9Cipher
    let cipher = mutate(good)
    let key = rng.below(4) == 0 ? mutate(sm9EncKey) : sm9EncKey
    do {
        let plain = try SM9.decrypt(cipher, userId: "Bob", userPrivateKey: key, mode: useSM4 ? .sm4 : .stream)
        accepted += 1
        check(cipher == good && plain == Array(encryptedMessage.utf8), "SM9 forged ciphertext accepted")
    } catch let error as SM9Error {
        if case .invalidKey = error {
            check(key != sm9EncKey, "valid key rejected")
        } else {
            check(error == .decryptionFailed("Decryption failed"), "non-uniform SM9 error")
        }
    } catch {
        check(false, "unexpected error type")
    }
}
suite("SM9.decapsulate", sm9Count) { _ in
    let cipher = mutate(sm9Kem.ciphertext)
    if let key = try? SM9.decapsulate(cipher, userId: "Bob", userPrivateKey: sm9EncKey, keyLength: fuzzedLength()) {
        accepted += 1
        check(cipher == sm9Kem.ciphertext || key.utf8.count % 2 == 0, "bad SM9 key shape")
    }
}
suite("SM9.exchangeRespond", sm9Count) { _ in
    let result = SM9.exchangeRespond(
        keyLength: fuzzedLength(), idA: fuzzedId("Alice"), idB: "Bob", masterPublicKey: sm9EncMaster.masterPublicKey,
        userPrivateKeyB: rng.below(4) == 0 ? mutate(sm9KeyB) : sm9KeyB, randomPrivateB: mutate(sm9InitB.randomPrivate),
        randomPointB: mutate(sm9InitB.randomPoint), randomPointA: mutate(sm9InitA.randomPoint))
    check(result.success == (result.sharedKey != nil), "SM9 respond inconsistent result")
    accepted += result.success ? 1 : 0
}
suite("SM9.exchangeConfirm", sm9Count) { _ in
    let sb = mutate(sm9Respond.sb ?? "")
    let result = SM9.exchangeConfirm(
        keyLength: 16, idA: "Alice", idB: "Bob", masterPublicKey: sm9EncMaster.masterPublicKey,
        userPrivateKeyA: sm9KeyA, randomPrivateA: sm9InitA.randomPrivate, randomPointA: sm9InitA.randomPoint,
        randomPointB: sm9InitB.randomPoint, sb: sb)
    accepted += result.success ? 1 : 0
    if result.success {
        check(sb == sm9Respond.sb, "SM9 confirm accepted a wrong S_B")
        check(SM9.exchangeCheck(s2: sm9Respond.s2 ?? "", sa: result.sa ?? ""), "SM9 S_A mismatch")
    }
}
suite("SM9.exchangeCheck", sm9Count * 100) { _ in
    let sa = mutate(sm9Respond.s2 ?? "")
    if SM9.exchangeCheck(s2: sm9Respond.s2 ?? "", sa: sa) {
        check(sa == sm9Respond.s2, "SM9 check accepted a wrong S_A")
    }
}

print("finished seed=\(seed) failures=\(failures)")
exit(failures == 0 ? 0 : 1)
