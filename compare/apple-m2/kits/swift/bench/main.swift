// SMX Swift benchmark for the Mac kit. Compiled into the same module as one side's library sources (base or new),
// so it can reach the internal SM3 type and SM2.getPublicKey, which exist on both sides. Only API present on both is used.
import Foundation

@inline(never) func consume<T>(_ value: T) { withExtendedLifetime(value) {} }
var sink = 0

func nowNanos() -> UInt64 { return DispatchTime.now().uptimeNanoseconds }

/// Warm up, then 7 samples of at least 200 ms; prints median and min in microseconds per operation.
func measure(_ name: String, _ body: () throws -> Int) rethrows {
    let warmupEnd = nowNanos() + 300_000_000
    var batch = 1
    while nowNanos() < warmupEnd {
        for _ in 0..<batch { sink &+= try body() }
        batch = min(batch * 2, 1 << 20)
    }
    // pick a batch size that takes at least 200 ms
    batch = 1
    while true {
        let start = nowNanos()
        for _ in 0..<batch { sink &+= try body() }
        if nowNanos() - start >= 200_000_000 { break }
        batch *= 2
    }
    var samples = [Double]()
    for _ in 0..<7 {
        var iterations = 0
        let start = nowNanos()
        var elapsed: UInt64 = 0
        repeat {
            for _ in 0..<batch { sink &+= try body() }
            iterations += batch
            elapsed = nowNanos() - start
        } while elapsed < 200_000_000
        samples.append(Double(elapsed) / 1000.0 / Double(iterations))
    }
    samples.sort()
    print("\(name)\t\(String(format: "%.3f", samples[3]))\t\(String(format: "%.3f", samples[0]))")
}

func check(_ condition: Bool, _ message: String) {
    if !condition {
        FileHandle.standardError.write("CHECK FAILED: \(message)\n".data(using: .utf8)!)
        exit(1)
    }
}

func unhex(_ hex: String) -> [UInt8] {
    let digits = Array(hex.utf8)
    func value(_ c: UInt8) -> UInt8 { return c <= 57 ? c - 48 : (c | 0x20) - 87 }
    return stride(from: 0, to: digits.count, by: 2).map { value(digits[$0]) << 4 | value(digits[$0 + 1]) }
}

func bytes(_ count: Int) -> [UInt8] { return (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 131 &+ 17) } }
func text(_ count: Int) -> String { return String(decoding: (0..<count).map { UInt8(97 + $0 % 26) }, as: UTF8.self) }

// MARK: - SM3: one-shot hash (the internal SM3 class on both sides; getHash returns hex on both)
let sm3Expected64 = SM3().update(bytes(64)).finalize().getHash()
for (name, size) in [("sm3/64B", 64), ("sm3/1KB", 1024), ("sm3/1MB", 1 << 20)] {
    let data = bytes(size)
    measure(name) { SM3().update(data).finalize().getHash().utf8.count }
}
check(SM3().update(Array("abc".utf8)).finalize().getHash() == "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0", "sm3 abc")
consume(sm3Expected64)

// MARK: - SM4: CBC + PKCS#7 through the public hex/string API
let keyHex = "0123456789abcdeffedcba9876543210"
let ivHex = "000102030405060708090a0b0c0d0e0f"
let otherKey = "fedcba98765432100123456789abcdef"
var flip = false
measure("sm4/key_schedule") {
    flip.toggle()
    return getSM4().setKey(key: flip ? keyHex : otherKey, iv: ivHex, hex: true) === nil ? 0 : 1
}
let sm4 = getSM4().setKey(key: keyHex, iv: ivHex, hex: true)
check(sm4.encrypt(text: "hello world") == "bd73e45045b9139bf5d9f533719cfcfd", "sm4 shared vector")
var ciphertexts = [Int: String]()
for size in [16, 1024, 1 << 20] {
    let plain = text(size)
    let cipher = sm4.encrypt(text: plain)
    check(cipher.utf8.count == (size / 16 + 1) * 32, "sm4 ciphertext length \(size)")
    check(sm4.decrypt(text: cipher) == plain, "sm4 round trip \(size)")
    ciphertexts[size] = cipher
}
for (name, size) in [("sm4/cbc_encrypt/16B", 16), ("sm4/cbc_encrypt/1KB", 1024), ("sm4/cbc_encrypt/1MB", 1 << 20)] {
    let plain = text(size)
    measure(name) { sm4.encrypt(text: plain).utf8.count }
}
for (name, size) in [("sm4/cbc_decrypt/16B", 16), ("sm4/cbc_decrypt/1KB", 1024), ("sm4/cbc_decrypt/1MB", 1 << 20)] {
    let cipher = ciphertexts[size]!
    measure(name) { sm4.decrypt(text: cipher).utf8.count }
}

// MARK: - SM2
let userId = "1234567812345678"
let message32 = text(32)
let (privateKey, publicKey) = SM2.genKeyPair()
let signature = try SM2.sign(userId: userId, message: message32, privateKey: privateKey)
check(SM2.verify(userId: userId, signature: signature, message: message32, publicKey: publicKey), "sm2 verify")
check(!SM2.verify(userId: userId, signature: signature, message: text(31) + "z", publicKey: publicKey), "sm2 verify wrong")
let ciphertext = try SM2.encrypt(message32, publicKey: publicKey)
check(try SM2.decrypt(ciphertext, privateKey: privateKey) == message32, "sm2 decrypt")

measure("sm2/keygen") { SM2.genKeyPair().publicKey.utf8.count }
try measure("sm2/sign") { try SM2.sign(userId: userId, message: message32, privateKey: privateKey).utf8.count }
measure("sm2/verify") { SM2.verify(userId: userId, signature: signature, message: message32, publicKey: publicKey) ? 1 : 0 }
try measure("sm2/encrypt/32B") { try SM2.encrypt(message32, publicKey: publicKey).utf8.count }
try measure("sm2/decrypt/32B") { try SM2.decrypt(ciphertext, privateKey: privateKey).utf8.count }

// Key exchange: long-term keys fixed; each operation generates both ephemeral key pairs and runs getSb, getSa
// (with the Sb check) and checkSa, deriving a 16-byte key on both sides.
let idA = "1234567812345678"
let idB = "1234567812345678"
let (dAHex, pAHex) = SM2.genKeyPair()
let (dBHex, pBHex) = SM2.genKeyPair()
let dA = BigInt256.fromHex(dAHex)
let dB = BigInt256.fromHex(dBHex)
let pA = ECPoint.fromHexEncoded(pAHex)
let pB = ECPoint.fromHexEncoded(pBHex)

func exchange() -> (String, String, Bool) {
    let (raHex, raPub) = SM2.genKeyPair()
    let (rbHex, rbPub) = SM2.genKeyPair()
    let ra = BigInt256.fromHex(raHex)
    let rb = BigInt256.fromHex(rbHex)
    let pointRa = ECPoint.fromHexEncoded(raPub)
    let pointRb = ECPoint.fromHexEncoded(rbPub)
    let b = SM2.getSb(byteLen: 16, pA: pA, Ra: pointRa, pB: pB, dB: dB, Rb: pointRb, rb: rb, IDa: idA, IDb: idB)
    let a = SM2.getSa(
        byteLen: 16, pB: pB, Rb: pointRb, pA: pA, dA: dA, Ra: pointRa, ra: ra, IDa: idA, IDb: idB, Sb: unhex(b.sb ?? ""))
    let confirmed = SM2.checkSa(
        V: b.v ?? pA, Za: b.za ?? [], Zb: b.zb ?? [], Ra: pointRa, Rb: pointRb, Sa: unhex(a.sa ?? ""))
    return (a.ka ?? "", b.kb ?? "", confirmed && a.success && b.success)
}
let (ka, kb, confirmed) = exchange()
check(confirmed && ka == kb && ka.utf8.count == 32, "sm2 key exchange")
measure("sm2/key_exchange") {
    let (ka, kb, ok) = exchange()
    return ka.utf8.count &+ kb.utf8.count &+ (ok ? 1 : 0)
}

FileHandle.standardError.write("checks passed (sink \(sink))\n".data(using: .utf8)!)
