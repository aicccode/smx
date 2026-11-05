// GMSwift benchmark. Not part of the package: compile it together with the library sources so that it
// sees the internal SM3 type and gets the same whole-module optimization a release build gets.
//
//   ./Benchmarks/run.sh [sources-dir]
//
// Each case runs in batches for at least `minSeconds`; the best batch out of `rounds` is reported.

import Foundation

let minSeconds = 0.25
let rounds = 5

var sink = 0

func now() -> Double {
    var ts = timespec()
    clock_gettime(CLOCK_MONOTONIC, &ts)
    return Double(ts.tv_sec) + Double(ts.tv_nsec) * 1e-9
}

func bench(_ name: String, bytes: Int = 0, _ body: () throws -> Int) rethrows {
    var best = Double.infinity
    for _ in 0..<rounds {
        var iterations = 0
        let start = now()
        var elapsed = 0.0
        repeat {
            sink &+= try body()
            iterations += 1
            elapsed = now() - start
        } while elapsed < minSeconds
        best = min(best, elapsed / Double(iterations))
    }
    let padded = name.padding(toLength: 24, withPad: " ", startingAt: 0)
    let time = String(format: "%14.2f ns/op", best * 1e9)
    let rate = bytes > 0 ? String(format: "  %10.2f MB/s", Double(bytes) / best / 1e6) : ""
    print("\(padded)\(time)\(rate)")
}

func testBytes(_ count: Int) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) }
}

func asciiString(_ count: Int) -> String {
    String(decoding: (0..<count).map { UInt8(97 + $0 % 26) }, as: UTF8.self)
}

for (name, size) in [("SM3 64B", 64), ("SM3 1KB", 1024), ("SM3 1MB", 1 << 20)] {
    let data = testBytes(size)
    bench(name, bytes: size) { SM3().update(data).finalize().getHash().utf8.count }
}

let keyHex = "0123456789abcdeffedcba9876543210"
bench("SM4 key schedule") {
    _ = getSM4().setKey(key: keyHex, iv: keyHex, hex: true)
    return 1
}

let sm4 = getSM4().setKey(key: keyHex, iv: keyHex, hex: true)
for (name, size) in [("16B", 16), ("1KB", 1024), ("1MB", 1 << 20)] {
    let text = asciiString(size)
    let cipher = sm4.encrypt(text: text)
    bench("SM4 encrypt \(name)", bytes: size) { sm4.encrypt(text: text).utf8.count }
    bench("SM4 decrypt \(name)", bytes: size) { sm4.decrypt(text: cipher).utf8.count }
}

let userId = "ALICE123@YAHOO.COM"
let message = "encryption standard"
let (privateKey, publicKey) = SM2.genKeyPair()
let signature = try SM2.sign(userId: userId, message: message, privateKey: privateKey)
let ciphertext = try SM2.encrypt(message, publicKey: publicKey)

bench("SM2 keygen") { SM2.genKeyPair().publicKey.utf8.count }
try bench("SM2 sign") { try SM2.sign(userId: userId, message: message, privateKey: privateKey).utf8.count }
bench("SM2 verify") {
    SM2.verify(userId: userId, signature: signature, message: message, publicKey: publicKey) ? 1 : 0
}
try bench("SM2 encrypt") { try SM2.encrypt(message, publicKey: publicKey).utf8.count }
try bench("SM2 decrypt") { try SM2.decrypt(ciphertext, privateKey: privateKey).utf8.count }

let idA = "ALICE123@YAHOO.COM"
let idB = "BILL456@YAHOO.COM"
let dA = BigInt256.fromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
let ra = BigInt256.fromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")
let dB = BigInt256.fromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")
let rb = BigInt256.fromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")
let pointA = SM2.getPublicKey(dA)
let pointRa = SM2.getPublicKey(ra)
let pointB = SM2.getPublicKey(dB)
let pointRb = SM2.getPublicKey(rb)

// One side's computation: [t](P + [x]R) plus the KDF and confirmation hashes.
bench("SM2 key exchange getSb") {
    SM2.getSb(
        byteLen: 16, pA: pointA, Ra: pointRa, pB: pointB, dB: dB, Rb: pointRb, rb: rb, IDa: idA, IDb: idB
    ).success ? 1 : 0
}

print("(sink \(sink))")
