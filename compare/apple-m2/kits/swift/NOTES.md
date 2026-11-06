# Swift kit

- `base/`: `swift/Sources/GMSwift` at 3397c6d (original code). `new/`: the same directory at HEAD of feat/deep-optimization (a327a78 when built).
- `bench/main.swift` is shared by both sides. It is compiled into the same module as each side's sources, because the SM3 type and
  `SM2.getPublicKey` are internal on both sides; everything else is public API that exists unchanged on both sides.
- Build: `swiftc -O -wmo -suppress-warnings -module-name SMXBench <side>/*.swift bench/main.swift` (whole-module, release), identical for
  both sides. `SWIFTC` may override the compiler path; default is `swiftc` from PATH (Xcode toolchain, Swift 5.10).
  Warnings are suppressed because the baseline has some; build.sh prints only errors. A build takes about 40 s.
- Measurement: 0.3 s warm-up per operation (AOT-compiled, no JIT), then 7 samples of at least 200 ms; median and min in µs per operation.
  Clock: `DispatchTime.now()` (monotonic). Results are consumed into a global sink. Self-checks (SM3 "abc" vector, SM4 shared vector,
  SM4 round trips, sign/verify including a wrong message, SM2 decrypt round trip, key-exchange Ka == Kb with confirmation) run outside
  the timing; a failure exits 1. "checks passed" goes to stderr.

## What each operation does (same calls on both sides)
- SM3: `SM3().update(bytes).finalize().getHash()`: includes the hex encoding of the 32-byte digest, which the API forces on both sides.
- SM4: hex key/IV through `getSM4().setKey(key:iv:hex: true)`; `encrypt(text:)` takes a String and returns lowercase hex; `decrypt(text:)`
  takes hex and returns a String. So encrypt includes UTF-8 conversion and hex encoding, decrypt includes hex decoding and String
  construction, on both sides. `key_schedule` is `getSM4().setKey(...)` with a new key each time (object creation, hex parse, schedule).
  Plaintext is ASCII. On the new side, decrypt additionally validates PKCS#7 in constant flow and runs a constant-flow UTF-8 check over
  the whole buffer (the padding-oracle fix); the S-box is a Boolean circuit instead of tables. These are security costs, not overhead.
- SM2: user ID "1234567812345678", 32-byte ASCII message. keygen = `genKeyPair()` (hex strings out). sign/verify/encrypt/decrypt take hex
  strings, so key parsing and hex conversion are included on both sides. sign recomputes the public key for Z on both sides.
  The new side validates keys, points and signatures strictly; the baseline does not.
- key_exchange: long-term key pairs fixed; per operation: two `genKeyPair()` calls for fresh ephemerals, hex parsing into
  `BigInt256`/`ECPoint`, `getSb` (B), `getSa` with Sb check (A), `checkSa` (B), 16-byte key on both sides.
- No operation is NA.

## Not comparable / notes
- The baseline RNG on non-Apple platforms called `UInt8.random` per byte; on macOS both sides use `SecRandomCopyBytes`.
- Baseline SM4 decrypt of bad padding is lenient; irrelevant here because all inputs are valid.
