# SMX - Multi-language implementation of the Chinese national cryptographic algorithms (SM2, SM3, SM4)

[中文](README.md) | English | [Español](README.es-ES.md)

Built entirely on the commercial cryptographic algorithm standards published by the State Cryptography Administration (OSCCA), this project provides complete implementations of the core Chinese national algorithms SM2, SM3, SM4 and SM9 in nine mainstream programming languages — **Java, JavaScript, Swift, Rust, Go, C, C#, Python and Dart** — with **zero third-party dependencies**.

Every implementation strictly follows the algorithm specifications and test vectors published by the State Cryptography Administration, and its output matches the official test reference values exactly, so it can be used directly in the development and deployment of commercial cryptographic products.

## Why SMX

Compared with OpenSSL and BouncyCastle:

- **Faster:** on an Apple M2, SM2 signing takes 31.6 µs in Rust, 32.7 µs in Go and 39.2 µs in Swift, against 55.0 µs for OpenSSL 3.6.5 and 603 µs for BouncyCastle. SM4 decryption of 1 MiB runs at 839 MB/s in Rust against 141 MB/s for OpenSSL. The Java version, compared with BouncyCastle (also Java), signs 7.5 times faster, completes a key exchange 13 times faster, and runs SM4 encryption 1.6 times and decryption 2 times faster. See "Performance" below, where every value in green bold beats both OpenSSL and BouncyCastle.
- **Complete SM2 key exchange:** OpenSSL 3.x offers no API for the GB/T 32918.3 SM2 key exchange; this library provides it in all nine languages, including the confirmation values.
- **Complete SM9 identity-based cryptography:** signatures, key exchange, key encapsulation, public key encryption (KDF stream cipher and SM4 block cipher) and master/user key generation, in all nine languages, each reproducing every worked example of GB/T 38635.5 appendices A to D byte for byte. OpenSSL 3.x has no SM9.
- **Nine languages, one behaviour:** the same API semantics and output formats, tested for interoperability, so languages can talk to each other directly, for example a JavaScript front end and a Java back end agreeing on a key and then encrypting with SM4. Every implementation also interoperates both ways with OpenSSL and BouncyCastle.
- **Zero dependencies:** no native OpenSSL library to install and no BouncyCastle jar to add. JavaScript and Python are pure source code and work where native libraries cannot be loaded, such as browsers.
- **Stricter standard compliance:** as GB/T 32918.4 requires, SM2 ciphertexts whose KDF output is all zero are rejected; OpenSSL 3.0 and BouncyCastle 1.86 do not check this.
- **Optional high-security version:** the `security` branch provides constant-time SM4 for environments such as clients, where untrusted code may share the CPU. On an Apple M2, OpenSSL 3.6.5 only has a table-based SM4, and BouncyCastle's SM4 is table-based as well.

## Choosing a version: high-performance or high-security

This repository has two branches. **The algorithms, API and output are identical, so the two can talk to each other and decrypt each other's data.** The only difference is the internal implementation of SM4:

| Branch | SM4 implementation | Recommended for |
|---|---|---|
| `main` (high-performance, default) | Table-based, the same approach as OpenSSL and BouncyCastle; fastest | Servers, and any other environment where no untrusted code shares the same CPU with you |
| `security` (high-security) | Constant-time, no key-dependent table lookups; SM4 is slower | Clients (apps, desktop programs, browsers), and cloud hosts whose physical CPU is shared with other tenants |

Apart from SM4, the code in the two branches is exactly the same: security measures such as the constant-time SM2 implementation, secure random number generation and strict input validation are present in both.

**High-performance does not mean insecure.** A table-based implementation is exposed to cache-timing attacks: the attacker cannot read your memory directly, but instead has to run their own program **on the same machine and the same CPU**, measure how fast their own memory accesses are, infer which table entries were looked up during encryption, and from that work out the key. Therefore:

- **On a server you control** that runs only your own services, the attacker has no opportunity to run code on the same CPU, so this attack has essentially nowhere to start. Measuring timing remotely over the network is possible in theory, but it requires a huge number of precise measurements and is extremely hard to pull off in practice. OpenSSL's SM4 on ARM and other platforms is also table-based, and it is widely used on servers.
- **On a client**, the same device may at the same time be running untrusted apps or web page scripts that share the CPU cache with your cryptographic code, so the risk is clearly higher.
- **On a cloud host with a shared physical CPU**, other tenants on the same physical host could in theory mount this attack. Using dedicated physical cores or a dedicated host avoids it.

One more point: if an attacker can already read your process memory directly, the key itself is exposed and neither version can defend against that; it is not a problem that choosing one branch or the other can solve.

To get the high-security version:

```bash
git clone -b security https://github.com/aicccode/smx.git
```

## Feature matrix

| Feature | Java | JavaScript | Swift | Rust | Go | C | C# | Python | Dart |
|------|:----:|:----------:|:-----:|:----:|:--:|:-:|:--:|:------:|:----:|
| SM3 hash | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM4 symmetric encryption/decryption (CBC/PKCS7) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM2 asymmetric encryption/decryption | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM2 digital signature/verification | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM2 key exchange | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM9 master/user key generation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM9 digital signature/verification | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM9 key exchange | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM9 key encapsulation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM9 public key encryption (stream / SM4) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## Project structure

```
smx/
├── java/            # Java implementation (Maven, site.aicc:gm-java)
├── javascript/      # JavaScript implementation (npm, ES Module)
├── swift/           # Swift implementation (SwiftPM, GMSwift)
├── rust/            # Rust implementation (Cargo, gm-rust)
├── go/              # Go implementation (Go Module, smx)
├── c/               # C implementation (Makefile, C99)
├── csharp/          # C# implementation (.NET 8, SMX)
├── python/          # Python implementation (pyproject, gm-python)
├── dart/            # Dart implementation (pub, smx)
├── testvectors/     # Shared test vectors, plus the independent SM9 reference and its spec
├── demo/            # Cross-language key exchange and encrypted communication demo
│   ├── server-java/     # Java HTTP server (side B)
│   ├── client-js/       # JavaScript client (side A)
│   ├── client-rust/     # Rust client (side A)
│   ├── client-swift/    # Swift client (side A)
│   ├── client-go/       # Go client (side A)
│   ├── client-c/        # C client (side A, libcurl)
│   ├── client-csharp/   # C# client (side A, .NET 8)
│   ├── client-python/   # Python client (side A)
│   ├── client-dart/     # Dart client (side A)
│   └── run-tests.sh     # One-command test script
└── doc/             # Algorithm specification documents (PDF)
```

## Implementations by language

### Java

```bash
cd java
mvn test        # run tests
mvn install     # install to the local repository
```

- **Build tool:** Maven
- **Package:** `site.aicc` (`gm-java:1.0.0`)
- **Minimum version:** Java 8+
- **Dependencies:** none (JUnit for tests only)

### JavaScript

```bash
cd javascript
npm test        # run tests
```

- **Build tool:** npm (ES Module)
- **Package:** `gm-js`
- **Runtime:** Node.js (ES Module)
- **Dependencies:** none

### Swift

```bash
cd swift
swift test      # run tests
swift build     # build
```

- **Build tool:** Swift Package Manager
- **Library:** `GMSwift`
- **Minimum version:** Swift 5.7+, iOS 15+, macOS 10.13+
- **Dependencies:** none

### Rust

```bash
cd rust
cargo test      # run tests
cargo build     # build
```

- **Build tool:** Cargo
- **Crate:** `gm-rust`
- **Minimum version:** Rust 1.85 (2024 edition)
- **Dependencies:** none

### Go

```bash
cd go
go test ./...   # run tests
```

- **Build tool:** Go Modules
- **Module:** `smx`
- **Minimum version:** Go 1.21+
- **Dependencies:** none

### C

```bash
cd c
make test       # build and run tests
```

- **Build tool:** Makefile (gcc)
- **Standard:** C99
- **Dependencies:** none (core library); libcurl (demo client only)

### C#

```bash
cd csharp
dotnet test     # run tests
dotnet build    # build
```

- **Build tool:** .NET SDK
- **Library:** `SMX`
- **Minimum version:** .NET 8.0
- **Dependencies:** none (xunit for tests only)

### Python

```bash
cd python
python3 -m unittest discover -s tests -t .   # run tests (no dependencies to install)
python3 -m pytest                            # or run them with pytest
SMX_SLOW_TESTS=1 python3 -m unittest discover -s tests -t .   # include the slow 512 MiB/1 GiB SM3 tests
```

- **Build tool:** setuptools (pyproject.toml)
- **Package:** `gm-python` (import name `smx`)
- **Minimum version:** Python 3.9+
- **Dependencies:** none (pytest optional, for tests only)

### Dart

```bash
cd dart
dart pub get
dart test                      # run the tests
dart run benchmark/bench.dart  # benchmarks
```

- **Build tool:** pub (pubspec.yaml)
- **Package name:** `smx` (`import 'package:smx/smx.dart';`)
- **Minimum version:** Dart 3.0+, Dart VM only (JIT, AOT and Flutter native platforms); compiling to JavaScript is not supported
- **Dependencies:** none (test for tests only)

## Using SM9

The SM9 API has the same semantics in every language, with names following each language's conventions. In Python:

```python
from smx import (sm9_gen_sign_master_key, sm9_gen_sign_user_key, sm9_sign, sm9_verify,
                 sm9_gen_enc_master_key, sm9_gen_enc_user_key, sm9_encrypt, sm9_decrypt)

# Key generation centre (KGC)
ks, ppub_s = sm9_gen_sign_master_key()          # signing master private key / public key (G2 point)
ds = sm9_gen_sign_user_key(ks, "Alice")         # Alice's signing private key (G1 point)

signature = sm9_sign("message", ds, ppub_s)     # h || S, lowercase hex
assert sm9_verify("message", signature, "Alice", ppub_s)   # the verifier needs only the ID and master public key

ke, ppub_e = sm9_gen_enc_master_key()           # encryption master private key / public key (G1 point)
de = sm9_gen_enc_user_key(ke, "Bob")            # Bob's encryption private key (G2 point)
c = sm9_encrypt("plaintext", "Bob", ppub_e)     # C1 || C3 || C2; mode="sm4" uses SM4
assert sm9_decrypt(c, "Bob", de) == b"plaintext"
```

Key encapsulation (`sm9_encapsulate` / `sm9_decapsulate`) and key exchange with confirmation (`sm9_exchange_init`, `sm9_exchange_respond`, `sm9_exchange_confirm`, `sm9_exchange_check`) are also provided. Encodings, the default hid values (signing 0x01, key exchange 0x02, encryption 0x03) and the input rules are in [`testvectors/SM9-SPEC.md`](testvectors/SM9-SPEC.md).

## Security notes

### Input requirements

- **SM4 keys and IVs must be exactly 16 bytes** (or 32 hex digits). Earlier versions hashed or truncated "text keys" of other lengths into a key, giving an actual strength of only about 64 bits; such keys are now rejected with an error. Old data encrypted with such keys cannot be decrypted by the new version; decrypt it with the old version and re-encrypt it.
- **Hex for signatures and ciphertexts must be lowercase**, matching this library's output, so that each signature has exactly one string form. Hex for public and private keys remains case-insensitive.
- Invalid input (points not on the curve, out-of-range private keys or signatures, wrong lengths, bad padding, etc.) always results in an error or failure return, following each language's conventions. The public API of every language has been fuzz-tested with no crashes or hangs found, but fuzzing cannot prove that such problems are entirely absent.

### Limitations of SM4-CBC

- **CBC provides confidentiality only, not integrity.** Ciphertext can be tampered with without detection. If you need integrity, use a separate MAC (for example HMAC-SM3) and verify it before decrypting.
- **Once a key is set on an SM4 object, every encryption uses the same IV.** Identical plaintexts produce identical ciphertexts. Use a fresh random IV for each message.
- Decryption results returned as strings must go through UTF-8 validation, and that validation's running time still depends on the plaintext content. For binary data, or when stricter timing guarantees are required, use the decryption API that returns bytes.

### Side channels

- In SM2, operations involving the private key (key generation, signing, decryption, key exchange) use fixed windows and masked table lookups, with no branches or memory addresses that depend on secret data. C, Rust and Swift come with tools that check the compiled output, such as `make check-ct` for C, `rust/tools/check_ct_asm.py` and `swift/Tools/check_constant_time.py`; rerun them after changing compiler versions.
- **SM4 on this branch (`main`) uses a table-based implementation**: it is fast, but it does not resist cache-timing attacks; see "Choosing a version" above for where it is appropriate. SM4 on the `security` branch uses no secret-dependent table lookups: it uses a hardware implementation when AES-NI, GFNI or ARM AES instructions are available, and otherwise an S-box implemented as a Boolean circuit.
- Java, C#, JavaScript, Python and Dart run in managed environments whose runtimes give no constant-time guarantees of their own; this library can only ensure that the source code has no secret-dependent branches or table lookups (for SM2; on the `security` branch, for SM4 as well).
- Signature verification handles only public data, and uses variable-time algorithms for speed.

### SM9

- Every point carries the `04` prefix: G1 points are 65 bytes, G2 points 129 bytes (`04 || x1 || x0 || y1 || y0`, high component first). C1 in the `C1 || C3 || C2` ciphertext also carries `04`, as in this library's SM2; the standard's example prints C1 without it, so ciphertexts here are 1 byte longer than the example and otherwise identical.
- The SM4 method uses ECB with PKCS#7 padding, as in the standard's example, with a fresh K1 derived by the KDF for every message. Decryption checks C3 in constant time before decrypting and removing the padding.
- **The ciphertext does not record the method**, so decryption must be told the method used for encryption. When C2 is exactly 16 bytes both methods derive the same K2, so decrypting with the wrong method passes the C3 check and returns 16 meaningless bytes instead of an error. It never reveals the plaintext; this follows from the standard's ciphertext format.
- Point multiplication and GT exponentiation with secret values (master private keys, the random r) use fixed windows and masked table lookups; the constant-time checking tools of C, Rust and Swift cover these SM9 paths too. Every decoded G2 point (master public key, user encryption private key) is checked to be in the order-N subgroup.
- The SM4 method of SM9 uses this branch's SM4, which likewise does not resist cache-timing attacks; when timing matters, use the default stream method or the `security` branch.

### Old keys that should be replaced

Keys generated by old versions in the following environments came from an insecure random source and **should be replaced**; old signatures made with these keys should also no longer be considered reliable:

- JavaScript running on Node.js 18 or earlier: randomness came entirely from `Math.random`
- JavaScript running in a browser or on Node.js 20 and later: `Math.random` and RC4 were mixed in; the risk is lower, but replacement is still recommended
- Rust compiled to wasm: randomness came from a linear congruential generator seeded with the time

### Differences from other implementations

GB/T 32918.4 requires decryption to reject ciphertexts for which the KDF output is all zeros. This library does so, whereas OpenSSL 3.0 and BouncyCastle 1.86 do not check. For a 1-byte plaintext, this happens about once every 256 times.

## Performance

### Apple M2: before the rework, high-security and high-performance

Measured on 2026-11-06 on an idle Apple M2 Mac (macOS 14.1.1). Each implementation was run 3 full times; in each run every operation takes the median of 7 samples, and the tables show the median of the 3 runs. The median run-to-run variation per implementation is between 0% and 3.7%. Full per-algorithm tables, the method, raw data and reproduction scripts are in [`compare/apple-m2/`](compare/apple-m2/README.md) (in Chinese).

High-performance version (`main`) compared with OpenSSL 3.6.5 and BouncyCastle 1.86:

Green bold marks results faster than both OpenSSL and BouncyCastle (by more than 2%).

| Operation | OpenSSL 3.6.5 | BouncyCastle 1.86 | C | Rust | Go | C# | Java | JavaScript | Python | Swift |
|---|---|---|---|---|---|---|---|---|---|---|
| SM3 1 MiB (MB/s) | 354 | 245 | 310 | $\color{green}{\textbf{388}}$ | 323 | $\color{green}{\textbf{371}}$ | 246 | 352 | 0.908 | $\color{green}{\textbf{373}}$ |
| SM4-CBC encrypt 1 MiB (MB/s) | 122 | 69.1 | $\color{green}{\textbf{136}}$ | $\color{green}{\textbf{155}}$ | $\color{green}{\textbf{126}}$ | 107 | 113 | 100 | 2.6 | $\color{green}{\textbf{139}}$ |
| SM4-CBC decrypt 1 MiB (MB/s) | 141 | 71.1 | $\color{green}{\textbf{373}}$ | $\color{green}{\textbf{839}}$ | $\color{green}{\textbf{396}}$ | $\color{green}{\textbf{175}}$ | 141 | 85.9 | 8.2 | 37.7 |
| SM4 key schedule (µs) | 0.35 | 0.19 | $\color{green}{\textbf{0.10}}$ | $\color{green}{\textbf{0.10}}$ | $\color{green}{\textbf{0.14}}$ | $\color{green}{\textbf{0.15}}$ | 0.36 | 0.32 | 13.2 | 0.63 |
| SM2 key generation (µs) | 30.9 | 527 | $\color{green}{\textbf{24.9}}$ | $\color{green}{\textbf{14.5}}$ | $\color{green}{\textbf{13.2}}$ | $\color{green}{\textbf{24.4}}$ | 40.1 | 70.9 | 334 | $\color{green}{\textbf{16.2}}$ |
| SM2 sign (µs) | 55.0 | 603 | $\color{green}{\textbf{50.0}}$ | $\color{green}{\textbf{31.6}}$ | $\color{green}{\textbf{32.7}}$ | $\color{green}{\textbf{49.9}}$ | 79.9 | 210 | 496 | $\color{green}{\textbf{39.2}}$ |
| SM2 verify (µs) | 115 | 850 | $\color{green}{\textbf{76.0}}$ | $\color{green}{\textbf{76.6}}$ | $\color{green}{\textbf{55.9}}$ | 123 | 227 | 242 | 709 | $\color{green}{\textbf{55.4}}$ |
| SM2 encrypt 32 B (µs) | 113 | 2560 | $\color{green}{\textbf{100}}$ | $\color{green}{\textbf{88.0}}$ | $\color{green}{\textbf{69.0}}$ | 171 | 257 | 342 | 1800 | $\color{green}{\textbf{76.1}}$ |
| SM2 decrypt 32 B (µs) | 77.6 | 1991 | 84.1 | $\color{green}{\textbf{72.6}}$ | $\color{green}{\textbf{59.0}}$ | 148 | 220 | 271 | 1628 | $\color{green}{\textbf{61.1}}$ |
| SM2 key exchange (µs) | — | 11536 | $\color{green}{\textbf{299}}$ | $\color{green}{\textbf{262}}$ | $\color{green}{\textbf{206}}$ | $\color{green}{\textbf{471}}$ | $\color{green}{\textbf{897}}$ | $\color{green}{\textbf{1019}}$ | $\color{green}{\textbf{6935}}$ | $\color{green}{\textbf{233}}$ |

The two branches differ only in SM4. Each cell below reads: before the rework / `security` (high-security) / `main` (high-performance):

| Language | Encrypt 1 MiB (MB/s) | Decrypt 1 MiB (MB/s) | Key schedule (µs) |
|---|---|---|---|
| C | 72.7 / 60.4 / **136** | 80.0 / 195 / **373** | 0.14 / 0.34 / **0.10** |
| Rust | 22.7 / 58.3 / **155** | 67.4 / 839 / **839** | 0.17 / 0.23 / **0.10** |
| Go | 58.2 / 25.1 / **126** | 59.3 / 113 / **396** | 0.22 / 0.64 / **0.14** |
| C# | 52.3 / 24.1 / **107** | 42.0 / 23.4 / **175** | 0.23 / 0.65 / **0.15** |
| Java | 36.8 / 24.1 / **113** | 40.4 / 23.1 / **141** | 0.58 / 0.97 / **0.36** |
| JavaScript | 12.2 / 20.1 / **100** | 17.6 / 43.9 / **85.9** | 1.29 / 0.84 / **0.32** |
| Python | 0.387 / 0.102 / **2.6** | 0.387 / 8.2 / **8.2** | 32.6 / 147 / **13.2** |
| Swift | 5.3 / 20.1 / **139** | 5.1 / 20.9 / **37.7** | 3.90 / 1.08 / **0.63** |

Speed-up of `main` over the code before the rework (above 1 means faster):

| Operation | C | Rust | Go | C# | Java | JavaScript | Python | Swift |
|---|---|---|---|---|---|---|---|---|
| SM3 1 MiB | **1.6×** | **2.9×** | **2.2×** | **2.2×** | **1.3×** | **4.3×** | **2.0×** | **3.3×** |
| SM4-CBC encrypt 1 MiB | **1.9×** | **6.8×** | **2.2×** | **2.0×** | **3.1×** | **8.2×** | **6.7×** | **26.2×** |
| SM4-CBC decrypt 1 MiB | **4.7×** | **12.4×** | **6.7×** | **4.2×** | **3.5×** | **4.9×** | **21.1×** | **7.3×** |
| SM4 key schedule | **1.5×** | **1.7×** | **1.6×** | **1.6×** | **1.6×** | **4.1×** | **2.5×** | **6.2×** |
| SM2 key generation | **8.1×** | **8.6×** | **48.4×** | **42.0×** | **459.0×** | **304.7×** | **4.8×** | **70.6×** |
| SM2 sign | **24.2×** | **34.4×** | **96.8×** | **86.1×** | **64.0×** | **228.5×** | **8.4×** | **79.4×** |
| SM2 verify | **3.5×** | **3.1×** | **24.1×** | **17.7×** | **21.1×** | **179.1×** | **5.9×** | **23.5×** |
| SM2 encrypt 32 B | **3.4×** | **2.8×** | **18.6×** | **12.1×** | **18.8×** | **126.3×** | **2.1×** | **29.7×** |
| SM2 decrypt 32 B | **1.4×** | **1.5×** | **11.1×** | **6.7×** | **11.0×** | **79.8×** | **1.3×** | **17.5×** |
| SM2 key exchange | **2.9×** | **2.6×** | **16.6×** | **11.7×** | **63.4×** | **127.9×** | **2.1×** | **35.7×** |

- **High-performance (`main`):** every language, operation and data size is faster than before the rework; nothing regressed. For 1 MiB SM4 encryption, Rust, Swift, C and Go beat OpenSSL 3.6.5, and Java, C# and JavaScript come close; for 1 MiB decryption, Rust, Go, C and C# beat OpenSSL and Java matches it.
- **High-security (`security`):** SM4 makes no table lookups indexed by secret data. Go, C#, Java and Python have no usable hardware instructions on ARM and must compute the S-box as a Boolean circuit, so their SM4 is slower than before the rework (encryption at 26% to 66% of the old speed). C and Rust use the ARM AES instructions and still decrypt fast.
- **SM2 and SM3 (identical on both branches):** every language is much faster. Rust, Go and Swift sign 1.4 to 1.7 times faster than OpenSSL 3.6.5; Java is 7.5 times (signing) to 13 times (key exchange) faster than BouncyCastle. OpenSSL does not offer SM2 key exchange.
- OpenSSL 3.6.5's SM4 on the M2 is table-based as well: its source only uses assembly when the CPU has the SM4 extension, or is a Neoverse N1/V1 or Kunpeng 920.

### x86: comparison with OpenSSL and BouncyCastle

On a single performance core of an Intel i5-13500H, compared with OpenSSL 3.0.13 and BouncyCastle 1.86 (excerpt; full results and how to reproduce them are in [`compare/`](compare/README.md)). These numbers were taken before SM4 was switched to tables, so the SM4 figures correspond to the `security` branch:

Green bold marks results faster than both OpenSSL and BouncyCastle (by more than 2%).

| Operation | OpenSSL | BouncyCastle | C | Rust | Go | Java |
|---|---|---|---|---|---|---|
| SM2 sign (µs) | 202 | 311 | $\color{green}{\textbf{37.6}}$ | $\color{green}{\textbf{27.5}}$ | $\color{green}{\textbf{31.7}}$ | $\color{green}{\textbf{77.1}}$ |
| SM2 verify (µs) | 192 | 367 | $\color{green}{\textbf{67.2}}$ | $\color{green}{\textbf{64.8}}$ | $\color{green}{\textbf{49.0}}$ | 221 |
| SM3 1 MiB (MB/s) | 471 | 288 | $\color{green}{\textbf{543}}$ | $\color{green}{\textbf{543}}$ | 440 | 284 |
| SM4 encrypt 1 MiB (MB/s) | 157 | 101 | 117 | 123 | 109 | 26.4 |
| SM4 decrypt 1 MiB (MB/s) | 177 | 103 | $\color{green}{\textbf{815}}$ | $\color{green}{\textbf{1298}}$ | $\color{green}{\textbf{519}}$ | 24.6 |

SM4 encryption on the `security` branch is slower than OpenSSL because it does not use table lookups indexed by secret data.

## Cross-language demo

The demo verifies that the SM2 implementations in all nine languages can complete the **key exchange protocol** and use the agreed key for **SM4-encrypted communication**.

### Architecture

```
┌─────────────┐     HTTP      ┌─────────────┐
│ JS Client   │─────────────>│             │
├─────────────┤              │             │
│ Rust Client │─────────────>│   Java      │
├─────────────┤              │   Server    │
│Swift Client │─────────────>│  (Side B)   │
├─────────────┤              │             │
│ Go Client   │─────────────>│             │
├─────────────┤              │             │
│  C Client   │─────────────>│             │
├─────────────┤              │             │
│  C# Client  │─────────────>│             │
├─────────────┤              │             │
│Python Client│─────────────>│             │
├─────────────┤              │             │
│ Dart Client │─────────────>│             │
└─────────────┘              └─────────────┘
   (Side A)
```

### Key exchange flow

```
Client(A)                          Server(B)
   │                                   │
   │ Generate dA/pA, ra/Ra             │
   │ POST /api/keyswap/init            │
   ├──────────────────────────────────>│
   │                                   │ Generate rb/Rb, compute Sb, Kb
   │        {sessionId, pB, Rb, Sb}    │
   │<──────────────────────────────────┤
   │                                   │
   │ Compute Sa, Ka, verify Sb         │
   │ POST /api/keyswap/confirm {Sa}    │
   ├──────────────────────────────────>│
   │                                   │ Verify Sa
   │                       {success}   │
   │<──────────────────────────────────┤
   │                                   │
   │ ====== Ka == Kb: key agreed ======│
   │                                   │
   │ SM4(Ka) encrypt message           │
   │ POST /api/crypto/test             │
   ├──────────────────────────────────>│
   │                                   │ SM4(Kb) decrypt & verify + encrypt reply
   │     {decryptMatch, ciphertext}    │
   │<──────────────────────────────────┤
   │ SM4(Ka) decrypt reply             │
```

### One-command test

```bash
cd demo
./run-tests.sh
```

## Algorithm overview

### SM2 elliptic curve public key cryptographic algorithm

Based on the hardness of the discrete logarithm problem in elliptic curve point groups; its 256-bit security level is equivalent to 2048-bit RSA. It consists of three core components:
- **SM2-1** Elliptic curve digital signature algorithm
- **SM2-2** Elliptic curve key exchange protocol
- **SM2-3** Elliptic curve public key encryption algorithm

### SM3 cryptographic hash algorithm

Produces a 256-bit hash value, with security significantly higher than MD5 (128-bit) and SHA-1 (160-bit). Suitable for digital signatures, message authentication codes, random number generation and similar uses.

### SM4 block cipher algorithm

Both the key length and the block length are 128 bits, the same parameters as AES. It is the core symmetric encryption algorithm in the Chinese national cryptography suite. This implementation uses CBC mode with PKCS7 padding.

### SM9 identity-based cryptographic algorithm

Built on the R-ate bilinear pairing over a BN curve. A user's public key is their identity (for example an email address or phone number), so no certificates are needed; a key generation centre (KGC) derives each user's private key from its master private key. It consists of:
- **SM9-2** digital signature algorithm
- **SM9-3** key exchange protocol
- **SM9-4** key encapsulation mechanism and public key encryption algorithm

## Reference documents

The `doc/` directory contains the algorithm specifications published by the State Cryptography Administration:

| Document | Description |
|------|------|
| `sm2.pdf` | SM2 elliptic curve public key cryptographic algorithm specification |
| `sm2_param.pdf` | SM2 recommended curve parameters |
| `sm3.pdf` | SM3 cryptographic hash algorithm specification |
| `SM4.pdf` | SM4 block cipher algorithm specification |
| `SM9.pdf` | SM9 identity-based cryptographic algorithm specification |

## License

[Apache License 2.0](LICENSE)
