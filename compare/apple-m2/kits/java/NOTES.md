# Java kit

- `base/`: `git archive 3397c6d java/src/site java/pom.xml`. `new/`: the same at HEAD of `feat/deep-optimization`.
- Build: `JAVA_HOME=<JBR 17> ./build.sh`. It runs `javac --release 8 -nowarn -encoding UTF-8` for both sides. It needs no Maven and no jars, since the benchmark uses no test framework. Output goes to `out/base` and `out/new`.
- Run: `./run.sh base` or `./run.sh new`. This is `$JAVA_HOME/bin/java -cp out/<side> MacBench` with JVM defaults: no flags, default GC, C2 tiered JIT.
- `bench/MacBench.java` is one program for both sides and calls only API that exists on both. Each operation gets 2 s of warm-up, then 7 samples of at least 200 ms each. It prints the median and the min in µs/op.
- Before timing, it checks that a signature verifies and a changed message does not, that SM2 and SM4 decrypt round-trip, and that the key exchange agrees and confirms. It throws if any check fails.

## Comparability

- **String and hex API on both sides:** SM4 encrypts a Java String (ASCII, so its UTF-8 length is the stated size) and returns hex, and decrypt takes hex and returns a String. SM2 encrypt, decrypt, sign and verify also take hex and String arguments. So every SM4 and SM2 number includes UTF-8 and hex conversion, identically on both sides.
- **SM4 key_schedule:** `new SM4().setKey(hexKey, hexIv, true)`, including hex decoding of key and IV.
- **sm2/keygen:** `SM2.genSM2KeyPair()`.
  - base: redraws until the private key and coordinates have a particular byte length (removed as a security bias), so it does about 8 scalar multiplications per key on average.
  - new: one draw and one multiplication.
- **sm2/sign:** both sides also derive the public key from the private key for Z, since the API takes only the private key.
- **sm2/key_exchange:** two `genSM2KeyPair()` calls for the ephemeral keys, `getSb`, `getSa` (which checks Sb) and `checkSa`, with a 16-byte key.
  - It inherits the base keygen cost above.
  - new: `getSb` and `getSa` also check that the caller's own public keys match its private keys (two fixed-base multiplications each). This is a security check the base lacks.
- **Expected regression:** new SM4 is slower by design. Its S-box is a constant-time Boolean circuit, where base used a secret-indexed table.
- No operation is NA.
