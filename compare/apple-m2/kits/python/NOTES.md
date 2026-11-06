# Python kit

- **Sides:** `base/` is `git archive 3397c6d:python`. `new/` is `git archive HEAD:python`,
  with HEAD at a327a78 on feat/deep-optimization. Both are pure Python with no
  dependencies.
- **Runtime:** `/usr/bin/python3` (3.9.6 on the Mac). Set `PYTHON` to use another
  interpreter.
- **build.sh:** byte-compiles both sides with `compileall`, so no timed run pays for
  compilation. There are no other build flags.
- **run.sh:** runs `python3 -I bench.py <side>`. `-I` ignores `PYTHON*` variables and
  user site-packages.
- **Benchmark:** one program, `bench.py`, serves both sides. The two APIs have the same
  names and signatures for everything measured, so the work is the same.

## Measurement

- **Warm-up:** at least 0.5 s per operation, or one call if a call takes longer.
  CPython has no JIT, so nothing more is needed.
- **Samples:** 7 samples of at least 200 ms each. A 1 MB operation takes longer than
  200 ms per call, so each of its samples is one call. The minimum sample time was not
  lowered.
- **Timing:** `time.perf_counter`, which is monotonic.
- **Self-checks:** before timing, the program checks the SM3 "abc" vector, the
  GB/T 32907 SM4 block, sign then verify (and a rejected wrong message), SM2 encrypt
  then decrypt, and every SM4 round trip. Each key exchange checks Ka == Kb and Sa
  inside the timed loop.

## Comparability

- **String-based API:** the API is string and hex based on both sides, and the
  benchmark uses it as callers do.
  - SM4 `encrypt` takes a str, encodes it as UTF-8 and returns lowercase hex.
  - SM4 `decrypt` takes hex and returns a str.
  - SM2 messages and plaintexts are 32 ASCII characters, so 32 bytes.
  - Signatures, ciphertexts and keys are hex strings.
  - Both sides pay for these conversions.
- **Payload sizes:** "16B" is 16 plaintext characters, so the ciphertext is 32 bytes,
  including PKCS#7 padding.
- **Key exchange:** each exchange includes two `sm2_gen_key_pair` calls for fresh
  ephemeral keys. It also includes decoding those keys and the `get_sb`, `get_sa` and
  `check_sa` calls with confirmation. The long-term keys are made once, outside the
  timing.
- **Per-key caches (new side only):** `new` keeps them on by default. Repeated sign,
  verify, encrypt and exchange with one key therefore reuse the public key, the Z value
  and point tables, much as a long-running server would. `base` has no caches.
  `run.sh` clears `SMX_DISABLE_KEY_CACHE` so the default applies.
- **New SM4 is slower by design:** the security pass replaced table lookups with a
  Boolean-circuit S-box. Serial work is therefore slower on `new`: key schedule, CBC
  encryption and single blocks. CBC decryption of many blocks runs in parallel lanes
  and is faster.
- **Other functional differences** do not affect these valid inputs. `new` rejects
  invalid input more strictly, accepts only lowercase hex for signatures and
  ciphertexts, and requires 16-byte SM4 keys and IVs.
- **No NA lines:** every operation exists on both sides.
- **Expected run time:** roughly 1 to 3 minutes for `new` on an M2. The serial
  `sm4/cbc_encrypt/1MB` (8 calls) dominates. `base` takes about as long, mostly in its
  1 MB cases.
