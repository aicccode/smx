# Rust kit: SM2/SM3/SM4 before (3397c6d) and after (HEAD)

- `base/` and `new/` are `git archive` of `rust/` at 3397c6d and at HEAD of feat/deep-optimization.
- One benchmark source, `bench/main.rs`, builds against each side (`bench_base/`, `bench_new/`). Both
  sides have the same public API, so the code and inputs are identical.
- Build: `./build.sh` (uses `$CARGO`, default `~/.cargo/bin/cargo`), release profile written out
  identically in both manifests: opt-level 3, no LTO, 16 codegen units, no debug info, unwind.
  No crates are used, so nothing is vendored and the build runs `--offline`. No target-cpu flags.
- Run: `./run.sh base` or `./run.sh new`. Output: `name<TAB>median_us<TAB>min_us`, 16 lines.
- Measurement: 300 ms warm-up per operation, then 7 samples of at least 200 ms each, median and
  minimum per operation; `std::time::Instant` (monotonic); results go through `black_box`.
- Correctness, checked once per run outside the timing: SM4 round trips at all three sizes, SM2
  signature verifies, SM2 decrypt round trips, key exchange keys agree (else the run panics).

## What each operation does (same on both sides)
- SM3: `Sm3::new`, one `update`, `finish`. Both sides' `finish` also builds the upper-case hex
  digest.
- SM4: the public API is string based: `encrypt(&str)` returns lower-case hex and `decrypt(&str)`
  takes it. Hex conversion is therefore part of every SM4 number, on both sides. The baseline
  formats hex with `format!` per byte, which dominates its SM4 times. `key_schedule` is
  `SM4::new` + `set_key` with a 16-byte key and IV.
- SM2: keys are hex strings, as the API takes them; sign/verify/encrypt/decrypt parse them on every
  call on both sides. Message and plaintext are 32 ASCII bytes, user ID "1234567812345678".
- `sm2/key_exchange`: two fresh ephemeral key pairs (`gen_key_pair`, then parsing the hex),
  `get_sb`, hex-decoding Sb, `get_sa`, hex-decoding Sa, `check_sa`, 16-byte key. Long-term keys
  are fixed and parsed once.

## Not identical between sides, by design of each version
- Randomness: the baseline opens and reads /dev/urandom on every draw; the new code calls
  `CCRandomGenerateBytes` on macOS. This is part of keygen, sign, encrypt and key exchange.
- The new code does work the baseline skips: point and key validation, constant-time scalar
  multiplication, wiping of secrets, constant-flow padding and UTF-8 checks in SM4 decrypt. The
  baseline's SM2 scalar multiplication is variable time.
- On Apple M2 the new SM4 uses the AES instructions with NEON; SM3 has no hardware path on arm64.
- Toolchain: the new code was tested earlier on this Mac's rustc 1.94.1. The baseline was built and
  run here on Linux with rustc 1.99 only; it needs edition 2024 (rustc >= 1.85), so 1.94 qualifies.
- No operation is NA on either side.
