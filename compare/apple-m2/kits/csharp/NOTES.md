# C# SMX benchmark kit

- `base/SMX`: `git archive 3397c6d csharp/SMX`. `new/SMX`: `git archive HEAD csharp/SMX` (HEAD a327a78).
- `bench/Program.cs` is one source compiled twice, `bench/base/Bench.csproj` and `bench/new/Bench.csproj`, each referencing
  only its own library. No NuGet package anywhere, so build and run need no network. `UseAppHost=false`, so no
  RID-specific apphost pack is needed either: the result is framework-dependent IL and runs on osx-arm64 as `$DOTNET SmxBench.dll`.
- `./build.sh` (needs `$DOTNET`, a .NET 8 SDK; idempotent, prints only errors), then `./run.sh base` or `./run.sh new`.
- Build: Release, `Optimize=true`; runtime: .NET 8 with tiered compilation and Dynamic PGO on (the defaults), workstation
  non-concurrent GC, invariant globalization. Same settings for both sides.
- Timing: 2 s warm-up per operation, then 7 samples of at least 200 ms each, `Stopwatch` (monotonic); prints median and
  min in microseconds per operation. Results are consumed into a sink.
- Correctness checks run once outside timing on each side: SM3("abc"), SM4 round trips at all three sizes, SM2 sign then
  verify (and a rejection), SM2 encrypt then decrypt, and a full key exchange. Any failure exits non-zero.

## How the work is defined, identically on both sides
- SM3: `new SM3()`, `Update(byte[])`, `Finish()`, `HashBytes()` on a buffer of the given size.
- SM4: 16-byte key and IV. The public API is string based: `Encrypt(string)` takes text, encodes UTF-8, pads, encrypts
  CBC and returns lowercase hex; `Decrypt(string)` decodes hex, decrypts, unpads and decodes UTF-8. So the 16B/1KB/1MB
  cases are ASCII strings of exactly that many bytes, and hex encoding/decoding and string work is included on both
  sides. `key_schedule` is `SetKey(key, iv)` on an existing instance.
- SM2: user ID "1234567812345678", message and plaintext are 32 ASCII characters (32 bytes). Keys, signatures and
  ciphertexts are hex strings, as the API takes them, on both sides.
- `key_exchange`: long-term key pairs are fixed in advance. Each operation generates both ephemeral key pairs
  (`GenKeyPair`, then parsing the hex), runs `GetSb` (responder), `GetSa` (initiator, which checks Sb) and `CheckSa`
  (responder checks Sa), with a 16-byte key, and checks Ka == Kb.

## Not comparable, or worth knowing
- The new library validates more (point on curve, key ranges, canonical hex), which costs a little on the new side only.
- SM4 on arm64: the new library has no ARM hardware path. Without AES-NI it uses a constant-time Boolean-circuit S-box
  instead of the baseline's table lookups, so on the M2 expect new SM4 to be several times slower than base. That is the
  intended security trade-off, not a regression to fix. On x86 with AES-NI the new side is faster.
- None of the new library's x86 intrinsics (AES-NI, SSSE3, AVX2, BMI2) exist on arm64, so the M2 runs its portable paths
  everywhere. Those paths pass the test suite with intrinsics disabled on x86, but have never run on arm64 hardware.
- No operation is NA on either side.
