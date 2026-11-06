# Go benchmark kit

- `base/go` is the library at 3397c6d, `new/go` at HEAD of feat/deep-optimization, both from `git archive`.
- `bench/main.go` is one program built against each side (`go.base.mod` for the baseline, `go.mod` for the new side), so both do the same work
  through the same public API calls. `build.sh` needs `$GO`; it sets `GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=0`
  and builds with default flags plus `-trimpath`. No network and no third-party modules.
- Timing: 0.5 s warm-up per operation (Go is compiled ahead of time, so there is no JIT to settle), then 7 samples
  of at least 200 ms each, median and min in microseconds per operation, monotonic clock.
- Correctness is checked once outside timing: SM3 "abc" known answer, SM4 round trips at every size, SM2 sign then
  verify (and rejection of a wrong message), SM2 encrypt then decrypt, and a full key exchange with Ka == Kb and Sa checked.

## API usage, the same on both sides
- SM3: `NewSM3`, `Update`, `Finish`, `HashBytes`.
- SM4: `SetKey(key, iv)` with 16-byte key and IV; `Encrypt(string)` returns lowercase hex and `Decrypt(hex)` returns a
  string, so every SM4 timing includes hex encoding or decoding of the ciphertext. That is the only API either side has.
- SM2: hex-string keys, `SM2Sign`/`SM2Verify` with user ID "1234567812345678" (Z is computed inside each call and the
  public key is derived from the private key inside `SM2Sign` on both sides), `SM2Encrypt`/`SM2Decrypt` with hex ciphertext.
- key_exchange: two fresh ephemeral key pairs (`SM2GenKeyPair`), `SM2GetSb`, `SM2GetSa`, `SM2CheckSa`, 16-byte key, plus
  decoding the hex points and Sb/Sa. Long-term keys are generated once, outside timing.

## Not directly comparable
- New side on arm64: SM4 has no hardware path yet, so it uses a bitsliced Boolean-circuit S-box (no secret-indexed
  table lookups). The baseline uses a plain S-box table, which is faster but leaks through the cache. The key
  schedule also uses the circuit on the new side. Expect SM4 and its key schedule to be slower on the Mac by design.
- New side validates every input (point on curve, key ranges, canonical hex) and uses constant-time scalar
  multiplication for secrets; the baseline does neither.
- All operations exist on both sides; nothing prints NA.
