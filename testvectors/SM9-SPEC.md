# SM9 implementation spec (shared by every language)

Standard: GB/T 38635 (GM/T 0044), full text in `doc/SM9.pdf`. Reference code:
`testvectors/sm9_ref.py` (plain Python integers, matches every worked example of
GB/T 38635.5). Test vectors: `testvectors/sm9-vectors.json`, produced by
`testvectors/generate_sm9.py`. Every implementation must reproduce every vector.

## Curve and towers

- BN curve `E: y^2 = x^3 + 5` over Fq, order N, cofactor 1. Parameters in the JSON (`params`).
- Twist `E': y^2 = x^3 + 5u` over Fq2. G2 has cofactor on the twist, so decoded G2
  points need an explicit subgroup check (`[N]Q == O`, or an equivalent faster check).
- Fq2 = Fq[u]/(u^2+2), Fq4 = Fq2[v]/(v^2-u), Fq12 = Fq4[w]/(w^3-v) (equivalently six Fq2
  coefficients of w^k with w^6 = u, as the reference does).
- Pairing: R-ate, a = 6t+2 (t = 0x600000000058F98A), Miller loop over Q in G2 with lines
  evaluated at P in G1, then `T += pi(Q)`, `T -= pi^2(Q)`, then final exponentiation
  `(q^12-1)/N`. Line values may be scaled by any element of a proper subfield (Fq2, Fq4,
  Fq6), the final exponentiation removes it. See `sm9_ref.py` for the untwist map and
  the Frobenius constants. Faster formulas (projective Miller loop, cyclotomic squaring,
  BN hard-part chain via t) are encouraged, and must give identical outputs.
- `e(P, Q)` is 1 if either point is the identity.

## Byte encodings (all hex output lowercase)

| Value | Encoding |
|---|---|
| scalar (master private key, temporary r) | 32 bytes big endian |
| G1 point | `04 || x || y`, 65 bytes |
| G2 point | `04 || x1 || x0 || y1 || y0`, 129 bytes (x = x0 + x1·u, high part first) |
| GT element (inside hashes only) | 384 bytes: `c2 || c1 || c0`, each Fq4 `c = a + b·v` as `b || a`, each Fq2 as `a1 || a0` |
| signature | `h || S`, h 32 bytes, S a G1 point: 97 bytes |
| ciphertext | `C1 || C3 || C2`, C1 a G1 point (65 bytes, **with** the 04 prefix, unlike the standard's printout), C3 32 bytes |
| KEM ciphertext | G1 point |
| key exchange R_A, R_B | G1 point |

Inside hashes and the KDF, points are `x || y` without the 04 prefix (G1: 64 bytes).
User identities are byte strings; string APIs use UTF-8. Empty identities are allowed.

Input rules, the same as the SM2 API of this repository:
- master/user keys and public keys: hex, case-insensitive, exact length, must decode to a
  valid value (scalars in [1, N-1]; points on the curve, not the identity, coordinates < q,
  G2 in the subgroup). Anything else is an error.
- signatures, ciphertexts (including the KEM ciphertext) and the key-exchange confirmation
  values S_A, S_B, S_2: lowercase hex only (one string form per value). R_A and R_B are
  points and, like public keys, accept either case.
- KEM and key-exchange key lengths: 1 byte to 1 MiB.
- `invalid_points` and `invalid_scalars` in the JSON must all be rejected.

## Algorithms (GB/T 38635.2-4)

- `H1(Z) = H(0x01, Z)`, `H2(Z) = H(0x02, Z)`; `H(tag, Z)`: `Ha = SM3(tag||Z||00000001) ||
  first 8 bytes of SM3(tag||Z||00000002)` (40 bytes), result `(Ha mod (N-1)) + 1`.
- `KDF(Z, klen) = SM3(Z||ct)...` with 32-bit big-endian ct from 1, truncated to klen bytes.
- `MAC(K2, Z) = SM3(Z || K2)`, K2 is 32 bytes.
- hid defaults: signing 0x01, key exchange 0x02, encryption/KEM 0x03. Every function that
  takes hid accepts any byte value.
- Signing key: `t1 = H1(ID||hid) + ks mod N` (t1 = 0 → error), `ds = [ks·t1^-1]P1`.
  Signing master public key `Ppub-s = [ks]P2` (G2).
- Encryption key: `t1 = H1(ID||hid) + ke mod N` (t1 = 0 → error), `de = [ke·t1^-1]P2`.
  Encryption master public key `Ppub-e = [ke]P1` (G1).
- Sign: `g = e(P1, Ppub-s)`, random r in [1, N-1], `w = g^r`, `h = H2(M || w)`,
  `l = r - h mod N` (l = 0 → new r), `S = [l]ds`.
- Verify: h in [1, N-1]; S valid G1 point; `t = g^h`; `P = [H1(ID||hid)]P2 + Ppub-s`;
  `u = e(S, P)`; accept iff `H2(M || u·t) == h`. Any malformed input → false (not an error).
- KEM: `QB = [H1(ID||hid)]P1 + Ppub-e`, `C = [r]QB`, `w = e(Ppub-e, P2)^r`,
  `K = KDF(C.xy || w || ID, klen)`; all-zero K → new r. Decapsulate: C valid G1,
  `w = e(C, de)`, same KDF, all-zero K → error.
- Encrypt, `C1 = [r]QB`, `w = e(Ppub-e, P2)^r`, `Z = C1.xy || w || ID`:
  - stream mode (default): `K = KDF(Z, mlen + 32)`, K1 = first mlen bytes (all zero → new r),
    `C2 = M xor K1`.
  - SM4 mode: `K = KDF(Z, 16 + 32)`, K1 = first 16 bytes (all zero → new r),
    `C2 = SM4-ECB(K1, PKCS#7(M))` (the mode used by the standard's example).
  - `C3 = SM3(C2 || K2)` with K2 the last 32 bytes of K.
  - Decrypt: parse, C1 valid G1, recompute K, check K1 not all-zero, **compare C3 in
    constant time before decrypting/unpadding**, then decrypt. Every failure gives the same
    error. The ciphertext does not record the mode, so decrypt takes the mode too.
  - Empty plaintext is rejected by encryption in both modes (as SM2 does here). In SM4
    mode an authentic ciphertext whose C2 is one full padding block decrypts to empty
    bytes (`extra.sm4_empty_plaintext`).
  - The ciphertext does not record the mode. When C2 is exactly 16 bytes both modes derive
    the same K2, so decrypting with the wrong mode passes C3 and returns 16 meaningless
    bytes instead of an error. It never reveals the plaintext; callers must agree on the mode.
- Key exchange, initiator A with ID_A, responder B with ID_B, klen bytes in [1, 1 MiB]:
  - init (either side): `R = [r]Q_peer`, `Q_peer = [H1(ID_peer||hid)]P1 + Ppub-e`, r random.
  - B: check R_A valid G1; `g1 = e(R_A, de_B)`, `g2 = e(Ppub-e, P2)^r_B`, `g3 = g1^r_B`;
    `SK_B = KDF(ID_A||ID_B||R_A.xy||R_B.xy||g1||g2||g3, klen)`;
    `S_B = SM3(0x82||g1||SM3(g2||g3||ID_A||ID_B||R_A.xy||R_B.xy))`, and the value it expects
    from A, `S_2 = SM3(0x83||g1||<same inner hash>)`.
  - A: check R_B valid G1; `g1 = e(Ppub-e, P2)^r_A`, `g2 = e(R_B, de_A)`, `g3 = g2^r_A`;
    verify `S_B` (constant-time) before releasing the key; `SK_A` and
    `S_A = SM3(0x83||g1||inner)`.
  - B finally checks `S_A == S_2` in constant time.

## Public API (adapt names to the language's conventions; keep the semantics)

Mirror the style of the existing SM2 API in the same language (hex strings in and out,
error type, result object). Suggested Python-style names:

```
SM9_HID_SIGN = 1, SM9_HID_EXCHANGE = 2, SM9_HID_ENCRYPT = 3
sm9_gen_sign_master_key() -> (master_private_hex, master_public_hex)      # ks, Ppub-s (G2)
sm9_sign_master_public_key(master_private_hex) -> master_public_hex
sm9_gen_sign_user_key(master_private_hex, user_id, hid=1) -> user_private_hex   # G1
sm9_gen_enc_master_key() -> (master_private_hex, master_public_hex)       # ke, Ppub-e (G1)
sm9_enc_master_public_key(master_private_hex) -> master_public_hex
sm9_gen_enc_user_key(master_private_hex, user_id, hid=3) -> user_private_hex    # G2
sm9_sign(message, user_private_hex, master_public_hex) -> signature_hex
sm9_verify(message, signature_hex, user_id, master_public_hex, hid=1) -> bool
sm9_encrypt(plaintext, user_id, master_public_hex, hid=3, mode=STREAM) -> ciphertext_hex
sm9_decrypt(ciphertext_hex, user_id, user_private_hex, mode=STREAM) -> plaintext
sm9_encapsulate(user_id, master_public_hex, key_len, hid=3) -> (key_hex, ciphertext_hex)
sm9_decapsulate(ciphertext_hex, user_id, user_private_hex, key_len) -> key_hex
sm9_exchange_init(peer_id, master_public_hex, hid=2) -> (r_hex, R_hex)   # r is secret
sm9_exchange_respond(key_len, id_a, id_b, master_public_hex, user_private_b_hex,
                     r_b_hex, R_b_hex, R_a_hex) -> {success, message, shared_key, s_b, s_2}
sm9_exchange_confirm(key_len, id_a, id_b, master_public_hex, user_private_a_hex,
                     r_a_hex, R_a_hex, R_b_hex, s_b_hex) -> {success, message, shared_key, s_a}
sm9_exchange_check(s_2_hex, s_a_hex) -> bool            # constant-time compare
```

Messages and plaintexts accept bytes (and UTF-8 strings where the SM2 API of that
language does); decrypt returns bytes (plus a string helper if SM2 has one).
For known-answer tests, expose internal (non-exported / package-private / test-only)
variants that take the random r explicitly: sign, encrypt, encapsulate, exchange init.

## Security requirements

- Randomness: the same OS CSPRNG wrapper the language's SM2 code already uses; r uniform in
  [1, N-1] (rejection sampling, no modulo bias). A failing RNG is an error, never a fallback.
- Secret scalars (master keys, r, l, t2) drive G1/G2 scalar multiplication and GT
  exponentiation with a regular schedule: fixed window with a full-table masked lookup or
  a Montgomery ladder; no branch or memory index depending on secret bits. Field arithmetic
  in fixed-width limbs (Montgomery form) where the language allows; JavaScript, Python and
  Dart may use their big integers, as their SM2 code does, and document that.
- Verification, public-key decoding and other public-data paths may be variable time.
- Compare MACs and confirmation values in constant time. Do not keep secrets in error
  messages or debug output.
