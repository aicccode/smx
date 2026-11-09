/**
 * SM9 known answers: every vector of ../../testvectors/sm9-vectors.json
 * (standard examples, extra cases, invalid points and scalars).
 */
import './support/rng-shim.js'
import * as api from '../index.js'
import {
  sm9EncapsulateWithRandom,
  sm9EncryptWithRandom,
  sm9ExchangeInitWithRandom,
  sm9SignWithRandom,
} from '../sm9/sm9.js'
import { Fp12, gtToBytes } from '../sm9/fp12.js'
import { P1, P2, g1Encode, g2Decode, g2Encode } from '../sm9/groups.js'
import { pairing } from '../sm9/pairing.js'
import { h1 } from '../sm9/hash.js'
import {
  DECRYPT_ERROR,
  N,
  SM4,
  STREAM,
  V,
  eq,
  finish,
  hex,
  hexToBytes,
  ok,
  scalarHex,
  sm9,
  throws,
} from './support/sm9-helpers.js'

// ---- parameters and exports ----
{
  eq('P1', hex(g1Encode(P1)), V.params.P1)
  eq('P2', hex(g2Encode(P2)), V.params.P2)
  eq('hid sign', api.SM9_HID_SIGN, V.params.hid_sign)
  eq('hid exchange', api.SM9_HID_EXCHANGE, V.params.hid_exchange)
  eq('hid encrypt', api.SM9_HID_ENCRYPT, V.params.hid_encrypt)
  ok('index exports getSM9', typeof api.getSM9 === 'function')
  ok(
    'index hides the explicit-r variants',
    !('sm9SignWithRandom' in api) && !('sm9EncryptWithRandom' in api),
  )
}

// ---- standard examples (GB/T 38635.5) ----
{
  const s = V.standard.sign
  eq(
    'std sign master public',
    sm9.sm9SignMasterPublicKey(s.master_private_key),
    s.master_public_key,
  )
  eq(
    'std sign user key',
    sm9.sm9GenSignUserKey(s.master_private_key, s.user_id, s.hid),
    s.user_private_key,
  )
  const g = new Fp12()
  const ppub = g2Decode(hexToBytes(s.master_public_key))
  pairing(g, P1.x, P1.y, ppub.x, ppub.y)
  eq('std pairing g', hex(gtToBytes(g)), s.pairing_g)
  eq(
    'std signature',
    sm9SignWithRandom(s.message, s.user_private_key, s.master_public_key, s.r),
    s.signature,
  )
  ok(
    'std verify',
    sm9.sm9Verify(
      s.message,
      s.signature,
      s.user_id,
      s.master_public_key,
      s.hid,
    ),
  )
  ok(
    'std verify uppercase key',
    sm9.sm9Verify(
      s.message,
      s.signature,
      s.user_id,
      s.master_public_key.toUpperCase(),
    ),
  )
  ok(
    'std verify wrong message',
    !sm9.sm9Verify(
      s.message + '.',
      s.signature,
      s.user_id,
      s.master_public_key,
    ),
  )
  ok(
    'std verify wrong id',
    !sm9.sm9Verify(s.message, s.signature, 'Bob', s.master_public_key),
  )
  ok(
    'std verify wrong hid',
    !sm9.sm9Verify(s.message, s.signature, s.user_id, s.master_public_key, 2),
  )

  const e = V.standard.encrypt
  eq(
    'std enc master public',
    sm9.sm9EncMasterPublicKey(e.master_private_key),
    e.master_public_key,
  )
  eq(
    'std enc user key',
    sm9.sm9GenEncUserKey(e.master_private_key, e.user_id, e.hid),
    e.user_private_key,
  )
  eq(
    'std encrypt stream',
    sm9EncryptWithRandom(
      e.plaintext,
      e.user_id,
      e.master_public_key,
      e.hid,
      STREAM,
      e.r,
    ),
    e.ciphertext_stream,
  )
  eq(
    'std encrypt sm4',
    sm9EncryptWithRandom(
      e.plaintext,
      e.user_id,
      e.master_public_key,
      e.hid,
      SM4,
      e.r,
    ),
    e.ciphertext_sm4,
  )
  eq(
    'std decrypt stream',
    sm9.sm9DecryptString(e.ciphertext_stream, e.user_id, e.user_private_key),
    e.plaintext,
  )
  eq(
    'std decrypt sm4',
    sm9.sm9DecryptString(e.ciphertext_sm4, e.user_id, e.user_private_key, SM4),
    e.plaintext,
  )

  const k = V.standard.encapsulate
  eq(
    'std kem user key',
    sm9.sm9GenEncUserKey(k.master_private_key, k.user_id, k.hid),
    k.user_private_key,
  )
  const kem = sm9EncapsulateWithRandom(
    k.user_id,
    k.master_public_key,
    k.key_len,
    k.hid,
    k.r,
  )
  eq('std kem ciphertext', kem.ciphertext, k.ciphertext)
  eq('std kem key', kem.key, k.key)
  eq(
    'std decapsulate',
    sm9.sm9Decapsulate(k.ciphertext, k.user_id, k.user_private_key, k.key_len),
    k.key,
  )

  checkExchange(
    'std',
    V.standard.exchange,
    V.standard.exchange.master_public_key,
    V.standard.exchange.master_private_key,
  )
}

function checkExchange(label, x, mpk, msk) {
  if (msk !== undefined) {
    eq(
      `${label} kx key A`,
      sm9.sm9GenEncUserKey(msk, x.id_a, api.SM9_HID_EXCHANGE),
      x.user_private_key_a,
    )
    eq(
      `${label} kx key B`,
      sm9.sm9GenEncUserKey(msk, x.id_b, api.SM9_HID_EXCHANGE),
      x.user_private_key_b,
    )
  }
  const a = sm9ExchangeInitWithRandom(x.id_b, mpk, api.SM9_HID_EXCHANGE, x.r_a)
  const b = sm9ExchangeInitWithRandom(x.id_a, mpk, api.SM9_HID_EXCHANGE, x.r_b)
  eq(`${label} kx R_A`, a.R, x.R_a)
  eq(`${label} kx R_B`, b.R, x.R_b)
  eq(`${label} kx r echoed`, a.r, x.r_a)
  const rb = sm9.sm9ExchangeRespond(
    x.key_len,
    x.id_a,
    x.id_b,
    mpk,
    x.user_private_key_b,
    x.r_b,
    x.R_b,
    x.R_a,
  )
  ok(`${label} kx respond`, rb.success, rb.message)
  eq(`${label} kx SK_B`, rb.sharedKey, x.shared_key)
  eq(`${label} kx S_B`, rb.sB, x.s_b)
  eq(`${label} kx S_2`, rb.s2, x.s_a)
  const ra = sm9.sm9ExchangeConfirm(
    x.key_len,
    x.id_a,
    x.id_b,
    mpk,
    x.user_private_key_a,
    x.r_a,
    x.R_a,
    x.R_b,
    x.s_b,
  )
  ok(`${label} kx confirm`, ra.success, ra.message)
  eq(`${label} kx SK_A`, ra.sharedKey, x.shared_key)
  eq(`${label} kx S_A`, ra.sA, x.s_a)
  ok(`${label} kx check`, sm9.sm9ExchangeCheck(rb.s2, ra.sA))
}

// ---- extra vectors ----
{
  const X = V.extra
  eq(
    'extra sign master public',
    sm9.sm9SignMasterPublicKey(X.sign_master_private_key),
    X.sign_master_public_key,
  )
  eq(
    'extra enc master public',
    sm9.sm9EncMasterPublicKey(X.enc_master_private_key),
    X.enc_master_public_key,
  )
  X.sign.forEach((c, i) => {
    const msg = hexToBytes(c.message_hex)
    eq(
      `extra sign ${i} user key`,
      sm9.sm9GenSignUserKey(X.sign_master_private_key, c.user_id),
      c.user_private_key,
    )
    eq(
      `extra sign ${i} signature`,
      sm9SignWithRandom(msg, c.user_private_key, X.sign_master_public_key, c.r),
      c.signature,
    )
    ok(
      `extra sign ${i} verify`,
      sm9.sm9Verify(msg, c.signature, c.user_id, X.sign_master_public_key),
    )
    ok(
      `extra sign ${i} verify bytes id`,
      sm9.sm9Verify(
        Array.from(msg),
        c.signature,
        new TextEncoder().encode(c.user_id),
        X.sign_master_public_key,
      ),
    )
  })
  X.encrypt.forEach((c, i) => {
    const pt = hexToBytes(c.plaintext_hex)
    eq(
      `extra enc ${i} user key`,
      sm9.sm9GenEncUserKey(X.enc_master_private_key, c.user_id),
      c.user_private_key,
    )
    eq(
      `extra enc ${i} stream`,
      sm9EncryptWithRandom(
        pt,
        c.user_id,
        X.enc_master_public_key,
        3,
        STREAM,
        c.r,
      ),
      c.ciphertext_stream,
    )
    eq(
      `extra enc ${i} sm4`,
      sm9EncryptWithRandom(pt, c.user_id, X.enc_master_public_key, 3, SM4, c.r),
      c.ciphertext_sm4,
    )
    eq(
      `extra dec ${i} stream`,
      hex(
        sm9.sm9Decrypt(
          c.ciphertext_stream,
          c.user_id,
          c.user_private_key,
          STREAM,
        ),
      ),
      c.plaintext_hex,
    )
    eq(
      `extra dec ${i} sm4`,
      hex(sm9.sm9Decrypt(c.ciphertext_sm4, c.user_id, c.user_private_key, SM4)),
      c.plaintext_hex,
    )
  })
  X.encapsulate.forEach((c, i) => {
    eq(
      `extra kem ${i} user key`,
      sm9.sm9GenEncUserKey(X.enc_master_private_key, c.user_id),
      c.user_private_key,
    )
    const kem = sm9EncapsulateWithRandom(
      c.user_id,
      X.enc_master_public_key,
      c.key_len,
      3,
      c.r,
    )
    eq(`extra kem ${i} ciphertext`, kem.ciphertext, c.ciphertext)
    eq(`extra kem ${i} key`, kem.key, c.key)
    eq(
      `extra kem ${i} decapsulate`,
      sm9.sm9Decapsulate(
        c.ciphertext,
        c.user_id,
        c.user_private_key,
        c.key_len,
      ),
      c.key,
    )
  })
  X.exchange.forEach((c, i) =>
    checkExchange(
      `extra ${i}`,
      c,
      X.enc_master_public_key,
      X.enc_master_private_key,
    ),
  )
}

// ---- invalid points and scalars from the JSON ----
const X = V.extra
const S0 = X.sign[1]
const E0 = X.encrypt[0]
const K0 = X.encapsulate[0]
const KX = X.exchange[0]
const SIG0 = sm9SignWithRandom(
  hexToBytes(S0.message_hex),
  S0.user_private_key,
  X.sign_master_public_key,
  S0.r,
)
const MSG0 = hexToBytes(S0.message_hex)
for (const { name, value } of V.invalid_points.g1) {
  throws(`G1 ${name}: enc master public key`, () =>
    sm9.sm9Encrypt('m', 'Bob', value),
  )
  throws(`G1 ${name}: kem master public key`, () =>
    sm9.sm9Encapsulate('Bob', value, 16),
  )
  throws(`G1 ${name}: kx master public key`, () =>
    sm9.sm9ExchangeInit('Bob', value),
  )
  throws(`G1 ${name}: sign user key`, () =>
    sm9.sm9Sign('m', value, X.sign_master_public_key),
  )
  ok(
    `G1 ${name}: signature S`,
    !sm9.sm9Verify(
      MSG0,
      SIG0.slice(0, 64) + value,
      S0.user_id,
      X.sign_master_public_key,
    ),
  )
  throws(
    `G1 ${name}: decapsulate`,
    () => sm9.sm9Decapsulate(value, K0.user_id, K0.user_private_key, 1),
    'SM9 decapsulation failed',
  )
  throws(
    `G1 ${name}: decrypt C1`,
    () =>
      sm9.sm9Decrypt(
        value + E0.ciphertext_stream.slice(130),
        E0.user_id,
        E0.user_private_key,
      ),
    DECRYPT_ERROR,
  )
  ok(
    `G1 ${name}: kx R_A`,
    !sm9.sm9ExchangeRespond(
      1,
      KX.id_a,
      KX.id_b,
      X.enc_master_public_key,
      KX.user_private_key_b,
      KX.r_b,
      KX.R_b,
      value,
    ).success,
  )
  ok(
    `G1 ${name}: kx R_B`,
    !sm9.sm9ExchangeConfirm(
      1,
      KX.id_a,
      KX.id_b,
      X.enc_master_public_key,
      KX.user_private_key_a,
      KX.r_a,
      KX.R_a,
      value,
      KX.s_b,
    ).success,
  )
}
for (const { name, value } of V.invalid_points.g2) {
  throws(`G2 ${name}: sign master public key`, () =>
    sm9.sm9Sign('m', S0.user_private_key, value),
  )
  ok(
    `G2 ${name}: verify master public key`,
    !sm9.sm9Verify(MSG0, SIG0, S0.user_id, value),
  )
  throws(`G2 ${name}: decrypt user key`, () =>
    sm9.sm9Decrypt(E0.ciphertext_stream, E0.user_id, value),
  )
  throws(`G2 ${name}: decapsulate user key`, () =>
    sm9.sm9Decapsulate(K0.ciphertext, K0.user_id, value, 1),
  )
  ok(
    `G2 ${name}: kx user key`,
    !sm9.sm9ExchangeRespond(
      1,
      KX.id_a,
      KX.id_b,
      X.enc_master_public_key,
      value,
      KX.r_b,
      KX.R_b,
      KX.R_a,
    ).success,
  )
}
for (const { name, value } of V.invalid_scalars) {
  throws(`scalar ${name}: sign master public`, () =>
    sm9.sm9SignMasterPublicKey(value),
  )
  throws(`scalar ${name}: enc master public`, () =>
    sm9.sm9EncMasterPublicKey(value),
  )
  throws(`scalar ${name}: sign user key`, () =>
    sm9.sm9GenSignUserKey(value, 'a'),
  )
  throws(`scalar ${name}: enc user key`, () => sm9.sm9GenEncUserKey(value, 'a'))
  throws(`scalar ${name}: sign r`, () =>
    sm9SignWithRandom(
      'm',
      S0.user_private_key,
      X.sign_master_public_key,
      value,
    ),
  )
  throws(`scalar ${name}: encrypt r`, () =>
    sm9EncryptWithRandom('m', 'Bob', X.enc_master_public_key, 3, STREAM, value),
  )
  throws(`scalar ${name}: kem r`, () =>
    sm9EncapsulateWithRandom('Bob', X.enc_master_public_key, 16, 3, value),
  )
  throws(`scalar ${name}: kx init r`, () =>
    sm9ExchangeInitWithRandom('Bob', X.enc_master_public_key, 2, value),
  )
  ok(
    `scalar ${name}: kx respond r`,
    !sm9.sm9ExchangeRespond(
      1,
      KX.id_a,
      KX.id_b,
      X.enc_master_public_key,
      KX.user_private_key_b,
      value,
      KX.R_b,
      KX.R_a,
    ).success,
  )
  ok(
    `scalar ${name}: kx confirm r`,
    !sm9.sm9ExchangeConfirm(
      1,
      KX.id_a,
      KX.id_b,
      X.enc_master_public_key,
      KX.user_private_key_a,
      value,
      KX.R_a,
      KX.R_b,
      KX.s_b,
    ).success,
  )
}
{
  const max = V.max_valid_master_private_key
  ok('max master key (sign)', sm9.sm9SignMasterPublicKey(max).length === 258)
  ok('max master key (enc)', sm9.sm9EncMasterPublicKey(max).length === 130)
  ok('max master key user key', sm9.sm9GenSignUserKey(max, 'a').length === 130)
  eq(
    'master key uppercase',
    sm9.sm9SignMasterPublicKey(X.sign_master_private_key.toUpperCase()),
    X.sign_master_public_key,
  )
  // h out of range in a signature
  for (const h of [0n, N, N + 1n, (1n << 256n) - 1n]) {
    ok(
      `signature h=${h.toString(16).slice(0, 8)}`,
      !sm9.sm9Verify(
        MSG0,
        scalarHex(h) + SIG0.slice(64),
        S0.user_id,
        X.sign_master_public_key,
      ),
    )
  }
  // t1 = H1(ID || hid) + ks = 0 mod N
  const ks = scalarHex(
    N - BigInt('0x' + hex(h1(new TextEncoder().encode('zero'), 1))),
  )
  throws('t1 = 0 sign user key', () => sm9.sm9GenSignUserKey(ks, 'zero'))
  ok(
    't1 = 0 other hid fine',
    sm9.sm9GenSignUserKey(ks, 'zero', 3).length === 130,
  )
  const ke = scalarHex(
    N - BigInt('0x' + hex(h1(new TextEncoder().encode('zero'), 3))),
  )
  throws('t1 = 0 enc user key', () => sm9.sm9GenEncUserKey(ke, 'zero'))
  // Q_B is the identity for that ID: encryption must refuse
  throws('identity Q_B encrypt', () =>
    sm9.sm9Encrypt('m', 'zero', sm9.sm9EncMasterPublicKey(ke)),
  )
}

finish('sm9')
