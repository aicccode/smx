/**
 * SM9 behaviour beyond the vectors: random round trips, tampering, wrong
 * identities, keys and modes, hex case rules, key-exchange mismatches, input
 * types and RNG failure.
 */
import './support/rng-shim.js'
import { withRandom } from './support/rng-shim.js'
import {
  DECRYPT_ERROR,
  SM4,
  STREAM,
  V,
  eq,
  finish,
  flipHex,
  hex,
  ok,
  sm9,
  throws,
} from './support/sm9-helpers.js'

const X = V.extra

// ---- random round trips ----
const signMaster = sm9.sm9GenSignMasterKey()
const encMaster = sm9.sm9GenEncMasterKey()
{
  ok(
    'gen sign master',
    signMaster.privateKey.length === 64 && signMaster.publicKey.length === 258,
  )
  ok(
    'gen enc master',
    encMaster.privateKey.length === 64 && encMaster.publicKey.length === 130,
  )
  eq(
    'sign master public matches',
    sm9.sm9SignMasterPublicKey(signMaster.privateKey),
    signMaster.publicKey,
  )
  eq(
    'enc master public matches',
    sm9.sm9EncMasterPublicKey(encMaster.privateKey),
    encMaster.publicKey,
  )
  const ds = sm9.sm9GenSignUserKey(signMaster.privateKey, 'alice@example.com')
  for (const msg of ['', 'hello', '国密 SM9', new Uint8Array(1000).fill(7)]) {
    const sig = sm9.sm9Sign(msg, ds, signMaster.publicKey)
    ok(
      `round trip sign ${msg.length}`,
      sig.length === 194 && sig === sig.toLowerCase(),
    )
    ok(
      `round trip verify ${msg.length}`,
      sm9.sm9Verify(msg, sig, 'alice@example.com', signMaster.publicKey),
    )
    ok(
      `verify wrong master ${msg.length}`,
      !sm9.sm9Verify(msg, sig, 'alice@example.com', X.sign_master_public_key),
    )
    ok(
      `verify uppercase sig ${msg.length}`,
      !sm9.sm9Verify(
        msg,
        sig.toUpperCase(),
        'alice@example.com',
        signMaster.publicKey,
      ),
    )
  }
  const sig = sm9.sm9Sign('tamper', ds, signMaster.publicKey)
  for (const at of [0, 63, 64, 66, 129, 130, 193]) {
    ok(
      `signature tamper at ${at}`,
      !sm9.sm9Verify(
        'tamper',
        flipHex(sig, at),
        'alice@example.com',
        signMaster.publicKey,
      ),
    )
  }
  ok(
    'signature truncated',
    !sm9.sm9Verify(
      'tamper',
      sig.slice(0, -2),
      'alice@example.com',
      signMaster.publicKey,
    ),
  )
  ok(
    'signature extended',
    !sm9.sm9Verify(
      'tamper',
      sig + '00',
      'alice@example.com',
      signMaster.publicKey,
    ),
  )
  ok('verify junk', !sm9.sm9Verify({}, null, 5, undefined))

  const de = sm9.sm9GenEncUserKey(encMaster.privateKey, 'bob')
  const other = sm9.sm9GenEncUserKey(encMaster.privateKey, 'carol')
  for (const mode of [STREAM, SM4]) {
    for (const len of [1, 15, 16, 17, 32, 100]) {
      const pt = new Uint8Array(len).map((_, i) => (i * 37 + len) & 255)
      const ct = sm9.sm9Encrypt(pt, 'bob', encMaster.publicKey, 3, mode)
      eq(
        `round trip ${mode} ${len}`,
        hex(sm9.sm9Decrypt(ct, 'bob', de, mode)),
        hex(pt),
      )
      const c2Len = mode === SM4 ? (Math.floor(len / 16) + 1) * 16 : len
      eq(`ciphertext length ${mode} ${len}`, ct.length, 2 * (65 + 32 + c2Len))
    }
    const ct = sm9.sm9Encrypt(
      'secret text',
      'bob',
      encMaster.publicKey,
      3,
      mode,
    )
    eq(
      `decrypt string ${mode}`,
      sm9.sm9DecryptString(ct, 'bob', de, mode),
      'secret text',
    )
    for (const at of [2, 129, 130, 193, 194, ct.length - 1]) {
      throws(
        `ciphertext tamper ${mode} at ${at}`,
        () => sm9.sm9Decrypt(flipHex(ct, at), 'bob', de, mode),
        DECRYPT_ERROR,
      )
    }
    throws(
      `wrong id ${mode}`,
      () => sm9.sm9Decrypt(ct, 'carol', de, mode),
      DECRYPT_ERROR,
    )
    throws(
      `wrong key ${mode}`,
      () => sm9.sm9Decrypt(ct, 'bob', other, mode),
      DECRYPT_ERROR,
    )
    throws(
      `uppercase ciphertext ${mode}`,
      () => sm9.sm9Decrypt(ct.toUpperCase(), 'bob', de, mode),
      DECRYPT_ERROR,
    )
    throws(
      `truncated ciphertext ${mode}`,
      () => sm9.sm9Decrypt(ct.slice(0, 194), 'bob', de, mode),
      DECRYPT_ERROR,
    )
    eq(
      `uppercase user key ${mode}`,
      sm9.sm9DecryptString(ct, 'bob', de.toUpperCase(), mode),
      'secret text',
    )
    throws(`empty plaintext ${mode}`, () =>
      sm9.sm9Encrypt('', 'bob', encMaster.publicKey, 3, mode),
    )
    const wrongHid = sm9.sm9Encrypt('x', 'bob', encMaster.publicKey, 4, mode)
    throws(
      `wrong hid ${mode}`,
      () => sm9.sm9Decrypt(wrongHid, 'bob', de, mode),
      DECRYPT_ERROR,
    )
  }
  const streamCt = sm9.sm9Encrypt(
    new Uint8Array(32).fill(1),
    'bob',
    encMaster.publicKey,
  )
  throws(
    'wrong mode stream->sm4',
    () => sm9.sm9Decrypt(streamCt, 'bob', de, SM4),
    DECRYPT_ERROR,
  )
  const sm4Ct = sm9.sm9Encrypt(
    new Uint8Array(32).fill(1),
    'bob',
    encMaster.publicKey,
    3,
    SM4,
  )
  throws(
    'wrong mode sm4->stream',
    () => sm9.sm9Decrypt(sm4Ct, 'bob', de, STREAM),
    DECRYPT_ERROR,
  )
  throws('bad mode encrypt', () =>
    sm9.sm9Encrypt('x', 'bob', encMaster.publicKey, 3, 'cbc'),
  )
  throws('bad mode decrypt', () => sm9.sm9Decrypt(streamCt, 'bob', de, 1))
  for (const hid of [-1, 256, 1.5, '3', null]) {
    throws(`bad hid ${hid}`, () =>
      sm9.sm9Encrypt('x', 'bob', encMaster.publicKey, hid),
    )
  }
  ok(
    'hid 0 and 255 accepted',
    sm9.sm9GenEncUserKey(encMaster.privateKey, 'bob', 0).length === 258 &&
      sm9.sm9GenSignUserKey(signMaster.privateKey, 'bob', 255).length === 130,
  )

  for (const len of [1, 32, 33, 1000]) {
    const { key, ciphertext } = sm9.sm9Encapsulate(
      'bob',
      encMaster.publicKey,
      len,
    )
    eq(
      `kem round trip ${len}`,
      sm9.sm9Decapsulate(ciphertext, 'bob', de, len),
      key,
    )
    ok(`kem key length ${len}`, key.length === 2 * len)
    ok(
      `kem wrong id ${len}`,
      sm9.sm9Decapsulate(ciphertext, 'carol', de, len) !== key,
    )
  }
  const kem = sm9.sm9Encapsulate('bob', encMaster.publicKey, 16)
  throws(
    'kem uppercase ciphertext',
    () => sm9.sm9Decapsulate(kem.ciphertext.toUpperCase(), 'bob', de, 16),
    'SM9 decapsulation failed',
  )
  for (const len of [0, -1, 1.5, (1 << 20) + 1, '16', NaN]) {
    throws(`kem bad length ${len}`, () =>
      sm9.sm9Encapsulate('bob', encMaster.publicKey, len),
    )
    throws(`decap bad length ${len}`, () =>
      sm9.sm9Decapsulate(kem.ciphertext, 'bob', de, len),
    )
  }
}

// ---- random key exchange and mismatches ----
{
  const mpk = encMaster.publicKey
  const dA = sm9.sm9GenEncUserKey(encMaster.privateKey, 'alice', 2)
  const dB = sm9.sm9GenEncUserKey(encMaster.privateKey, 'bob', 2)
  const a = sm9.sm9ExchangeInit('bob', mpk)
  const b = sm9.sm9ExchangeInit('alice', mpk)
  const rb = sm9.sm9ExchangeRespond(48, 'alice', 'bob', mpk, dB, b.r, b.R, a.R)
  ok('kx random respond', rb.success, rb.message)
  const ra = sm9.sm9ExchangeConfirm(
    48,
    'alice',
    'bob',
    mpk,
    dA,
    a.r,
    a.R,
    b.R,
    rb.sB,
  )
  ok('kx random confirm', ra.success, ra.message)
  eq('kx random keys agree', ra.sharedKey, rb.sharedKey)
  ok('kx random key length', ra.sharedKey.length === 96)
  ok('kx random check', sm9.sm9ExchangeCheck(rb.s2, ra.sA))
  ok('kx check wrong sA', !sm9.sm9ExchangeCheck(rb.s2, flipHex(ra.sA, 5)))
  ok(
    'kx check uppercase',
    /[a-f]/.test(ra.sA) === !sm9.sm9ExchangeCheck(rb.s2, ra.sA.toUpperCase()),
  )
  ok('kx check junk', !sm9.sm9ExchangeCheck(null, 5))
  const bad = (name, res) =>
    ok(
      name,
      !res.success && res.sharedKey === null && typeof res.message === 'string',
    )
  bad(
    'kx confirm wrong sB',
    sm9.sm9ExchangeConfirm(
      48,
      'alice',
      'bob',
      mpk,
      dA,
      a.r,
      a.R,
      b.R,
      flipHex(rb.sB, 0),
    ),
  )
  bad(
    'kx confirm uppercase sB',
    sm9.sm9ExchangeConfirm(
      48,
      'alice',
      'bob',
      mpk,
      dA,
      a.r,
      a.R,
      b.R,
      rb.sB.toUpperCase(),
    ),
  )
  bad(
    'kx confirm wrong id',
    sm9.sm9ExchangeConfirm(48, 'alice', 'bobby', mpk, dA, a.r, a.R, b.R, rb.sB),
  )
  bad(
    'kx confirm wrong r',
    sm9.sm9ExchangeConfirm(48, 'alice', 'bob', mpk, dA, b.r, a.R, b.R, rb.sB),
  )
  bad(
    'kx confirm swapped R',
    sm9.sm9ExchangeConfirm(48, 'alice', 'bob', mpk, dA, a.r, b.R, a.R, rb.sB),
  )
  bad(
    'kx confirm wrong key',
    sm9.sm9ExchangeConfirm(48, 'alice', 'bob', mpk, dB, a.r, a.R, b.R, rb.sB),
  )
  const shorter = sm9.sm9ExchangeConfirm(
    16,
    'alice',
    'bob',
    mpk,
    dA,
    a.r,
    a.R,
    b.R,
    rb.sB,
  )
  ok(
    'kx other length is a prefix',
    shorter.success && rb.sharedKey.startsWith(shorter.sharedKey),
  )
  for (const len of [0, (1 << 20) + 1, 2.5]) {
    bad(
      `kx respond bad length ${len}`,
      sm9.sm9ExchangeRespond(len, 'alice', 'bob', mpk, dB, b.r, b.R, a.R),
    )
  }
  // B responding for the wrong peer: confirmation fails on A's side
  const rbWrong = sm9.sm9ExchangeRespond(
    48,
    'mallory',
    'bob',
    mpk,
    dB,
    b.r,
    b.R,
    a.R,
  )
  ok('kx respond other id succeeds locally', rbWrong.success)
  bad(
    'kx mismatched ids rejected by A',
    sm9.sm9ExchangeConfirm(
      48,
      'alice',
      'bob',
      mpk,
      dA,
      a.r,
      a.R,
      b.R,
      rbWrong.sB,
    ),
  )
}

// ---- input types and RNG failure ----
{
  const ds = sm9.sm9GenSignUserKey(signMaster.privateKey, 'x')
  throws('lone surrogate message', () =>
    sm9.sm9Sign('\ud800', ds, signMaster.publicKey),
  )
  throws('lone surrogate id', () =>
    sm9.sm9GenSignUserKey(signMaster.privateKey, '\udc00'),
  )
  throws('non-byte array message', () =>
    sm9.sm9Sign([256], ds, signMaster.publicKey),
  )
  throws('object id', () => sm9.sm9GenSignUserKey(signMaster.privateKey, {}))
  throws(
    'RNG all zeros',
    () =>
      withRandom(
        (a) => a.fill(0),
        () => sm9.sm9GenSignMasterKey(),
      ),
    'Random source failed to produce a valid scalar',
  )
  throws(
    'RNG all ones',
    () =>
      withRandom(
        (a) => a.fill(255),
        () => sm9.sm9Sign('m', ds, signMaster.publicKey),
      ),
    'Random source failed to produce a valid scalar',
  )
  throws(
    'RNG throws',
    () =>
      withRandom(
        () => {
          throw new Error('rng down')
        },
        () => sm9.sm9Encrypt('m', 'b', encMaster.publicKey),
      ),
    'rng down',
  )
  const json = JSON.stringify(sm9)
  ok('instance holds no state', json === '{}')
}

finish('sm9-roundtrip')
