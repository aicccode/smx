/**
 * Security behaviour: the shared vectors in ../../testvectors, plus rejection of
 * invalid input, round trips and failure handling specific to this language.
 *
 * The slow 512 MiB and 1 GiB SM3 cases run unless SMX_SKIP_SLOW=1.
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { getSM2 } from '../sm2/sm2.js'
import { SM3 } from '../sm3/sm3.js'
import { SM4 } from '../sm4/sm4.js'
import { sboxPlanes, sboxWord } from '../sm4/sbox-circuit.js'
import { BigInteger, SecureRandom } from '../sm2/biginteger.js'
import { ECCurveFp, ECPointFp } from '../sm2/ec.js'
import * as util from '../sm2/utils.js'
import * as common from '../common/utils.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(
  readFileSync(
    resolve(here, '../../testvectors/security-vectors.json'),
    'utf8',
  ),
)

let passed = 0
let failed = 0
function ok(name, condition, detail = '') {
  if (condition) {
    passed++
  } else {
    failed++
    console.error(`[FAIL] ${name} ${detail}`)
  }
}
function throws(name, fn, message) {
  try {
    const v = fn()
    ok(name, false, `returned ${String(v).slice(0, 60)}`)
  } catch (e) {
    const right =
      e instanceof Error && (message == null || e.message === message)
    ok(name, right, `threw ${e && e.message}`)
  }
}

const hexOf = (n) => n.toString(16).padStart(64, '0')
const sm2 = getSM2()
const V = vectors.sm2
const { curve, G } = util.generateEcparam()
const N = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n
const P = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn
const B_COEFFICIENT =
  0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n
function powerMod(a, e, m) {
  let r = 1n
  let c = ((a % m) + m) % m
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * c) % m
    c = (c * c) % m
  }
  return r
}

// ---- deterministic scalar source, restored after use ----
const realCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
function withRandom(getRandomValues, fn) {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: { getRandomValues },
  })
  try {
    return fn()
  } finally {
    if (realCrypto) Object.defineProperty(globalThis, 'crypto', realCrypto)
    else delete globalThis.crypto
  }
}
function fromHex(h) {
  return common.hexToBytes(h)
}
function queueSource(...draws) {
  const q = draws.map(fromHex)
  return (a) => {
    a.set(q.shift())
    return a
  }
}

// ---- shared vectors: valid values ----
ok(
  'vector public key',
  sm2.getPublicKeyFromPrivateKey(V.private_key) === V.public_key,
)
ok(
  'vector signature verifies',
  sm2.sm2VerifySign(V.user_id, V.r + 'h' + V.s, V.message, V.public_key),
)
ok(
  'vector signature from nonce',
  withRandom(queueSource(V.nonce_k), () =>
    sm2.sm2Sign(V.user_id, V.private_key, V.message),
  ) ===
    V.r + 'h' + V.s,
)
ok(
  'vector ciphertext from nonce',
  withRandom(queueSource(V.nonce_k), () =>
    sm2.sm2Encrypt(V.plaintext, V.public_key),
  ) === V.ciphertext,
)
ok(
  'vector decrypt',
  sm2.sm2Decrypt(V.ciphertext, V.private_key) === V.plaintext,
)
ok(
  'max private key is valid',
  sm2
    .getPublicKeyFromPrivateKey(V.n_minus_2_is_max_valid_private_key)
    .startsWith('04'),
)

// ---- shared vectors: invalid values, at every entry point ----
for (const c of V.invalid_public_keys) {
  const n = `public key ${c.name}`
  ok(`${n}: verifyPublicKey`, util.verifyPublicKey(c.value) === false)
  throws(`${n}: decodePointHex`, () => curve.decodePointHex(c.value))
  throws(`${n}: encrypt`, () => sm2.sm2Encrypt('x', c.value))
  ok(
    `${n}: verify`,
    sm2.sm2VerifySign(V.user_id, V.r + 'h' + V.s, V.message, c.value) === false,
  )
  throws(`${n}: userSM3Z`, () => sm2.userSM3Z(c.value))
  const k = V.public_key
  const d = V.private_key
  throws(`${n}: getSb pA`, () =>
    sm2.getSb(16, c.value, k, 'a', 'b', d, k, d, k),
  )
  throws(`${n}: getSb Ra`, () =>
    sm2.getSb(16, k, c.value, 'a', 'b', d, k, d, k),
  )
  throws(`${n}: getSb pB`, () =>
    sm2.getSb(16, k, k, 'a', 'b', d, c.value, d, k),
  )
  throws(`${n}: getSb Rb`, () =>
    sm2.getSb(16, k, k, 'a', 'b', d, k, d, c.value),
  )
  throws(`${n}: getSa pB`, () =>
    sm2.getSa(16, c.value, k, k, k, 'a', 'b', d, d, ''),
  )
  throws(`${n}: getSa Rb`, () =>
    sm2.getSa(16, k, c.value, k, k, 'a', 'b', d, d, ''),
  )
  throws(`${n}: getSa pA`, () =>
    sm2.getSa(16, k, k, c.value, k, 'a', 'b', d, d, ''),
  )
  throws(`${n}: getSa Ra`, () =>
    sm2.getSa(16, k, k, k, c.value, 'a', 'b', d, d, ''),
  )
  ok(
    `${n}: comparePublicKeyHex`,
    util.comparePublicKeyHex(c.value, k) === false,
  )
}
for (const c of V.invalid_private_keys) {
  const n = `private key ${c.name}`
  const k = V.public_key
  throws(
    `${n}: public key`,
    () => sm2.getPublicKeyFromPrivateKey(c.value),
    'Invalid private key',
  )
  throws(
    `${n}: sign`,
    () => sm2.sm2Sign('a', c.value, 'm'),
    'Invalid private key',
  )
  throws(
    `${n}: decrypt`,
    () => sm2.sm2Decrypt(V.ciphertext, c.value),
    'Invalid private key',
  )
  throws(
    `${n}: getSb d`,
    () => sm2.getSb(16, k, k, 'a', 'b', c.value, k, V.private_key, k),
    'Invalid private key',
  )
  throws(
    `${n}: getSb r`,
    () => sm2.getSb(16, k, k, 'a', 'b', V.private_key, k, c.value, k),
    'Invalid private key',
  )
  throws(
    `${n}: getSa d`,
    () => sm2.getSa(16, k, k, k, k, 'a', 'b', c.value, V.private_key, ''),
    'Invalid private key',
  )
  throws(
    `${n}: getSa r`,
    () => sm2.getSa(16, k, k, k, k, 'a', 'b', V.private_key, c.value, ''),
    'Invalid private key',
  )
}
for (const c of V.invalid_signatures) {
  const sig = c.r === '' && c.s === '' ? '' : c.r + 'h' + c.s
  ok(
    `signature ${c.name}`,
    sm2.sm2VerifySign(V.user_id, sig, V.message, V.public_key) === false,
  )
}
for (const c of V.invalid_ciphertexts) {
  throws(
    `ciphertext ${c.name}`,
    () => sm2.sm2Decrypt(c.value, V.private_key),
    'SM2 decryption failed',
  )
}
ok(
  'user id at the limit',
  sm2.userSM3Z(V.public_key, 'x'.repeat(V.user_id_max_bytes)).length === 32,
)
throws('user id over the limit', () =>
  sm2.userSM3Z(V.public_key, 'x'.repeat(V.user_id_first_invalid_bytes)),
)
throws('user id over the limit: sign', () =>
  sm2.sm2Sign('x'.repeat(8192), V.private_key, 'm'),
)
ok(
  'user id over the limit: verify',
  sm2.sm2VerifySign(
    'x'.repeat(8192),
    V.r + 'h' + V.s,
    V.message,
    V.public_key,
  ) === false,
)
throws('user id counts bytes, not characters', () =>
  sm2.userSM3Z(V.public_key, '国'.repeat(2731)),
)

// ---- SM4 shared vectors ----
const S = vectors.sm4
const sm4 = () => new SM4().setKey(S.key, S.iv, true)
ok(
  'sm4 padded',
  sm4().encrypt(S.valid_padded_plaintext) === S.valid_padded_ciphertext,
)
ok(
  'sm4 padded decrypt',
  sm4().decrypt(S.valid_padded_ciphertext) === S.valid_padded_plaintext,
)
{
  const c = sm4()
  const plain = c.decrypt(S.valid_full_padding_block_ciphertext)
  ok(
    'sm4 full padding block',
    c.encrypt(plain) === S.valid_full_padding_block_ciphertext,
  )
}
for (const n of S.invalid_key_lengths_bytes) {
  throws(`sm4 hex key ${n} bytes`, () =>
    new SM4().setKey('00'.repeat(n), S.iv, true),
  )
  throws(`sm4 text key ${n} bytes`, () =>
    new SM4().setKey('k'.repeat(n), 'i'.repeat(16)),
  )
}
for (const n of S.invalid_iv_lengths_bytes) {
  throws(`sm4 hex iv ${n} bytes`, () =>
    new SM4().setKey(S.key, '00'.repeat(n), true),
  )
  throws(`sm4 text iv ${n} bytes`, () =>
    new SM4().setKey('k'.repeat(16), 'i'.repeat(n)),
  )
}
const SM4_ERROR = 'SM4 decryption failed'
for (const c of S.invalid_paddings) {
  throws(`sm4 padding ${c.name}`, () => sm4().decrypt(c.value), SM4_ERROR)
}
for (const n of S.invalid_ciphertext_lengths_bytes) {
  throws(
    `sm4 ciphertext ${n} bytes`,
    () => sm4().decrypt('00'.repeat(n)),
    SM4_ERROR,
  )
}
throws('sm4 non-hex', () => sm4().decrypt('zz'.repeat(16)), SM4_ERROR)
throws('sm4 odd hex', () => sm4().decrypt('0'.repeat(33)), SM4_ERROR)
throws('sm4 not a string', () => sm4().decrypt(5), SM4_ERROR)

// ---- SM4 specifics ----
throws('sm4 no key: encrypt', () => new SM4().encrypt('x'))
throws('sm4 no key: decrypt', () => new SM4().decrypt('00'.repeat(16)))
throws('sm4 no key: block', () =>
  new SM4()._encryptBlock(new Uint8Array(16), new Uint8Array(16), 0),
)
throws('sm4 old text key', () =>
  new SM4().setKey('this is the key', 'this is the iv'),
)
throws('sm4 text key, 32 hex digits without the hex flag', () =>
  new SM4().setKey(S.key, S.iv),
)
throws('sm4 key not a string', () =>
  new SM4().setKey(new Uint8Array(16), S.iv, true),
)
throws('sm4 non-hex key', () => new SM4().setKey('zz'.repeat(16), S.iv, true))
throws('sm4 encrypt non-string', () => sm4().encrypt(new Uint8Array(4)))
throws('sm4 encrypt lone surrogate', () => sm4().encrypt('\ud800'))

// The published S-box, from GB/T 32907
const SBOX = fromHex(
  'd690e9fecce13db716b614c228fb2c05' +
    '2b679a762abe04c3aa44132649860699' +
    '9c4250f491ef987a33540b43edcfac62' +
    'e4b31ca9c908e89580df94fa758f3fa6' +
    '4707a7fcf37317ba83593c19e6854fa8' +
    '686b81b27164da8bf8eb0f4b70569d35' +
    '1e240e5e6358d1a225227c3b01217887' +
    'd40046579fd327524c3602e7a0c4c89e' +
    'eabf8ad240c738b5a3f7f2cef96115a1' +
    'e0ae5da49b341a55ad933230f58cb1e3' +
    '1df6e22e8266ca60c02923ab0d534e6f' +
    'd5db3745defd8e2f03ff6a726d6c5b51' +
    '8d1baf92bbddbc7f11d95c411f105ad8' +
    '0ac13188a5cd7bbd2d74d012b8e5b4b0' +
    '8969974a0c96777e65b9f109c56ec684' +
    '18f07dec3adc4d2079ee5f3ed7cb3948',
)
for (let x = 0; x < 256; x++) {
  const word = (x << 24) | (x << 16) | (x << 8) | x
  const y = SBOX[x]
  const expected = (y << 24) | (y << 16) | (y << 8) | y
  ok(`sbox word ${x}`, sboxWord(word) === expected)
  const planes = new Int32Array(8)
  for (let bit = 0; bit < 8; bit++) planes[bit] = (x >> bit) & 1 ? -1 : 0
  sboxPlanes(planes)
  let same = true
  for (let bit = 0; bit < 8; bit++) {
    same = same && planes[bit] === ((y >> bit) & 1 ? -1 : 0)
  }
  ok(`sbox planes ${x}`, same)
}
ok(
  'sbox word mixes four separate bytes',
  sboxWord(0x00015380 | 0) ===
    ((SBOX[0x00] << 24) | (SBOX[0x01] << 16) | (SBOX[0x53] << 8) | SBOX[0x80]),
)

// Encrypt and the parallel decrypt path agree at every length around the lane size.
{
  const c = sm4()
  for (const n of [
    0, 1, 15, 16, 17, 31, 127, 128, 129, 143, 144, 255, 256, 1000,
  ]) {
    const text = 'p'.repeat(n)
    ok(`sm4 round trip ${n}`, c.decrypt(c.encrypt(text)) === text)
  }
  const reused = c.encrypt('same')
  ok('sm4 state does not chain between calls', c.encrypt('same') === reused)
  const bom = '\ufeffbom'
  ok('sm4 keeps a leading BOM', c.decrypt(c.encrypt(bom)) === bom)
}

// ---- RNG ----
{
  const failing = () => {
    throw new Error('source failed')
  }
  const zeros = (a) => a.fill(0)
  throws(
    'rng failure: keygen',
    () => withRandom(failing, () => util.generateKeyPairHex()),
    'source failed',
  )
  throws('rng failure: sign', () =>
    withRandom(failing, () => sm2.sm2Sign('a', V.private_key, 'm')),
  )
  throws('rng failure: encrypt', () =>
    withRandom(failing, () => sm2.sm2Encrypt('m', V.public_key)),
  )
  throws('rng zeros: keygen', () =>
    withRandom(zeros, () => util.generateKeyPairHex()),
  )
  throws('rng zeros: sign', () =>
    withRandom(zeros, () => sm2.sm2Sign('a', V.private_key, 'm')),
  )
  throws('rng zeros: encrypt', () =>
    withRandom(zeros, () => sm2.sm2Encrypt('m', V.public_key)),
  )
  const stuck = (a) => a.fill(0xff)
  throws('rng stuck high: keygen', () =>
    withRandom(stuck, () => util.generateKeyPairHex()),
  )
  throws('rng failure: SecureRandom', () =>
    withRandom(failing, () => new SecureRandom().nextBytes(new Array(4))),
  )

  // Without any source there is an error, not a fallback.
  if (realCrypto) {
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: undefined,
    })
    let threw = false
    try {
      util.generateKeyPairHex()
    } catch (e) {
      threw = e.message === 'No secure random source is available'
    }
    Object.defineProperty(globalThis, 'crypto', realCrypto)
    ok('no random source is an error', threw)
  }

  const high = 'ff'.repeat(32)
  const nHex = hexOf(N)
  const nMinus1 = hexOf(N - 1n)
  const pick = '00'.repeat(31) + '07'
  const picked = withRandom(
    queueSource(high, nHex, nMinus1, '00'.repeat(32), pick),
    () => util.generateKeyPairHex(),
  )
  ok('rejection sampling skips out-of-range draws', picked.privateKey === pick)

  throws('SecureRandom huge sparse array', () =>
    new SecureRandom().nextBytes(new Array(2 ** 31)),
  )
  throws('SecureRandom array-like', () =>
    new SecureRandom().nextBytes({ length: 1e9 }),
  )
  const large = new Array(70000)
  new SecureRandom().nextBytes(large)
  ok(
    'SecureRandom fills beyond one Web Crypto call',
    large.some((b) => b !== large[0]),
  )
}

// ---- keys, signatures, ciphertext formats ----
{
  const low = '0'.repeat(62) + 'ab'
  ok(
    'leading zeros are kept in a generated key',
    withRandom(queueSource(low), () => util.generateKeyPairHex()).privateKey ===
      low,
  )
  const k = util.generateKeyPairHex()
  ok(
    'generated key width',
    k.privateKey.length === 64 && k.publicKey.length === 130,
  )
  ok(
    'generated key is usable',
    sm2.getPublicKeyFromPrivateKey(k.privateKey) === k.publicKey,
  )
  let widths = true
  for (let i = 0; i < 300; i++) {
    const sig = sm2.sm2Sign('a', k.privateKey, 'm' + i)
    widths = widths && /^[0-9a-f]{64}h[0-9a-f]{64}$/.test(sig)
    widths = widths && sm2.sm2VerifySign('a', sig, 'm' + i, k.publicKey)
  }
  ok('every signature is fixed width and verifies', widths)
  ok(
    'nonces differ',
    sm2.sm2Sign('a', k.privateKey, 'm') !== sm2.sm2Sign('a', k.privateKey, 'm'),
  )
  ok(
    'negative key rejected',
    (() => {
      try {
        sm2.sm2Sign('a', '-5', 'm')
      } catch (e) {
        return e.message === 'Invalid private key'
      }
      return false
    })(),
  )
  try {
    sm2.getPublicKeyFromPrivateKey(hexOf(N))
  } catch (e) {
    ok('error does not contain the key', !e.message.includes(hexOf(N)))
  }

  const sig = V.r + 'h' + V.s
  const verify = (s, m = V.message, id = V.user_id, key = V.public_key) =>
    sm2.sm2VerifySign(id, s, m, key)
  ok('verify: extra separator', verify(sig + 'hff') === false)
  ok('verify: not a string', verify(5) === false)
  ok('verify: undefined', verify(undefined) === false)
  ok('verify: message not a string', verify(sig, new Uint8Array(1)) === false)
  ok('verify: lone surrogate', verify(sig, '\ud800') === false)
  ok('verify: key not a string', verify(sig, V.message, V.user_id, 7) === false)
  ok('verify: id not a string', verify(sig, V.message, 7) === false)
  ok(
    'verify: bare key without prefix',
    verify(sig, V.message, V.user_id, V.public_key.slice(2)) === false,
  )
  const s = BigInt('0x' + V.s)
  ok(
    'verify: s + n is not accepted',
    s + N < 1n << 256n ? verify(V.r + 'h' + hexOf(s + N)) === false : true,
  )
  const r = BigInt('0x' + V.r)
  // s*G + t*P at infinity: for d = 1, t = -s (mod n), which means 2s + r = 0.
  const inverse2 = (N + 1n) / 2n
  const infS = ((N - 5n) * inverse2) % N
  ok(
    'verify: infinity is false',
    sm2.sm2VerifySign(
      'a',
      hexOf(5n) + 'h' + hexOf(infS),
      'x',
      sm2.getPublicKeyFromPrivateKey(hexOf(1n)),
    ) === false,
  )
  ok('r parsed', r > 0n)

  throws('sign: message not a string', () =>
    sm2.sm2Sign('a', V.private_key, new Uint8Array(2)),
  )
  throws('sign: lone surrogate', () =>
    sm2.sm2Sign('a', V.private_key, '\udc00'),
  )
  throws('sign: id not a string', () => sm2.sm2Sign(5, V.private_key, 'm'))
  throws('encrypt: empty', () => sm2.sm2Encrypt('', V.public_key))
  throws('encrypt: empty array', () => sm2.sm2Encrypt([], V.public_key))
  throws('encrypt: element out of range', () =>
    sm2.sm2Encrypt([300], V.public_key),
  )
  throws('encrypt: fractional element', () =>
    sm2.sm2Encrypt([1.5], V.public_key),
  )
  throws('encrypt: hole', () => sm2.sm2Encrypt(new Array(2), V.public_key))
  throws('encrypt: number', () => sm2.sm2Encrypt(5, V.public_key))
  throws('encrypt: Uint16Array', () =>
    sm2.sm2Encrypt(new Uint16Array(1), V.public_key),
  )
  throws('encrypt: lone surrogate', () =>
    sm2.sm2Encrypt('\ud800', V.public_key),
  )
  const compressedC1 =
    util.compressPublicKeyHex(V.ciphertext.slice(0, 130)) +
    V.ciphertext.slice(130)
  throws(
    'decrypt: compressed C1',
    () => sm2.sm2Decrypt(compressedC1, V.private_key),
    'SM2 decryption failed',
  )
  throws(
    'decrypt: wrong key',
    () => sm2.sm2Decrypt(V.ciphertext, hexOf(5n)),
    'SM2 decryption failed',
  )
  throws(
    'decrypt: not a string',
    () => sm2.sm2Decrypt(5, V.private_key),
    'SM2 decryption failed',
  )
  throws(
    'decrypt: key not a string',
    () => sm2.sm2Decrypt(V.ciphertext, 5),
    'Invalid private key',
  )
  for (const text of ['a', '国密', '\ufeffbom', 'k'.repeat(65)]) {
    ok(
      `sm2 round trip ${text.slice(0, 4)}`,
      sm2.sm2Decrypt(sm2.sm2Encrypt(text, k.publicKey), k.privateKey) === text,
    )
  }
}

// ---- round-trip property, on random text and bytes of random sizes ----
{
  const ROUNDS = Number(process.env.ROUNDTRIP_CASES ?? 2000)
  let state = 0x2545f491
  const next = () => {
    state ^= state << 13
    state ^= state >>> 17
    state ^= state << 5
    return state >>> 0
  }
  const ALPHABET = ['a', '0', '国', '密', '🚀', '\ufeff', '\u0000', 'é', ' ']
  const text = (n) => {
    let s = ''
    for (let i = 0; i < n; i++) s += ALPHABET[next() % ALPHABET.length]
    return s
  }
  const k = util.generateKeyPairHex()
  const keyText = 'k'.repeat(16)
  let good = true
  for (let i = 0; i < ROUNDS && good; i++) {
    const m = text(1 + (next() % 80))
    good = sm2.sm2Decrypt(sm2.sm2Encrypt(m, k.publicKey), k.privateKey) === m
    const sig = sm2.sm2Sign(m, k.privateKey, m)
    good = good && sm2.sm2VerifySign(m, sig, m, k.publicKey)
    good = good && !sm2.sm2VerifySign(m, sig, m + 'x', k.publicKey)
    const c = new SM4().setKey(keyText, 'i'.repeat(16))
    const long = text(next() % 400)
    good = good && c.decrypt(c.encrypt(long)) === long
    const bytes = new Uint8Array(next() % 300).map(() => next())
    const whole = new SM3().update(bytes).hexDigest()
    const cut = next() % (bytes.length + 1)
    const parts = new SM3()
      .update(bytes.subarray(0, cut))
      .update(Array.from(bytes.subarray(cut)))
    good = good && parts.hexDigest() === whole
    good =
      good &&
      common.bytesToHex(common.hexToBytes(common.bytesToHex(bytes))) ===
        common.bytesToHex(bytes)
  }
  ok(`round trips over ${ROUNDS} random cases`, good)
}

// ---- key exchange ----
{
  const a = util.generateKeyPairHex()
  const b = util.generateKeyPairHex()
  let agree = true
  let shortCoordinates = 0
  for (let i = 0; i < 200; i++) {
    const ra = util.generateKeyPairHex()
    const rb = util.generateKeyPairHex()
    const B = sm2.getSb(
      16,
      a.publicKey,
      ra.publicKey,
      'a',
      'b',
      b.privateKey,
      b.publicKey,
      rb.privateKey,
      rb.publicKey,
    )
    const A = sm2.getSa(
      16,
      b.publicKey,
      rb.publicKey,
      a.publicKey,
      ra.publicKey,
      'a',
      'b',
      a.privateKey,
      ra.privateKey,
      B.Sb,
    )
    agree = agree && A.Ka === B.Kb && B.V.length === 128
    agree = agree && sm2.checkSa(B.V, B.Za, B.Zb, ra.publicKey, B.Rb, A.Sa)
    if (B.V[0] === '0' || B.V[64] === '0') shortCoordinates++
  }
  ok('key exchange always agrees', agree)
  ok('the test met coordinates with leading zeros', shortCoordinates > 0)

  const ra = util.generateKeyPairHex()
  const rb = util.generateKeyPairHex()
  const exchange = (len, pA = a.publicKey) =>
    sm2.getSb(
      len,
      pA,
      ra.publicKey,
      'a',
      'b',
      b.privateKey,
      b.publicKey,
      rb.privateKey,
      rb.publicKey,
    )
  const B = exchange(16)
  const A = sm2.getSa(
    16,
    b.publicKey,
    rb.publicKey,
    a.publicKey,
    ra.publicKey,
    'a',
    'b',
    a.privateKey,
    ra.privateKey,
    B.Sb,
  )
  for (const len of [0, -1, 1.5, NaN, '16', undefined, 1048577]) {
    throws(`key length ${len}`, () => exchange(len))
    throws(`key length ${len}: getSa`, () =>
      sm2.getSa(
        len,
        b.publicKey,
        rb.publicKey,
        a.publicKey,
        ra.publicKey,
        'a',
        'b',
        a.privateKey,
        ra.privateKey,
        B.Sb,
      ),
    )
  }
  ok('key length 1 MiB', exchange(1048576).Kb.length === 2097152)
  for (const bad of [
    '',
    '00',
    A.Sa.slice(0, 62),
    A.Sa + '00',
    'z'.repeat(64),
    null,
    undefined,
    5,
  ]) {
    ok(
      `checkSa rejects ${bad}`,
      sm2.checkSa(B.V, B.Za, B.Zb, ra.publicKey, B.Rb, bad) === false,
    )
    throws(`getSa rejects Sb ${bad}`, () =>
      sm2.getSa(
        16,
        b.publicKey,
        rb.publicKey,
        a.publicKey,
        ra.publicKey,
        'a',
        'b',
        a.privateKey,
        ra.privateKey,
        bad,
      ),
    )
  }
  ok(
    'checkSa: bad V',
    sm2.checkSa('00', B.Za, B.Zb, ra.publicKey, B.Rb, A.Sa) === false,
  )
  ok(
    'checkSa: bad Za',
    sm2.checkSa(B.V, 'zz', B.Zb, ra.publicKey, B.Rb, A.Sa) === false,
  )
  ok(
    'checkSa: bad Ra',
    sm2.checkSa(B.V, B.Za, B.Zb, '00', B.Rb, A.Sa) === false,
  )
  ok(
    'checkSa: bad Rb',
    sm2.checkSa(B.V, B.Za, B.Zb, ra.publicKey, null, A.Sa) === false,
  )
  ok(
    'checkSa: Rb is not a point',
    sm2.checkSa(B.V, B.Za, B.Zb, ra.publicKey, {}, A.Sa) === false,
  )
  throws('getSb: id too long', () =>
    sm2.getSb(
      16,
      a.publicKey,
      ra.publicKey,
      'x'.repeat(8192),
      'b',
      b.privateKey,
      b.publicKey,
      rb.privateKey,
      rb.publicKey,
    ),
  )
}

// ---- points ----
{
  const p = G.multiply(new BigInteger('abcdef', 16))
  const x = p.getX().toBigInteger()
  const y = p.getY().toBigInteger()
  const q = curve.q
  const xh = hexOf(BigInt('0x' + x.toString(16)))
  const yh = hexOf(BigInt('0x' + y.toString(16)))
  const raw = (a, b, z) =>
    new ECPointFp(curve, curve.fromBigInteger(a), curve.fromBigInteger(b), z)
  const nonCanonical = raw(x.add(q), y)
  const negative = raw(x.subtract(q), y)
  const offCurve = raw(x, y.add(BigInteger.ONE))
  const projective = raw(x, y, new BigInteger('2', 16))
  ok('x >= p is invalid', nonCanonical.isValid() === false)
  ok('negative x is invalid', negative.isValid() === false)
  ok('off-curve is invalid', offCurve.isValid() === false)
  for (const [name, bad] of [
    ['non-canonical', nonCanonical],
    ['negative', negative],
    ['off-curve', offCurve],
    ['projective', projective],
  ]) {
    throws(
      `${name}: multiply`,
      () => bad.multiply(new BigInteger('5', 16)),
      'Invalid point',
    )
    throws(`${name}: add left`, () => bad.add(p), 'Invalid point')
    throws(`${name}: add right`, () => p.add(bad), 'Invalid point')
    throws(`${name}: twice`, () => bad.twice(), 'Invalid point')
    throws(`${name}: timesPow2`, () => bad.timesPow2(2), 'Invalid point')
  }
  for (const tag of ['06', '07', '05', '00', '01']) {
    throws(`tag ${tag}`, () => curve.decodePointHex(tag + xh + yh))
  }
  throws('bare 64 bytes', () => curve.decodePointHex(xh + yh))
  throws('not a string', () => curve.decodePointHex(5))
  // Half of all x values have no point. Find one by Euler's criterion.
  for (let cx = 1n; ; cx++) {
    const rhs = (((cx * cx * cx - 3n * cx + B_COEFFICIENT) % P) + P) % P
    if (powerMod(rhs, (P - 1n) / 2n, P) === 1n) continue
    throws('compressed x with no point', () =>
      curve.decodePointHex('02' + hexOf(cx)),
    )
    break
  }
  throws('compressed x >= p', () => curve.decodePointHex('02' + hexOf(P)))
  throws('compress: off-curve', () =>
    util.compressPublicKeyHex('04' + 'a'.repeat(128)),
  )
  throws('compress: short', () => util.compressPublicKeyHex('04ab'))
  ok(
    'compress: compressed key round trip',
    util.comparePublicKeyHex(
      util.compressPublicKeyHex('04' + xh + yh),
      '04' + xh + yh,
    ),
  )
  throws('infinity getX', () => curve.getInfinity().getX())
  throws('infinity getY', () => curve.getInfinity().getY())
  ok('infinity negate', curve.getInfinity().negate().isInfinity())
  throws('z = 0 getX', () => raw(x, y, BigInteger.ZERO).getX())
  throws('timesPow2 huge', () => p.timesPow2(1e12))
  throws('timesPow2 fractional', () => p.timesPow2(1.5))
  throws(
    'multiply: scalar too large',
    () => p.multiply(new BigInteger('1' + '0'.repeat(64), 16)),
    'k is too large',
  )
  throws('field divide by zero', () =>
    curve.fromBigInteger(x).divide(curve.fromBigInteger(BigInteger.ZERO)),
  )
  ok(
    'field divide by a negative value is reduced first',
    curve
      .fromBigInteger(x)
      .divide(curve.fromBigInteger(new BigInteger('-1', 16)))
      .toBigInteger()
      .equals(q.subtract(x)),
  )

  // A curve whose bit length made the original's comb width fractional: compare with a reference.
  const P192 = 0xfffffffffffffffffffffffffffffffeffffffffffffffffn
  const B192 = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1n
  const pow = powerMod
  const refAdd = (u, v) => {
    if (u === null) return v
    const l =
      u[0] === v[0]
        ? ((3n * u[0] * u[0] - 3n) % P192) * pow(2n * u[1], P192 - 2n, P192)
        : (v[1] - u[1]) * pow(v[0] - u[0], P192 - 2n, P192)
    const lam = ((l % P192) + P192) % P192
    const rx = (((lam * lam - u[0] - v[0]) % P192) + P192) % P192
    return [rx, (((lam * (u[0] - rx) - u[1]) % P192) + P192) % P192]
  }
  const G192 = [
    0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012n,
    0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811n,
  ]
  const big = (v) => new BigInteger(v.toString(16), 16)
  const c192 = new ECCurveFp(big(P192), big(P192 - 3n), big(B192))
  const g192 = c192.decodePointHex(
    '04' +
      G192[0].toString(16).padStart(48, '0') +
      G192[1].toString(16).padStart(48, '0'),
  )
  for (const k of [1n, 2n, 3n, 0xabcdef0123456789n, (1n << 180n) + 12345n]) {
    let r = null
    let a = G192
    for (let e = k; e > 0n; e >>= 1n) {
      if (e & 1n) r = refAdd(r, a)
      a = refAdd(a, a)
    }
    const got = g192.multiply(big(k))
    ok(
      `generic curve multiply ${k}`,
      got.getX().toBigInteger().toString(16) === r[0].toString(16) &&
        got.getY().toBigInteger().toString(16) === r[1].toString(16),
    )
  }
}

// ---- BigInteger ----
{
  const b16 = (s) => new BigInteger(s, 16)
  throws('undefined', () => new BigInteger(undefined))
  throws('no argument', () => new BigInteger())
  for (const s of [
    '',
    '-',
    'xyz',
    'a b',
    'a-b',
    '1z',
    '0x10',
    ' 1',
    '--1',
    '\u0661',
  ]) {
    throws(`junk ${JSON.stringify(s)}`, () => new BigInteger(s, 16))
  }
  throws('digit outside radix', () => new BigInteger('9', 8))
  for (const r of [1, 0, -1, 37, 1.5, NaN]) {
    throws(`radix ${r}`, () => new BigInteger('1', r))
    throws(`output radix ${r}`, () => b16('5').toRadix(r))
  }
  throws('object value', () => new BigInteger({}))
  throws('huge bit count', () => new BigInteger(1e12, new SecureRandom()))
  throws('negative bit count', () => new BigInteger(-1, new SecureRandom()))
  throws('fractional bit count', () => new BigInteger(1.5, new SecureRandom()))
  throws('huge string', () => new BigInteger('1'.repeat(1 << 20), 16))
  const bigModulus = new BigInteger('1'.repeat(4000), 16)
  throws('modPow modulus above the cost limit', () =>
    b16('3').modPow(b16('3'), bigModulus),
  )
  throws('modPow exponent above the cost limit', () =>
    b16('3').modPow(bigModulus, b16('b')),
  )
  throws(
    'prime search above the cost limit',
    () => new BigInteger(1 << 13, 1, new SecureRandom()),
  )
  throws('ZERO is immutable', () => BigInteger.ZERO.dAddOffset(1, 0))
  throws('ONE is immutable', () => BigInteger.ONE.fromInt(5))
  const seven = b16('7')
  const zero = BigInteger.ZERO
  ok('modInverse(0) does not hang', zero.modInverse(b16('b')).equals(zero))
  ok(
    'modInverse of a multiple of m',
    b16('b').modInverse(b16('b')).equals(zero),
  )
  ok(
    'modInverse of a negative value',
    b16('-3').modInverse(b16('7')).equals(b16('2')),
  )
  ok('modInverse above m', b16('a').modInverse(b16('7')).equals(b16('5')))
  throws('modInverse mod 0', () => seven.modInverse(zero))
  throws('modInverse mod negative', () => seven.modInverse(b16('-7')))
  throws('modPow mod 0', () => seven.modPow(seven, zero))
  throws('modPow mod negative', () => seven.modPow(seven, b16('-7')))
  throws('modPow negative exponent', () => seven.modPow(b16('-1'), b16('b')))
  throws('modPowInt mod 0', () => seven.modPowInt(3, zero))
  throws('divide by zero', () => seven.divide(zero))
  throws('mod zero', () => seven.mod(zero))
  throws('remainder by zero', () => seven.remainder(zero))
  throws('huge shift', () => seven.shiftLeft(1e12))
  throws('huge setBit', () => seven.setBit(1e12))
  throws('NaN shift', () => seven.shiftLeft(NaN))
  throws('huge pow', () => seven.pow(0xffffffff))
  throws('huge square chain', () => {
    let x = b16('f'.repeat(1000))
    for (let i = 0; i < 40; i++) x = x.square()
  })
  throws('dAddOffset huge', () => b16('1').dAddOffset(1, 1e15))
  throws('dlShiftTo huge', () => b16('1').dlShiftTo(1e15, BigInteger.nbi()))
  throws('fromInt huge', () => BigInteger.nbv(1e300))
  throws('fromInt fraction', () => BigInteger.nbv(1.5))
  throws('am huge', () => seven.am(0, 1, [], 0, 0, 1e15))
  throws('multiplyUpperTo huge', () =>
    seven.multiplyUpperTo(seven, -1e15, BigInteger.nbi()),
  )
  ok('toRadix of a negative value', b16('-ff').toRadix(10) === '-255')
}

// ---- SM3 ----
{
  const h = () => new SM3()
  for (const [name, value] of [
    ['string', 'abc'],
    ['null', null],
    ['undefined', undefined],
    ['object', {}],
    ['Uint16Array', new Uint16Array(2)],
    ['Float64Array', new Float64Array(2)],
    ['fraction', 1.5],
    ['too large', 256],
    ['too small', -129],
    ['NaN', NaN],
    ['array with large', [300]],
    ['array with hole', new Array(1)],
    ['array with string', ['1']],
  ]) {
    throws(`sm3 update ${name}`, () => h().update(value))
  }
  throws('sm3 updateBytes past the end', () => h().updateBytes([1, 2], 0, 5))
  throws('sm3 updateBytes negative offset', () =>
    h().updateBytes([1, 2], -1, 1),
  )
  throws('sm3 updateBytes negative length', () =>
    h().updateBytes([1, 2], 0, -1),
  )
  throws('sm3 updateBytes fractional', () => h().updateBytes([1, 2], 0.5, 1))
  throws('sm3 updateString non-string', () => h().updateString(5))
  throws('sm3 lone surrogate', () => h().updateString('\ud800'))
  throws('sm3 hash lone surrogate', () => SM3.hash('\udfff'))
  const used = h().update([1])
  const d = used.digest()
  throws('sm3 update after digest', () => used.update([2]))
  throws('sm3 updateBytes after digest', () => used.updateBytes([2], 0, 1))
  ok(
    'sm3 digest stays stable',
    common.bytesToHex(used.digest()) === common.bytesToHex(d),
  )
  const shared = h().update([1]).finish()
  const code = shared.getHashCode()
  shared.getHashBytes()[0] ^= 1
  ok(
    'sm3 getHashCode ignores changes to the returned bytes',
    shared.getHashCode() === code,
  )
  const big = h()
  big._len = Number.MAX_SAFE_INTEGER
  throws('sm3 past the tracked length', () => big.update([1]))
  ok(
    'sm3 update(Int8Array)',
    common.bytesToHex(
      h()
        .update(new Int8Array([-1]))
        .digest(),
    ) === common.bytesToHex(h().update([255]).digest()),
  )

  if (process.env.SMX_SKIP_SLOW !== '1') {
    const chunk = new Uint8Array(1 << 24)
    for (const [mib, want] of [
      [512, vectors.sm3.zeros_512_mib],
      [1024, vectors.sm3.zeros_1024_mib],
    ]) {
      const stream = h()
      for (let i = 0; i < mib / 16; i++) stream.update(chunk)
      ok(`sm3 ${mib} MiB of zeros`, common.bytesToHex(stream.digest()) === want)
    }
    const one = new Uint8Array(1 << 29)
    ok(
      'sm3 512 MiB in one call',
      common.bytesToHex(h().update(one).digest()) === vectors.sm3.zeros_512_mib,
    )
  }
}

// ---- utilities ----
{
  for (const s of [
    'a',
    'abc',
    'zz',
    '1z',
    ' 1',
    '+1',
    '-1',
    '0x',
    '国密',
    '\u0661\u0661',
  ]) {
    throws(
      `hexToBytes ${JSON.stringify(s)}`,
      () => common.hexToBytes(s),
      'Invalid hex string',
    )
    throws(
      `hexToArray ${JSON.stringify(s)}`,
      () => util.hexToArray(s),
      'Invalid hex string',
    )
  }
  throws('hexToBytes non-string', () => common.hexToBytes(5))
  throws('stringToBytes non-string', () =>
    common.stringToBytes(new Uint8Array(1)),
  )
  throws('stringToBytes undefined', () => common.stringToBytes(undefined))
  throws('stringToBytes lone surrogate', () => common.stringToBytes('a\ud800b'))
  ok('stringToBytes pair', common.stringToBytes('🚀').length === 4)
  throws('bytesToHex out of range', () => common.bytesToHex([256]))
  throws('bytesToHex fraction', () => common.bytesToHex([1.5]))
  throws('bytesToHex non-bytes', () => common.bytesToHex('abc'))
  throws('arrayToHex typed non-bytes', () =>
    util.arrayToHex(new Uint16Array(1)),
  )
  throws('bytesToString non-bytes', () => common.bytesToString('abc'))
  ok('hex of a typed array', util.arrayToHex(new Uint8Array([10])) === '0a')
  ok(
    'BOM survives',
    common.bytesToString(common.stringToBytes('\ufeffa')) === '\ufeffa',
  )
  const all = new Uint8Array(256).map((_, i) => i)
  ok(
    'hex round trip',
    common.bytesToHex(common.hexToBytes(common.bytesToHex(all))) ===
      common.bytesToHex(all),
  )
}

console.log(`security: ${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
