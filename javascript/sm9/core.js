/**
 * SM9 operations behind the public API in sm9.js: input parsing, the master key
 * cache and one attempt of each algorithm. Internal module, not part of the
 * public API; see sm9.js for the conventions and the security notes.
 */
import {
  decodeHex,
  decodeLowerHex,
  encodeHex,
  toByteArray,
} from '../common/hex.js'
import * as util from '../common/utils.js'
import { SM4 } from '../sm4/sm4.js'
import { wipeFpScratch } from './fp.js'
import { wipeFp2Scratch } from './fp2.js'
import { Fp12, fp12Mul, gtToBytes, wipeFp12Scratch } from './fp12.js'
import {
  G1_BYTES,
  G2_BYTES,
  P1,
  P2,
  g1Add,
  g1Decode,
  g1Encode,
  g1MulBase,
  g1MulSecret,
  g1XY,
  g2Add,
  g2Decode,
  g2Encode,
  g2MulBase,
  wipeGroupScratch,
} from './groups.js'
import { anyNonZeroMask, equalBytes, h1, h2, kdf, sm3Parts } from './hash.js'
import {
  gtMakeComb,
  gtPow,
  gtPowComb,
  pairing,
  wipePairingScratch,
} from './pairing.js'
import {
  SCALAR_BYTES,
  randomScalar,
  scalarAdd,
  scalarDiv,
  scalarSub,
  scalarValidMask,
} from './scalar.js'

export const SM9_HID_SIGN = 1
export const SM9_HID_EXCHANGE = 2
export const SM9_HID_ENCRYPT = 3
export const SM9_MODE_STREAM = 'stream'
export const SM9_MODE_SM4 = 'sm4'

const SCALAR_HEX = 2 * SCALAR_BYTES
const SIGNATURE_BYTES = SCALAR_BYTES + G1_BYTES
const MAC_BYTES = 32
const SM4_KEY_BYTES = 16
const SM4_BLOCK = 16
const MAX_KEY_BYTES = 1 << 20
/** Retries on values that a working RNG hits with negligible probability. */
const MAX_ATTEMPTS = 64
const DECRYPT_ERROR = 'SM9 decryption failed'
export const DECAPSULATE_ERROR = 'SM9 decapsulation failed'
const CONFIRM_B = 0x82
const CONFIRM_A = 0x83

// ---- input parsing ----

export function parseScalar(hex, what) {
  const bytes =
    typeof hex === 'string' && hex.length === SCALAR_HEX ? decodeHex(hex) : null
  if (bytes === null || scalarValidMask(bytes) === 0) {
    if (bytes !== null) bytes.fill(0)
    throw new Error(`Invalid SM9 ${what}`)
  }
  return bytes
}

function parsePoint(hex, length, decode, what, lowercase = false) {
  const bytes =
    typeof hex === 'string' && hex.length === 2 * length
      ? (lowercase ? decodeLowerHex : decodeHex)(hex)
      : null
  const point = bytes === null ? null : decode(bytes)
  if (bytes !== null) bytes.fill(0)
  if (point === null) throw new Error(`Invalid SM9 ${what}`)
  return point
}

export const parseG1 = (hex, what, lowercase) =>
  parsePoint(hex, G1_BYTES, g1Decode, what, lowercase)
export const parseG2 = (hex, what) => parsePoint(hex, G2_BYTES, g2Decode, what)

/** Identity → new byte array. Strings are UTF-8. */
export function idBytes(id) {
  return typeof id === 'string'
    ? util.stringToBytes(id)
    : Uint8Array.from(toByteArray(id))
}

/** Message → new byte array. Strings are UTF-8. */
export const messageBytes = idBytes

export function requireHid(hid) {
  if (!Number.isInteger(hid) || hid < 0 || hid > 255) {
    throw new RangeError('hid must be an integer from 0 to 255')
  }
  return hid
}

export function requireKeyLength(len) {
  if (!Number.isInteger(len) || len < 1 || len > MAX_KEY_BYTES) {
    throw new RangeError('Key length must be from 1 to 1048576 bytes')
  }
  return len
}

export function requireMode(mode) {
  if (mode !== SM9_MODE_STREAM && mode !== SM9_MODE_SM4) {
    throw new TypeError("Mode must be 'stream' or 'sm4'")
  }
  return mode
}

/** Best-effort erasure of every module-level buffer that held secret values. */
export function wipeScratch() {
  wipeFpScratch()
  wipeFp2Scratch()
  wipeFp12Scratch()
  wipePairingScratch()
  wipeGroupScratch()
}

// ---- master public keys: validated point and its pairing, cached ----

const CACHE_LIMIT = 16
const masterCache = new Map()

/**
 * Decoded master public key and g = e(P1, Ppub-s) (signing) or e(Ppub-e, P2)
 * (encryption). Both are public, so they are kept for the next call.
 */
export function masterKey(hex, sign) {
  const what = sign
    ? 'signing master public key'
    : 'encryption master public key'
  const length = sign ? G2_BYTES : G1_BYTES
  const bytes =
    typeof hex === 'string' && hex.length === 2 * length ? decodeHex(hex) : null
  if (bytes === null) throw new Error(`Invalid SM9 ${what}`)
  const key = (sign ? 's' : 'e') + encodeHex(bytes)
  const hit = masterCache.get(key)
  if (hit !== undefined) return hit
  const point = sign ? g2Decode(bytes) : g1Decode(bytes)
  if (point === null) throw new Error(`Invalid SM9 ${what}`)
  const g = new Fp12()
  if (sign) pairing(g, P1.x, P1.y, point.x, point.y)
  else pairing(g, point.x, point.y, P2.x, P2.y)
  const entry = { point, g, comb: gtMakeComb(g) }
  if (masterCache.size >= CACHE_LIMIT) {
    masterCache.delete(masterCache.keys().next().value)
  }
  masterCache.set(key, entry)
  return entry
}

/** g^r as its 384-byte encoding, r secret; g a master entry or an Fp12. */
function gtPowBytes(g, r) {
  const w = new Fp12()
  if (g instanceof Fp12) gtPow(w, g, r)
  else gtPowComb(w, g.comb, r, true)
  const out = gtToBytes(w)
  w.v.fill(0)
  return out
}

/** e(P, Q) as an Fp12. */
export function pair(P, Q) {
  const out = new Fp12()
  pairing(out, P.x, P.y, Q.x, Q.y)
  return out
}

/** Q = [H1(ID || hid)] P1 + Ppub-e, or an error if it is the identity. */
export function encryptionPoint(id, hid, ppub) {
  const Q = g1Add(g1MulBase(h1(id, hid), false), ppub)
  if (Q === null) throw new Error('SM9 identity has no valid key')
  return Q
}

// ---- key generation ----

export function userKey(masterHex, id, hid, sign) {
  const ks = parseScalar(masterHex, 'master private key')
  try {
    const t1 = scalarAdd(h1(idBytes(id), requireHid(hid)), ks)
    if (t1.zero) throw new Error('SM9 user key cannot be generated for this ID')
    const t2 = scalarDiv(ks, t1.value)
    t1.value.fill(0)
    const key = sign ? g1MulBase(t2, true) : g2MulBase(t2, true)
    t2.fill(0)
    return encodeHex(sign ? g1Encode(key) : g2Encode(key))
  } finally {
    ks.fill(0)
    wipeScratch()
  }
}

export function masterPublic(ks, sign) {
  try {
    return encodeHex(
      sign ? g2Encode(g2MulBase(ks, true)) : g1Encode(g1MulBase(ks, true)),
    )
  } finally {
    wipeScratch()
  }
}

export function generateMaster(sign) {
  const ks = randomScalar()
  try {
    return { privateKey: encodeHex(ks), publicKey: masterPublic(ks, sign) }
  } finally {
    ks.fill(0)
  }
}

// ---- signatures ----

/** One signing attempt with a given r; null when l = 0. */
export function signOnce(message, ds, master, r) {
  const w = gtPowBytes(master, r)
  const h = h2(message, w)
  const l = scalarSub(r, h)
  if (l.zero) return null
  const S = g1MulSecret(ds, l.value)
  l.value.fill(0)
  const out = new Uint8Array(SIGNATURE_BYTES)
  out.set(h)
  out.set(g1Encode(S), SCALAR_BYTES)
  return encodeHex(out)
}

export function verifySignature(message, signature, id, masterHex, hid) {
  if (
    typeof signature !== 'string' ||
    signature.length !== 2 * SIGNATURE_BYTES
  ) {
    return false
  }
  const sig = decodeLowerHex(signature)
  if (sig === null) return false
  const h = sig.subarray(0, SCALAR_BYTES)
  if (scalarValidMask(h) === 0) return false
  const S = g1Decode(sig.subarray(SCALAR_BYTES))
  if (S === null) return false
  const master = masterKey(masterHex, true)
  const msg = messageBytes(message)
  const P = g2Add(
    g2MulBase(h1(idBytes(id), requireHid(hid)), false),
    master.point,
  )
  if (P === null) return false
  const t = new Fp12()
  gtPowComb(t, master.comb, h, false)
  const u = pair(S, P)
  fp12Mul(u, u, t)
  return equalBytes(h2(msg, gtToBytes(u)), h)
}

// ---- encryption ----

function sm4Ecb(key, data, decrypt) {
  const sm4 = new SM4()
  sm4._expandKey(key)
  sm4._keyed = true
  const out = new Uint8Array(data.length)
  for (let o = 0; o < data.length; o += SM4_BLOCK) {
    sm4._processBlock(data, o, out, o, decrypt)
  }
  sm4._rk.fill(0)
  return out
}

function pkcs7Pad(data) {
  const pad = SM4_BLOCK - (data.length % SM4_BLOCK)
  const out = new Uint8Array(data.length + pad)
  out.set(data)
  out.fill(pad, data.length)
  return out
}

/** -1 if the PKCS#7 padding of data (a nonzero multiple of 16 bytes) is bad. */
function pkcs7BadMask(data) {
  const n = data.length
  const pad = data[n - 1]
  let bad = (pad - 1) | (SM4_BLOCK - pad)
  for (let i = 1; i <= SM4_BLOCK; i++) {
    const inPadding = (i - pad - 1) >> 31
    bad |= inPadding & -(data[n - i] ^ pad)
  }
  return bad >> 31
}

/** KDF output split as K1 (cipher key or stream) and K2 (MAC key). */
function encryptionKeys(c1xy, w, id, k1Length) {
  const k = kdf([c1xy, w, id], k1Length + MAC_BYTES)
  return { k, k1: k.subarray(0, k1Length), k2: k.subarray(k1Length) }
}

/** One encryption attempt with a given r; null when K1 is all zero. */
export function encryptOnce(data, id, master, Q, r, mode) {
  const C1 = g1MulSecret(Q, r)
  const w = gtPowBytes(master, r)
  const c1xy = g1XY(C1)
  const sm4 = mode === SM9_MODE_SM4
  const { k, k1, k2 } = encryptionKeys(
    c1xy,
    w,
    id,
    sm4 ? SM4_KEY_BYTES : data.length,
  )
  w.fill(0)
  try {
    if (anyNonZeroMask(k1) === 0) return null
    let c2
    if (sm4) {
      const padded = pkcs7Pad(data)
      c2 = sm4Ecb(k1, padded, false)
      padded.fill(0)
    } else {
      c2 = new Uint8Array(data.length)
      for (let i = 0; i < data.length; i++) c2[i] = data[i] ^ k1[i]
    }
    const c3 = sm3Parts([c2, k2])
    return encodeHex(g1Encode(C1)) + encodeHex(c3) + encodeHex(c2)
  } finally {
    k.fill(0)
  }
}

export function decryptBytes(ciphertext, id, userKeyHex, mode) {
  requireMode(mode)
  const idb = idBytes(id)
  const sm4 = mode === SM9_MODE_SM4
  const head = G1_BYTES + MAC_BYTES
  const bytes = decodeLowerHex(ciphertext)
  if (
    bytes === null ||
    bytes.length <= head ||
    (sm4 && (bytes.length - head) % SM4_BLOCK !== 0)
  ) {
    throw new Error(DECRYPT_ERROR)
  }
  const C1 = g1Decode(bytes.subarray(0, G1_BYTES))
  if (C1 === null) throw new Error(DECRYPT_ERROR)
  const de = parseG2(userKeyHex, 'user private key')
  const c3 = bytes.subarray(G1_BYTES, head)
  const c2 = bytes.subarray(head)
  const w = pair(C1, de)
  de.x.v.fill(0)
  de.y.v.fill(0)
  const wb = gtToBytes(w)
  w.v.fill(0)
  const { k, k1, k2 } = encryptionKeys(
    g1XY(C1),
    wb,
    idb,
    sm4 ? SM4_KEY_BYTES : c2.length,
  )
  wb.fill(0)
  try {
    const usable = anyNonZeroMask(k1) !== 0
    const valid = equalBytes(sm3Parts([c2, k2]), c3)
    if (!usable || !valid) throw new Error(DECRYPT_ERROR)
    if (!sm4) {
      const out = new Uint8Array(c2.length)
      for (let i = 0; i < c2.length; i++) out[i] = c2[i] ^ k1[i]
      return out
    }
    const padded = sm4Ecb(k1, c2, true)
    const bad = pkcs7BadMask(padded)
    const removed = (padded[padded.length - 1] & ~bad) | (SM4_BLOCK & bad)
    const out = padded.slice(0, padded.length - removed)
    padded.fill(0)
    if (bad !== 0) {
      out.fill(0)
      throw new Error(DECRYPT_ERROR)
    }
    return out
  } finally {
    k.fill(0)
    wipeScratch()
  }
}

// ---- key encapsulation ----

export function encapsulateOnce(id, master, Q, keyLength, r) {
  const C = g1MulSecret(Q, r)
  const w = gtPowBytes(master, r)
  const key = kdf([g1XY(C), w, id], keyLength)
  w.fill(0)
  if (anyNonZeroMask(key) === 0) return null
  const result = { key: encodeHex(key), ciphertext: encodeHex(g1Encode(C)) }
  key.fill(0)
  return result
}

// ---- key exchange ----

function exchangeValues(idA, idB, RA, RB, g1, g2, g3, keyLength) {
  const raxy = g1XY(RA)
  const rbxy = g1XY(RB)
  const key = kdf([idA, idB, raxy, rbxy, g1, g2, g3], keyLength)
  const inner = sm3Parts([g2, g3, idA, idB, raxy, rbxy])
  const sB = sm3Parts([Uint8Array.of(CONFIRM_B), g1, inner])
  const sA = sm3Parts([Uint8Array.of(CONFIRM_A), g1, inner])
  inner.fill(0)
  return { key, sB, sA }
}

export function failure(e, fields) {
  const message = e instanceof Error ? e.message : 'SM9 key exchange failed'
  return { success: false, message, sharedKey: null, ...fields }
}

/** Constant-time comparison of two 64-digit lowercase hex strings. */
export function equalConfirmation(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  if (a.length !== SCALAR_HEX || b.length !== SCALAR_HEX) return false
  const x = decodeLowerHex(a)
  const y = decodeLowerHex(b)
  return x !== null && y !== null && equalBytes(x, y)
}

export function exchangeRespond(
  keyLength,
  idA,
  idB,
  masterHex,
  deHex,
  rHex,
  RBHex,
  RAHex,
) {
  requireKeyLength(keyLength)
  const ida = idBytes(idA)
  const idb = idBytes(idB)
  const master = masterKey(masterHex, false)
  const RA = parseG1(RAHex, 'R_A')
  const RB = parseG1(RBHex, 'R_B')
  const de = parseG2(deHex, 'user private key')
  const r = parseScalar(rHex, 'random r')
  try {
    const e1 = pair(RA, de)
    const g1 = gtToBytes(e1)
    const g2 = gtPowBytes(master, r)
    const g3 = gtPowBytes(e1, r)
    e1.v.fill(0)
    const v = exchangeValues(ida, idb, RA, RB, g1, g2, g3, keyLength)
    for (const b of [g1, g2, g3]) b.fill(0)
    const result = {
      success: true,
      message: '',
      sharedKey: encodeHex(v.key),
      sB: encodeHex(v.sB),
      s2: encodeHex(v.sA),
    }
    v.key.fill(0)
    return result
  } finally {
    r.fill(0)
    de.x.v.fill(0)
    de.y.v.fill(0)
    wipeScratch()
  }
}

export function exchangeConfirm(
  keyLength,
  idA,
  idB,
  masterHex,
  deHex,
  rHex,
  RAHex,
  RBHex,
  sB,
) {
  requireKeyLength(keyLength)
  const ida = idBytes(idA)
  const idb = idBytes(idB)
  const master = masterKey(masterHex, false)
  const RA = parseG1(RAHex, 'R_A')
  const RB = parseG1(RBHex, 'R_B')
  const de = parseG2(deHex, 'user private key')
  const r = parseScalar(rHex, 'random r')
  try {
    const g1 = gtPowBytes(master, r)
    const e2 = pair(RB, de)
    const g2 = gtToBytes(e2)
    const g3 = gtPowBytes(e2, r)
    e2.v.fill(0)
    const v = exchangeValues(ida, idb, RA, RB, g1, g2, g3, keyLength)
    for (const b of [g1, g2, g3]) b.fill(0)
    if (!equalConfirmation(sB, encodeHex(v.sB))) {
      v.key.fill(0)
      throw new Error('SM9 key exchange confirmation failed')
    }
    const result = {
      success: true,
      message: '',
      sharedKey: encodeHex(v.key),
      sA: encodeHex(v.sA),
    }
    v.key.fill(0)
    return result
  } finally {
    r.fill(0)
    de.x.v.fill(0)
    de.y.v.fill(0)
    wipeScratch()
  }
}

export function exchangeInit(peerId, masterHex, hid, r) {
  const master = masterKey(masterHex, false)
  const Q = encryptionPoint(idBytes(peerId), requireHid(hid), master.point)
  try {
    return { r: encodeHex(r), R: encodeHex(g1Encode(g1MulSecret(Q, r))) }
  } finally {
    wipeScratch()
  }
}

/** Retries op with fresh random scalars until it returns non-null. */
export function withRandomScalar(op, error) {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const r = randomScalar()
    try {
      const out = op(r)
      if (out !== null) return out
    } finally {
      r.fill(0)
    }
  }
  throw new Error(error)
}

/** Decapsulation: C must be a valid G1 point, an all-zero key is an error. */
export function decapsulate(ciphertext, userId, userPrivateKey, keyLength) {
  requireKeyLength(keyLength)
  const idb = idBytes(userId)
  let C
  try {
    C = parseG1(ciphertext, 'ciphertext', true)
  } catch {
    throw new Error(DECAPSULATE_ERROR)
  }
  const de = parseG2(userPrivateKey, 'user private key')
  try {
    const w = pair(C, de)
    const wb = gtToBytes(w)
    w.v.fill(0)
    const key = kdf([g1XY(C), wb, idb], keyLength)
    wb.fill(0)
    if (anyNonZeroMask(key) === 0) throw new Error(DECAPSULATE_ERROR)
    const out = encodeHex(key)
    key.fill(0)
    return out
  } finally {
    de.x.v.fill(0)
    de.y.v.fill(0)
    wipeScratch()
  }
}
