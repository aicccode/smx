/**
 * SM9 hash functions H1/H2, the KDF and the MAC, on top of SM3. Internal module,
 * not part of the public API.
 */
import { SM3 } from '../sm3/sm3.js'
import { SCALAR_BYTES } from './scalar.js'

const N_MINUS_1 =
  0xb640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf24n
const HASH_BYTES = 40 // hlen = 8 * ceil(5 * 256 / 32) bits
const MAX_KDF_BYTES = 0xffffffff * 32

function counterBytes(out, ct) {
  out[0] = ct >>> 24
  out[1] = ct >>> 16
  out[2] = ct >>> 8
  out[3] = ct
}

/**
 * H(tag, Z) = (Ha mod (N - 1)) + 1, Ha the first 40 bytes of
 * SM3(tag || Z || 00000001) || SM3(tag || Z || 00000002). The parts are byte
 * arrays hashed in order as Z. The result is public in every use (it hashes an
 * identity, or a message with the signature's w), so native BigInt is used.
 * @returns {Uint8Array} 32 bytes in [1, N - 1]
 */
function hashToRange(tag, parts) {
  const prefix = new SM3().update(tag)
  for (const p of parts) prefix.update(p)
  const counter = new Uint8Array(4)
  let hex = ''
  for (let ct = 1; ct <= 2; ct++) {
    counterBytes(counter, ct)
    const block = new SM3()._copyStateFrom(prefix).update(counter).digest()
    const take = ct === 1 ? 32 : HASH_BYTES - 32
    for (let i = 0; i < take; i++) hex += block[i].toString(16).padStart(2, '0')
  }
  prefix._wipe()
  const h = (BigInt('0x' + hex) % N_MINUS_1) + 1n
  const out = new Uint8Array(SCALAR_BYTES)
  let v = h
  for (let i = SCALAR_BYTES - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/** H1(ID || hid) */
export function h1(id, hid) {
  return hashToRange(1, [id, Uint8Array.of(hid)])
}

/** H2(M || w), w the 384-byte GT encoding */
export function h2(message, w) {
  return hashToRange(2, [message, w])
}

/**
 * KDF(Z, klen) with Z the concatenation of parts: SM3(Z || ct) for ct = 1, 2, ...
 * truncated to klen bytes. Z is hashed once and its state reused.
 * @returns {Uint8Array}
 */
export function kdf(parts, klen) {
  if (klen > MAX_KDF_BYTES) throw new RangeError('KDF output is too long')
  const prefix = new SM3()
  for (const p of parts) prefix.update(p)
  const out = new Uint8Array(klen)
  const counter = new Uint8Array(4)
  const sm3 = new SM3()
  for (let offset = 0, ct = 1; offset < klen; ct++) {
    counterBytes(counter, ct)
    const block = sm3._copyStateFrom(prefix).update(counter).digest()
    const end = Math.min(32, klen - offset)
    for (let i = 0; i < end; i++) out[offset + i] = block[i]
    block.fill(0)
    offset += end
  }
  sm3._wipe()
  prefix._wipe()
  return out
}

/** SM3 of the concatenation of parts. */
export function sm3Parts(parts) {
  const h = new SM3()
  for (const p of parts) h.update(p)
  const out = h.digest()
  h._wipe()
  return out
}

/** -1 when any byte is nonzero, else 0. Constant-flow. */
export function anyNonZeroMask(bytes, start = 0, end = bytes.length) {
  let acc = 0
  for (let i = start; i < end; i++) acc |= bytes[i]
  return ~((acc - 1) >> 31)
}

/** Equal-length byte arrays compared in time independent of their contents. */
export function equalBytes(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}
