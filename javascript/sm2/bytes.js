/**
 * Conversions between BigInteger and fixed 32-byte big-endian arrays.
 *
 * Internal module, not part of the public API.
 */
import { BigInteger } from './biginteger.js'

const DB = 28
const DV = 1 << DB

/** Writes a non-negative BigInteger below 2^256 as 32 big-endian bytes. */
export function bigToBytes(x, out) {
  let acc = 0
  let bits = 0
  let digit = 0
  for (let i = 31; i >= 0; i--) {
    if (bits < 8 && digit < x.t) {
      acc += x[digit++] * 2 ** bits
      bits += DB
    }
    out[i] = acc
    acc = Math.floor(acc / 256)
    bits -= 8
  }
  return out
}

/** Reads 32 big-endian bytes as a non-negative BigInteger. */
export function bytesToBig(b) {
  const r = new BigInteger(null)
  let acc = 0
  let bits = 0
  let t = 0
  for (let i = 31; i >= 0; i--) {
    acc += b[i] * 2 ** bits
    bits += 8
    if (bits >= DB) {
      const low = acc % DV
      r[t++] = low
      acc = (acc - low) / DV
      bits -= DB
    }
  }
  r[t++] = acc
  r.t = t
  r.s = 0
  r.clamp()
  return r
}
