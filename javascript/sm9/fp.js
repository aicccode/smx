/**
 * Arithmetic modulo the SM9 prime q (and the limb helpers shared with the
 * scalar code modulo N).
 *
 * Internal module, not part of the public API.
 *
 * Representation: Float64Array(11) of balanced base-2^24 limbs, Montgomery form
 * with R = 2^264, as in sm2/fe.js. Measured on V8 (Node 22), the unrolled
 * multiplier is about 2.6x faster than a BigInt multiply-and-mod and does not
 * allocate.
 *
 * Invariant: every value stored by these functions is "reduced": limbs carried to
 * |limb| <= 2^23 (the top limb holds the rest) and |value| a small multiple of q
 * (far below 2^263). Every function here takes reduced inputs and writes a reduced
 * output, so callers never track bounds. Inside fpMul a column is at most
 * 11 * k1 * k2 * 2^46 plus the reduction terms, where k1 and k2 bound how many
 * reduced values were summed into each operand; the code in this directory passes
 * at most k1 * k2 = 6 (the limit is 10). Multiply and square return
 * |value| < 0.6 q.
 *
 * Timing: no data-dependent branches or memory accesses, except functions
 * documented as public-data only. JavaScript gives no formal constant-time
 * guarantee: the JIT, the GC and the CPU are outside our control.
 */
import { fpMul, fpSqr } from './fp-mul.js'

export { fpMul, fpSqr }

export const LIMBS = 11
const BASE = 16777216
const INV = 1 / 16777216

/** Big-endian 64-hex-digit constant to 32 bytes. */
export function hexBytes(hex) {
  const out = new Uint8Array(hex.length >>> 1)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(2 * i, 2 * i + 2), 16)
  }
  return out
}

export const Q_BYTES = hexBytes(
  'b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d',
)

/** Big-endian 32 bytes to unsigned limbs: each limb is exactly three bytes. */
export function limbsFromBytes(r, b, offset = 0) {
  for (let i = 0; i < 10; i++) {
    const o = offset + 31 - 3 * i
    r[i] = b[o] | (b[o - 1] << 8) | (b[o - 2] << 16)
  }
  r[10] = b[offset + 1] | (b[offset] << 8)
}

export function feNew() {
  return new Float64Array(LIMBS)
}

export function feCopy(r, a) {
  for (let i = 0; i < LIMBS; i++) r[i] = a[i]
}

/** r = mask ? b : a, where mask is 0 or -1. Limbs of reduced values fit in 32 bits. */
export function feSelect(r, a, b, mask) {
  const inverse = ~mask
  for (let i = 0; i < LIMBS; i++) r[i] = (a[i] & inverse) | (b[i] & mask)
}

/** Carries the limbs without changing the value. Works for either modulus. */
export function feCarry(r, a) {
  let carry = 0
  for (let i = 0; i < LIMBS - 1; i++) {
    const x = a[i] + carry
    carry = Math.floor(x * INV + 0.5)
    r[i] = x - carry * BASE
  }
  r[LIMBS - 1] = a[LIMBS - 1] + carry
}

/** r = a + b, carried. */
export function feAdd(r, a, b) {
  let carry = 0
  for (let i = 0; i < LIMBS - 1; i++) {
    const x = a[i] + b[i] + carry
    carry = Math.floor(x * INV + 0.5)
    r[i] = x - carry * BASE
  }
  r[LIMBS - 1] = a[LIMBS - 1] + b[LIMBS - 1] + carry
}

/** r = a - b, carried. */
export function feSub(r, a, b) {
  let carry = 0
  for (let i = 0; i < LIMBS - 1; i++) {
    const x = a[i] - b[i] + carry
    carry = Math.floor(x * INV + 0.5)
    r[i] = x - carry * BASE
  }
  r[LIMBS - 1] = a[LIMBS - 1] - b[LIMBS - 1] + carry
}

/** r = -a. Negating balanced limbs keeps them carried. */
export function feNeg(r, a) {
  for (let i = 0; i < LIMBS; i++) r[i] = -a[i]
}

/** r = k * a for a small integer k (|k| <= 64), carried. */
export function feMulSmall(r, a, k) {
  let carry = 0
  for (let i = 0; i < LIMBS - 1; i++) {
    const x = a[i] * k + carry
    carry = Math.floor(x * INV + 0.5)
    r[i] = x - carry * BASE
  }
  r[LIMBS - 1] = a[LIMBS - 1] * k + carry
}

const scratch = feNew()
const scratch2 = feNew()
const RAW_ONE = feNew()
RAW_ONE[0] = 1
const discard = new Uint8Array(32)

/**
 * Writes a value in (-m, m) to canonical big-endian bytes in [0, m), adding the
 * modulus through a mask if it is negative. Returns the limbs ORed together, so
 * the result is zero exactly when the value is zero.
 */
export function canonicalBytes(out, v, modulus, offset = 0) {
  let carry = 0
  for (let i = 0; i < 10; i++) {
    const x = v[i] + carry
    carry = Math.floor(x * INV)
    scratch2[i] = x - carry * BASE
  }
  const top = v[10] + carry
  const neg = (top >> 31) & 1
  carry = 0
  let acc = 0
  for (let i = 0; i < 10; i++) {
    const x = scratch2[i] + neg * modulus[i] + carry
    carry = Math.floor(x * INV)
    const limb = (x - carry * BASE) | 0
    acc |= limb
    const o = offset + 31 - 3 * i
    out[o] = limb
    out[o - 1] = limb >>> 8
    out[o - 2] = limb >>> 16
  }
  const last = (top + neg * modulus[10] + carry) | 0
  acc |= last
  out[offset + 1] = last
  out[offset] = last >>> 8
  return acc
}

/** -1 when acc (an OR of limbs) is zero, else 0. */
export function maskFromAcc(acc) {
  return (acc - 1) >> 31
}

/**
 * -1 if the 32 bytes at b[offset..] encode a value below the modulus m (given as
 * bytes), else 0. Constant-flow.
 */
export function bytesBelowMask(b, offset, m) {
  let borrow = 0
  for (let i = 31; i >= 0; i--) {
    borrow = (b[offset + i] - m[i] - borrow) >> 31
    borrow &= 1
  }
  return -borrow
}

// ---- modulo q ----

const Q_LIMBS = feNew()
limbsFromBytes(Q_LIMBS, Q_BYTES)
const FP_R2 = feNew()
export const FP_ONE = feNew()

/** r = bytes * R mod q. Accepts any 256-bit input, including values >= q. */
export function fpFromBytes(r, b, offset = 0) {
  limbsFromBytes(scratch, b, offset)
  fpMul(r, scratch, FP_R2)
}

/** Canonical big-endian bytes of a. Returns 0 exactly when a = 0 mod q. */
export function fpToBytes(out, a, offset = 0) {
  fpMul(scratch, a, RAW_ONE)
  return canonicalBytes(out, scratch, Q_LIMBS, offset)
}

const Q_TOP = Number(Q_BYTES[0] * 256 + Q_BYTES[1]) + Q_BYTES[2] / 256

/**
 * r = a - k q with k = round(a / q) estimated from the top limb: brings a reduced
 * value of any size back to |value| < 0.6 q without a multiplication. For outputs
 * built only from additions of their own inputs (the cyclotomic squaring), which
 * would otherwise grow with every call. No branches.
 */
export function fpReduce(r, a) {
  const k = Math.round(a[LIMBS - 1] / Q_TOP)
  let carry = 0
  for (let i = 0; i < LIMBS - 1; i++) {
    const x = a[i] - k * Q_LIMBS[i] + carry
    carry = Math.floor(x * INV + 0.5)
    r[i] = x - carry * BASE
  }
  r[LIMBS - 1] = a[LIMBS - 1] - k * Q_LIMBS[LIMBS - 1] + carry
}

/** -1 if a = 0 mod q, else 0. */
export function fpIsZeroMask(a) {
  return maskFromAcc(fpToBytes(discard, a))
}

/** r = a^e for a public exponent e (32 bytes), 4-bit fixed window. */
const powTable = Array.from({ length: 16 }, feNew)
export function fpPowPublic(r, a, e) {
  feCopy(powTable[1], a)
  for (let i = 2; i < 16; i++) fpMul(powTable[i], powTable[i - 1], a)
  feCopy(r, FP_ONE)
  for (let i = 0; i < 32; i++) {
    const byte = e[i]
    for (let s = 0; s < 4; s++) fpSqr(r, r)
    if (byte >>> 4 !== 0) fpMul(r, r, powTable[byte >>> 4])
    for (let s = 0; s < 4; s++) fpSqr(r, r)
    if ((byte & 15) !== 0) fpMul(r, r, powTable[byte & 15])
  }
}

const Q_MINUS_2 = hexBytes(
  'b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457b',
)

/** r = 1/a mod q by Fermat. The exponent is public; a = 0 gives 0. */
export function fpInv(r, a) {
  fpPowPublic(r, a, Q_MINUS_2)
}

/** Loads a canonical constant (hex) into reduced Montgomery limbs. */
export function fpConstant(hex) {
  const r = feNew()
  fpFromBytes(r, hexBytes(hex))
  return r
}

/** Loads a canonical value, already multiplied by R, into reduced limbs. */
export function loadRaw(r, hex) {
  limbsFromBytes(scratch, hexBytes(hex))
  feCarry(r, scratch)
}

loadRaw(
  FP_ONE,
  '6c3ffffc4c80e2dce0dac2dea4c68e0d64d371addd9b09a1407d6b1039078db5',
)
loadRaw(
  FP_R2,
  '83a656493b69cca914b0869cba091e9f701b5c7b154a6dcb6963262f7d005898',
)

/** Every module-level buffer in this file that can hold values derived from a secret. */
const SECRET_SCRATCH = [scratch, scratch2, discard, ...powTable]

/** Best-effort erasure. The garbage collector may keep copies out of reach. */
export function wipeFpScratch() {
  for (const a of SECRET_SCRATCH) a.fill(0)
}
