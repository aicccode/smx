/**
 * Field arithmetic modulo the SM2 prime p and the group order n.
 *
 * Internal module, not part of the public API.
 *
 * Representation: Float64Array(11) of balanced base-2^24 limbs, in Montgomery
 * form with R = 2^264. Measured on V8, this was about 3x faster than BigInt and
 * 2.5x faster than Int32Array with 13-bit limbs, and it does not allocate.
 *
 * Exactness bound: a "reduced" value has |limb| <= 2^23, which every multiply,
 * square and carry guarantees. If operand a is a sum of k1 reduced values and b a
 * sum of k2, then a product stays exact provided k1 * k2 <= 10, because each
 * column is at most 11 * k1 * k2 * 2^46 < 2^53. Multiply and square also return
 * |value| < 0.6 * m. A carry keeps the value, so it can be a small multiple of m.
 *
 * Timing: this code has no data-dependent branches or memory accesses, except
 * functions documented as public-data only. A JavaScript engine gives no formal
 * constant-time guarantee, since the JIT and GC are outside our control.
 */
import { fpMul, fpSqr, fnMul, fnSqr } from './fe-mul.js'

export { fpMul, fpSqr, fnMul, fnSqr }

export const LIMBS = 11
const BASE = 16777216
const INV = 1 / 16777216

const N_BYTES = hexBytes(
  'fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123',
)
const P_BYTES = hexBytes(
  'fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff',
)
/** Unsigned base-2^24 limbs of the moduli */
const P_LIMBS = new Float64Array(LIMBS)
const N_LIMBS = new Float64Array(LIMBS)
limbsFromBytes(N_LIMBS, N_BYTES)
limbsFromBytes(P_LIMBS, P_BYTES)

function hexBytes(hex) {
  const out = new Uint8Array(hex.length >>> 1)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(2 * i, 2 * i + 2), 16)
  }
  return out
}

/** Big-endian 32 bytes to unsigned limbs: each limb is exactly three bytes. */
export function limbsFromBytes(r, b) {
  for (let i = 0; i < 10; i++) {
    const o = 31 - 3 * i
    r[i] = b[o] | (b[o - 1] << 8) | (b[o - 2] << 16)
  }
  r[10] = b[1] | (b[0] << 8)
}

const scratch = new Float64Array(LIMBS)
const scratch2 = new Float64Array(LIMBS)
const RAW_ONE = new Float64Array(LIMBS)
RAW_ONE[0] = 1

/**
 * Writes a value in (-m, m) to canonical big-endian bytes in [0, m), adding the
 * modulus through a mask if it is negative. The limbs are then returned ORed
 * together, so the result is zero exactly when the value is zero.
 */
function canonicalBytes(out, v, modulus) {
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
    const o = 31 - 3 * i
    out[o] = limb
    out[o - 1] = limb >>> 8
    out[o - 2] = limb >>> 16
  }
  const last = (top + neg * modulus[10] + carry) | 0
  acc |= last
  out[1] = last
  out[0] = last >>> 8
  return acc
}

const discard = new Uint8Array(32)

function maskFromAcc(acc) {
  return (acc - 1) >> 31
}

export function feNew() {
  return new Float64Array(LIMBS)
}

export function feCopy(r, a) {
  for (let i = 0; i < LIMBS; i++) r[i] = a[i]
}

/** r = mask ? b : a, where mask is 0 or -1 and limbs fit in 32 bits. */
export function feSelect(r, a, b, mask) {
  const inverse = ~mask
  for (let i = 0; i < LIMBS; i++) r[i] = (a[i] & inverse) | (b[i] & mask)
}

export function feAdd(r, a, b) {
  for (let i = 0; i < LIMBS; i++) r[i] = a[i] + b[i]
}

export function feSub(r, a, b) {
  for (let i = 0; i < LIMBS; i++) r[i] = a[i] - b[i]
}

/** Works for either modulus: the value is unchanged, the limbs are reduced. */
export function feCarry(r, a) {
  let carry = 0
  for (let i = 0; i < LIMBS - 1; i++) {
    const x = a[i] + carry
    carry = Math.floor(x * INV + 0.5)
    r[i] = x - carry * BASE
  }
  r[LIMBS - 1] = a[LIMBS - 1] + carry
}

// ---- modulo p ----

const FP_R2 = new Float64Array(LIMBS)
const FP_ONE = new Float64Array(LIMBS)
export const FP_B = new Float64Array(LIMBS)

/** r = bytes * R mod p. Accepts any 256-bit input, including values >= p. */
export function fpFromBytes(r, b) {
  limbsFromBytes(scratch, b)
  fpMul(r, scratch, FP_R2)
}

/** Canonical big-endian bytes of a. Returns 0 exactly when a = 0 mod p. */
export function fpToBytes(out, a) {
  fpMul(scratch, a, RAW_ONE)
  return canonicalBytes(out, scratch, P_LIMBS)
}

/** -1 if a = 0 mod p, else 0. */
export function fpIsZeroMask(a) {
  return maskFromAcc(fpToBytes(discard, a))
}

function fpSqrN(r, a, n) {
  fpSqr(r, a)
  for (let i = 1; i < n; i++) fpSqr(r, r)
}

const x1 = feNew()
const x2 = feNew()
const x3 = feNew()
const x6 = feNew()
const x12 = feNew()
const x24 = feNew()
const x30 = feNew()
const x32 = feNew()

/** Computes a^(2^k - 1) for the k used by the addition chains below. */
function fpPowerChain(a) {
  feCopy(x1, a)
  fpSqr(x2, x1)
  fpMul(x2, x2, x1)
  fpSqr(x3, x2)
  fpMul(x3, x3, x1)
  fpSqrN(x6, x3, 3)
  fpMul(x6, x6, x3)
  fpSqrN(x12, x6, 6)
  fpMul(x12, x12, x6)
  fpSqrN(x24, x12, 12)
  fpMul(x24, x24, x12)
  fpSqrN(x30, x24, 6)
  fpMul(x30, x30, x6)
  fpSqrN(x32, x30, 2)
  fpMul(x32, x32, x2)
}

/**
 * r = 1/a mod p by Fermat, with a fixed sequence of operations: a = 0 gives 0.
 * p - 2 in 32-bit words: fffffffe ffffffff*4 00000000 ffffffff fffffffd.
 */
export function fpInv(r, a) {
  fpPowerChain(a)
  fpSqr(r, x30)
  fpMul(r, r, x1) // 31 ones
  fpSqr(r, r) // fffffffe
  for (let i = 0; i < 4; i++) {
    fpSqrN(r, r, 32)
    fpMul(r, r, x32)
  }
  fpSqrN(r, r, 32) // 00000000
  fpSqrN(r, r, 32)
  fpMul(r, r, x32) // ffffffff
  fpSqrN(r, r, 30)
  fpMul(r, r, x30)
  fpSqrN(r, r, 2)
  fpMul(r, r, x1) // fffffffd
}

/**
 * r = a^((p + 1) / 4) mod p, the baseline's square root. It does not check that
 * a is a residue. The exponent in 32-bit words is 3fffffff bfffffff ffffffff*3
 * c0000000 40000000 00000000.
 */
export function fpSqrtCandidate(r, a) {
  fpPowerChain(a)
  feCopy(r, x30) // 3fffffff
  fpSqr(r, r)
  fpMul(r, r, x1) // the leading 1 of bfffffff
  fpSqr(r, r) // the 0 of bfffffff
  fpSqrN(r, r, 30)
  fpMul(r, r, x30) // the rest of bfffffff
  for (let i = 0; i < 3; i++) {
    fpSqrN(r, r, 32)
    fpMul(r, r, x32)
  }
  fpSqrN(r, r, 2)
  fpMul(r, r, x2) // the 11 of c0000000
  fpSqrN(r, r, 32) // 30 zeros, then the 00 of 40000000... see next line
  fpMul(r, r, x1) // the 1 of 40000000 sits 30 + 2 bits below the 11
  fpSqrN(r, r, 62) // 30 + 32 trailing zeros
}

// ---- modulo n ----

const FN_R2 = new Float64Array(LIMBS)
export const FN_ONE = new Float64Array(LIMBS)

export function fnFromBytes(r, b) {
  limbsFromBytes(scratch, b)
  fnMul(r, scratch, FN_R2)
}

export function fnToBytes(out, a) {
  fnMul(scratch, a, RAW_ONE)
  return canonicalBytes(out, scratch, N_LIMBS)
}

/** Fixed-window Fermat inverse. The exponent n - 2 is public, a is not. */
const fnTable = Array.from({ length: 16 }, feNew)
export function fnInv(r, a) {
  feCopy(fnTable[1], a)
  for (let i = 2; i < 16; i++) fnMul(fnTable[i], fnTable[i - 1], a)
  feCopy(r, FN_ONE)
  for (let i = 0; i < 32; i++) {
    const byte = i === 31 ? N_BYTES[31] - 2 : N_BYTES[i]
    for (let s = 0; s < 4; s++) fnSqr(r, r)
    fnMulOrSkip(r, byte >>> 4)
    for (let s = 0; s < 4; s++) fnSqr(r, r)
    fnMulOrSkip(r, byte & 15)
  }
}

function fnMulOrSkip(r, nibble) {
  if (nibble !== 0) fnMul(r, r, fnTable[nibble])
}

// ---- constants ----

/** Loads a canonical value into reduced limbs, without changing the value. */
function loadConstant(r, hex) {
  limbsFromBytes(scratch, hexBytes(hex))
  feCarry(r, scratch)
}

// R = 2^264 and R^2 = 2^528, each reduced mod p and mod n
loadConstant(
  FP_ONE,
  '00000100000000000000000000000000000000ffffffff000000000000000100',
)
loadConstant(
  FP_R2,
  '000400000002000000010000000100000002ffffffff00000002000000030000',
)
loadConstant(
  FN_ONE,
  '0000010000000000000000000000008dfc2094de39fad4ac440bf6c62abedd00',
)
loadConstant(
  FN_R2,
  'e412c0e03d3b620fc84c3affe0d4456c3f5f59bb8d5dd49f5832dcc46db6d841',
)
fpFromBytes(
  FP_B,
  hexBytes('28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93'),
)

export { FP_ONE, P_BYTES, N_BYTES }
