/**
 * Arithmetic modulo the group order n on 32-byte big-endian values.
 *
 * Internal module, not part of the public API. A fixed sequence of operations,
 * with the same caveats about JavaScript timing as fe.js.
 */
import {
  FN_ONE,
  N_BYTES,
  P_BYTES,
  feAdd,
  feNew,
  feSub,
  fnFromBytes,
  fnInv,
  fnMul,
  fnToBytes,
  wipeFieldScratch,
} from './fe.js'

const a = feNew()
const b = feNew()
const c = feNew()
const d = feNew()

/** Erases intermediates, which include the private key during signing. */
function finish(out) {
  const acc = fnToBytes(out, c)
  for (const buffer of SCRATCH) buffer.fill(0)
  wipeFieldScratch()
  return acc
}

const SCRATCH = [a, b, c, d]

/** For tests only. */
export function scalarScratchForTest() {
  return SCRATCH
}

/** out = (x + y) mod n. Returns 0 exactly when the result is zero. */
export function scalarAdd(out, x, y) {
  fnFromBytes(a, x)
  fnFromBytes(b, y)
  feAdd(c, a, b)
  return finish(out)
}

/** out = (x - y) mod n. */
export function scalarSub(out, x, y) {
  fnFromBytes(a, x)
  fnFromBytes(b, y)
  feSub(c, a, b)
  return finish(out)
}

/** out = (x * y + z) mod n. */
export function scalarMulAdd(out, x, y, z) {
  fnFromBytes(a, x)
  fnFromBytes(b, y)
  fnMul(c, a, b)
  fnFromBytes(d, z)
  feAdd(c, c, d)
  return finish(out)
}

/** out = (1 + x)^-1 * (k - r * x) mod n, the SM2 signature s. */
export function signatureS(out, x, k, r) {
  fnFromBytes(a, x)
  fnFromBytes(b, r)
  fnMul(b, b, a) // r * x
  fnFromBytes(c, k)
  feSub(c, c, b) // k - r * x
  feAdd(a, a, FN_ONE) // 1 + x
  fnInv(d, a)
  fnMul(c, c, d)
  return finish(out)
}

/** Lexicographic comparison of equal-length big-endian public values. */
function lessThan(a, b) {
  for (let i = 0; i < 32; i++) {
    if (a[i] !== b[i]) return a[i] < b[i]
  }
  return false
}

/** p - n, the range of x for which x + n is still a field element. */
const P_MINUS_N = new Uint8Array(32)
{
  let borrow = 0
  for (let i = 31; i >= 0; i--) {
    const v = P_BYTES[i] - N_BYTES[i] - borrow
    P_MINUS_N[i] = v
    borrow = v < 0 ? 1 : 0
  }
}

/** Whether a public value is below n. */
export function isBelowN(x) {
  return lessThan(x, N_BYTES)
}

/** x + n if that stays below p, else null. For public values only. */
export function plusNBelowP(x) {
  if (!lessThan(x, P_MINUS_N)) return null
  const out = new Uint8Array(32)
  let carry = 0
  for (let i = 31; i >= 0; i--) {
    const v = x[i] + N_BYTES[i] + carry
    out[i] = v
    carry = v >>> 8
  }
  return out
}

/**
 * Constant-flow check that a secret 32-byte value is in [1, limit - 1]. Compares by
 * running a borrow through the whole value and never looks at where bytes differ.
 */
function isInRangeFromOne(x, limit) {
  let borrow = 0
  let any = 0
  for (let i = 31; i >= 0; i--) {
    const v = x[i] - limit[i] - borrow
    borrow = (v >> 31) & 1
    any |= x[i]
  }
  const nonZero = ((any - 1) >> 31) + 1 // 0 when any = 0, else 1
  return (borrow & nonZero) === 1
}

const N_MINUS_1 = new Uint8Array(N_BYTES)
N_MINUS_1[31] -= 1

/** Private key range: [1, n - 2]. Excluding n - 1 keeps 1 + d invertible. */
export function isValidPrivateScalar(x) {
  return isInRangeFromOne(x, N_MINUS_1)
}

/** Nonce and signature component range: [1, n - 1]. */
export function isInScalarRange(x) {
  return isInRangeFromOne(x, N_BYTES)
}
