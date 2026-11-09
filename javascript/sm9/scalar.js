/**
 * Scalars modulo the SM9 group order N, as 32-byte big-endian Uint8Arrays.
 * Internal module, not part of the public API.
 *
 * Arithmetic uses the same Montgomery limbs as fp.js (see fn-mul.js), with no
 * data-dependent branches; only final zero tests are branched on by callers.
 */
import { randomFill } from '../common/rng.js'
import { fnMul, fnSqr } from './fn-mul.js'
import {
  bytesBelowMask,
  canonicalBytes,
  feAdd,
  feCopy,
  feNew,
  feSub,
  hexBytes,
  limbsFromBytes,
  loadRaw,
} from './fp.js'

export const SCALAR_BYTES = 32
export const N_BYTES = hexBytes(
  'b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25',
)
const N_MINUS_2 = hexBytes(
  'b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf23',
)
const N_LIMBS = feNew()
limbsFromBytes(N_LIMBS, N_BYTES)
const FN_ONE = feNew()
const FN_R2 = feNew()
loadRaw(
  FN_ONE,
  '6c3ffffc4c80e2dce0dac2dea4c68f3c4cd371b00f15c3fc41819d0f074b831d',
)
loadRaw(
  FN_R2,
  '0351616f042427514fbdf32bffb8414d8c9a45e378890efbb2b9a9c5cc6bff7e',
)

const RAW_ONE = feNew()
RAW_ONE[0] = 1
const scratch = feNew()
const ta = feNew()
const tb = feNew()
const tc = feNew()

/** -1 if k (32 bytes) is in [1, N - 1], else 0. Constant-flow. */
export function scalarValidMask(k) {
  let acc = 0
  for (let i = 0; i < SCALAR_BYTES; i++) acc |= k[i]
  return ~((acc - 1) >> 31) & bytesBelowMask(k, 0, N_BYTES)
}

/** r = k R mod N for any 32-byte k. */
function fnFromBytes(r, k) {
  limbsFromBytes(scratch, k)
  fnMul(r, scratch, FN_R2)
}

/** Canonical bytes of a Montgomery value; returns 0 exactly when it is 0 mod N. */
function fnToBytes(out, a) {
  fnMul(scratch, a, RAW_ONE)
  return canonicalBytes(out, scratch, N_LIMBS)
}

/** a^e for a public 32-byte exponent, Montgomery form, square-and-multiply. */
function fnPowPublic(r, a, e) {
  feCopy(tc, a)
  feCopy(r, FN_ONE)
  for (let i = 0; i < SCALAR_BYTES * 8; i++) {
    fnSqr(r, r)
    if (((e[i >>> 3] >>> (7 - (i & 7))) & 1) === 1) fnMul(r, r, tc)
  }
}

/**
 * (a + b) mod N as new bytes, and whether it is zero. Inputs are below 2^256.
 * @returns {{value: Uint8Array, zero: boolean}}
 */
export function scalarAdd(a, b) {
  fnFromBytes(ta, a)
  fnFromBytes(tb, b)
  feAdd(ta, ta, tb)
  const value = new Uint8Array(SCALAR_BYTES)
  const acc = fnToBytes(value, ta)
  wipe()
  return { value, zero: acc === 0 }
}

/** (a - b) mod N as new bytes, and whether it is zero. */
export function scalarSub(a, b) {
  fnFromBytes(ta, a)
  fnFromBytes(tb, b)
  feSub(ta, ta, tb)
  const value = new Uint8Array(SCALAR_BYTES)
  const acc = fnToBytes(value, ta)
  wipe()
  return { value, zero: acc === 0 }
}

/**
 * a / b mod N as new bytes, b nonzero mod N. The inverse is b^(N - 2), with a
 * public exponent, so the schedule does not depend on b.
 */
export function scalarDiv(a, b) {
  fnFromBytes(tb, b)
  fnPowPublic(tb, tb, N_MINUS_2)
  fnFromBytes(ta, a)
  fnMul(ta, ta, tb)
  const value = new Uint8Array(SCALAR_BYTES)
  fnToBytes(value, ta)
  wipe()
  return value
}

/** A MAX_DRAWS failure means the source is broken (for example all zeros). */
const MAX_DRAWS = 64

/** Uniform scalar in [1, N - 1] by rejection sampling on the OS CSPRNG. */
export function randomScalar() {
  const k = new Uint8Array(SCALAR_BYTES)
  for (let draw = 0; draw < MAX_DRAWS; draw++) {
    randomFill(k)
    if (scalarValidMask(k) !== 0) return k
  }
  k.fill(0)
  throw new Error('Random source failed to produce a valid scalar')
}

function wipe() {
  for (const e of [scratch, ta, tb, tc]) e.fill(0)
}
