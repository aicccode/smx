/**
 * Fq2 = Fq[u] / (u^2 + 2). An element a0 + a1 u is an Fp2 object whose c0 and c1
 * are views of one Float64Array(22), so it can live inside a larger buffer (the
 * Fq12 elements do) and be copied or selected limb by limb.
 *
 * Internal module, not part of the public API. Same reduced-input, reduced-output
 * rule and timing notes as fp.js; outputs may alias inputs.
 */
import {
  LIMBS,
  FP_ONE,
  feAdd,
  feCarry,
  feCopy,
  feMulSmall,
  feNeg,
  feSelect,
  feSub,
  fpInv,
  fpIsZeroMask,
  fpMul,
  fpReduce,
  fpSqr,
  feNew,
} from './fp.js'

export const FP2_SIZE = 2 * LIMBS

export class Fp2 {
  /** A new zero element, or a view of buffer[offset .. offset + 22). */
  constructor(buffer, offset = 0) {
    this.v =
      buffer === undefined
        ? new Float64Array(FP2_SIZE)
        : buffer.subarray(offset, offset + FP2_SIZE)
    this.c0 = this.v.subarray(0, LIMBS)
    this.c1 = this.v.subarray(LIMBS, FP2_SIZE)
  }
}

const t0 = feNew()
const t1 = feNew()
const t2 = feNew()
const s0 = feNew()
const s1 = feNew()

export function fp2Copy(r, a) {
  r.v.set(a.v)
}

export function fp2Zero(r) {
  r.v.fill(0)
}

export function fp2One(r) {
  r.v.fill(0)
  feCopy(r.c0, FP_ONE)
}

export function fp2Add(r, a, b) {
  feAdd(r.c0, a.c0, b.c0)
  feAdd(r.c1, a.c1, b.c1)
}

export function fp2Sub(r, a, b) {
  feSub(r.c0, a.c0, b.c0)
  feSub(r.c1, a.c1, b.c1)
}

export function fp2Neg(r, a) {
  feNeg(r.c0, a.c0)
  feNeg(r.c1, a.c1)
}

/** r = k * a for a small integer k. */
export function fp2MulSmall(r, a, k) {
  feMulSmall(r.c0, a.c0, k)
  feMulSmall(r.c1, a.c1, k)
}

/** Brings both components below 0.6 q, see fpReduce. */
export function fp2Reduce(r, a) {
  fpReduce(r.c0, a.c0)
  fpReduce(r.c1, a.c1)
}

/** r = a0 - a1 u */
export function fp2Conj(r, a) {
  feCopy(r.c0, a.c0)
  feNeg(r.c1, a.c1)
}

/** r = a * u = -2 a1 + a0 u */
export function fp2MulU(r, a) {
  feCopy(t0, a.c0)
  feMulSmall(r.c0, a.c1, -2)
  feCopy(r.c1, t0)
}

/** r = a * k for k in Fq */
export function fp2MulFp(r, a, k) {
  fpMul(r.c0, a.c0, k)
  fpMul(r.c1, a.c1, k)
}

/** Karatsuba: 3 multiplications. */
export function fp2Mul(r, a, b) {
  const a0 = a.c0
  const a1 = a.c1
  const b0 = b.c0
  const b1 = b.c1
  fpMul(t0, a0, b0)
  fpMul(t1, a1, b1)
  for (let i = 0; i < LIMBS; i++) {
    s0[i] = a0[i] + a1[i]
    s1[i] = b0[i] + b1[i]
  }
  fpMul(t2, s0, s1)
  // c1 = t2 - t0 - t1, c0 = t0 - 2 t1
  for (let i = 0; i < LIMBS; i++) t2[i] -= t0[i] + t1[i]
  feCarry(r.c1, t2)
  for (let i = 0; i < LIMBS; i++) t0[i] -= 2 * t1[i]
  feCarry(r.c0, t0)
}

/** (a0 + a1 u)^2 = (a0 + a1)(a0 - 2 a1) + a0 a1 + 2 a0 a1 u: 2 multiplications. */
export function fp2Sqr(r, a) {
  const a0 = a.c0
  const a1 = a.c1
  fpMul(t0, a0, a1)
  for (let i = 0; i < LIMBS; i++) {
    s0[i] = a0[i] + a1[i]
    s1[i] = a0[i] - 2 * a1[i]
  }
  fpMul(t1, s0, s1)
  feAdd(r.c0, t1, t0)
  feMulSmall(r.c1, t0, 2)
}

/** 1/a = (a0 - a1 u) / (a0^2 + 2 a1^2). a = 0 gives 0. */
export function fp2Inv(r, a) {
  fpSqr(t0, a.c0)
  fpSqr(t1, a.c1)
  feMulSmall(t1, t1, 2)
  feAdd(t0, t0, t1)
  fpInv(t2, t0)
  fpMul(r.c0, a.c0, t2)
  fpMul(t1, a.c1, t2)
  feNeg(r.c1, t1)
}

/** r = mask ? b : a, mask 0 or -1. */
export function fp2Select(r, a, b, mask) {
  feSelect(r.c0, a.c0, b.c0, mask)
  feSelect(r.c1, a.c1, b.c1, mask)
}

/** -1 if a = 0, else 0. */
export function fp2IsZeroMask(a) {
  return fpIsZeroMask(a.c0) & fpIsZeroMask(a.c1)
}

const eq = new Fp2()
/** -1 if a = b, else 0. */
export function fp2EqualMask(a, b) {
  fp2Sub(eq, a, b)
  return fp2IsZeroMask(eq)
}

/** Every module-level buffer that can hold secret-derived values. */
export function wipeFp2Scratch() {
  for (const a of [t0, t1, t2, s0, s1, eq.v]) a.fill(0)
}
