/**
 * Fq12 for the SM9 pairing. Internal module, not part of the public API.
 *
 * An element is kept as six Fq2 coefficients x0..x5 of 1, w, ..., w^5 with
 * w^6 = u, exactly as testvectors/sm9_ref.py does. The standard's tower
 * Fq4 = Fq2[v]/(v^2 - u), Fq12 = Fq4[w]/(w^3 - v) is the same field with
 * v = w^3, so its Fq4 coefficient c_i is x_i + x_{i+3} v.
 *
 * For multiplication the same coefficients are read as the 2-3-2 tower
 * Fq12 = Fq6[w]/(w^2 - s), Fq6 = Fq2[s]/(s^3 - u), s = w^2:
 * f = A + B w with A = (x0, x2, x4) and B = (x1, x3, x5).
 *
 * All six coefficients share one Float64Array(132), so copies and masked table
 * lookups work on the whole element. Outputs may alias inputs. Same timing notes
 * as fp.js.
 */
import { FP_ONE, LIMBS, feCopy, fpConstant, fpToBytes } from './fp.js'
import {
  FP2_SIZE,
  Fp2,
  fp2Add,
  fp2Conj,
  fp2Copy,
  fp2Inv,
  fp2Mul,
  fp2MulFp,
  fp2MulU,
  fp2Neg,
  fp2Reduce,
  fp2Sqr,
  fp2Sub,
} from './fp2.js'

export const FP12_SIZE = 6 * FP2_SIZE

export class Fp12 {
  constructor() {
    this.v = new Float64Array(FP12_SIZE)
    this.x = []
    for (let k = 0; k < 6; k++) this.x.push(new Fp2(this.v, k * FP2_SIZE))
    this.a = [this.x[0], this.x[2], this.x[4]]
    this.b = [this.x[1], this.x[3], this.x[5]]
  }
}

const newFp6 = () => [new Fp2(), new Fp2(), new Fp2()]

export function fp12One(r) {
  r.v.fill(0)
  feCopy(r.x[0].c0, FP_ONE)
}

export function fp12Copy(r, a) {
  r.v.set(a.v)
}

// ---- Fq6 = Fq2[s] / (s^3 - u), as arrays of three Fp2 ----

function fp6Add(r, a, b) {
  for (let i = 0; i < 3; i++) fp2Add(r[i], a[i], b[i])
}

function fp6Sub(r, a, b) {
  for (let i = 0; i < 3; i++) fp2Sub(r[i], a[i], b[i])
}

function fp6Copy(r, a) {
  for (let i = 0; i < 3; i++) fp2Copy(r[i], a[i])
}

const sTmp = new Fp2()
/** r = a * s = u a2 + a0 s + a1 s^2 */
function fp6MulS(r, a) {
  fp2MulU(sTmp, a[2])
  fp2Copy(r[2], a[1])
  fp2Copy(r[1], a[0])
  fp2Copy(r[0], sTmp)
}

const m0 = new Fp2()
const m1 = new Fp2()
const m2 = new Fp2()
const ma = new Fp2()
const mb = new Fp2()
const mc0 = new Fp2()
const mc1 = new Fp2()
const mc2 = new Fp2()

/** Karatsuba, 6 Fq2 multiplications. */
function fp6Mul(r, a, b) {
  fp2Mul(m0, a[0], b[0])
  fp2Mul(m1, a[1], b[1])
  fp2Mul(m2, a[2], b[2])
  // c0 = v0 + u ((a1 + a2)(b1 + b2) - v1 - v2)
  fp2Add(ma, a[1], a[2])
  fp2Add(mb, b[1], b[2])
  fp2Mul(mc0, ma, mb)
  fp2Sub(mc0, mc0, m1)
  fp2Sub(mc0, mc0, m2)
  fp2MulU(mc0, mc0)
  fp2Add(mc0, mc0, m0)
  // c1 = (a0 + a1)(b0 + b1) - v0 - v1 + u v2
  fp2Add(ma, a[0], a[1])
  fp2Add(mb, b[0], b[1])
  fp2Mul(mc1, ma, mb)
  fp2Sub(mc1, mc1, m0)
  fp2Sub(mc1, mc1, m1)
  fp2MulU(ma, m2)
  fp2Add(mc1, mc1, ma)
  // c2 = (a0 + a2)(b0 + b2) - v0 - v2 + v1
  fp2Add(ma, a[0], a[2])
  fp2Add(mb, b[0], b[2])
  fp2Mul(mc2, ma, mb)
  fp2Sub(mc2, mc2, m0)
  fp2Sub(mc2, mc2, m2)
  fp2Add(r[2], mc2, m1)
  fp2Copy(r[0], mc0)
  fp2Copy(r[1], mc1)
}

/** r = a * (b0 + b1 s): 5 Fq2 multiplications. */
function fp6MulBy01(r, a, b0, b1) {
  fp2Mul(m0, a[0], b0)
  fp2Mul(m1, a[1], b1)
  // c0 = a0 b0 + u a2 b1
  fp2Mul(mc0, a[2], b1)
  fp2MulU(mc0, mc0)
  fp2Add(mc0, mc0, m0)
  // c1 = (a0 + a1)(b0 + b1) - v0 - v1
  fp2Add(ma, a[0], a[1])
  fp2Add(mb, b0, b1)
  fp2Mul(mc1, ma, mb)
  fp2Sub(mc1, mc1, m0)
  fp2Sub(mc1, mc1, m1)
  // c2 = a1 b1 + a2 b0
  fp2Mul(mc2, a[2], b0)
  fp2Add(r[2], mc2, m1)
  fp2Copy(r[0], mc0)
  fp2Copy(r[1], mc1)
}

const ia = new Fp2()
const ib = new Fp2()
const ic = new Fp2()
const it = new Fp2()
/** 1 / (a0 + a1 s + a2 s^2) through the norm to Fq2. */
function fp6Inv(r, a) {
  // t0 = a0^2 - u a1 a2, t1 = u a2^2 - a0 a1, t2 = a1^2 - a0 a2
  fp2Mul(it, a[1], a[2])
  fp2MulU(it, it)
  fp2Sqr(ia, a[0])
  fp2Sub(ia, ia, it)
  fp2Sqr(it, a[2])
  fp2MulU(it, it)
  fp2Mul(ib, a[0], a[1])
  fp2Sub(ib, it, ib)
  fp2Sqr(it, a[1])
  fp2Mul(ic, a[0], a[2])
  fp2Sub(ic, it, ic)
  // norm = a0 t0 + u (a2 t1 + a1 t2)
  fp2Mul(it, a[2], ib)
  fp2Mul(mc0, a[1], ic)
  fp2Add(it, it, mc0)
  fp2MulU(it, it)
  fp2Mul(mc0, a[0], ia)
  fp2Add(it, it, mc0)
  fp2Inv(it, it)
  fp2Mul(r[0], ia, it)
  fp2Mul(r[1], ib, it)
  fp2Mul(r[2], ic, it)
}

// ---- Fq12 = Fq6[w] / (w^2 - s) ----

const t0 = newFp6()
const t1 = newFp6()
const t2 = newFp6()
const t3 = newFp6()

/** 3 Fq6 multiplications. */
export function fp12Mul(r, f, g) {
  fp6Mul(t0, f.a, g.a)
  fp6Mul(t1, f.b, g.b)
  fp6Add(t2, f.a, f.b)
  fp6Add(t3, g.a, g.b)
  fp6Mul(t2, t2, t3)
  fp6Sub(t2, t2, t0)
  fp6Sub(r.b, t2, t1)
  fp6MulS(t1, t1)
  fp6Add(r.a, t0, t1)
}

/** Complex squaring: 2 Fq6 multiplications. */
export function fp12Sqr(r, f) {
  fp6Mul(t0, f.a, f.b) // v = A B
  fp6MulS(t1, f.b)
  fp6Add(t1, t1, f.a) // A + s B
  fp6Add(t2, f.a, f.b)
  fp6Mul(t2, t2, t1) // A^2 + s B^2 + (1 + s) v
  fp6Sub(t2, t2, t0)
  fp6MulS(t1, t0)
  fp6Sub(r.a, t2, t1)
  fp6Add(r.b, t0, t0)
}

const lineSum = new Fp2()
/**
 * f = f * L for a Miller loop line L = l0 + l2 w^2 + l3 w^3, which is
 * (l0 + l2 s) + (l3 s) w in the 2-3-2 tower. 13 Fq2 multiplications.
 */
export function fp12MulLine(f, l0, l2, l3) {
  fp6MulBy01(t0, f.a, l0, l2) // A (l0 + l2 s)
  for (let i = 0; i < 3; i++) fp2Mul(t1[i], f.b[i], l3)
  fp6MulS(t1, t1) // B l3 s
  fp6Add(t2, f.a, f.b)
  fp2Add(lineSum, l2, l3)
  fp6MulBy01(t2, t2, l0, lineSum)
  fp6Sub(t2, t2, t0)
  fp6Sub(f.b, t2, t1)
  fp6MulS(t1, t1)
  fp6Add(f.a, t0, t1)
}

/** r = f^(q^6): w -> -w, so the odd coefficients change sign. */
export function fp12Conj(r, f) {
  fp6Copy(r.a, f.a)
  for (let i = 0; i < 3; i++) fp2Neg(r.b[i], f.b[i])
}

/** r = 1/f = (A - B w) / (A^2 - s B^2). */
export function fp12Inv(r, f) {
  fp6Mul(t0, f.a, f.a)
  fp6Mul(t1, f.b, f.b)
  fp6MulS(t1, t1)
  fp6Sub(t0, t0, t1)
  fp6Inv(t0, t0)
  fp6Mul(r.a, f.a, t0)
  fp6Mul(t1, f.b, t0)
  for (let i = 0; i < 3; i++) fp2Neg(r.b[i], t1[i])
}

// ---- Frobenius: x^(q^k) maps x_j w^j to conj^k(x_j) gamma_k^j w^j ----
// gamma_k = u^((q^k - 1) / 6); for SM9 every gamma_k^j lies in Fq.

const GAMMA = [
  null,
  [
    '3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b',
    '0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334',
    '6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011',
    '0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333',
    '2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686',
  ],
  [
    '0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334',
    '0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333',
    'b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c',
    'b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249',
    'b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24a',
  ],
  [
    '6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011',
    'b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c',
    '49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756c',
    '0000000000000000000000000000000000000000000000000000000000000001',
    '6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011',
  ],
].map((row) => (row === null ? null : row.map(fpConstant)))

/** r = f^(q^k), k in 1..3. */
export function fp12Frobenius(r, f, k) {
  const odd = (k & 1) === 1
  const g = GAMMA[k]
  for (let j = 0; j < 6; j++) {
    if (odd) fp2Conj(r.x[j], f.x[j])
    else fp2Copy(r.x[j], f.x[j])
    if (j > 0) fp2MulFp(r.x[j], r.x[j], g[j - 1])
  }
}

// ---- cyclotomic squaring (Granger-Scott) ----

const ca = new Fp2()
const cb = new Fp2()
const cs = new Fp2()
const sq = [new Fp2(), new Fp2(), new Fp2(), new Fp2(), new Fp2(), new Fp2()]

/** (x + y v)^2 = (x^2 + u y^2) + 2 x y v, with 3 Fq2 squarings. */
function fp4Sqr(rx, ry, x, y) {
  fp2Sqr(ca, x)
  fp2Sqr(cb, y)
  fp2Add(cs, x, y)
  fp2Sqr(cs, cs)
  fp2Sub(cs, cs, ca)
  fp2Sub(ry, cs, cb)
  fp2MulU(cb, cb)
  fp2Add(rx, ca, cb)
}

/** r = 3 a - 2 b */
function threeMinusTwo(r, a, b) {
  fp2Sub(cs, a, b)
  fp2Add(cs, cs, cs)
  fp2Add(cs, cs, a)
  fp2Reduce(r, cs)
}

/** r = 3 a + 2 b */
function threePlusTwo(r, a, b) {
  fp2Add(cs, a, b)
  fp2Add(cs, cs, cs)
  fp2Add(cs, cs, a)
  fp2Reduce(r, cs)
}

/**
 * r = f^2 for f in the cyclotomic subgroup (after the easy part of the final
 * exponentiation). With f = c0 + c1 w + c2 w^2 over Fq4:
 * f^2 = (3 c0^2 - 2 conj(c0)) + (3 v c2^2 + 2 conj(c1)) w + (3 c1^2 - 2 conj(c2)) w^2.
 */
export function fp12CycSqr(r, f) {
  const x = f.x
  fp4Sqr(sq[0], sq[3], x[0], x[3]) // c0^2
  fp4Sqr(sq[1], sq[4], x[1], x[4]) // c1^2
  fp4Sqr(sq[2], sq[5], x[2], x[5]) // c2^2
  const y = r.x
  threeMinusTwo(y[0], sq[0], x[0])
  threePlusTwo(y[3], sq[3], x[3])
  // v c2^2 = u (c2^2).y + (c2^2).x v
  fp2MulU(sq[5], sq[5])
  threePlusTwo(y[1], sq[5], x[1])
  threeMinusTwo(y[4], sq[2], x[4])
  threeMinusTwo(y[2], sq[1], x[2])
  threePlusTwo(y[5], sq[4], x[5])
}

/** Every module-level buffer that can hold secret-derived values. */
export function wipeFp12Scratch() {
  const all = [
    sTmp,
    m0,
    m1,
    m2,
    ma,
    mb,
    mc0,
    mc1,
    mc2,
    ia,
    ib,
    ic,
    it,
    lineSum,
    ca,
    cb,
    cs,
    ...sq,
    ...t0,
    ...t1,
    ...t2,
    ...t3,
  ]
  for (const e of all) e.v.fill(0)
}

export { LIMBS }

const GT_ORDER = [5, 2, 4, 1, 3, 0]
/** 384 bytes c2 || c1 || c0, each Fq4 c_i as x_{i+3} || x_i, each Fq2 as a1 || a0. */
export function gtToBytes(f) {
  const out = new Uint8Array(384)
  for (let i = 0; i < 6; i++) {
    const c = f.x[GT_ORDER[i]]
    fpToBytes(out, c.c1, 64 * i)
    fpToBytes(out, c.c0, 64 * i + 32)
  }
  return out
}
