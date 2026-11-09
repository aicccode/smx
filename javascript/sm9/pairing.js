/**
 * The SM9 R-ate pairing and GT exponentiation. Internal module, not part of the
 * public API.
 *
 * Miller loop over a = 6t + 2 with T on the twist in homogeneous projective
 * coordinates, lines evaluated at P and multiplied in sparsely, then the lines for
 * pi(Q) and -pi^2(Q). Lines are scaled by Fq2 factors (the Z coordinates), which
 * the final exponentiation removes, so the result equals testvectors/sm9_ref.py
 * exactly. The final exponentiation is f^((q^6 - 1)(q^2 + 1)) followed by the BN
 * hard part as a vectorial addition chain in t (Scott et al. 2009) with
 * cyclotomic squarings.
 *
 * The Miller loop and the final exponentiation have a fixed schedule: nothing
 * depends on P or Q, which matters because decryption pairs with the private key.
 * Same timing notes as fp.js.
 */
import { LIMBS, feMulSmall, feNeg, feNew, fpConstant } from './fp.js'
import {
  Fp2,
  fp2Add,
  fp2Conj,
  fp2Copy,
  fp2Mul,
  fp2MulFp,
  fp2MulSmall,
  fp2MulU,
  fp2Neg,
  fp2One,
  fp2Sqr,
  fp2Sub,
} from './fp2.js'
import {
  Fp12,
  fp12Conj,
  fp12Copy,
  fp12CycSqr,
  fp12Frobenius,
  fp12Inv,
  fp12Mul,
  fp12MulLine,
  fp12One,
  fp12Sqr,
} from './fp12.js'

/** a = 6t + 2 below its leading bit, most significant first. */
const LOOP_BITS =
  '00100000000000000000000000000000000000010000101011101100100111110'
/** t = 0x600000000058f98a, most significant first. */
const T_BITS = '110000000000000000000000000000000000000010110001111100110001010'

// pi(x', y') = (conj(x') PI_X, conj(y') PI_Y) on the twist, both constants in Fq.
const PI_X = fpConstant(
  'b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24a',
)
const PI_Y = fpConstant(
  '49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756c',
)

const TX = new Fp2()
const TY = new Fp2()
const TZ = new Fp2()
const l0 = new Fp2()
const l2 = new Fp2()
const l3 = new Fp2()
const A = new Fp2()
const B = new Fp2()
const C = new Fp2()
const D = new Fp2()
const E = new Fp2()
const F = new Fp2()
const G = new Fp2()
const H = new Fp2()
const YZ = new Fp2()
const xP = feNew()
const negYP = feNew()
const negTwoYP = feNew()
const q1x = new Fp2()
const q1y = new Fp2()
const q2x = new Fp2()
const q2y = new Fp2()

/** f = f^2 * line(T, T)(P), T = 2T. */
function doublingStep(f) {
  fp2Sqr(A, TX)
  fp2Sqr(B, TY)
  fp2Sqr(C, TZ)
  fp2Mul(YZ, TY, TZ)
  // F = 3 b' Z^2 with b' = 5u
  fp2MulU(F, C)
  fp2MulSmall(F, F, 15)
  // line: (3 b' Z^2 - Y^2) + (3 X^2 xP) w^2 + (-2 Y Z yP) w^3
  fp2Sub(l0, F, B)
  fp2MulSmall(l2, A, 3)
  fp2MulFp(l2, l2, xP)
  fp2MulFp(l3, YZ, negTwoYP)
  // 4 * (X3, Y3, Z3): X3 = 2 X Y (B - 3F), Y3 = (B + 3F)^2 - 12 F^2, Z3 = 8 B Y Z
  fp2MulSmall(E, F, 3)
  fp2Mul(D, TX, TY)
  fp2Sub(G, B, E)
  fp2Mul(D, D, G)
  fp2Add(TX, D, D)
  fp2Add(G, B, E)
  fp2Sqr(G, G)
  fp2Sqr(H, F)
  fp2MulSmall(H, H, 12)
  fp2Sub(TY, G, H)
  fp2Mul(TZ, B, YZ)
  fp2MulSmall(TZ, TZ, 8)
  fp12Sqr(f, f)
  fp12MulLine(f, l0, l2, l3)
}

/** f = f * line(T, Q)(P), T = T + Q, for an affine Q different from +-T. */
function additionStep(f, qx, qy) {
  // theta = Y - yQ Z, delta = X - xQ Z
  fp2Mul(A, qy, TZ)
  fp2Sub(A, TY, A)
  fp2Mul(B, qx, TZ)
  fp2Sub(B, TX, B)
  // line: (delta yQ - theta xQ) + (theta xP) w^2 + (-delta yP) w^3
  fp2Mul(l0, B, qy)
  fp2Mul(C, A, qx)
  fp2Sub(l0, l0, C)
  fp2MulFp(l2, A, xP)
  fp2MulFp(l3, B, negYP)
  fp2Sqr(C, A) // theta^2
  fp2Sqr(D, B) // delta^2
  fp2Mul(E, B, D) // delta^3
  fp2Mul(F, TZ, C)
  fp2Mul(G, TX, D)
  fp2Add(H, E, F)
  fp2Sub(H, H, G)
  fp2Sub(H, H, G)
  fp2Mul(TX, B, H)
  fp2Sub(G, G, H)
  fp2Mul(G, A, G)
  fp2Mul(C, E, TY)
  fp2Sub(TY, G, C)
  fp2Mul(TZ, TZ, E)
  fp12MulLine(f, l0, l2, l3)
}

/** pi(x, y) on the twist */
function twistFrobenius(rx, ry, x, y) {
  fp2Conj(rx, x)
  fp2MulFp(rx, rx, PI_X)
  fp2Conj(ry, y)
  fp2MulFp(ry, ry, PI_Y)
}

/** f = Miller loop value for P = (px, py) in G1 and Q = (qx, qy) in G2, affine. */
export function millerLoop(f, px, py, qx, qy) {
  for (let i = 0; i < LIMBS; i++) xP[i] = px[i]
  feNeg(negYP, py)
  feMulSmall(negTwoYP, py, -2)
  fp2Copy(TX, qx)
  fp2Copy(TY, qy)
  fp2One(TZ)
  fp12One(f)
  for (let i = 0; i < LOOP_BITS.length; i++) {
    doublingStep(f)
    if (LOOP_BITS.charCodeAt(i) === 49) additionStep(f, qx, qy)
  }
  twistFrobenius(q1x, q1y, qx, qy)
  twistFrobenius(q2x, q2y, q1x, q1y)
  fp2Neg(q2y, q2y)
  additionStep(f, q1x, q1y)
  additionStep(f, q2x, q2y)
}

const e0 = new Fp12()
const e1 = new Fp12()
const fx = new Fp12()
const fx2 = new Fp12()
const fx3 = new Fp12()
const y0 = new Fp12()
const y1 = new Fp12()
const y2 = new Fp12()
const y3 = new Fp12()
const y4 = new Fp12()
const y5 = new Fp12()
const y6 = new Fp12()

/** r = f^t for f in the cyclotomic subgroup, t public. r must not alias f. */
function cycPowT(r, f) {
  fp12Copy(r, f)
  for (let i = 1; i < T_BITS.length; i++) {
    fp12CycSqr(r, r)
    if (T_BITS.charCodeAt(i) === 49) fp12Mul(r, r, f)
  }
}

/** r = f^((q^12 - 1) / N) */
export function finalExponentiation(r, f) {
  // easy part: f^((q^6 - 1)(q^2 + 1))
  fp12Inv(e0, f)
  fp12Conj(e1, f)
  fp12Mul(e0, e1, e0)
  fp12Frobenius(e1, e0, 2)
  fp12Mul(e0, e1, e0)
  // hard part: (q^4 - q^2 + 1) / N
  const m = e0
  cycPowT(fx, m)
  cycPowT(fx2, fx)
  cycPowT(fx3, fx2)
  fp12Frobenius(y0, m, 1)
  fp12Frobenius(e1, m, 2)
  fp12Mul(y0, y0, e1)
  fp12Frobenius(e1, m, 3)
  fp12Mul(y0, y0, e1)
  fp12Conj(y1, m)
  fp12Frobenius(y2, fx2, 2)
  fp12Frobenius(y3, fx, 1)
  fp12Conj(y3, y3)
  fp12Frobenius(y4, fx2, 1)
  fp12Mul(y4, y4, fx)
  fp12Conj(y4, y4)
  fp12Conj(y5, fx2)
  fp12Frobenius(y6, fx3, 1)
  fp12Mul(y6, y6, fx3)
  fp12Conj(y6, y6)
  // T0 = y6^2 y4 y5, T1 = y3 y5 T0, T0 = T0 y2, T1 = (T1^2 T0)^2,
  // T0 = T1 y1, T1 = T1 y0, T0 = T0^2, result = T1 T0
  const T0 = fx
  const T1 = fx2
  fp12CycSqr(T0, y6)
  fp12Mul(T0, T0, y4)
  fp12Mul(T0, T0, y5)
  fp12Mul(T1, y3, y5)
  fp12Mul(T1, T1, T0)
  fp12Mul(T0, T0, y2)
  fp12CycSqr(T1, T1)
  fp12Mul(T1, T1, T0)
  fp12CycSqr(T1, T1)
  fp12Mul(T0, T1, y1)
  fp12Mul(T1, T1, y0)
  fp12CycSqr(T0, T0)
  fp12Mul(r, T1, T0)
}

const millerValue = new Fp12()

/**
 * r = e(P, Q) for P = (px, py) in G1 and Q = (qx, qy) in G2, given as affine
 * coordinates of validated points other than the identity.
 */
export function pairing(r, px, py, qx, qy) {
  millerLoop(millerValue, px, py, qx, qy)
  finalExponentiation(r, millerValue)
}

// ---- GT exponentiation ----

const WINDOW = 4
const TABLE_SIZE = 1 << WINDOW
const gtTable = Array.from({ length: TABLE_SIZE }, () => new Fp12())
const gtAcc = new Int32Array(gtTable[0].v.length)
const gtSel = new Fp12()

function buildTable(g) {
  fp12One(gtTable[0])
  fp12Copy(gtTable[1], g)
  for (let i = 2; i < TABLE_SIZE; i++) fp12Mul(gtTable[i], gtTable[i - 1], g)
}

/** gtSel = table[digit], scanning every entry through masks. */
function selectMasked(digit, table = gtTable) {
  gtAcc.fill(0)
  const n = gtAcc.length
  for (let j = 0; j < table.length; j++) {
    const mask = ((j ^ digit) - 1) >> 31
    const v = table[j].v
    for (let l = 0; l < n; l++) gtAcc[l] |= v[l] & mask
  }
  const out = gtSel.v
  for (let l = 0; l < n; l++) out[l] = gtAcc[l]
}

/**
 * r = g^k for g in GT and k a 32-byte big-endian scalar. Fixed 4-bit windows,
 * one squaring chain and one multiplication per window whatever the digit, and
 * a full masked table scan: regular for a secret k. r must not alias g.
 */
export function gtPow(r, g, k) {
  buildTable(g)
  fp12One(r)
  for (let i = 0; i < 64; i++) {
    const byte = k[i >>> 1]
    const digit = (i & 1) === 0 ? byte >>> 4 : byte & 15
    for (let s = 0; s < WINDOW; s++) fp12CycSqr(r, r)
    selectMasked(digit)
    fp12Mul(r, r, gtSel)
  }
  gtAcc.fill(0)
  gtSel.v.fill(0)
  for (const t of gtTable) t.v.fill(0)
}

// ---- fixed base: Lim-Lee comb with 4 teeth ----

const COMB_TEETH = 4
const COMB_D = 64

/**
 * Comb table for a fixed g in GT (a cached master-key pairing): entry b is the
 * product over the set bits j of b of g^(2^(64 j)). Public data.
 */
export function gtMakeComb(g) {
  const table = Array.from({ length: 1 << COMB_TEETH }, () => new Fp12())
  const B = new Fp12()
  fp12Copy(B, g)
  fp12One(table[0])
  for (let j = 0; j < COMB_TEETH; j++) {
    if (j > 0) for (let s = 0; s < COMB_D; s++) fp12CycSqr(B, B)
    const half = 1 << j
    for (let b = 0; b < half; b++) fp12Mul(table[half + b], table[b], B)
  }
  return table
}

/**
 * r = g^k from g's comb table: one cyclotomic squaring and one multiplication
 * per column. secret selects the full masked table scan.
 */
export function gtPowComb(r, table, k, secret) {
  fp12One(r)
  for (let i = COMB_D - 1; i >= 0; i--) {
    fp12CycSqr(r, r)
    let index = 0
    for (let j = 0; j < COMB_TEETH; j++) {
      const p = COMB_D * j + i
      index |= ((k[31 - (p >>> 3)] >>> (p & 7)) & 1) << j
    }
    if (secret) {
      selectMasked(index, table)
      fp12Mul(r, r, gtSel)
    } else {
      fp12Mul(r, r, table[index])
    }
  }
  gtAcc.fill(0)
  gtSel.v.fill(0)
}

/** Best-effort erasure of the pairing scratch, which can hold secret-derived values. */
export function wipePairingScratch() {
  const fp2s = [TX, TY, TZ, l0, l2, l3, A, B, C, D, E, F, G, H, YZ]
  for (const e of fp2s) e.v.fill(0)
  for (const e of [q1x, q1y, q2x, q2y]) e.v.fill(0)
  xP.fill(0)
  negYP.fill(0)
  negTwoYP.fill(0)
  for (const e of [e0, e1, fx, fx2, fx3, y0, y1, y2, y3, y4, y5, y6]) {
    e.v.fill(0)
  }
  millerValue.v.fill(0)
}
