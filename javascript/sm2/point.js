/**
 * SM2 curve group operations on Jacobian coordinates (a = -3).
 *
 * Internal module, not part of the public API. Inputs and outputs at this
 * boundary are 32-byte big-endian Uint8Arrays.
 *
 * Secret scalars (mulG, mulPoint) use signed fixed windows, scan the whole table
 * through masks and have no scalar-dependent branches. Public scalars (mulPublic
 * and verifyCombination) use wNAF and branch freely. JavaScript cannot give a
 * real constant-time guarantee, because the JIT, the GC and the CPU are all out
 * of reach, so treat the fixed-window paths as hardening rather than a proof.
 */
import {
  LIMBS,
  FP_B,
  FP_ONE,
  feAdd,
  feCarry,
  feCopy,
  feNew,
  feSelect,
  feSub,
  fnFromBytes,
  fnToBytes,
  fpFromBytes,
  fpInv,
  fpIsZeroMask,
  fpMul,
  fpSqr,
  fpSqrtCandidate,
  fpToBytes,
} from './fe.js'

const GX = '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
const GY = 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0'

function bytesFromHex(hex) {
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.substring(2 * i, 2 * i + 2), 16)
  }
  return out
}

export const G_X_BYTES = bytesFromHex(GX)
export const G_Y_BYTES = bytesFromHex(GY)

class Jacobian {
  constructor() {
    this.x = feNew()
    this.y = feNew()
    this.z = feNew()
  }
}

// ---- formula scratch space; none of it holds state between calls ----

const t0 = feNew()
const t1 = feNew()
const t2 = feNew()
const t3 = feNew()
const t4 = feNew()
const t5 = feNew()
const t6 = feNew()
const addH = feNew()
const addR = feNew()

/** dbl-2001-b: R = 2P. R may alias P. The result for Z = 0 has Z = 0. */
function dbl(R, P) {
  const { x, y, z } = P
  fpSqr(t0, z) // delta
  fpSqr(t1, y) // gamma
  fpMul(t2, x, t1) // beta
  feSub(t3, x, t0)
  feAdd(t4, x, t0)
  fpMul(t3, t3, t4)
  for (let i = 0; i < LIMBS; i++) t3[i] *= 3
  feCarry(t3, t3) // alpha
  fpMul(R.z, y, z)
  for (let i = 0; i < LIMBS; i++) R.z[i] *= 2
  feCarry(R.z, R.z)
  fpSqr(t4, t3)
  const rx = R.x
  for (let i = 0; i < LIMBS; i++) rx[i] = t4[i] - 8 * t2[i]
  feCarry(rx, rx)
  for (let i = 0; i < LIMBS; i++) t4[i] = 4 * t2[i] - rx[i]
  fpMul(t4, t3, t4)
  fpSqr(t1, t1)
  const ry = R.y
  for (let i = 0; i < LIMBS; i++) ry[i] = t4[i] - 8 * t1[i]
  feCarry(ry, ry)
}

/**
 * Mixed addition: R = P + (x2, y2, 1). R may alias P. Not valid when P is at
 * infinity or P = +-(x2, y2); addH and addR expose the test for those cases.
 */
function madd(R, P, x2, y2) {
  const { x, y, z } = P
  fpSqr(t0, z)
  fpMul(t1, x2, t0)
  fpMul(t2, y2, t0)
  fpMul(t2, t2, z)
  feSub(addH, t1, x)
  feSub(addR, t2, y)
  fpMul(R.z, z, addH)
  feCarry(R.z, R.z)
  fpSqr(t3, addH) // HH
  fpMul(t4, addH, t3) // HHH
  fpMul(t3, x, t3) // V
  fpMul(t5, y, t4) // Y1 * HHH
  fpSqr(t6, addR)
  const rx = R.x
  for (let i = 0; i < LIMBS; i++) rx[i] = t6[i] - t4[i] - 2 * t3[i]
  feCarry(rx, rx)
  feSub(t3, t3, rx)
  fpMul(t3, addR, t3)
  const ry = R.y
  for (let i = 0; i < LIMBS; i++) ry[i] = t3[i] - t5[i]
  feCarry(ry, ry)
}

/** add-1998-cmo: R = P + Q. R may alias P. Same exceptions as madd. */
function add(R, P, Q) {
  fpSqr(t0, Q.z)
  fpMul(t1, P.x, t0) // U1
  fpMul(t0, t0, Q.z)
  fpMul(t2, P.y, t0) // S1
  fpSqr(t0, P.z)
  fpMul(t3, Q.x, t0) // U2
  fpMul(t0, t0, P.z)
  fpMul(t4, Q.y, t0) // S2
  feSub(addH, t3, t1)
  feSub(addR, t4, t2)
  fpMul(t3, P.z, Q.z)
  fpMul(R.z, t3, addH)
  feCarry(R.z, R.z)
  fpSqr(t3, addH) // HH
  fpMul(t4, addH, t3) // HHH
  fpMul(t3, t1, t3) // V = U1 * HH
  fpMul(t5, t2, t4) // S1 * HHH
  fpSqr(t6, addR)
  const rx = R.x
  for (let i = 0; i < LIMBS; i++) rx[i] = t6[i] - t4[i] - 2 * t3[i]
  feCarry(rx, rx)
  feSub(t3, t3, rx)
  fpMul(t3, addR, t3)
  const ry = R.y
  for (let i = 0; i < LIMBS; i++) ry[i] = t3[i] - t5[i]
  feCarry(ry, ry)
}

/**
 * Public-data only. A carried sum can be a small multiple of p, and p = -1 mod
 * 2^24, so the low limb of a zero value is a small integer. Anything else is
 * rejected without the multiplication that the exact test needs.
 */
function isZeroVar(a) {
  if (((a[0] + 15) & 0xffffff) > 30) return false
  return fpIsZeroMask(a) !== 0
}

/**
 * Best-effort erasure of intermediate values derived from a secret scalar. The
 * garbage collector may have copied or may retain what JavaScript cannot reach.
 */
function wipeSecretScratch() {
  for (const a of FORMULA_SCRATCH) a.fill(0)
  for (const p of SCRATCH_POINTS) {
    p.x.fill(0)
    p.y.fill(0)
    p.z.fill(0)
  }
  selAcc.fill(0)
  selX.fill(0)
  selY.fill(0)
  varTable.fill(0)
  scalarBytes.fill(0)
  fixedDigits.fill(0)
  varDigits.fill(0)
  affineZ.fill(0)
  affineZ2.fill(0)
  affineTmp.fill(0)
}

// ---- conversion ----

const affineZ = feNew()
const affineZ2 = feNew()
const affineTmp = feNew()

/** Writes canonical affine bytes. Z must be nonzero. */
function toAffineBytes(P, outX, outY) {
  fpInv(affineZ, P.z)
  fpSqr(affineZ2, affineZ)
  fpMul(affineTmp, P.x, affineZ2)
  fpToBytes(outX, affineTmp)
  fpMul(affineZ2, affineZ2, affineZ)
  fpMul(affineTmp, P.y, affineZ2)
  fpToBytes(outY, affineTmp)
}

const curveX = feNew()
const curveY = feNew()
const curveL = feNew()
const curveR = feNew()

/** Whether (x, y), in Montgomery form, satisfies y^2 = x^3 - 3x + b. */
function isOnCurveFe(x, y) {
  fpSqr(curveL, y)
  fpSqr(curveR, x)
  fpMul(curveR, curveR, x)
  for (let i = 0; i < LIMBS; i++) {
    curveR[i] = curveR[i] - 3 * x[i] + FP_B[i] - curveL[i]
  }
  return fpIsZeroMask(curveR) !== 0
}

export function isOnCurve(xBytes, yBytes) {
  fpFromBytes(curveX, xBytes)
  fpFromBytes(curveY, yBytes)
  return isOnCurveFe(curveX, curveY)
}

// ---- scalars ----

const scalarFe = feNew()
const scalarBytes = new Uint8Array(32)

/** out = k mod n, for any 256-bit k. Fixed sequence of operations. */
function reduceScalar(out, k) {
  fnFromBytes(scalarFe, k)
  // fnToBytes divides by R, which fnFromBytes multiplied in.
  fnToBytes(out, scalarFe)
}

/** Signed fixed-window recoding: digits in [-(2^(w-1) - 1), 2^(w-1)]. No branches. */
function recodeSigned(digits, k, w, windows) {
  const half = 1 << (w - 1)
  const mask = (1 << w) - 1
  let carry = 0
  for (let i = 0; i < windows; i++) {
    const bit = i * w
    const lo = 31 - (bit >>> 3)
    const hi = lo - 1
    const pair = (lo >= 0 ? k[lo] : 0) | ((hi >= 0 ? k[hi] : 0) << 8)
    const value = ((pair >>> (bit & 7)) & mask) + carry
    carry = ((half - value) >> 31) & 1
    digits[i] = value - (carry << w)
  }
}

// ---- secret scalar: fixed base ----

const FIXED_W = 6
const FIXED_WINDOWS = 43
const FIXED_ENTRIES = 32
const FIXED_POINT_SIZE = 2 * LIMBS
let fixedTable = null

const fixedDigits = new Int32Array(FIXED_WINDOWS)
const selX = feNew()
const selY = feNew()
const selAcc = new Int32Array(3 * LIMBS)

/** Montgomery's trick: converts Jacobian points to affine limbs in `out`. */
function batchToAffine(points, out) {
  const count = points.length
  const prefix = new Float64Array(count * LIMBS)
  const acc = feNew()
  const inverse = feNew()
  const zInv = feNew()
  const zz = feNew()
  const value = feNew()
  feCopy(acc, FP_ONE)
  for (let i = 0; i < count; i++) {
    prefix.set(acc, i * LIMBS)
    fpMul(acc, acc, points[i].z)
  }
  fpInv(inverse, acc)
  for (let i = count - 1; i >= 0; i--) {
    const before = prefix.subarray(i * LIMBS, (i + 1) * LIMBS)
    fpMul(zInv, inverse, before)
    fpMul(inverse, inverse, points[i].z)
    fpSqr(zz, zInv)
    fpMul(value, points[i].x, zz)
    const base = i * FIXED_POINT_SIZE
    for (let l = 0; l < LIMBS; l++) out[base + l] = value[l]
    fpMul(zz, zz, zInv)
    fpMul(value, points[i].y, zz)
    for (let l = 0; l < LIMBS; l++) out[base + LIMBS + l] = value[l]
  }
}

function baseJacobian() {
  const g = new Jacobian()
  fpFromBytes(g.x, G_X_BYTES)
  fpFromBytes(g.y, G_Y_BYTES)
  feCopy(g.z, FP_ONE)
  return g
}

function copyPoint(r, p) {
  feCopy(r.x, p.x)
  feCopy(r.y, p.y)
  feCopy(r.z, p.z)
}

/** Table of d * 2^(6i) * G for d in 1..32, built on first use. */
function getFixedTable() {
  if (fixedTable !== null) return fixedTable
  const points = []
  let base = baseJacobian()
  for (let window = 0; window < FIXED_WINDOWS; window++) {
    let previous = null
    for (let d = 1; d <= FIXED_ENTRIES; d++) {
      const p = new Jacobian()
      if (d === 1) copyPoint(p, base)
      else if (d === 2) dbl(p, base)
      else add(p, previous, base)
      points.push(p)
      previous = p
    }
    const next = new Jacobian()
    dbl(next, previous)
    base = next
  }
  const table = new Int32Array(points.length * FIXED_POINT_SIZE)
  batchToAffine(points, table)
  fixedTable = table
  return table
}

const selMasks = new Int32Array(FIXED_ENTRIES)

/**
 * Scans all `count` affine entries with masks, then negates y through a mask.
 * It goes limb by limb with a local accumulator, which measured faster than
 * accumulating entry by entry in a typed array.
 */
function selectAffine(table, offset, count, digit, outX, outY) {
  const sign = digit >> 31
  const abs = (digit ^ sign) - sign
  const masks = selMasks
  for (let j = 0; j < count; j++) masks[j] = (((j + 1) ^ abs) - 1) >> 31
  for (let l = 0; l < LIMBS; l++) {
    let x = 0
    let y = 0
    let at = offset + l
    for (let j = 0; j < count; j++, at += FIXED_POINT_SIZE) {
      const m = masks[j]
      x |= table[at] & m
      y |= table[at + LIMBS] & m
    }
    outX[l] = x
    outY[l] = (y ^ sign) - sign
  }
  masks.fill(0)
}

const fixedR = new Jacobian()
const fixedT = new Jacobian()

/**
 * out = k * G. Returns false for the point at infinity, i.e. k = 0 mod n.
 *
 * Adds from the lowest window up, so the partial sum S satisfies |S| < 2^(6i) at
 * window i. A mixed addition is exceptional only if S = +-d * 2^(6i) mod n. Size
 * rules out equality without wrapping, and wrapping around n would need k >= n or
 * k = 0, so for a reduced nonzero k the only special case is S at infinity.
 */
export function mulG(k, outX, outY) {
  const table = getFixedTable()
  reduceScalar(scalarBytes, k)
  recodeSigned(fixedDigits, scalarBytes, FIXED_W, FIXED_WINDOWS)
  const R = fixedR
  const T = fixedT
  R.x.fill(0)
  R.y.fill(0)
  R.z.fill(0)
  let infinity = -1
  const windowSize = FIXED_ENTRIES * FIXED_POINT_SIZE
  for (let i = 0; i < FIXED_WINDOWS; i++) {
    const digit = fixedDigits[i]
    selectAffine(table, i * windowSize, FIXED_ENTRIES, digit, selX, selY)
    madd(T, R, selX, selY)
    const nonzero = ~((digit - 1) >> 31) | (digit >> 31)
    // infinity and nonzero: take the table point; otherwise: the sum if nonzero.
    feSelect(T.x, T.x, selX, infinity)
    feSelect(T.y, T.y, selY, infinity)
    feSelect(T.z, T.z, FP_ONE, infinity)
    feSelect(R.x, R.x, T.x, nonzero)
    feSelect(R.y, R.y, T.y, nonzero)
    feSelect(R.z, R.z, T.z, nonzero)
    infinity &= ~nonzero
  }
  const finite = infinity === 0
  if (finite) toAffineBytes(R, outX, outY)
  wipeSecretScratch()
  return finite
}

// ---- secret scalar: variable base ----

const VAR_W = 5
const VAR_WINDOWS = 52
const VAR_ENTRIES = 16
const VAR_POINT_SIZE = 3 * LIMBS
const varTable = new Int32Array(VAR_ENTRIES * VAR_POINT_SIZE)
const varDigits = new Int32Array(VAR_WINDOWS)
const varBase = new Jacobian()
const varR = new Jacobian()
const varS = new Jacobian()
const varT = new Jacobian()
const varD = new Jacobian()

const FORMULA_SCRATCH = [t0, t1, t2, t3, t4, t5, t6, addH, addR, scalarFe]
const SCRATCH_POINTS = [fixedR, fixedT, varBase, varR, varS, varT, varD]

function storeJacobian(table, index, p) {
  const base = index * VAR_POINT_SIZE
  for (let l = 0; l < LIMBS; l++) {
    table[base + l] = p.x[l]
    table[base + LIMBS + l] = p.y[l]
    table[base + 2 * LIMBS + l] = p.z[l]
  }
}

function selectJacobian(table, digit, out) {
  const sign = digit >> 31
  const abs = (digit ^ sign) - sign
  selAcc.fill(0)
  for (let j = 0; j < VAR_ENTRIES; j++) {
    const m = (((j + 1) ^ abs) - 1) >> 31
    const entry = j * VAR_POINT_SIZE
    for (let l = 0; l < VAR_POINT_SIZE; l++) {
      selAcc[l] |= table[entry + l] & m
    }
  }
  for (let l = 0; l < LIMBS; l++) {
    out.x[l] = selAcc[l]
    out.y[l] = (selAcc[LIMBS + l] ^ sign) - sign
    out.z[l] = selAcc[2 * LIMBS + l]
  }
}

/**
 * out = k * (px, py), for a point already known to be on the curve. Returns
 * false for infinity.
 *
 * Works from the top window down. Before an addition R = A * P with A a multiple
 * of 32 and |d| <= 16, so a nonzero A cannot equal +-d unless it wraps around n,
 * and that needs |A| close to n, which can only happen in the final window. That
 * one addition therefore also computes the doubling and selects it with a mask.
 */
export function mulPoint(px, py, k, outX, outY) {
  const P = varBase
  fpFromBytes(P.x, px)
  fpFromBytes(P.y, py)
  feCopy(P.z, FP_ONE)
  reduceScalar(scalarBytes, k)
  recodeSigned(varDigits, scalarBytes, VAR_W, VAR_WINDOWS)

  const T = varT
  storeJacobian(varTable, 0, P)
  dbl(T, P)
  storeJacobian(varTable, 1, T)
  for (let d = 3; d <= VAR_ENTRIES; d++) {
    madd(T, T, P.x, P.y)
    storeJacobian(varTable, d - 1, T)
  }

  const R = varR
  const S = varS
  R.x.fill(0)
  R.y.fill(0)
  R.z.fill(0)
  let infinity = -1
  for (let i = VAR_WINDOWS - 1; i >= 0; i--) {
    for (let s = 0; s < VAR_W; s++) dbl(R, R)
    const digit = varDigits[i]
    selectJacobian(varTable, digit, S)
    add(T, R, S)
    if (i === 0) {
      const same = fpIsZeroMask(addH) & fpIsZeroMask(addR)
      dbl(varD, S)
      feSelect(T.x, T.x, varD.x, same)
      feSelect(T.y, T.y, varD.y, same)
      feSelect(T.z, T.z, varD.z, same)
    }
    const nonzero = ~((digit - 1) >> 31) | (digit >> 31)
    feSelect(T.x, T.x, S.x, infinity)
    feSelect(T.y, T.y, S.y, infinity)
    feSelect(T.z, T.z, S.z, infinity)
    feSelect(R.x, R.x, T.x, nonzero)
    feSelect(R.y, R.y, T.y, nonzero)
    feSelect(R.z, R.z, T.z, nonzero)
    infinity &= ~nonzero
  }
  const finite = infinity === 0 && fpIsZeroMask(R.z) === 0
  if (finite) toAffineBytes(R, outX, outY)
  wipeSecretScratch()
  return finite
}

// ---- public scalars: wNAF, variable time ----

const WNAF_G = 8
const WNAF_P = 5
const WNAF_LENGTH = 258
const nafG = new Int16Array(WNAF_LENGTH)
const nafP = new Int16Array(WNAF_LENGTH)
let gOddTable = null

/** Width-w NAF of a reduced public scalar. Returns the highest nonzero index, or -1. */
function wnaf(digits, k, w) {
  digits.fill(0)
  const mask = (1 << w) - 1
  let carry = 0
  let top = -1
  let i = 0
  while (i < WNAF_LENGTH) {
    const lo = 31 - (i >>> 3)
    const hi = lo - 1
    const hi2 = lo - 2
    const bits =
      (lo >= 0 ? k[lo] : 0) |
      ((hi >= 0 ? k[hi] : 0) << 8) |
      ((hi2 >= 0 ? k[hi2] : 0) << 16)
    const value = (bits >>> (i & 7)) & mask
    if ((value & 1) === carry) {
      i++
      continue
    }
    const v = value + carry
    carry = (v >>> (w - 1)) & 1
    digits[i] = v - (carry << w)
    top = i
    i += w
  }
  return top
}

/** Odd multiples 1G, 3G, ..., (2^(w-1) - 1)G as affine limbs, built on first use. */
function getGOddTable() {
  if (gOddTable !== null) return gOddTable
  const count = 1 << (WNAF_G - 2)
  const g = baseJacobian()
  const two = new Jacobian()
  dbl(two, g)
  const points = [g]
  for (let i = 1; i < count; i++) {
    const p = new Jacobian()
    add(p, points[i - 1], two)
    points.push(p)
  }
  const table = new Int32Array(count * FIXED_POINT_SIZE)
  batchToAffine(points, table)
  gOddTable = table
  return table
}

const pubR = new Jacobian()
const pubT = new Jacobian()
const pubD = new Jacobian()
const pubQ = new Jacobian()
const pubOdd = Array.from({ length: 1 << (WNAF_P - 2) }, () => new Jacobian())
const negY = feNew()
const affX = feNew()
const affY = feNew()

function buildOddMultiples(q) {
  copyPoint(pubOdd[0], q)
  dbl(pubD, q)
  for (let i = 1; i < pubOdd.length; i++) {
    add(pubOdd[i], pubOdd[i - 1], pubD)
  }
}

/** Interleaved s*G + t*Q into pubR. Returns false when the result is infinity. */
function combine(topG, topQ, useQ) {
  const R = pubR
  const top = Math.max(topG, topQ)
  let infinity = true
  const gTable = topG >= 0 ? getGOddTable() : null
  for (let i = top; i >= 0; i--) {
    if (!infinity) dbl(R, R)
    const dg = nafG[i]
    if (dg !== 0) {
      const abs = dg < 0 ? -dg : dg
      const base = ((abs - 1) >> 1) * FIXED_POINT_SIZE
      for (let l = 0; l < LIMBS; l++) {
        affX[l] = gTable[base + l]
        const y = gTable[base + LIMBS + l]
        affY[l] = dg < 0 ? -y : y
      }
      if (infinity) {
        feCopy(R.x, affX)
        feCopy(R.y, affY)
        feCopy(R.z, FP_ONE)
        infinity = false
      } else {
        madd(R, R, affX, affY)
        if (isZeroVar(addH)) {
          if (isZeroVar(addR)) {
            feCopy(pubT.x, affX)
            feCopy(pubT.y, affY)
            feCopy(pubT.z, FP_ONE)
            dbl(R, pubT)
          } else {
            infinity = true
          }
        }
      }
    }
    const dq = useQ ? nafP[i] : 0
    if (dq !== 0) {
      const abs = dq < 0 ? -dq : dq
      const q = pubOdd[(abs - 1) >> 1]
      if (dq < 0) {
        for (let l = 0; l < LIMBS; l++) negY[l] = -q.y[l]
      } else {
        feCopy(negY, q.y)
      }
      copyPointWithY(pubT, q, negY)
      if (infinity) {
        copyPoint(R, pubT)
        infinity = false
      } else {
        add(R, R, pubT)
        if (isZeroVar(addH)) {
          if (isZeroVar(addR)) dbl(R, pubT)
          else infinity = true
        }
      }
    }
  }
  return !infinity
}

function copyPointWithY(r, p, y) {
  feCopy(r.x, p.x)
  feCopy(r.y, y)
  feCopy(r.z, p.z)
}

const reducedA = new Uint8Array(32)
const reducedB = new Uint8Array(32)

/** out = k * (px, py) for a public k and on-curve point. False for infinity. */
export function mulPublic(px, py, k, outX, outY) {
  reduceScalar(reducedA, k)
  const topQ = wnaf(nafP, reducedA, WNAF_P)
  nafG.fill(0)
  fpFromBytes(pubQ.x, px)
  fpFromBytes(pubQ.y, py)
  feCopy(pubQ.z, FP_ONE)
  buildOddMultiples(pubQ)
  if (!combine(-1, topQ, true)) return false
  toAffineBytes(pubR, outX, outY)
  return true
}

const verifyZ2 = feNew()
const verifyX = feNew()

/**
 * Computes R = s*G + t*Q for public s and t, and tests whether R.x, reduced mod
 * n, equals `candidate`. Comparing X with x * Z^2 avoids a field inversion.
 * Returns -1 if R is at infinity, otherwise 1 for a match and 0 for no match.
 * candidate is null when no reduced value can match. candidatePlusN is
 * candidate + n when that value is below p, otherwise null.
 */
export function verifyCombination(s, t, qx, qy, candidate, candidatePlusN) {
  reduceScalar(reducedA, s)
  reduceScalar(reducedB, t)
  const topG = wnaf(nafG, reducedA, WNAF_G)
  const topQ = wnaf(nafP, reducedB, WNAF_P)
  fpFromBytes(pubQ.x, qx)
  fpFromBytes(pubQ.y, qy)
  feCopy(pubQ.z, FP_ONE)
  buildOddMultiples(pubQ)
  if (!combine(topG, topQ, true)) return -1
  const R = pubR
  fpSqr(verifyZ2, R.z)
  if (candidate === null) return 0
  if (matchesX(R, candidate)) return 1
  return candidatePlusN !== null && matchesX(R, candidatePlusN) ? 1 : 0
}

function matchesX(R, xBytes) {
  fpFromBytes(verifyX, xBytes)
  fpMul(verifyX, verifyX, verifyZ2)
  feSub(verifyX, verifyX, R.x)
  return isZeroVar(verifyX)
}

// ---- affine helpers used by the public point class ----

const aX = feNew()
const aY = feNew()
const bX = feNew()
const bY = feNew()
const lambda = feNew()
const denom = feNew()
const num = feNew()
const outXFe = feNew()

function finishAffine(lam, x1, y1, x2, outX, outY) {
  fpSqr(outXFe, lam)
  for (let i = 0; i < LIMBS; i++) outXFe[i] = outXFe[i] - x1[i] - x2[i]
  feCarry(outXFe, outXFe)
  feSub(num, x1, outXFe)
  fpMul(num, lam, num)
  feSub(num, num, y1)
  fpToBytes(outX, outXFe)
  fpToBytes(outY, num)
}

/**
 * Affine doubling, as defined by the group law. It uses only a = -3, so it is
 * also correct for off-curve input. Returns false when y = 0.
 */
export function affineDouble(x, y, outX, outY) {
  fpFromBytes(aX, x)
  fpFromBytes(aY, y)
  if (fpIsZeroMask(aY) !== 0) return false
  fpSqr(num, aX)
  for (let i = 0; i < LIMBS; i++) num[i] = 3 * num[i] - 3 * FP_ONE[i]
  feCarry(num, num)
  for (let i = 0; i < LIMBS; i++) denom[i] = 2 * aY[i]
  fpInv(denom, denom)
  fpMul(lambda, num, denom)
  finishAffine(lambda, aX, aY, aX, outX, outY)
  return true
}

/**
 * Affine addition by the chord formula. Returns 1 for a normal result, 2 if the
 * points are equal (the caller doubles) and 0 if they are inverses (infinity).
 */
export function affineAdd(x1, y1, x2, y2, outX, outY) {
  fpFromBytes(aX, x1)
  fpFromBytes(aY, y1)
  fpFromBytes(bX, x2)
  fpFromBytes(bY, y2)
  feSub(denom, bX, aX)
  feSub(num, bY, aY)
  if (fpIsZeroMask(denom) !== 0) return fpIsZeroMask(num) !== 0 ? 2 : 0
  fpInv(denom, denom)
  fpMul(lambda, num, denom)
  finishAffine(lambda, aX, aY, bX, outX, outY)
  return 1
}

const sqrtIn = feNew()
const sqrtOut = feNew()

/** y^2 = x^3 + ax + b, then y = rhs^((p + 1) / 4). The caller picks the sign. */
export function decompressY(x, outY) {
  fpFromBytes(aX, x)
  fpSqr(sqrtIn, aX)
  fpMul(sqrtIn, sqrtIn, aX)
  for (let i = 0; i < LIMBS; i++) {
    sqrtIn[i] = sqrtIn[i] - 3 * aX[i] + FP_B[i]
  }
  feCarry(sqrtIn, sqrtIn)
  fpSqrtCandidate(sqrtOut, sqrtIn)
  fpToBytes(outY, sqrtOut)
}

// ---- field operations on bytes, for the public field element class ----

export function fieldMulBytes(a, b, out) {
  fpFromBytes(aX, a)
  fpFromBytes(aY, b)
  fpMul(num, aX, aY)
  fpToBytes(out, num)
}

export function fieldSqrBytes(a, out) {
  fpFromBytes(aX, a)
  fpSqr(num, aX)
  fpToBytes(out, num)
}

export function fieldDivBytes(a, b, out) {
  fpFromBytes(aX, a)
  fpFromBytes(aY, b)
  fpInv(denom, aY)
  fpMul(num, aX, denom)
  fpToBytes(out, num)
}
