/**
 * G1 = E(Fq), y^2 = x^3 + 5, and G2 on the twist E'(Fq2), y^2 = x^3 + 5u:
 * byte encodings, validation and scalar multiplication. Internal module, not
 * part of the public API.
 *
 * Points cross this boundary as affine objects {x, y} (Fq limbs for G1, Fp2 for
 * G2), never the identity. Encodings: G1 04 || x || y (65 bytes), G2
 * 04 || x1 || x0 || y1 || y0 (129 bytes). Decoding is constant-flow up to the
 * final valid or invalid answer, because private keys are points too.
 */
import { makeCurve } from './curve.js'
import {
  FP_ONE,
  Q_BYTES,
  bytesBelowMask,
  feAdd,
  feCopy,
  feMulSmall,
  feNew,
  feSub,
  fpConstant,
  fpFromBytes,
  fpInv,
  fpIsZeroMask,
  fpMul,
  fpSqr,
  fpToBytes,
  hexBytes,
} from './fp.js'
import {
  FP2_SIZE,
  Fp2,
  fp2Add,
  fp2Copy,
  fp2EqualMask,
  fp2Inv,
  fp2IsZeroMask,
  fp2Mul,
  fp2MulSmall,
  fp2MulU,
  fp2One,
  fp2Sqr,
  fp2Sub,
  fp2Zero,
} from './fp2.js'
import { N_BYTES } from './scalar.js'

export const G1_BYTES = 65
export const G2_BYTES = 129

const g1Curve = makeCurve({
  newElem: feNew,
  raw: (e) => e,
  size: 11,
  copy: feCopy,
  add: feAdd,
  sub: feSub,
  mul: fpMul,
  sqr: fpSqr,
  mulSmall: feMulSmall,
  mulB3: (r, a) => feMulSmall(r, a, 15),
  one: (r) => feCopy(r, FP_ONE),
  zero: (r) => r.fill(0),
  inv: fpInv,
  isZeroMask: fpIsZeroMask,
})

const g2Curve = makeCurve({
  newElem: () => new Fp2(),
  raw: (e) => e.v,
  size: FP2_SIZE,
  copy: fp2Copy,
  add: fp2Add,
  sub: fp2Sub,
  mul: fp2Mul,
  sqr: fp2Sqr,
  mulSmall: fp2MulSmall,
  mulB3: (r, a) => {
    fp2MulU(r, a)
    fp2MulSmall(r, r, 15)
  },
  one: fp2One,
  zero: fp2Zero,
  inv: fp2Inv,
  isZeroMask: fp2IsZeroMask,
})

const FP_FIVE = fpConstant(
  '0000000000000000000000000000000000000000000000000000000000000005',
)

// ---- G1 ----

const c1 = feNew()
const c2 = feNew()

/** -1 if y^2 = x^3 + 5, else 0. */
function g1OnCurveMask(x, y) {
  fpSqr(c1, y)
  fpSqr(c2, x)
  fpMul(c2, c2, x)
  feAdd(c2, c2, FP_FIVE)
  feSub(c1, c1, c2)
  return fpIsZeroMask(c1)
}

/** Decodes 04 || x || y. Returns {x, y} or null. */
export function g1Decode(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== G1_BYTES) return null
  let ok = ((bytes[0] ^ 4) - 1) >> 31
  ok &= bytesBelowMask(bytes, 1, Q_BYTES) & bytesBelowMask(bytes, 33, Q_BYTES)
  const x = feNew()
  const y = feNew()
  fpFromBytes(x, bytes, 1)
  fpFromBytes(y, bytes, 33)
  ok &= g1OnCurveMask(x, y)
  if (ok === 0) {
    x.fill(0)
    y.fill(0)
    return null
  }
  return { x, y }
}

/** 64 bytes x || y. */
export function g1XY(P) {
  const out = new Uint8Array(64)
  fpToBytes(out, P.x, 0)
  fpToBytes(out, P.y, 32)
  return out
}

/** 65 bytes 04 || x || y. */
export function g1Encode(P) {
  const out = new Uint8Array(G1_BYTES)
  out[0] = 4
  fpToBytes(out, P.x, 1)
  fpToBytes(out, P.y, 33)
  return out
}

const g1R = g1Curve.newPoint()
const g1S = g1Curve.newPoint()

function g1Result(R) {
  const x = feNew()
  const y = feNew()
  return g1Curve.toAffine(x, y, R) ? { x, y } : null
}

/** k P for a secret 32-byte scalar. Returns null for the identity. */
export function g1MulSecret(P, k) {
  g1Curve.fromAffine(g1S, P.x, P.y)
  g1Curve.mulSecret(g1R, g1S, k)
  const out = g1Result(g1R)
  g1Curve.setIdentity(g1R)
  g1Curve.setIdentity(g1S)
  return out
}

/** k P for a public 32-byte scalar. Returns null for the identity. */
export function g1MulPublic(P, k) {
  g1Curve.fromAffine(g1S, P.x, P.y)
  g1Curve.mulPublic(g1R, g1S, k)
  return g1Result(g1R)
}

/** P + Q, or null for the identity. */
export function g1Add(P, Q) {
  g1Curve.fromAffine(g1R, P.x, P.y)
  g1Curve.fromAffine(g1S, Q.x, Q.y)
  g1Curve.add(g1R, g1R, g1S)
  return g1Result(g1R)
}

// ---- G2 ----

const d1 = new Fp2()
const d2 = new Fp2()
const B_TWIST = new Fp2()
feCopy(B_TWIST.c1, FP_FIVE)

/** -1 if y^2 = x^3 + 5u, else 0. */
function g2OnCurveMask(x, y) {
  fp2Sqr(d1, y)
  fp2Sqr(d2, x)
  fp2Mul(d2, d2, x)
  fp2Add(d2, d2, B_TWIST)
  return fp2EqualMask(d1, d2)
}

const g2R = g2Curve.newPoint()
const g2S = g2Curve.newPoint()

/** -1 if N Q is the identity. N is public, so this may run on a private key. */
function g2SubgroupMask(Q) {
  g2Curve.fromAffine(g2S, Q.x, Q.y)
  g2Curve.mulPublic(g2R, g2S, N_BYTES)
  const mask = fp2IsZeroMask(g2R.z)
  g2Curve.wipe()
  g2Curve.setIdentity(g2R)
  g2Curve.setIdentity(g2S)
  return mask
}

/** Decodes 04 || x1 || x0 || y1 || y0, including the subgroup check. */
export function g2Decode(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== G2_BYTES) return null
  let ok = ((bytes[0] ^ 4) - 1) >> 31
  for (let o = 1; o < G2_BYTES; o += 32) ok &= bytesBelowMask(bytes, o, Q_BYTES)
  const x = new Fp2()
  const y = new Fp2()
  fpFromBytes(x.c1, bytes, 1)
  fpFromBytes(x.c0, bytes, 33)
  fpFromBytes(y.c1, bytes, 65)
  fpFromBytes(y.c0, bytes, 97)
  ok &= g2OnCurveMask(x, y)
  // An off-curve input would make the subgroup test meaningless, not unsafe.
  ok &= g2SubgroupMask({ x, y })
  if (ok === 0) {
    x.v.fill(0)
    y.v.fill(0)
    return null
  }
  return { x, y }
}

/** 129 bytes 04 || x1 || x0 || y1 || y0. */
export function g2Encode(P) {
  const out = new Uint8Array(G2_BYTES)
  out[0] = 4
  fpToBytes(out, P.x.c1, 1)
  fpToBytes(out, P.x.c0, 33)
  fpToBytes(out, P.y.c1, 65)
  fpToBytes(out, P.y.c0, 97)
  return out
}

function g2Result(R) {
  const x = new Fp2()
  const y = new Fp2()
  return g2Curve.toAffine(x, y, R) ? { x, y } : null
}

/** k Q for a secret 32-byte scalar. Returns null for the identity. */
export function g2MulSecret(Q, k) {
  g2Curve.fromAffine(g2S, Q.x, Q.y)
  g2Curve.mulSecret(g2R, g2S, k)
  const out = g2Result(g2R)
  g2Curve.setIdentity(g2R)
  g2Curve.setIdentity(g2S)
  return out
}

/** k Q for a public 32-byte scalar. Returns null for the identity. */
export function g2MulPublic(Q, k) {
  g2Curve.fromAffine(g2S, Q.x, Q.y)
  g2Curve.mulPublic(g2R, g2S, k)
  return g2Result(g2R)
}

/** P + Q, or null for the identity. */
export function g2Add(P, Q) {
  g2Curve.fromAffine(g2R, P.x, P.y)
  g2Curve.fromAffine(g2S, Q.x, Q.y)
  g2Curve.add(g2R, g2R, g2S)
  return g2Result(g2R)
}

// ---- generators ----

export const P1 = g1Decode(
  hexBytes(
    '0493de051d62bf718ff5ed0704487d01d6e1e4086909dc3280e8c4e4817c66dddd' +
      '21fe8dda4f21e607631065125c395bbc1c1c00cbfa6024350c464cd70a3ea616',
  ),
)
export const P2 = g2Decode(
  hexBytes(
    '0485aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141' +
      '3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b' +
      '17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96' +
      'a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7',
  ),
)
if (P1 === null || P2 === null) throw new Error('SM9 generator check failed')

// ---- fixed-base multiplication of the generators ----

/** Secret scalars use 4 teeth (16-entry masked scan), public ones 8 teeth. */
const SECRET_TEETH = 4
const PUBLIC_TEETH = 8
const combs = new Map()

function combFor(curve, P, name, teeth) {
  const key = name + teeth
  let comb = combs.get(key)
  if (comb === undefined) {
    const R = curve.newPoint()
    curve.fromAffine(R, P.x, P.y)
    comb = curve.makeComb(R, teeth)
    combs.set(key, comb)
  }
  return comb
}

/** k P1. secret selects the regular schedule. Returns null for the identity. */
export function g1MulBase(k, secret) {
  const comb = combFor(g1Curve, P1, 'P1', secret ? SECRET_TEETH : PUBLIC_TEETH)
  g1Curve.mulComb(g1R, comb, k, secret)
  const out = g1Result(g1R)
  g1Curve.setIdentity(g1R)
  return out
}

/** k P2. secret selects the regular schedule. Returns null for the identity. */
export function g2MulBase(k, secret) {
  const comb = combFor(g2Curve, P2, 'P2', secret ? SECRET_TEETH : PUBLIC_TEETH)
  g2Curve.mulComb(g2R, comb, k, secret)
  const out = g2Result(g2R)
  g2Curve.setIdentity(g2R)
  return out
}

/** Best-effort erasure of the group scratch. */
export function wipeGroupScratch() {
  g1Curve.wipe()
  g2Curve.wipe()
  for (const e of [c1, c2]) e.fill(0)
  for (const e of [d1, d2]) e.v.fill(0)
  for (const p of [g1R, g1S]) for (const e of [p.x, p.y, p.z]) e.fill(0)
  for (const p of [g2R, g2S]) for (const e of [p.x, p.y, p.z]) e.v.fill(0)
}
