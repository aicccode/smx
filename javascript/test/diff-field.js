/**
 * Randomized differential tests of the internal field, scalar and group code
 * against a slow reference built on native BigInt (test-only; the library itself
 * does not use BigInt). Includes edge values and maximal-carry operands.
 */
import { performance } from 'node:perf_hooks'
import * as fe from '../sm2/fe.js'
import * as pt from '../sm2/point.js'
import * as sc from '../sm2/scalar.js'
import { bigToBytes, bytesToBig } from '../sm2/bytes.js'
import { BigInteger } from '../sm2/biginteger.js'

const ITER = Number(process.env.DIFF_ITER ?? 3000)
const P = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn
const N = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n
const B = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n
const GX = 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7n
const GY = 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0n
const MASK256 = (1n << 256n) - 1n

let seed = 0x9e3779b97f4a7c15n
function rnd64() {
  seed ^= (seed << 13n) & 0xffffffffffffffffn
  seed ^= seed >> 7n
  seed ^= (seed << 17n) & 0xffffffffffffffffn
  return seed
}
const rnd256 = () =>
  (rnd64() << 192n) | (rnd64() << 128n) | (rnd64() << 64n) | rnd64()

const EDGE = [
  0n,
  1n,
  2n,
  3n,
  P - 1n,
  P - 2n,
  P,
  P + 1n,
  N - 1n,
  N,
  N + 1n,
  MASK256,
  MASK256 - 1n,
  1n << 255n,
  (1n << 255n) - 1n,
  1n << 224n,
  (1n << 224n) - 1n,
  1n << 96n,
  1n << 64n,
  (1n << 64n) - 1n,
  0xffffffn,
  0xffffffffffffn,
  0x800000800000800000800000800000800000800000800000800000800000n,
  0x7fffff7fffff7fffff7fffff7fffff7fffff7fffff7fffff7fffff7fffffn,
]

const samples = (i) => {
  const r = i % 4
  if (i < EDGE.length * EDGE.length) {
    return [EDGE[i % EDGE.length], EDGE[Math.floor(i / EDGE.length)]]
  }
  if (r === 0) return [rnd256(), rnd256()]
  if (r === 1) return [rnd256() % (1n << 128n), rnd256()]
  if (r === 2) return [MASK256 - (rnd256() % 1000n), rnd256()]
  return [P - (rnd256() % 1000n), N - (rnd256() % 1000n)]
}

const toBytes = (x) => {
  const b = new Uint8Array(32)
  let v = x & MASK256
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return b
}
const fromBytes = (b) => {
  let v = 0n
  for (const x of b) v = (v << 8n) | BigInt(x)
  return v
}
const mod = (x, m) => ((x % m) + m) % m
const pow = (a, e, m) => {
  let r = 1n
  let x = mod(a, m)
  while (e > 0n) {
    if (e & 1n) r = (r * x) % m
    x = (x * x) % m
    e >>= 1n
  }
  return r
}

let checks = 0
let failures = 0
function eq(name, got, want, context) {
  checks++
  if (got !== want) {
    failures++
    if (failures < 20) {
      console.error(`[FAIL] ${name}: got ${got} want ${want}`, context ?? '')
    }
  }
}

// ---- field and scalar ----
function fieldTests() {
  const a = fe.feNew()
  const b = fe.feNew()
  const c = fe.feNew()
  const out = new Uint8Array(32)
  const decode = (limbs) => {
    fe.fpToBytes(out, limbs)
    return fromBytes(out)
  }
  const decodeN = (limbs) => {
    fe.fnToBytes(out, limbs)
    return fromBytes(out)
  }
  for (let i = 0; i < ITER + EDGE.length ** 2; i++) {
    const [x, y] = samples(i)
    const xb = toBytes(x)
    const yb = toBytes(y)
    const xp = mod(x, P)
    const yp = mod(y, P)
    fe.fpFromBytes(a, xb)
    fe.fpFromBytes(b, yb)
    eq('fp roundtrip', decode(a), xp, x)
    fe.fpMul(c, a, b)
    eq('fp mul', decode(c), (xp * yp) % P, [x, y])
    fe.fpSqr(c, a)
    eq('fp sqr', decode(c), (xp * xp) % P, x)
    fe.feAdd(c, a, b)
    eq('fp add', decode(c), (xp + yp) % P, [x, y])
    fe.feSub(c, a, b)
    eq('fp sub', decode(c), mod(xp - yp, P), [x, y])
    fe.feCarry(c, c)
    eq('fp carry', decode(c), mod(xp - yp, P), [x, y])
    eq('fp zero', fe.fpIsZeroMask(a), xp === 0n ? -1 : 0, x)

    // Largest allowed lazy operands: k1 = k2 = 3.
    for (let l = 0; l < fe.LIMBS; l++) c[l] = a[l] + a[l] - b[l]
    const lazy = fe.feNew()
    for (let l = 0; l < fe.LIMBS; l++) lazy[l] = b[l] - a[l] - a[l]
    const r = fe.feNew()
    fe.fpMul(r, c, lazy)
    const lc = mod(2n * xp - yp, P)
    const ll = mod(yp - 2n * xp, P)
    eq('fp lazy mul', decode(r), (lc * ll) % P, [x, y])
    fe.fpSqr(r, c)
    eq('fp lazy sqr', decode(r), (lc * lc) % P, [x, y])

    if (i % 8 === 0) {
      fe.fpInv(c, a)
      eq('fp inv', decode(c), pow(xp, P - 2n, P), x)
      fe.fpSqrtCandidate(c, a)
      eq('fp sqrt', decode(c), pow(xp, (P + 1n) / 4n, P), x)
    }

    const xn = mod(x, N)
    const yn = mod(y, N)
    fe.fnFromBytes(a, xb)
    fe.fnFromBytes(b, yb)
    eq('fn roundtrip', decodeN(a), xn, x)
    fe.fnMul(c, a, b)
    eq('fn mul', decodeN(c), (xn * yn) % N, [x, y])
    fe.fnSqr(c, a)
    eq('fn sqr', decodeN(c), (xn * xn) % N, x)
    if (i % 8 === 0) {
      fe.fnInv(c, a)
      eq('fn inv', decodeN(c), pow(xn, N - 2n, N), x)
    }

    const o = new Uint8Array(32)
    eq(
      'scalar add zero flag',
      sc.scalarAdd(o, xb, yb) === 0,
      (xn + yn) % N === 0n,
    )
    eq('scalar add', fromBytes(o), (xn + yn) % N, [x, y])
    sc.scalarSub(o, xb, yb)
    eq('scalar sub', fromBytes(o), mod(xn - yn, N), [x, y])
    const zb = toBytes(rnd256())
    const zn = mod(fromBytes(zb), N)
    sc.scalarMulAdd(o, xb, yb, zb)
    eq('scalar muladd', fromBytes(o), (xn * yn + zn) % N, [x, y])
    if (i % 8 === 0) {
      sc.signatureS(o, xb, yb, zb)
      const inv = pow(xn + 1n, N - 2n, N)
      eq('signature s', fromBytes(o), (inv * mod(yn - zn * xn, N)) % N, [x, y])
    }
    eq('isBelowN', sc.isBelowN(xb), (x & MASK256) < N, x)
    const pm = sc.plusNBelowP(xb)
    const v = x & MASK256
    eq('plusN', pm === null ? null : fromBytes(pm), v + N < P ? v + N : null, x)

    if (x >= 0n && x <= MASK256) {
      const big = new BigInteger(x.toString(16), 16)
      eq('bigToBytes', fromBytes(bigToBytes(big, new Uint8Array(32))), x)
      eq('bytesToBig', bytesToBig(xb).toString(16), x.toString(16))
      eq('bytesToBig eq', bytesToBig(xb).equals(big), true)
    }
  }
}

// ---- reference group law ----
const inv = (a) => pow(a, P - 2n, P)
function refAdd(p, q) {
  if (p === null) return q
  if (q === null) return p
  const [x1, y1] = p
  const [x2, y2] = q
  let l
  if (x1 === x2) {
    if (mod(y1 + y2, P) === 0n) return null
    l = (((3n * x1 * x1 - 3n) % P) * inv(2n * y1)) % P
  } else {
    l = (mod(y2 - y1, P) * inv(mod(x2 - x1, P))) % P
  }
  const x3 = mod(l * l - x1 - x2, P)
  return [x3, mod(l * (x1 - x3) - y1, P)]
}
function refMul(k, p) {
  let r = null
  let a = p
  let e = mod(k, N)
  while (e > 0n) {
    if (e & 1n) r = refAdd(r, a)
    a = refAdd(a, a)
    e >>= 1n
  }
  return r
}
const G = [GX, GY]

function scalarEdges() {
  const list = [
    1n,
    2n,
    3n,
    4n,
    5n,
    15n,
    16n,
    17n,
    31n,
    32n,
    33n,
    63n,
    64n,
    65n,
    N - 1n,
    N - 2n,
    N - 3n,
    N - 4n,
    N - 15n,
    N - 16n,
    N - 17n,
    N - 31n,
    N - 32n,
    N - 33n,
    N - 64n,
    N,
    N + 1n,
    N + 2n,
    MASK256,
    MASK256 - N,
    1n << 255n,
    (1n << 252n) + 1n,
    (15n << 252n) + 3n,
    (1n << 256n) - (1n << 224n),
    N >> 1n,
    (N >> 1n) + 1n,
  ]
  for (let w = 1n; w < 256n; w += 37n) {
    list.push(1n << w, (1n << w) - 1n, (1n << w) + 1n)
  }
  // Scalars whose fixed-window digits are all at the recoding boundaries
  list.push(
    0x820820820820820820820820820820820820820820820820820820820820820n,
    0x7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7df7dfn,
    0x8421084210842108421084210842108421084210842108421084210842108n,
    0xf7bdef7bdef7bdef7bdef7bdef7bdef7bdef7bdef7bdef7bdef7bdef7bdef7n,
  )
  return list
}

function groupTests() {
  const ox = new Uint8Array(32)
  const oy = new Uint8Array(32)
  const check = (name, finite, want, ctx) => {
    if (want === null) return eq(`${name} inf`, finite, false, ctx)
    eq(`${name} finite`, finite, true, ctx)
    eq(`${name} x`, fromBytes(ox), want[0], ctx)
    eq(`${name} y`, fromBytes(oy), want[1], ctx)
  }

  const Q = refMul(0x1234567890abcdefn, G)
  const qx = toBytes(Q[0])
  const qy = toBytes(Q[1])
  const R = refMul(rnd256(), G)

  const count = Math.max(40, Math.floor(ITER / 40))
  const scalars = scalarEdges()
  for (let i = 0; i < count; i++) scalars.push(rnd256())
  scalars.push(0n)
  for (const k of scalars) {
    const kb = toBytes(k)
    check('mulG', pt.mulG(kb, ox, oy), refMul(k, G), k)
    check('mulPoint Q', pt.mulPoint(qx, qy, kb, ox, oy), refMul(k, Q), k)
    check(
      'mulPoint G',
      pt.mulPoint(pt.G_X_BYTES, pt.G_Y_BYTES, kb, ox, oy),
      refMul(k, G),
      k,
    )
    check('mulPublic Q', pt.mulPublic(qx, qy, kb, ox, oy), refMul(k, Q), k)
    check(
      'mulPublic G',
      pt.mulPublic(pt.G_X_BYTES, pt.G_Y_BYTES, kb, ox, oy),
      refMul(k, G),
      k,
    )
  }

  // Combination: compare against every outcome, including exceptional sums.
  const combine = (s, t, q) => refAdd(refMul(s, G), refMul(t, q))
  const pairs = []
  for (let i = 0; i < count; i++) pairs.push([rnd256(), rnd256(), Q])
  for (const s of scalars.slice(0, 40)) pairs.push([s, rnd256(), R])
  for (const t of scalars.slice(0, 40)) pairs.push([rnd256(), t, R])
  pairs.push([5n, N - 5n, G], [5n, 5n, G], [N - 1n, 1n, G], [1n, 1n, G])
  pairs.push([0n, 7n, Q], [7n, 0n, Q], [0n, 0n, Q], [1n, N - 1n, G])
  // s*G and t*Q that meet exactly at the last addition, with Q = 2^130 * G
  const Q2 = refMul(1n << 130n, G)
  pairs.push([1n << 130n, 1n, Q2], [1n << 130n, N - 1n, Q2])
  pairs.push([(1n << 131n) + (1n << 130n), N - 3n, Q2])
  for (const [s, t, q] of pairs) {
    const sum = combine(s, t, q)
    const qxb = toBytes(q[0])
    const qyb = toBytes(q[1])
    if (sum === null) {
      eq(
        'combine inf',
        pt.verifyCombination(toBytes(s), toBytes(t), qxb, qyb, null, null),
        -1,
        [s, t],
      )
      continue
    }
    const hit = pt.verifyCombination(
      toBytes(s),
      toBytes(t),
      qxb,
      qyb,
      toBytes(sum[0]),
      null,
    )
    eq('combine match', hit, 1, [s, t])
    const miss = pt.verifyCombination(
      toBytes(s),
      toBytes(t),
      qxb,
      qyb,
      toBytes(mod(sum[0] + 1n, P)),
      toBytes(mod(sum[0] + 2n, P)),
    )
    eq('combine miss', miss, 0, [s, t])
    const second = pt.verifyCombination(
      toBytes(s),
      toBytes(t),
      qxb,
      qyb,
      toBytes(mod(sum[0] + 1n, P)),
      toBytes(sum[0]),
    )
    eq('combine second candidate', second, 1, [s, t])
  }

  // On-curve checks, including non-canonical coordinates
  eq('curve G', pt.isOnCurve(pt.G_X_BYTES, pt.G_Y_BYTES), true)
  eq('curve Q', pt.isOnCurve(qx, qy), true)
  eq('curve off', pt.isOnCurve(qx, toBytes(Q[1] + 1n)), false)
  eq('curve zero', pt.isOnCurve(toBytes(0n), toBytes(0n)), false)
  for (let i = 0; i < 200; i++) {
    const x = rnd256() % P
    const y = rnd256() % P
    const on = mod(y * y - (x * x * x - 3n * x + B), P) === 0n
    eq('curve random', pt.isOnCurve(toBytes(x), toBytes(y)), on)
  }

  // Affine add and double, including P + P, P + (-P), and off-curve input
  const neg = (p) => [p[0], mod(-p[1], P)]
  const affineCases = [
    [Q, R],
    [R, Q],
    [G, Q],
    [Q, neg(R)],
  ]
  for (const [a, b] of affineCases) {
    const status = pt.affineAdd(
      toBytes(a[0]),
      toBytes(a[1]),
      toBytes(b[0]),
      toBytes(b[1]),
      ox,
      oy,
    )
    eq('affine add status', status, 1)
    check('affine add', true, refAdd(a, b))
  }
  eq('affine P+P', pt.affineAdd(qx, qy, qx, qy, ox, oy), 2)
  eq('affine P+-P', pt.affineAdd(qx, qy, qx, toBytes(mod(-Q[1], P)), ox, oy), 0)
  eq('affine dbl', pt.affineDouble(qx, qy, ox, oy), true)
  check('affine dbl', true, refAdd(Q, Q))
  eq('affine dbl y=0', pt.affineDouble(qx, toBytes(0n), ox, oy), false)
  eq('affine dbl y=p', pt.affineDouble(qx, toBytes(P), ox, oy), false)

  // Square root candidate on the curve equation
  for (let i = 0; i < 50; i++) {
    const x = rnd256() % P
    pt.decompressY(toBytes(x), oy)
    const rhs = mod(x * x * x - 3n * x + B, P)
    eq('decompress', fromBytes(oy), pow(rhs, (P + 1n) / 4n, P), x)
  }
}

const start = performance.now()
fieldTests()
groupTests()
const ms = Math.round(performance.now() - start)
console.log(
  `diff-field: ${checks - failures} passed, ${failures} failed (${ms} ms)`,
)
process.exit(failures ? 1 : 0)
