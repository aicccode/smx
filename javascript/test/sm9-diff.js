/**
 * Randomized differential tests of the SM9 field, scalar, group and pairing code
 * against native BigInt (test-only; the library uses BigInt only in H1/H2), with
 * edge values and maximal-carry operands, plus algebraic identities.
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { performance } from 'node:perf_hooks'
import { encodeHex } from '../common/hex.js'
import * as fp from '../sm9/fp.js'
import * as f2 from '../sm9/fp2.js'
import * as f12 from '../sm9/fp12.js'
import * as grp from '../sm9/groups.js'
import * as sc from '../sm9/scalar.js'
import { gtMakeComb, gtPow, gtPowComb, pairing } from '../sm9/pairing.js'

const here = dirname(fileURLToPath(import.meta.url))
const V = JSON.parse(
  readFileSync(resolve(here, '../../testvectors/sm9-vectors.json'), 'utf8'),
)
const ITER = Number(process.env.DIFF_ITER ?? 2000)
const Q = BigInt('0x' + V.params.q)
const N = BigInt('0x' + V.params.n)
const MASK256 = (1n << 256n) - 1n

let checks = 0
let failures = 0
function eq(name, got, want, input = '') {
  checks++
  if (got !== want) {
    failures++
    if (failures < 20) {
      console.error(`[FAIL] ${name} ${input}\n  got  ${got}\n  want ${want}`)
    }
  }
}

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
  Q - 1n,
  Q - 2n,
  Q,
  Q + 1n,
  N - 1n,
  N,
  MASK256,
  1n << 255n,
  0xffffffn,
  0x800000800000800000800000800000800000800000800000800000800000n,
]
const mod = (a, m) => ((a % m) + m) % m
const toBytes = (v) => {
  const out = new Uint8Array(32)
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}
const fromBytes = (b) => BigInt('0x' + (encodeHex(b) || '0'))
function pow(a, e, m) {
  let r = 1n
  a = mod(a, m)
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * a) % m
    a = (a * a) % m
  }
  return r
}
function load(v) {
  const r = fp.feNew()
  fp.fpFromBytes(r, toBytes(v & MASK256))
  return r
}
function value(a) {
  const out = new Uint8Array(32)
  fp.fpToBytes(out, a)
  return fromBytes(out)
}
const sample = (i) =>
  i < EDGE.length * EDGE.length ? EDGE[i % EDGE.length] : rnd256()
const sample2 = (i) =>
  i < EDGE.length * EDGE.length ? EDGE[Math.floor(i / EDGE.length)] : rnd256()

function fieldTests() {
  const r = fp.feNew()
  const s = fp.feNew()
  for (let i = 0; i < ITER; i++) {
    const a = sample(i) & MASK256
    const b = sample2(i) & MASK256
    const x = load(a)
    const y = load(b)
    const ctx = `a=${a.toString(16)} b=${b.toString(16)}`
    fp.fpMul(r, x, y)
    eq('fpMul', value(r), mod(a * b, Q), ctx)
    fp.fpSqr(r, x)
    eq('fpSqr', value(r), mod(a * a, Q), ctx)
    fp.feAdd(r, x, y)
    eq('feAdd', value(r), mod(a + b, Q), ctx)
    fp.feSub(r, x, y)
    eq('feSub', value(r), mod(a - b, Q), ctx)
    // lazy sums up to the documented operand bound (k1 * k2 = 6)
    for (let l = 0; l < 11; l++) s[l] = x[l] + y[l] + x[l]
    fp.feAdd(r, x, y)
    fp.fpMul(r, s, r)
    eq('fpMul lazy 3x2', value(r), mod((2n * a + b) * (a + b), Q), ctx)
    // growth then weak reduction
    fp.feMulSmall(r, x, 50)
    fp.feAdd(r, r, y)
    fp.fpReduce(r, r)
    eq('fpReduce', value(r), mod(50n * a + b, Q), ctx)
    let top = 0
    for (let l = 0; l < 11; l++) top = Math.max(top, Math.abs(r[l]))
    eq('fpReduce bound', top <= 0x800000 || Math.abs(r[10]) < 0xb640, true, ctx)
    if (i % 20 === 0) {
      fp.fpInv(r, x)
      eq('fpInv', value(r), a % Q === 0n ? 0n : pow(a, Q - 2n, Q), ctx)
    }
  }
  // Fq2 multiplication, squaring and inversion
  const u = new f2.Fp2()
  const v = new f2.Fp2()
  const w = new f2.Fp2()
  for (let i = 0; i < ITER / 4; i++) {
    const [a0, a1, b0, b1] = [rnd256(), rnd256(), rnd256(), rnd256()].map(
      (t) => t % Q,
    )
    u.c0.set(load(a0))
    u.c1.set(load(a1))
    v.c0.set(load(b0))
    v.c1.set(load(b1))
    f2.fp2Mul(w, u, v)
    eq('fp2Mul c0', value(w.c0), mod(a0 * b0 - 2n * a1 * b1, Q))
    eq('fp2Mul c1', value(w.c1), mod(a0 * b1 + a1 * b0, Q))
    f2.fp2Sqr(w, u)
    eq('fp2Sqr c0', value(w.c0), mod(a0 * a0 - 2n * a1 * a1, Q))
    eq('fp2Sqr c1', value(w.c1), mod(2n * a0 * a1, Q))
    f2.fp2Inv(w, u)
    f2.fp2Mul(w, w, u)
    eq('fp2Inv', value(w.c0) * 2n ** 256n + value(w.c1), 2n ** 256n)
  }
}

function scalarTests() {
  for (let i = 0; i < ITER; i++) {
    const a = sample(i) & MASK256
    const b = sample2(i) & MASK256
    const ctx = `a=${a.toString(16)} b=${b.toString(16)}`
    const s = sc.scalarAdd(toBytes(a), toBytes(b))
    eq('scalarAdd', fromBytes(s.value), mod(a + b, N), ctx)
    eq('scalarAdd zero', s.zero, mod(a + b, N) === 0n, ctx)
    const d = sc.scalarSub(toBytes(a), toBytes(b))
    eq('scalarSub', fromBytes(d.value), mod(a - b, N), ctx)
    eq(
      'scalarValid',
      sc.scalarValidMask(toBytes(a)) !== 0,
      a >= 1n && a < N,
      ctx,
    )
    if (i % 10 === 0 && b % N !== 0n) {
      const q = sc.scalarDiv(toBytes(a), toBytes(b))
      eq('scalarDiv', fromBytes(q), mod(a * pow(b, N - 2n, N), N), ctx)
    }
  }
}

const g1Hex = (P) => (P === null ? 'O' : encodeHex(grp.g1Encode(P)))
const g2Hex = (P) => (P === null ? 'O' : encodeHex(grp.g2Encode(P)))
const gtHex = (f) => encodeHex(f12.gtToBytes(f))

function groupTests() {
  const rounds = Math.max(3, Math.floor(ITER / 400))
  for (let i = 0; i < rounds; i++) {
    const a = (rnd256() % (N - 1n)) + 1n
    const b = (rnd256() % (N - 1n)) + 1n
    const ab = mod(a * b, N)
    const A1 = grp.g1MulSecret(grp.P1, toBytes(a))
    eq(
      'g1 secret = public',
      g1Hex(A1),
      g1Hex(grp.g1MulPublic(grp.P1, toBytes(a))),
    )
    eq(
      'g1 [b][a]P = [ab]P',
      g1Hex(grp.g1MulSecret(A1, toBytes(b))),
      g1Hex(grp.g1MulSecret(grp.P1, toBytes(ab))),
    )
    eq(
      'g1 [a]P + [b]P',
      g1Hex(grp.g1Add(A1, grp.g1MulPublic(grp.P1, toBytes(b)))),
      g1Hex(grp.g1MulPublic(grp.P1, toBytes(mod(a + b, N)))),
    )
    eq(
      'g1 P + P = 2P',
      g1Hex(grp.g1Add(A1, A1)),
      g1Hex(grp.g1MulPublic(A1, toBytes(2n))),
    )
    eq(
      'g1 P + (-P) = O',
      g1Hex(grp.g1Add(A1, grp.g1MulPublic(A1, toBytes(N - 1n)))),
      'O',
    )
    eq('g1 [N]P = O', g1Hex(grp.g1MulSecret(A1, toBytes(N))), 'O')
    eq('g1 [0]P = O', g1Hex(grp.g1MulSecret(A1, toBytes(0n))), 'O')
    const B2 = grp.g2MulSecret(grp.P2, toBytes(b))
    eq(
      'g2 secret = public',
      g2Hex(B2),
      g2Hex(grp.g2MulPublic(grp.P2, toBytes(b))),
    )
    eq(
      'g2 [a][b]Q = [ab]Q',
      g2Hex(grp.g2MulSecret(B2, toBytes(a))),
      g2Hex(grp.g2MulSecret(grp.P2, toBytes(ab))),
    )
    eq(
      'g2 Q + Q = 2Q',
      g2Hex(grp.g2Add(B2, B2)),
      g2Hex(grp.g2MulPublic(B2, toBytes(2n))),
    )
    eq(
      'g2 Q + (-Q) = O',
      g2Hex(grp.g2Add(B2, grp.g2MulPublic(B2, toBytes(N - 1n)))),
      'O',
    )
    eq('g2 decode encode', g2Hex(grp.g2Decode(grp.g2Encode(B2))), g2Hex(B2))
    eq('g1 decode encode', g1Hex(grp.g1Decode(grp.g1Encode(A1))), g1Hex(A1))
    // bilinearity: e([a]P1, [b]P2) = e(P1, P2)^(ab)
    const lhs = new f12.Fp12()
    pairing(lhs, A1.x, A1.y, B2.x, B2.y)
    const base = new f12.Fp12()
    pairing(base, grp.P1.x, grp.P1.y, grp.P2.x, grp.P2.y)
    const rhs = new f12.Fp12()
    gtPow(rhs, base, toBytes(ab))
    eq('bilinearity', gtHex(lhs), gtHex(rhs))
    const comb = gtMakeComb(base)
    for (const secret of [true, false]) {
      const viaComb = new f12.Fp12()
      gtPowComb(viaComb, comb, toBytes(ab), secret)
      eq(`gtPowComb secret=${secret}`, gtHex(viaComb), gtHex(rhs))
      eq(
        `g1 comb secret=${secret}`,
        g1Hex(grp.g1MulBase(toBytes(a), secret)),
        g1Hex(A1),
      )
      eq(
        `g2 comb secret=${secret}`,
        g2Hex(grp.g2MulBase(toBytes(b), secret)),
        g2Hex(B2),
      )
    }
    for (const k of [0n, 1n, N - 1n, N, MASK256]) {
      eq(
        'g1 comb edge',
        g1Hex(grp.g1MulBase(toBytes(k), true)),
        g1Hex(grp.g1MulPublic(grp.P1, toBytes(k))),
      )
    }
    const nth = new f12.Fp12()
    gtPow(nth, base, toBytes(N))
    const one = new f12.Fp12()
    f12.fp12One(one)
    eq('g^N = 1', gtHex(nth), gtHex(one))
  }
  // The off-subgroup vector is on the twist; only the subgroup check rejects it.
  const off = V.invalid_points.g2.find(
    (p) => p.name === 'not_in_subgroup',
  ).value
  const c = [1, 2, 3, 4].map((k) =>
    BigInt('0x' + off.slice(2 + 64 * (k - 1), 2 + 64 * k)),
  )
  const [x1, x0, y1, y0] = c
  // y^2 = x^3 + 5u in Fq[u]/(u^2 + 2)
  const mul = ([a0, a1], [b0, b1]) => [
    mod(a0 * b0 - 2n * a1 * b1, Q),
    mod(a0 * b1 + a1 * b0, Q),
  ]
  const yy = mul([y0, y1], [y0, y1])
  const xxx = mul(mul([x0, x1], [x0, x1]), [x0, x1])
  eq(
    'off-subgroup point is on the twist',
    `${yy[0]},${yy[1]}`,
    `${xxx[0]},${mod(xxx[1] + 5n, Q)}`,
  )
  eq(
    'off-subgroup point rejected',
    grp.g2Decode(Uint8Array.from(off.match(/../g), (x) => parseInt(x, 16))),
    null,
  )
}

const start = performance.now()
fieldTests()
scalarTests()
groupTests()
const ms = Math.round(performance.now() - start)
console.log(
  `sm9-diff: ${checks - failures} passed, ${failures} failed (${ms} ms)`,
)
process.exit(failures ? 1 : 0)
