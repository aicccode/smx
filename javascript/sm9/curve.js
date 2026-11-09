/**
 * Group law and scalar multiplication shared by G1 (over Fq) and G2 (over Fq2).
 * Internal module, not part of the public API.
 *
 * Points are homogeneous projective (X : Y : Z) on y^2 = x^3 + b with a = 0 and
 * use the complete formulas of Renes, Costello and Batina (2016, algorithms 7
 * and 9). They are correct for every input, the identity (0 : 1 : 0) included,
 * so scalar multiplication needs no special cases and no branches on the data.
 *
 * Secret scalars use 4-bit fixed windows: four doublings and one addition per
 * window whatever the digit, with the table entry read by a full masked scan.
 * Public scalars index the table directly. The fixed generators use a Lim-Lee
 * comb (one doubling and one addition per column), with the same masked scan
 * for secret scalars. Same timing notes as fp.js.
 */

const WINDOW = 4
const TABLE_SIZE = 1 << WINDOW
const WINDOWS = 64

/**
 * @param {object} f field operations: newElem, raw (element -> Float64Array),
 *   size (doubles per element), copy, add, sub, mul, sqr, mulSmall, mulB3
 *   (multiply by 3b), one, zero, inv, isZeroMask
 */
export function makeCurve(f) {
  const newPoint = () => ({ x: f.newElem(), y: f.newElem(), z: f.newElem() })
  const t0 = f.newElem()
  const t1 = f.newElem()
  const t2 = f.newElem()
  const t3 = f.newElem()
  const t4 = f.newElem()
  const x3 = f.newElem()
  const y3 = f.newElem()
  const z3 = f.newElem()

  function setIdentity(R) {
    f.zero(R.x)
    f.one(R.y)
    f.zero(R.z)
  }

  function copyPoint(R, P) {
    f.copy(R.x, P.x)
    f.copy(R.y, P.y)
    f.copy(R.z, P.z)
  }

  /** R = P + Q, complete (algorithm 7). R may alias P or Q. */
  function add(R, P, Q) {
    f.mul(t0, P.x, Q.x)
    f.mul(t1, P.y, Q.y)
    f.mul(t2, P.z, Q.z)
    f.add(t3, P.x, P.y)
    f.add(t4, Q.x, Q.y)
    f.mul(t3, t3, t4)
    f.add(t4, t0, t1)
    f.sub(t3, t3, t4)
    f.add(t4, P.y, P.z)
    f.add(x3, Q.y, Q.z)
    f.mul(t4, t4, x3)
    f.add(x3, t1, t2)
    f.sub(t4, t4, x3)
    f.add(x3, P.x, P.z)
    f.add(y3, Q.x, Q.z)
    f.mul(x3, x3, y3)
    f.add(y3, t0, t2)
    f.sub(y3, x3, y3)
    f.add(x3, t0, t0)
    f.add(t0, x3, t0)
    f.mulB3(t2, t2)
    f.add(z3, t1, t2)
    f.sub(t1, t1, t2)
    f.mulB3(y3, y3)
    f.mul(x3, t4, y3)
    f.mul(t2, t3, t1)
    f.sub(R.x, t2, x3)
    f.mul(y3, y3, t0)
    f.mul(t1, t1, z3)
    f.add(R.y, t1, y3)
    f.mul(t0, t0, t3)
    f.mul(z3, z3, t4)
    f.add(R.z, z3, t0)
  }

  /** R = 2P, complete (algorithm 9). R may alias P. */
  function dbl(R, P) {
    f.sqr(t0, P.y)
    f.mulSmall(z3, t0, 8)
    f.mul(t1, P.y, P.z)
    f.sqr(t2, P.z)
    f.mulB3(t2, t2)
    f.mul(x3, t2, z3)
    f.add(y3, t0, t2)
    f.mul(z3, t1, z3)
    f.add(t1, t2, t2)
    f.add(t2, t1, t2)
    f.sub(t0, t0, t2)
    f.mul(y3, t0, y3)
    f.add(y3, x3, y3)
    f.mul(t1, P.x, P.y)
    f.mul(x3, t0, t1)
    f.add(R.x, x3, x3)
    f.copy(R.y, y3)
    f.copy(R.z, z3)
  }

  const POINT_SIZE = 3 * f.size
  const table = new Float64Array(TABLE_SIZE * POINT_SIZE)
  const acc = new Int32Array(POINT_SIZE)
  const T = newPoint()
  const S = newPoint()
  const A = newPoint()

  function store(index, P) {
    const base = index * POINT_SIZE
    table.set(f.raw(P.x), base)
    table.set(f.raw(P.y), base + f.size)
    table.set(f.raw(P.z), base + 2 * f.size)
  }

  function load(out, base, from = table) {
    f.raw(out.x).set(from.subarray(base, base + f.size))
    f.raw(out.y).set(from.subarray(base + f.size, base + 2 * f.size))
    f.raw(out.z).set(from.subarray(base + 2 * f.size, base + POINT_SIZE))
  }

  function buildTable(P) {
    setIdentity(T)
    store(0, T)
    copyPoint(T, P)
    store(1, T)
    for (let i = 2; i < TABLE_SIZE; i++) {
      add(T, T, P)
      store(i, T)
    }
  }

  function selectMasked(out, digit, from = table, count = TABLE_SIZE) {
    acc.fill(0)
    for (let j = 0; j < count; j++) {
      const mask = ((j ^ digit) - 1) >> 31
      const base = j * POINT_SIZE
      for (let l = 0; l < POINT_SIZE; l++) acc[l] |= from[base + l] & mask
    }
    const n = f.size
    const rx = f.raw(out.x)
    const ry = f.raw(out.y)
    const rz = f.raw(out.z)
    for (let l = 0; l < n; l++) {
      rx[l] = acc[l]
      ry[l] = acc[n + l]
      rz[l] = acc[2 * n + l]
    }
  }

  const digitOf = (k, i) => {
    const byte = k[i >>> 1]
    return (i & 1) === 0 ? byte >>> 4 : byte & 15
  }

  /** R = k P for a secret 32-byte big-endian k. Regular schedule. */
  function mulSecret(R, P, k) {
    copyPoint(A, P)
    buildTable(A)
    setIdentity(R)
    for (let i = 0; i < WINDOWS; i++) {
      for (let s = 0; s < WINDOW; s++) dbl(R, R)
      selectMasked(S, digitOf(k, i))
      add(R, R, S)
    }
    wipe()
  }

  /** R = k P for a public 32-byte big-endian k. Variable time. */
  function mulPublic(R, P, k) {
    copyPoint(A, P)
    buildTable(A)
    setIdentity(R)
    let started = false
    for (let i = 0; i < WINDOWS; i++) {
      if (started) for (let s = 0; s < WINDOW; s++) dbl(R, R)
      const digit = digitOf(k, i)
      if (digit !== 0) {
        load(S, digit * POINT_SIZE)
        add(R, R, S)
        started = true
      }
    }
  }

  // ---- fixed base: Lim-Lee comb ----

  /**
   * Comb table for a fixed point P with `teeth` teeth: entry b is
   * sum over the set bits j of b of [2^(d j)] P, d = 256 / teeth.
   */
  function makeComb(P, teeth) {
    const d = 256 / teeth
    const count = 1 << teeth
    const combTable = new Float64Array(count * POINT_SIZE)
    const put = (index, Pt) => {
      const base = index * POINT_SIZE
      combTable.set(f.raw(Pt.x), base)
      combTable.set(f.raw(Pt.y), base + f.size)
      combTable.set(f.raw(Pt.z), base + 2 * f.size)
    }
    const B = newPoint()
    const E = newPoint()
    copyPoint(B, P)
    setIdentity(E)
    put(0, E)
    for (let j = 0; j < teeth; j++) {
      if (j > 0) for (let s = 0; s < d; s++) dbl(B, B)
      const half = 1 << j
      for (let b = 0; b < half; b++) {
        load(E, b * POINT_SIZE, combTable)
        add(E, E, B)
        put(half + b, E)
      }
    }
    return { table: combTable, teeth, d, count }
  }

  /** The comb index for column i: bit d j + i of k for every tooth j. */
  function combIndex(comb, k, i) {
    let index = 0
    for (let j = 0; j < comb.teeth; j++) {
      const p = comb.d * j + i
      index |= ((k[31 - (p >>> 3)] >>> (p & 7)) & 1) << j
    }
    return index
  }

  /** R = k P with P's comb table. secret selects the masked table scan. */
  function mulComb(R, comb, k, secret) {
    setIdentity(R)
    for (let i = comb.d - 1; i >= 0; i--) {
      dbl(R, R)
      const index = combIndex(comb, k, i)
      if (secret) selectMasked(S, index, comb.table, comb.count)
      else load(S, index * POINT_SIZE, comb.table)
      add(R, R, S)
    }
    if (secret) wipe()
  }

  const zInv = f.newElem()
  /**
   * Affine coordinates of P into (outX, outY). Returns false, writing nothing
   * useful, when P is the identity.
   */
  function toAffine(outX, outY, P) {
    if (f.isZeroMask(P.z) !== 0) return false
    f.inv(zInv, P.z)
    f.mul(outX, P.x, zInv)
    f.mul(outY, P.y, zInv)
    return true
  }

  function fromAffine(R, x, y) {
    f.copy(R.x, x)
    f.copy(R.y, y)
    f.one(R.z)
  }

  function wipe() {
    table.fill(0)
    acc.fill(0)
    for (const e of [t0, t1, t2, t3, t4, x3, y3, z3, zInv]) f.raw(e).fill(0)
    for (const p of [T, S, A]) {
      for (const e of [p.x, p.y, p.z]) f.raw(e).fill(0)
    }
  }

  return {
    newPoint,
    add,
    dbl,
    mulSecret,
    mulPublic,
    makeComb,
    mulComb,
    toAffine,
    fromAffine,
    setIdentity,
    wipe,
  }
}
