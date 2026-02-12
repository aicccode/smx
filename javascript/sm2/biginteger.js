/**
 * BigInteger 大整数运算库
 * 基于 Tom Wu 的 jsbn，清理为现代 ES Module 风格
 */

// ---- 模块级常量 ----

const DB = 28                      // 每个 digit 的位数（统一用 am3 策略）
const DM = (1 << DB) - 1           // digit 掩码
const DV = 1 << DB                 // digit 值上限

const BI_FP = 52
const FV = Math.pow(2, BI_FP)
const F1 = BI_FP - DB
const F2 = 2 * DB - BI_FP

const BI_RM = '0123456789abcdefghijklmnopqrstuvwxyz'
const BI_RC = []
let rr = '0'.charCodeAt(0)
for (let vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv
rr = 'a'.charCodeAt(0)
for (let vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv
rr = 'A'.charCodeAt(0)
for (let vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv

const LOW_PRIMES = [
  2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
  73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
  157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
  239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
  331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
  421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
  509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
  613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
  709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
  821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
  919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
]
const LP_LIM = (1 << 26) / LOW_PRIMES[LOW_PRIMES.length - 1]

// ---- 辅助函数 ----

function nbi() { return new BigInteger(null) }
function nbv(i) { const r = nbi(); r.fromInt(i); return r }

function int2char(n) { return BI_RM.charAt(n) }
function intAt(s, i) { const c = BI_RC[s.charCodeAt(i)]; return (c == null) ? -1 : c }

function nbits(x) {
  let r = 1, t
  if ((t = x >>> 16) !== 0) { x = t; r += 16 }
  if ((t = x >> 8) !== 0) { x = t; r += 8 }
  if ((t = x >> 4) !== 0) { x = t; r += 4 }
  if ((t = x >> 2) !== 0) { x = t; r += 2 }
  if ((t = x >> 1) !== 0) { r += 1 }
  return r
}

function lbit(x) {
  if (x === 0) return -1
  let r = 0
  if ((x & 0xffff) === 0) { x >>= 16; r += 16 }
  if ((x & 0xff) === 0) { x >>= 8; r += 8 }
  if ((x & 0xf) === 0) { x >>= 4; r += 4 }
  if ((x & 3) === 0) { x >>= 2; r += 2 }
  if ((x & 1) === 0) ++r
  return r
}

function cbit(x) {
  let r = 0
  while (x !== 0) { x &= x - 1; ++r }
  return r
}

// ---- BigInteger 核心类 ----

export class BigInteger {
  constructor(a, b, c) {
    if (a != null) {
      if (typeof a === 'number') this.fromNumber(a, b, c)
      else if (b == null && typeof a !== 'string') this.fromString(a, 256)
      else this.fromString(a, b)
    }
  }

  /** am3: 28-bit 乘法累加（适合所有现代 JS 引擎） */
  am(i, x, w, j, c, n) {
    const xl = x & 0x3fff, xh = x >> 14
    while (--n >= 0) {
      let l = this[i] & 0x3fff
      const h = this[i++] >> 14
      const m = xh * l + h * xl
      l = xl * l + ((m & 0x3fff) << 14) + w[j] + c
      c = (l >> 28) + (m >> 14) + xh * h
      w[j++] = l & 0xfffffff
    }
    return c
  }

  // ---- 基础操作 ----

  copyTo(r) {
    for (let i = this.t - 1; i >= 0; --i) r[i] = this[i]
    r.t = this.t
    r.s = this.s
  }

  fromInt(x) {
    this.t = 1
    this.s = (x < 0) ? -1 : 0
    if (x > 0) this[0] = x
    else if (x < -1) this[0] = x + DV
    else this.t = 0
  }

  fromString(s, b) {
    let k
    if (b === 16) k = 4
    else if (b === 8) k = 3
    else if (b === 256) k = 8
    else if (b === 2) k = 1
    else if (b === 32) k = 5
    else if (b === 4) k = 2
    else { this.fromRadix(s, b); return }
    this.t = 0
    this.s = 0
    let i = s.length, mi = false, sh = 0
    while (--i >= 0) {
      const x = (k === 8) ? s[i] & 0xff : intAt(s, i)
      if (x < 0) {
        if (s.charAt(i) === '-') mi = true
        continue
      }
      mi = false
      if (sh === 0) this[this.t++] = x
      else if (sh + k > DB) {
        this[this.t - 1] |= (x & ((1 << (DB - sh)) - 1)) << sh
        this[this.t++] = (x >> (DB - sh))
      } else this[this.t - 1] |= x << sh
      sh += k
      if (sh >= DB) sh -= DB
    }
    if (k === 8 && (s[0] & 0x80) !== 0) {
      this.s = -1
      if (sh > 0) this[this.t - 1] |= ((1 << (DB - sh)) - 1) << sh
    }
    this.clamp()
    if (mi) BigInteger.ZERO.subTo(this, this)
  }

  clamp() {
    const c = this.s & DM
    while (this.t > 0 && this[this.t - 1] === c) --this.t
  }

  // ---- 转换 ----

  toString(b) {
    if (this.s < 0) return '-' + this.negate().toString(b)
    let k
    if (b === 16) k = 4
    else if (b === 8) k = 3
    else if (b === 2) k = 1
    else if (b === 32) k = 5
    else if (b === 4) k = 2
    else return this.toRadix(b)
    const km = (1 << k) - 1
    let d, m = false, r = '', i = this.t
    let p = DB - (i * DB) % k
    if (i-- > 0) {
      if (p < DB && (d = this[i] >> p) > 0) { m = true; r = int2char(d) }
      while (i >= 0) {
        if (p < k) {
          d = (this[i] & ((1 << p) - 1)) << (k - p)
          d |= this[--i] >> (p += DB - k)
        } else {
          d = (this[i] >> (p -= k)) & km
          if (p <= 0) { p += DB; --i }
        }
        if (d > 0) m = true
        if (m) r += int2char(d)
      }
    }
    return m ? r : '0'
  }

  toRadix(b) {
    if (b == null) b = 10
    if (this.signum() === 0 || b < 2 || b > 36) return '0'
    const cs = this.chunkSize(b)
    const a = Math.pow(b, cs)
    const d = nbv(a), y = nbi(), z = nbi()
    let r = ''
    this.divRemTo(d, y, z)
    while (y.signum() > 0) {
      r = (a + z.intValue()).toString(b).substr(1) + r
      y.divRemTo(d, y, z)
    }
    return z.intValue().toString(b) + r
  }

  fromRadix(s, b) {
    this.fromInt(0)
    if (b == null) b = 10
    const cs = this.chunkSize(b)
    const d = Math.pow(b, cs)
    let mi = false, j = 0, w = 0
    for (let i = 0; i < s.length; ++i) {
      const x = intAt(s, i)
      if (x < 0) {
        if (s.charAt(i) === '-' && this.signum() === 0) mi = true
        continue
      }
      w = b * w + x
      if (++j >= cs) {
        this.dMultiply(d)
        this.dAddOffset(w, 0)
        j = 0
        w = 0
      }
    }
    if (j > 0) {
      this.dMultiply(Math.pow(b, j))
      this.dAddOffset(w, 0)
    }
    if (mi) BigInteger.ZERO.subTo(this, this)
  }

  fromNumber(a, b, c) {
    if (typeof b === 'number') {
      if (a < 2) this.fromInt(1)
      else {
        this.fromNumber(a, c)
        if (!this.testBit(a - 1)) this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this)
        if (this.isEven()) this.dAddOffset(1, 0)
        while (!this.isProbablePrime(b)) {
          this.dAddOffset(2, 0)
          if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this)
        }
      }
    } else {
      const x = [], t = a & 7
      x.length = (a >> 3) + 1
      b.nextBytes(x)
      if (t > 0) x[0] &= ((1 << t) - 1); else x[0] = 0
      this.fromString(x, 256)
    }
  }

  toByteArray() {
    let i = this.t
    const r = []
    r[0] = this.s
    let p = DB - (i * DB) % 8, d, k = 0
    if (i-- > 0) {
      if (p < DB && (d = this[i] >> p) !== (this.s & DM) >> p) r[k++] = d | (this.s << (DB - p))
      while (i >= 0) {
        if (p < 8) {
          d = (this[i] & ((1 << p) - 1)) << (8 - p)
          d |= this[--i] >> (p += DB - 8)
        } else {
          d = (this[i] >> (p -= 8)) & 0xff
          if (p <= 0) { p += DB; --i }
        }
        if ((d & 0x80) !== 0) d |= -256
        if (k === 0 && (this.s & 0x80) !== (d & 0x80)) ++k
        if (k > 0 || d !== this.s) r[k++] = d
      }
    }
    return r
  }

  // ---- 算术运算 ----

  negate() { const r = nbi(); BigInteger.ZERO.subTo(this, r); return r }
  abs() { return (this.s < 0) ? this.negate() : this }
  clone() { const r = nbi(); this.copyTo(r); return r }

  compareTo(a) {
    let r = this.s - a.s
    if (r !== 0) return r
    let i = this.t
    r = i - a.t
    if (r !== 0) return (this.s < 0) ? -r : r
    while (--i >= 0) if ((r = this[i] - a[i]) !== 0) return r
    return 0
  }

  equals(a) { return this.compareTo(a) === 0 }
  min(a) { return (this.compareTo(a) < 0) ? this : a }
  max(a) { return (this.compareTo(a) > 0) ? this : a }

  signum() {
    if (this.s < 0) return -1
    if (this.t <= 0 || (this.t === 1 && this[0] <= 0)) return 0
    return 1
  }

  intValue() {
    if (this.s < 0) {
      if (this.t === 1) return this[0] - DV
      if (this.t === 0) return -1
    } else if (this.t === 1) return this[0]
    else if (this.t === 0) return 0
    return ((this[1] & ((1 << (32 - DB)) - 1)) << DB) | this[0]
  }

  byteValue() { return (this.t === 0) ? this.s : (this[0] << 24) >> 24 }
  shortValue() { return (this.t === 0) ? this.s : (this[0] << 16) >> 16 }
  chunkSize(r) { return Math.floor(Math.LN2 * DB / Math.log(r)) }
  isEven() { return ((this.t > 0) ? (this[0] & 1) : this.s) === 0 }
  bitLength() {
    if (this.t <= 0) return 0
    return DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & DM))
  }

  // ---- 位移操作 ----

  dlShiftTo(n, r) {
    for (let i = this.t - 1; i >= 0; --i) r[i + n] = this[i]
    for (let i = n - 1; i >= 0; --i) r[i] = 0
    r.t = this.t + n
    r.s = this.s
  }

  drShiftTo(n, r) {
    for (let i = n; i < this.t; ++i) r[i - n] = this[i]
    r.t = Math.max(this.t - n, 0)
    r.s = this.s
  }

  lShiftTo(n, r) {
    const bs = n % DB
    const cbs = DB - bs
    const bm = (1 << cbs) - 1
    const ds = Math.floor(n / DB)
    let c = (this.s << bs) & DM
    for (let i = this.t - 1; i >= 0; --i) {
      r[i + ds + 1] = (this[i] >> cbs) | c
      c = (this[i] & bm) << bs
    }
    for (let i = ds - 1; i >= 0; --i) r[i] = 0
    r[ds] = c
    r.t = this.t + ds + 1
    r.s = this.s
    r.clamp()
  }

  rShiftTo(n, r) {
    r.s = this.s
    const ds = Math.floor(n / DB)
    if (ds >= this.t) { r.t = 0; return }
    const bs = n % DB
    const cbs = DB - bs
    const bm = (1 << bs) - 1
    r[0] = this[ds] >> bs
    for (let i = ds + 1; i < this.t; ++i) {
      r[i - ds - 1] |= (this[i] & bm) << cbs
      r[i - ds] = this[i] >> bs
    }
    if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs
    r.t = this.t - ds
    r.clamp()
  }

  shiftLeft(n) {
    const r = nbi()
    if (n < 0) this.rShiftTo(-n, r); else this.lShiftTo(n, r)
    return r
  }

  shiftRight(n) {
    const r = nbi()
    if (n < 0) this.lShiftTo(-n, r); else this.rShiftTo(n, r)
    return r
  }

  // ---- 加减乘除 ----

  addTo(a, r) {
    let i = 0, c = 0
    const m = Math.min(a.t, this.t)
    while (i < m) {
      c += this[i] + a[i]
      r[i++] = c & DM
      c >>= DB
    }
    if (a.t < this.t) {
      c += a.s
      while (i < this.t) { c += this[i]; r[i++] = c & DM; c >>= DB }
      c += this.s
    } else {
      c += this.s
      while (i < a.t) { c += a[i]; r[i++] = c & DM; c >>= DB }
      c += a.s
    }
    r.s = (c < 0) ? -1 : 0
    if (c > 0) r[i++] = c
    else if (c < -1) r[i++] = DV + c
    r.t = i
    r.clamp()
  }

  subTo(a, r) {
    let i = 0, c = 0
    const m = Math.min(a.t, this.t)
    while (i < m) {
      c += this[i] - a[i]
      r[i++] = c & DM
      c >>= DB
    }
    if (a.t < this.t) {
      c -= a.s
      while (i < this.t) { c += this[i]; r[i++] = c & DM; c >>= DB }
      c += this.s
    } else {
      c += this.s
      while (i < a.t) { c -= a[i]; r[i++] = c & DM; c >>= DB }
      c -= a.s
    }
    r.s = (c < 0) ? -1 : 0
    if (c < -1) r[i++] = DV + c
    else if (c > 0) r[i++] = c
    r.t = i
    r.clamp()
  }

  multiplyTo(a, r) {
    const x = this.abs(), y = a.abs()
    let i = x.t
    r.t = i + y.t
    while (--i >= 0) r[i] = 0
    for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t)
    r.s = 0
    r.clamp()
    if (this.s !== a.s) BigInteger.ZERO.subTo(r, r)
  }

  squareTo(r) {
    const x = this.abs()
    let i = r.t = 2 * x.t
    while (--i >= 0) r[i] = 0
    for (i = 0; i < x.t - 1; ++i) {
      const c = x.am(i, x[i], r, 2 * i, 0, 1)
      if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
        r[i + x.t] -= x.DV
        r[i + x.t + 1] = 1
      }
    }
    if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1)
    r.s = 0
    r.clamp()
  }

  divRemTo(m, q, r) {
    const pm = m.abs()
    if (pm.t <= 0) return
    const pt = this.abs()
    if (pt.t < pm.t) {
      if (q != null) q.fromInt(0)
      if (r != null) this.copyTo(r)
      return
    }
    if (r == null) r = nbi()
    const y = nbi(), ts = this.s, ms = m.s
    const nsh = DB - nbits(pm[pm.t - 1])
    if (nsh > 0) { pm.lShiftTo(nsh, y); pt.lShiftTo(nsh, r) }
    else { pm.copyTo(y); pt.copyTo(r) }
    const ys = y.t
    const y0 = y[ys - 1]
    if (y0 === 0) return
    const yt = y0 * (1 << F1) + ((ys > 1) ? y[ys - 2] >> F2 : 0)
    const d1 = FV / yt, d2 = (1 << F1) / yt, e = 1 << F2
    let i = r.t, j = i - ys
    const t = (q == null) ? nbi() : q
    y.dlShiftTo(j, t)
    if (r.compareTo(t) >= 0) {
      r[r.t++] = 1
      r.subTo(t, r)
    }
    nbv(1).dlShiftTo(ys, t)
    t.subTo(y, y)
    while (y.t < ys) y[y.t++] = 0
    while (--j >= 0) {
      let qd = (r[--i] === y0) ? DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2)
      if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
        y.dlShiftTo(j, t)
        r.subTo(t, r)
        while (r[i] < --qd) r.subTo(t, r)
      }
    }
    if (q != null) {
      r.drShiftTo(ys, q)
      if (ts !== ms) BigInteger.ZERO.subTo(q, q)
    }
    r.t = ys
    r.clamp()
    if (nsh > 0) r.rShiftTo(nsh, r)
    if (ts < 0) BigInteger.ZERO.subTo(r, r)
  }

  add(a) { const r = nbi(); this.addTo(a, r); return r }
  subtract(a) { const r = nbi(); this.subTo(a, r); return r }
  multiply(a) { const r = nbi(); this.multiplyTo(a, r); return r }
  square() { const r = nbi(); this.squareTo(r); return r }
  divide(a) { const r = nbi(); this.divRemTo(a, r, null); return r }
  remainder(a) { const r = nbi(); this.divRemTo(a, null, r); return r }
  divideAndRemainder(a) { const q = nbi(), r = nbi(); this.divRemTo(a, q, r); return [q, r] }

  mod(a) {
    const r = nbi()
    this.abs().divRemTo(a, null, r)
    if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r)
    return r
  }

  dMultiply(n) {
    this[this.t] = this.am(0, n - 1, this, 0, 0, this.t)
    ++this.t
    this.clamp()
  }

  dAddOffset(n, w) {
    if (n === 0) return
    while (this.t <= w) this[this.t++] = 0
    this[w] += n
    while (this[w] >= DV) {
      this[w] -= DV
      if (++w >= this.t) this[this.t++] = 0
      ++this[w]
    }
  }

  // ---- 位运算 ----

  bitwiseTo(a, op, r) {
    const m = Math.min(a.t, this.t)
    let i, f
    for (i = 0; i < m; ++i) r[i] = op(this[i], a[i])
    if (a.t < this.t) {
      f = a.s & DM
      for (i = m; i < this.t; ++i) r[i] = op(this[i], f)
      r.t = this.t
    } else {
      f = this.s & DM
      for (i = m; i < a.t; ++i) r[i] = op(f, a[i])
      r.t = a.t
    }
    r.s = op(this.s, a.s)
    r.clamp()
  }

  and(a) { const r = nbi(); this.bitwiseTo(a, op_and, r); return r }
  or(a) { const r = nbi(); this.bitwiseTo(a, op_or, r); return r }
  xor(a) { const r = nbi(); this.bitwiseTo(a, op_xor, r); return r }
  andNot(a) { const r = nbi(); this.bitwiseTo(a, op_andnot, r); return r }

  not() {
    const r = nbi()
    for (let i = 0; i < this.t; ++i) r[i] = DM & ~this[i]
    r.t = this.t
    r.s = ~this.s
    return r
  }

  getLowestSetBit() {
    for (let i = 0; i < this.t; ++i) if (this[i] !== 0) return i * DB + lbit(this[i])
    if (this.s < 0) return this.t * DB
    return -1
  }

  bitCount() {
    let r = 0
    const x = this.s & DM
    for (let i = 0; i < this.t; ++i) r += cbit(this[i] ^ x)
    return r
  }

  testBit(n) {
    const j = Math.floor(n / DB)
    if (j >= this.t) return (this.s !== 0)
    return ((this[j] & (1 << (n % DB))) !== 0)
  }

  changeBit(n, op) {
    const r = BigInteger.ONE.shiftLeft(n)
    this.bitwiseTo(r, op, r)
    return r
  }

  setBit(n) { return this.changeBit(n, op_or) }
  clearBit(n) { return this.changeBit(n, op_andnot) }
  flipBit(n) { return this.changeBit(n, op_xor) }

  // ---- 模运算 ----

  invDigit() {
    if (this.t < 1) return 0
    const x = this[0]
    if ((x & 1) === 0) return 0
    let y = x & 3
    y = (y * (2 - (x & 0xf) * y)) & 0xf
    y = (y * (2 - (x & 0xff) * y)) & 0xff
    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff
    y = (y * (2 - x * y % DV)) % DV
    return (y > 0) ? DV - y : -y
  }

  modPowInt(e, m) {
    let z
    if (e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m)
    return this.exp(e, z)
  }

  exp(e, z) {
    if (e > 0xffffffff || e < 1) return BigInteger.ONE
    let r = nbi(), r2 = nbi()
    const g = z.convert(this)
    let i = nbits(e) - 1
    g.copyTo(r)
    while (--i >= 0) {
      z.sqrTo(r, r2)
      if ((e & (1 << i)) > 0) z.mulTo(r2, g, r)
      else { const t = r; r = r2; r2 = t }
    }
    return z.revert(r)
  }

  modPow(e, m) {
    let i = e.bitLength(), k, r = nbv(1), z
    if (i <= 0) return r
    else if (i < 18) k = 1
    else if (i < 48) k = 3
    else if (i < 144) k = 4
    else if (i < 768) k = 5
    else k = 6
    if (i < 8) z = new Classic(m)
    else if (m.isEven()) z = new Barrett(m)
    else z = new Montgomery(m)

    const g = [], k1 = k - 1, km = (1 << k) - 1
    let n = 3
    g[1] = z.convert(this)
    if (k > 1) {
      const g2 = nbi()
      z.sqrTo(g[1], g2)
      while (n <= km) {
        g[n] = nbi()
        z.mulTo(g2, g[n - 2], g[n])
        n += 2
      }
    }

    let j = e.t - 1, w, is1 = true, r2 = nbi(), t
    i = nbits(e[j]) - 1
    while (j >= 0) {
      if (i >= k1) w = (e[j] >> (i - k1)) & km
      else {
        w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i)
        if (j > 0) w |= e[j - 1] >> (DB + i - k1)
      }
      n = k
      while ((w & 1) === 0) { w >>= 1; --n }
      if ((i -= n) < 0) { i += DB; --j }
      if (is1) { g[w].copyTo(r); is1 = false }
      else {
        while (n > 1) { z.sqrTo(r, r2); z.sqrTo(r2, r); n -= 2 }
        if (n > 0) z.sqrTo(r, r2); else { t = r; r = r2; r2 = t }
        z.mulTo(r2, g[w], r)
      }
      while (j >= 0 && (e[j] & (1 << i)) === 0) {
        z.sqrTo(r, r2); t = r; r = r2; r2 = t
        if (--i < 0) { i = DB - 1; --j }
      }
    }
    return z.revert(r)
  }

  modInverse(m) {
    const ac = m.isEven()
    if ((this.isEven() && ac) || m.signum() === 0) return BigInteger.ZERO
    const u = m.clone(), v = this.clone()
    const a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1)
    while (u.signum() !== 0) {
      while (u.isEven()) {
        u.rShiftTo(1, u)
        if (ac) {
          if (!a.isEven() || !b.isEven()) { a.addTo(this, a); b.subTo(m, b) }
          a.rShiftTo(1, a)
        } else if (!b.isEven()) b.subTo(m, b)
        b.rShiftTo(1, b)
      }
      while (v.isEven()) {
        v.rShiftTo(1, v)
        if (ac) {
          if (!c.isEven() || !d.isEven()) { c.addTo(this, c); d.subTo(m, d) }
          c.rShiftTo(1, c)
        } else if (!d.isEven()) d.subTo(m, d)
        d.rShiftTo(1, d)
      }
      if (u.compareTo(v) >= 0) {
        u.subTo(v, u)
        if (ac) a.subTo(c, a)
        b.subTo(d, b)
      } else {
        v.subTo(u, v)
        if (ac) c.subTo(a, c)
        d.subTo(b, d)
      }
    }
    if (v.compareTo(BigInteger.ONE) !== 0) return BigInteger.ZERO
    if (d.compareTo(m) >= 0) return d.subtract(m)
    if (d.signum() < 0) d.addTo(m, d); else return d
    if (d.signum() < 0) return d.add(m); else return d
  }

  pow(e) { return this.exp(e, new NullExp()) }

  gcd(a) {
    let x = (this.s < 0) ? this.negate() : this.clone()
    let y = (a.s < 0) ? a.negate() : a.clone()
    if (x.compareTo(y) < 0) { const t = x; x = y; y = t }
    let i = x.getLowestSetBit(), g = y.getLowestSetBit()
    if (g < 0) return x
    if (i < g) g = i
    if (g > 0) { x.rShiftTo(g, x); y.rShiftTo(g, y) }
    while (x.signum() > 0) {
      if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x)
      if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y)
      if (x.compareTo(y) >= 0) { x.subTo(y, x); x.rShiftTo(1, x) }
      else { y.subTo(x, y); y.rShiftTo(1, y) }
    }
    if (g > 0) y.lShiftTo(g, y)
    return y
  }

  modInt(n) {
    if (n <= 0) return 0
    const d = DV % n
    let r = (this.s < 0) ? n - 1 : 0
    if (this.t > 0) {
      if (d === 0) r = this[0] % n
      else for (let i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n
    }
    return r
  }

  // ---- 素性测试 ----

  isProbablePrime(t) {
    let i
    const x = this.abs()
    if (x.t === 1 && x[0] <= LOW_PRIMES[LOW_PRIMES.length - 1]) {
      for (i = 0; i < LOW_PRIMES.length; ++i) if (x[0] === LOW_PRIMES[i]) return true
      return false
    }
    if (x.isEven()) return false
    i = 1
    while (i < LOW_PRIMES.length) {
      let m = LOW_PRIMES[i], j = i + 1
      while (j < LOW_PRIMES.length && m < LP_LIM) m *= LOW_PRIMES[j++]
      m = x.modInt(m)
      while (i < j) if (m % LOW_PRIMES[i++] === 0) return false
    }
    return x.millerRabin(t)
  }

  millerRabin(t) {
    const n1 = this.subtract(BigInteger.ONE)
    const k = n1.getLowestSetBit()
    if (k <= 0) return false
    const r = n1.shiftRight(k)
    t = (t + 1) >> 1
    if (t > LOW_PRIMES.length) t = LOW_PRIMES.length
    const a = nbi()
    for (let i = 0; i < t; ++i) {
      a.fromInt(LOW_PRIMES[Math.floor(Math.random() * LOW_PRIMES.length)])
      let y = a.modPow(r, this)
      if (y.compareTo(BigInteger.ONE) !== 0 && y.compareTo(n1) !== 0) {
        let j = 1
        while (j++ < k && y.compareTo(n1) !== 0) {
          y = y.modPowInt(2, this)
          if (y.compareTo(BigInteger.ONE) === 0) return false
        }
        if (y.compareTo(n1) !== 0) return false
      }
    }
    return true
  }

  // ---- lower/upper multiply ----

  multiplyLowerTo(a, n, r) {
    let i = Math.min(this.t + a.t, n)
    r.s = 0
    r.t = i
    while (i > 0) r[--i] = 0
    let j
    for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t)
    for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i)
    r.clamp()
  }

  multiplyUpperTo(a, n, r) {
    --n
    let i = r.t = this.t + a.t - n
    r.s = 0
    while (--i >= 0) r[i] = 0
    for (i = Math.max(n - this.t, 0); i < a.t; ++i) r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n)
    r.clamp()
    r.drShiftTo(1, r)
  }

  // ---- 兼容只读属性 ----

  get DV() { return DV }
  get DM() { return DM }
  get DB() { return DB }
}

// 位运算操作符函数
function op_and(x, y) { return x & y }
function op_or(x, y) { return x | y }
function op_xor(x, y) { return x ^ y }
function op_andnot(x, y) { return x & ~y }

// 静态常量（延迟初始化避免循环依赖）
BigInteger.ZERO = nbv(0)
BigInteger.ONE = nbv(1)

// 静态工厂方法
BigInteger.nbi = nbi
BigInteger.nbv = nbv

// ---- 模约简器 ----

class NullExp {
  convert(x) { return x }
  revert(x) { return x }
  mulTo(x, y, r) { x.multiplyTo(y, r) }
  sqrTo(x, r) { x.squareTo(r) }
}

class Classic {
  constructor(m) { this.m = m }
  convert(x) { return (x.s < 0 || x.compareTo(this.m) >= 0) ? x.mod(this.m) : x }
  revert(x) { return x }
  reduce(x) { x.divRemTo(this.m, null, x) }
  mulTo(x, y, r) { x.multiplyTo(y, r); this.reduce(r) }
  sqrTo(x, r) { x.squareTo(r); this.reduce(r) }
}

class Montgomery {
  constructor(m) {
    this.m = m
    this.mp = m.invDigit()
    this.mpl = this.mp & 0x7fff
    this.mph = this.mp >> 15
    this.um = (1 << (DB - 15)) - 1
    this.mt2 = 2 * m.t
  }

  convert(x) {
    const r = nbi()
    x.abs().dlShiftTo(this.m.t, r)
    r.divRemTo(this.m, null, r)
    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r)
    return r
  }

  revert(x) {
    const r = nbi()
    x.copyTo(r)
    this.reduce(r)
    return r
  }

  reduce(x) {
    while (x.t <= this.mt2) x[x.t++] = 0
    for (let i = 0; i < this.m.t; ++i) {
      let j = x[i] & 0x7fff
      const u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & DM
      j = i + this.m.t
      x[j] += this.m.am(0, u0, x, i, 0, this.m.t)
      while (x[j] >= DV) { x[j] -= DV; x[++j]++ }
    }
    x.clamp()
    x.drShiftTo(this.m.t, x)
    if (x.compareTo(this.m) >= 0) x.subTo(this.m, x)
  }

  mulTo(x, y, r) { x.multiplyTo(y, r); this.reduce(r) }
  sqrTo(x, r) { x.squareTo(r); this.reduce(r) }
}

class Barrett {
  constructor(m) {
    this.r2 = nbi()
    this.q3 = nbi()
    BigInteger.ONE.dlShiftTo(2 * m.t, this.r2)
    this.mu = this.r2.divide(m)
    this.m = m
  }

  convert(x) {
    if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m)
    if (x.compareTo(this.m) < 0) return x
    const r = nbi(); x.copyTo(r); this.reduce(r); return r
  }

  revert(x) { return x }

  reduce(x) {
    x.drShiftTo(this.m.t - 1, this.r2)
    if (x.t > this.m.t + 1) { x.t = this.m.t + 1; x.clamp() }
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3)
    this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2)
    while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1)
    x.subTo(this.r2, x)
    while (x.compareTo(this.m) >= 0) x.subTo(this.m, x)
  }

  mulTo(x, y, r) { x.multiplyTo(y, r); this.reduce(r) }
  sqrTo(x, r) { x.squareTo(r); this.reduce(r) }
}

// ---- SecureRandom ----

class Arcfour {
  constructor() {
    this.i = 0
    this.j = 0
    this.S = new Array(256)
  }

  init(key) {
    for (let i = 0; i < 256; ++i) this.S[i] = i
    let j = 0
    for (let i = 0; i < 256; ++i) {
      j = (j + this.S[i] + key[i % key.length]) & 255
      const t = this.S[i]
      this.S[i] = this.S[j]
      this.S[j] = t
    }
    this.i = 0
    this.j = 0
  }

  next() {
    this.i = (this.i + 1) & 255
    this.j = (this.j + this.S[this.i]) & 255
    const t = this.S[this.i]
    this.S[this.i] = this.S[this.j]
    this.S[this.j] = t
    return this.S[(t + this.S[this.i]) & 255]
  }
}

const RNG_PSIZE = 256

export class SecureRandom {
  constructor() {
    this._state = null
    this._pool = []
    this._pptr = 0

    // 使用平台 CSPRNG 初始化熵池
    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
      const ua = new Uint8Array(32)
      globalThis.crypto.getRandomValues(ua)
      for (let i = 0; i < 32; ++i) this._pool[this._pptr++] = ua[i]
    }

    // 补充到 RNG_PSIZE
    while (this._pptr < RNG_PSIZE) {
      const t = Math.floor(65536 * Math.random())
      this._pool[this._pptr++] = t >>> 8
      this._pool[this._pptr++] = t & 255
    }
    this._pptr = 0
    this._seedTime()
  }

  nextBytes(ba) {
    for (let i = 0; i < ba.length; ++i) ba[i] = this._getByte()
  }

  _seedInt(x) {
    this._pool[this._pptr++] ^= x & 255
    this._pool[this._pptr++] ^= (x >> 8) & 255
    this._pool[this._pptr++] ^= (x >> 16) & 255
    this._pool[this._pptr++] ^= (x >> 24) & 255
    if (this._pptr >= RNG_PSIZE) this._pptr -= RNG_PSIZE
  }

  _seedTime() {
    this._seedInt(Date.now())
  }

  _getByte() {
    if (this._state === null) {
      this._seedTime()
      this._state = new Arcfour()
      this._state.init(this._pool)
      for (this._pptr = 0; this._pptr < this._pool.length; ++this._pptr) this._pool[this._pptr] = 0
      this._pptr = 0
    }
    return this._state.next()
  }
}
