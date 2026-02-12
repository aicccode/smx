import { BigInteger } from './biginteger.js'

const ZERO = BigInteger.ZERO
const ONE = BigInteger.ONE
const TWO = BigInteger.nbv(2)
const THREE = BigInteger.nbv(3)

/**
 * 椭圆曲线域元素 Fp
 */
class ECFieldElementFp {
  constructor(q, x) {
    this.x = x
    this.q = q
  }

  equals(other) {
    if (other === this) return true
    return this.q.equals(other.q) && this.x.equals(other.x)
  }

  toBigInteger() {
    return this.x
  }
  isZero() {
    return this.x.signum() === 0
  }

  negate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q))
  }

  add(b) {
    return new ECFieldElementFp(
      this.q,
      this.x.add(b.toBigInteger()).mod(this.q),
    )
  }

  subtract(b) {
    return new ECFieldElementFp(
      this.q,
      this.x.subtract(b.toBigInteger()).mod(this.q),
    )
  }

  multiply(b) {
    return new ECFieldElementFp(
      this.q,
      this.x.multiply(b.toBigInteger()).mod(this.q),
    )
  }

  divide(b) {
    return new ECFieldElementFp(
      this.q,
      this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q),
    )
  }

  square() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q))
  }
}

/**
 * 椭圆曲线点 (仿射 / 射影坐标)
 */
export class ECPointFp {
  constructor(curve, x, y, z) {
    this.curve = curve
    this.x = x
    this.y = y
    this.z = z == null ? ONE : z
    this.zinv = null
  }

  isValid() {
    if (this.isInfinity()) return true
    // y² = x³ + ax + b
    return this.x
      .square()
      .add(this.curve.a)
      .multiply(this.x)
      .add(this.curve.b)
      .equals(this.y.square())
  }

  getX() {
    if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q)
    return this.curve.fromBigInteger(
      this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q),
    )
  }

  getY() {
    if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q)
    return this.curve.fromBigInteger(
      this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q),
    )
  }

  equals(other) {
    if (other === this) return true
    if (this.isInfinity()) return other.isInfinity()
    if (other.isInfinity()) return this.isInfinity()

    const u = other.y
      .toBigInteger()
      .multiply(this.z)
      .subtract(this.y.toBigInteger().multiply(other.z))
      .mod(this.curve.q)
    if (!u.equals(ZERO)) return false

    const v = other.x
      .toBigInteger()
      .multiply(this.z)
      .subtract(this.x.toBigInteger().multiply(other.z))
      .mod(this.curve.q)
    return v.equals(ZERO)
  }

  isInfinity() {
    if (this.x === null && this.y === null) return true
    return this.z.equals(ZERO) && !this.y.toBigInteger().equals(ZERO)
  }

  negate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z)
  }

  add(b) {
    if (this.isInfinity()) return b
    if (b.isInfinity()) return this
    if (this === b) return this.twice()

    const x1 = this.x,
      y1 = this.y
    const x2 = b.x,
      y2 = b.y
    const dx = x2.subtract(x1)
    const dy = y2.subtract(y1)

    if (dx.isZero()) {
      return dy.isZero() ? this.twice() : this.curve.infinity
    }

    const gamma = dy.divide(dx)
    const x3 = gamma.square().subtract(x1).subtract(x2)
    const y3 = gamma.multiply(x1.subtract(x3)).subtract(y1)
    return new ECPointFp(this.curve, x3, y3, this.z)
  }

  twice() {
    if (this.isInfinity()) return this
    if (!this.y.toBigInteger().signum()) return this.curve.infinity

    const x1 = this.x,
      y1 = this.y
    const a = this.curve.a
    const gamma = x1
      .square()
      .multiply(this.curve.fromBigInteger(THREE))
      .add(a)
      .divide(y1.multiply(this.curve.fromBigInteger(TWO)))
    const x3 = gamma
      .square()
      .subtract(x1.multiply(this.curve.fromBigInteger(TWO)))
    const y3 = gamma.multiply(x1.subtract(x3)).subtract(y1)
    return new ECPointFp(this.curve, x3, y3, this.z)
  }

  subtract(v) {
    if (v.isInfinity()) return this
    return this.add(v.negate())
  }

  timesPow2(e) {
    if (e < 0) throw new Error('Invalid value for "e", it must be positive')
    let p = this
    while (--e >= 0) p = p.twice()
    return p
  }

  /**
   * 标量乘法 k * P
   */
  multiply(k) {
    if (this.isInfinity()) return this
    if (k.signum() === 0) return this.curve.getInfinity()
    const positive = this._multiplyPositive(k.abs())
    const result = k.signum() > 0 ? positive : positive.negate()
    if (!result.isValid()) throw new Error('Invalid point')
    return result
  }

  // ---- 内部: Comb 标量乘法 ----

  _multiplyPositive(k) {
    const size = this.curve.q.bitLength()
    if (k.bitLength() > size) throw new Error('k is too large')

    const info = this._preCalc()
    const width = info.width
    const d = (size + width - 1) / width
    const l = d * width
    const K = this._fromBigInteger(l, k)
    let Q = new ECPointFp(this.curve, null, null, null)

    for (let i = 0; i < d; ++i) {
      let idx = 0
      for (let j = l - 1 - i; j >= 0; j -= d) {
        idx <<= 1
        idx |= this._getBit(K, j)
      }
      Q = Q.twice().add(info.preComp[idx])
    }
    return Q.add(info.offset)
  }

  _getCombSize() {
    return this.curve.q.bitLength()
  }

  _preCalc() {
    const bits = this._getCombSize()
    const minWidth = bits > 256 ? 6 : 5
    const n = 1 << minWidth
    const d = (bits + minWidth - 1) / minWidth

    const pow2Table = new Array(minWidth + 1)
    pow2Table[0] = this
    for (let i = 1; i < minWidth; ++i)
      pow2Table[i] = pow2Table[i - 1].timesPow2(d)
    pow2Table[minWidth] = pow2Table[0].subtract(pow2Table[1])
    this.curve.checkPoints(pow2Table, 0, pow2Table.length)

    const preComp = new Array(n)
    preComp[0] = pow2Table[0]
    for (let bit = minWidth - 1; bit >= 0; --bit) {
      const pow2 = pow2Table[bit]
      const step = 1 << bit
      for (let i = step; i < n; i += step << 1) {
        preComp[i] = preComp[i - step].add(pow2)
      }
    }
    this.curve.checkPoints(preComp, 0, preComp.length)

    return { offset: pow2Table[minWidth], preComp, width: minWidth }
  }

  _getBit(x, bit) {
    if (bit === 0) return x[0] & 1
    const w = bit >> 5
    if (w < 0 || w >= x.length) return 0
    return (x[w] >>> (bit & 31)) & 1
  }

  _fromBigInteger(bits, x) {
    if (x.signum() < 0 || x.bitLength() > bits)
      throw new Error('BigInteger not in range')
    const len = (bits + 31) >> 5
    const z = new Array(len)
    let i = 0
    while (x.signum() !== 0) {
      z[i++] = x.intValue()
      x = x.shiftRight(32)
    }
    return z
  }
}

/**
 * 椭圆曲线 y² = x³ + ax + b (mod q)
 */
export class ECCurveFp {
  constructor(q, a, b) {
    this.q = q
    this.a = this.fromBigInteger(a)
    this.b = this.fromBigInteger(b)
    this.infinity = new ECPointFp(this, null, null)
  }

  getInfinity() {
    return this.infinity
  }

  equals(other) {
    if (other === this) return true
    return (
      this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b)
    )
  }

  fromBigInteger(x) {
    return new ECFieldElementFp(this.q, x)
  }

  validatePoint(x, y) {
    const point = new ECPointFp(this, x, y)
    if (!point.isValid()) throw new Error('Point is not on this curve.')
  }

  checkPoints(points, off, len) {
    if (!points) throw new Error('points is null')
    if (off < 0 || len < 0 || off > points.length - len)
      throw new Error('Invalid range')
    for (let i = 0; i < len; ++i) {
      const point = points[off + i]
      if (!point || this !== point.curve)
        throw new Error(`points[${off + i}] is invalid`)
    }
  }

  /**
   * 解析十六进制串为椭圆曲线点
   */
  decodePointHex(s) {
    const tag = parseInt(s.substring(0, 2), 16)
    switch (tag) {
      case 0:
        return this.infinity

      case 2:
      case 3: {
        const x = this.fromBigInteger(new BigInteger(s.substring(2), 16))
        let y = this.fromBigInteger(
          x
            .multiply(x.square())
            .add(x.multiply(this.a))
            .add(this.b)
            .toBigInteger()
            .modPow(this.q.divide(new BigInteger('4')).add(ONE), this.q),
        )
        if (
          !y
            .toBigInteger()
            .mod(TWO)
            .equals(new BigInteger(s.substring(0, 2), 16).subtract(TWO))
        ) {
          y = y.negate()
        }
        return new ECPointFp(this, x, y)
      }

      case 4:
      case 6:
      case 7: {
        const len = (s.length - 2) / 2
        const xHex = s.substring(2, 2 + len)
        const yHex = s.substring(2 + len, 2 + 2 * len)
        return new ECPointFp(
          this,
          this.fromBigInteger(new BigInteger(xHex, 16)),
          this.fromBigInteger(new BigInteger(yHex, 16)),
        )
      }

      default:
        return null
    }
  }
}
