/* eslint-disable no-case-declarations, max-len */

import { BigInteger } from './biginteger.js'

const ZERO = new BigInteger('0')
const ONE = new BigInteger('1')
const TWO = new BigInteger('2')
const THREE = new BigInteger('3')

/**
 * 椭圆曲线域元素
 */
class ECFieldElementFp {
  constructor(q, x) {
    this.x = x
    this.q = q
    // TODO if (x.compareTo(q) >= 0) error
  }

  /**
   * 判断相等
   */
  equals(other) {
    if (other === this) return true
    return (this.q.equals(other.q) && this.x.equals(other.x))
  }

  /**
   * 返回具体数值
   */
  toBigInteger() {
    return this.x
  }

  isZero() {
    return this.toBigInteger().signum() == 0
  }

  /**
   * 取反
   */
  negate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q))
  }

  /**
   * 相加
   */
  add(b) {
    return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q))
  }

  /**
   * 相减
   */
  subtract(b) {
    return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q))
  }

  /**
   * 相乘
   */
  multiply(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q))
  }

  /**
   * 相除
   */
  divide(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q))
  }

  /**
   * 平方
   */
  square() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q))
  }
}

export class ECPointFp {
  constructor(curve, x, y, z) {
    this.curve = curve
    this.x = x
    this.y = y
    // 标准射影坐标系：zinv == null 或 z * zinv == 1
    this.z = z == null ? ONE : z
    this.zinv = null
  }

  isValid() {
    if (this.isInfinity()) {
      return true;
    }
    return this.x.square().add(this.curve.a).multiply(this.x).add(this.curve.b).equals(this.y.square())
  }

  getX() {
    if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q)

    return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q))
  }

  getY() {
    if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q)

    return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q))
  }

  /**
   * 判断相等
   */
  equals(other) {
    if (other === this) return true
    if (this.isInfinity()) return other.isInfinity()
    if (other.isInfinity()) return this.isInfinity()

    // u = y2 * z1 - y1 * z2
    const u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q)
    if (!u.equals(ZERO)) return false

    // v = x2 * z1 - x1 * z2
    const v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q)
    return v.equals(ZERO)
  }

  /**
   * 是否是无穷远点
   */
  isInfinity() {
    if ((this.x === null) && (this.y === null)) return true
    return this.z.equals(ZERO) && !this.y.toBigInteger().equals(ZERO)
  }

  /**
   * 取反，x 轴对称点
   */
  negate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z)
  }
  n
  /**
   * 相加
   */
  add(b) {
    if (this.isInfinity()) return b
    if (b.isInfinity()) return this
    if (this == b) return this.twice()

    const curve = this.curve
    const x1 = this.x
    const y1 = this.y
    const x2 = b.x
    const y2 = b.y
    const dx = x2.subtract(x1)
    const dy = y2.subtract(y1)
    if (dx.isZero()) {
      if (dy.isZero()) {
        return this.twice()
      }
      return curve.infinity()
    }
    const gramma = dy.divide(dx)
    const x3 = gramma.square().subtract(x1).subtract(x2)
    const y3 = gramma.multiply(x1.subtract(x3)).subtract(y1)
    return new ECPointFp(this.curve, x3, y3, this.z)
  }

  /**
   * 自加
   */
  twice() {
    if (this.isInfinity()) return this
    if (!this.y.toBigInteger().signum()) return this.curve.infinity

    const x1 = this.x
    const y1 = this.y

    const z1 = this.z
    const a = this.curve.a

    const x1squared = x1.square()
    const gramma = x1squared.multiply(this.curve.fromBigInteger(THREE)).add(a).divide(y1.multiply(this.curve.fromBigInteger(TWO)))
    const x3 = gramma.square().subtract(x1.multiply(this.curve.fromBigInteger(TWO)))
    const y3 = gramma.multiply(x1.subtract(x3)).subtract(y1)
    return new ECPointFp(this.curve, x3, y3, z1)
  }
  subtract(v) {
    if (v.isInfinity()) {
      return this
    }
    return this.add(v.negate())
  }

  timesPow2(e) {
    if (e < 0) {
      throw new Error('Invalid value for "e", it must be positive')
    }
    let p = this
    while (--e >= 0) {
      p = p.twice()
    }
    return p;
  }

  /**
   * 倍点计算
   */

  multiply(k) {
    if (this.isInfinity()) return this;
    if (k.signum() == 0 || this.isInfinity()) return this.curve.getInfinity();
    const positive = this.multiplyPositive(k.abs());
    const result = k.signum() > 0 ? positive : positive.negate();
    if (!result.isValid()) {
      throw new Error('Invalid point');
    }
    return result
  }

  getBit(x, bit) {
    if (bit == 0) {
      return x[0] & 1;
    }
    const w = bit >> 5;
    if (w < 0 || w >= x.length) {
      return 0;
    }
    const b = bit & 31;
    return (x[w] >>> b) & 1;
  }

  multiplyPositive(k) {
    const p = this;
    const c = p.curve
    const size = this.getCombSize()
    if (k.bitLength() > size) {
      throw new Error('k is too large')
    }
    const info = this.preCalc()
    const width = info.width
    const d = (size + width - 1) / width;
    let Q = new ECPointFp(c, null, null, null);
    const l = d * width
    const K = this.fromBigInteger(l, k)
    for (let i = 0; i < d; ++i) {
      let idx = 0;
      for (let j = l - 1 - i; j >= 0; j -= d) {
        idx <<= 1
        idx |= this.getBit(K, j)
      }
      const add = info.preComp[idx]
      Q = Q.twice().add(add)
    }
    return Q.add(info.offset)
  }

  getCombSize() {
    return this.curve.q.bitLength()
  }

  preCalc() {
    const p = this;
    const curve = p.curve
    const bits = this.getCombSize()
    const minWidth = bits > 256 ? 6 : 5
    const n = 1 << minWidth
    const d = (bits + minWidth - 1) / minWidth
    const pow2Table = new Array(minWidth + 1)
    pow2Table[0] = p
    for (let i = 1; i < minWidth; ++i) {
      pow2Table[i] = pow2Table[i - 1].timesPow2(d)
    }
    pow2Table[minWidth] = pow2Table[0].subtract(pow2Table[1])
    curve.checkPoints(pow2Table, 0, pow2Table.length)
    const preComp = new Array(n)
    preComp[0] = pow2Table[0]
    for (let bit = minWidth - 1; bit >= 0; --bit) {
      const pow2 = pow2Table[bit]
      const step = 1 << bit;
      for (let i = step; i < n; i += (step << 1)) {
        preComp[i] = preComp[i - step].add(pow2)
      }
    }
    curve.checkPoints(preComp, 0, preComp.length)
    return { 'offset': pow2Table[minWidth], 'preComp': preComp, 'width': minWidth }
  }

  fromBigInteger(bits, x) {
    if (x.signum() < 0 || x.bitLength() > bits) {
      throw new Error('BigInteger not in range');
    }
    const len = (bits + 31) >> 5;
    const z = new Array(len);
    let i = 0;
    while (x.signum() != 0) {
      z[i++] = x.intValue();
      x = x.shiftRight(32);
    }
    return z;
  }
}

/**
 * 椭圆曲线 y^2 = x^3 + ax + b
 */
export class ECCurveFp {
  constructor(q, a, b) {
    this.q = q
    this.a = this.fromBigInteger(a)
    this.b = this.fromBigInteger(b)
    this.infinity = new ECPointFp(this, null, null) // 无穷远点
  }

  getInfinity() {
    return this.infinity
  }
  /**
   * 判断两个椭圆曲线是否相等
   */
  equals(other) {
    if (other === this) return true
    return (this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b))
  }

  /**
   * 生成椭圆曲线域元素
   */
  fromBigInteger(x) {
    return new ECFieldElementFp(this.q, x)
  }

  validatePoint(x, y) {
    const point = new ECPointFp(this, x, y)
    if (!point.isValid()) {
      throw new Error('Point is not on this curve.')
    }
  }

  checkPoints(points, off, len) {
    if (!points) {
      throw new Error('points is null')
    }
    if (off < 0 || len < 0 || (off > (points.length - len))) {
      throw new Error('Invalid range')
    }
    for (let i = 0; i < len; ++i) {
      const point = points[off + i]
      if (!point || this != point.curve) {
        throw new Error('points[' + (off + i) + '] is invalid')
      }
    }
  }

  /**
   * 解析 16 进制串为椭圆曲线点
   */
  decodePointHex(s) {
    switch (parseInt(s.substr(0, 2), 16)) {
      // 第一个字节
      case 0:
        return this.infinity
      case 2:
      case 3:
        // 压缩
        const x = this.fromBigInteger(new BigInteger(s.substr(2), 16))
        // 对 p ≡ 3 (mod4)，即存在正整数 u，使得 p = 4u + 3
        // 计算 y = (√ (x^3 + ax + b) % p)^(u + 1) modp
        let y = this.fromBigInteger(x.multiply(x.square()).add(
          x.multiply(this.a)
        ).add(this.b).toBigInteger()
          .modPow(
            this.q.divide(new BigInteger('4')).add(ONE), this.q
          ))
        // 算出结果 2 进制最后 1 位不等于第 1 个字节减 2 则取反
        if (!y.toBigInteger().mod(TWO).equals(new BigInteger(s.substr(0, 2), 16).subtract(TWO))) {
          y = y.negate()
        }
        return new ECPointFp(this, x, y)
      case 4:
      case 6:
      case 7:
        const len = (s.length - 2) / 2
        const xHex = s.substr(2, len)
        const yHex = s.substr(len + 2, len)

        return new ECPointFp(this, this.fromBigInteger(new BigInteger(xHex, 16)), this.fromBigInteger(new BigInteger(yHex, 16)))
      default:
        // 不支持
        return null
    }
  }
}
