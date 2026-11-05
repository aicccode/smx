import { BigInteger } from './biginteger.js'
import { decodeHex } from '../common/hex.js'
import { bigToBytes, bytesToBig } from './bytes.js'
import {
  G_X_BYTES,
  G_Y_BYTES,
  affineAdd,
  affineDouble,
  decompressY,
  fieldDivBytes,
  fieldMulBytes,
  fieldSqrBytes,
  isOnCurve,
  mulG,
  mulPoint,
  mulPublic,
} from './point.js'

const ZERO = BigInteger.ZERO
const ONE = BigInteger.ONE
const TWO = BigInteger.nbv(2)
const THREE = BigInteger.nbv(3)

const SM2_P = new BigInteger(
  'fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff',
  16,
)
const SM2_A = new BigInteger(
  'fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc',
  16,
)
const SM2_B = new BigInteger(
  '28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93',
  16,
)
const SM2_GX = bytesToBig(G_X_BYTES)
const SM2_GY = bytesToBig(G_Y_BYTES)
const SM2_BITS = 256
const INVALID_POINT = 'Invalid point encoding'
const MAX_DOUBLINGS = 65536

// Reused across calls. JavaScript is single-threaded and nothing here yields.
const bufA = new Uint8Array(32)
const bufB = new Uint8Array(32)
const bufC = new Uint8Array(32)
const bufD = new Uint8Array(32)
const outX = new Uint8Array(32)
const outY = new Uint8Array(32)

function isSm2Prime(q) {
  return q === SM2_P || q.equals(SM2_P)
}

/** v mod q, skipping the division when one subtraction or addition is enough. */
function reduce(v, q) {
  if (q.s < 0) return v.mod(q)
  if (v.s >= 0) {
    if (v.compareTo(q) < 0) return v
    const r = v.subtract(q)
    if (r.compareTo(q) < 0) return r
  } else {
    const r = v.add(q)
    if (r.s >= 0) return r
  }
  return v.mod(q)
}

function isExactlyOne(z) {
  return z.t === 1 && z[0] === 1 && z.s === 0
}

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
    return new ECFieldElementFp(this.q, reduce(this.x.negate(), this.q))
  }

  add(b) {
    return new ECFieldElementFp(
      this.q,
      reduce(this.x.add(b.toBigInteger()), this.q),
    )
  }

  subtract(b) {
    return new ECFieldElementFp(
      this.q,
      reduce(this.x.subtract(b.toBigInteger()), this.q),
    )
  }

  multiply(b) {
    const q = this.q
    if (isSm2Prime(q)) {
      bigToBytes(reduce(this.x, q), bufA)
      bigToBytes(reduce(b.toBigInteger(), q), bufB)
      fieldMulBytes(bufA, bufB, bufC)
      return new ECFieldElementFp(q, bytesToBig(bufC))
    }
    return new ECFieldElementFp(q, this.x.multiply(b.toBigInteger()).mod(q))
  }

  divide(b) {
    const q = this.q
    const divisor = reduce(b.toBigInteger(), q)
    if (divisor.signum() === 0) throw new RangeError('Division by zero')
    if (isSm2Prime(q)) {
      bigToBytes(reduce(this.x, q), bufA)
      bigToBytes(divisor, bufB)
      fieldDivBytes(bufA, bufB, bufC)
      return new ECFieldElementFp(q, bytesToBig(bufC))
    }
    return new ECFieldElementFp(
      q,
      this.x.multiply(divisor.modInverse(q)).mod(q),
    )
  }

  square() {
    const q = this.q
    if (isSm2Prime(q)) {
      bigToBytes(reduce(this.x, q), bufA)
      fieldSqrBytes(bufA, bufC)
      return new ECFieldElementFp(q, bytesToBig(bufC))
    }
    return new ECFieldElementFp(q, this.x.square().mod(q))
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

  /**
   * Whether this is the point at infinity, or a finite point with canonical
   * coordinates in [0, q) that satisfies y² = x³ + ax + b.
   */
  isValid() {
    if (this.isInfinity()) return true
    if (this.x === null || this.y === null) return false
    const q = this.curve.q
    const x = this.x.toBigInteger()
    const y = this.y.toBigInteger()
    if (x.s < 0 || y.s < 0 || x.compareTo(q) >= 0 || y.compareTo(q) >= 0) {
      return false
    }
    if (this.curve._isSm2) {
      bigToBytes(x, bufA)
      bigToBytes(y, bufB)
      return isOnCurve(bufA, bufB)
    }
    // y² = x³ + ax + b
    return this.x
      .square()
      .add(this.curve.a)
      .multiply(this.x)
      .add(this.curve.b)
      .equals(this.y.square())
  }

  /** Throws unless this is a valid affine point or the point at infinity. */
  _requireUsable() {
    if (!this.isValid() || (!this.isInfinity() && !isExactlyOne(this.z))) {
      throw new Error('Invalid point')
    }
  }

  /** Writes the raw x and y, reduced mod q, ignoring z. */
  _coordinatesTo(x, y) {
    const q = this.curve.q
    bigToBytes(reduce(this.x.toBigInteger(), q), x)
    bigToBytes(reduce(this.y.toBigInteger(), q), y)
  }

  _pointFromBytes(x, y) {
    return new ECPointFp(
      this.curve,
      this.curve.fromBigInteger(bytesToBig(x)),
      this.curve.fromBigInteger(bytesToBig(y)),
      this.z,
    )
  }

  getX() {
    return this._affine(this.x)
  }

  getY() {
    return this._affine(this.y)
  }

  _affine(coordinate) {
    if (this.isInfinity())
      throw new Error('Point at infinity has no coordinates')
    const q = this.curve.q
    if (isExactlyOne(this.z)) {
      this.zinv = ONE
      return this.curve.fromBigInteger(reduce(coordinate.toBigInteger(), q))
    }
    if (this.zinv === null) this.zinv = this.z.modInverse(q)
    return this.curve.fromBigInteger(
      coordinate.toBigInteger().multiply(this.zinv).mod(q),
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
    if (this.isInfinity()) return this
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z)
  }

  add(b) {
    this._requireUsable()
    b._requireUsable()
    return this._addTrusted(b)
  }

  _addTrusted(b) {
    if (this.isInfinity()) return b
    if (b.isInfinity()) return this
    if (this === b) return this._twiceTrusted()

    if (this.curve._isSm2) {
      this._coordinatesTo(bufA, bufB)
      b._coordinatesTo(bufC, bufD)
      const status = affineAdd(bufA, bufB, bufC, bufD, outX, outY)
      if (status === 0) return this.curve.infinity
      return status === 2
        ? this._twiceTrusted()
        : this._pointFromBytes(outX, outY)
    }

    const x1 = this.x
    const y1 = this.y
    const x2 = b.x
    const y2 = b.y
    const dx = x2.subtract(x1)
    const dy = y2.subtract(y1)

    if (dx.isZero()) {
      return dy.isZero() ? this._twiceTrusted() : this.curve.infinity
    }

    const gamma = dy.divide(dx)
    const x3 = gamma.square().subtract(x1).subtract(x2)
    const y3 = gamma.multiply(x1.subtract(x3)).subtract(y1)
    return new ECPointFp(this.curve, x3, y3, this.z)
  }

  twice() {
    this._requireUsable()
    return this._twiceTrusted()
  }

  _twiceTrusted() {
    if (this.isInfinity()) return this
    if (!this.y.toBigInteger().signum()) return this.curve.infinity

    if (this.curve._isSm2) {
      this._coordinatesTo(bufA, bufB)
      if (!affineDouble(bufA, bufB, outX, outY)) return this.curve.infinity
      return this._pointFromBytes(outX, outY)
    }

    const x1 = this.x
    const y1 = this.y
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
    if (v.isInfinity()) return this.add(v)
    return this.add(v.negate())
  }

  timesPow2(e) {
    if (!Number.isInteger(e) || e < 0 || e > MAX_DOUBLINGS) {
      throw new Error('Invalid value for "e", it must be positive')
    }
    this._requireUsable()
    let p = this
    while (--e >= 0) p = p._twiceTrusted()
    return p
  }

  /**
   * 标量乘法 k * P
   *
   * On the SM2 curve this uses fixed windows and masked table selection, so k
   * may be secret. Any other curve takes the generic, variable-time comb path.
   */
  multiply(k) {
    this._requireUsable()
    if (this.isInfinity()) return this
    if (k.signum() === 0) return this.curve.getInfinity()
    const abs = k.abs()
    const positive = this.curve._isSm2
      ? this._multiplySm2(abs, false)
      : this._multiplyPositive(abs)
    const result = k.signum() > 0 ? positive : positive.negate()
    if (!result.isValid()) throw new Error('Invalid point')
    return result
  }

  /**
   * Same result as multiply, in variable time. Only for a public k and only on
   * the SM2 curve, e.g. the x-bar scalar in key exchange.
   */
  _multiplyPublic(k) {
    this._requireUsable()
    if (this.isInfinity()) return this
    if (k.signum() === 0) return this.curve.getInfinity()
    if (k.signum() < 0 || !this.curve._isSm2) {
      return this.multiply(k)
    }
    const result = this._multiplySm2(k, true)
    if (!result.isValid()) throw new Error('Invalid point')
    return result
  }

  _multiplySm2(k, isPublic) {
    if (k.bitLength() > SM2_BITS) throw new Error('k is too large')
    bigToBytes(k, bufC)
    this._coordinatesTo(bufA, bufB)
    let finite
    if (
      !isPublic &&
      this.x.toBigInteger().equals(SM2_GX) &&
      this.y.toBigInteger().equals(SM2_GY)
    ) {
      finite = mulG(bufC, outX, outY)
    } else {
      finite = isPublic
        ? mulPublic(bufA, bufB, bufC, outX, outY)
        : mulPoint(bufA, bufB, bufC, outX, outY)
    }
    bufC.fill(0)
    return finite ? this._pointFromBytes(outX, outY) : this.curve.infinity
  }

  // ---- 内部: 通用 Comb 标量乘法（非 SM2 曲线）----

  _multiplyPositive(k) {
    const size = this.curve.q.bitLength()
    if (k.bitLength() > size) throw new Error('k is too large')

    const info = this._preCalc()
    const width = info.width
    const d = Math.floor((size + width - 1) / width)
    const l = d * width
    const K = this._fromBigInteger(l, k)
    let Q = new ECPointFp(this.curve, null, null, null)

    for (let i = 0; i < d; ++i) {
      let idx = 0
      for (let j = l - 1 - i; j >= 0; j -= d) {
        idx <<= 1
        idx |= this._getBit(K, j)
      }
      Q = Q._twiceTrusted()._addTrusted(info.preComp[idx])
    }
    return Q._addTrusted(info.offset)
  }

  _getCombSize() {
    return this.curve.q.bitLength()
  }

  _preCalc() {
    const bits = this._getCombSize()
    const minWidth = bits > 256 ? 6 : 5
    const n = 1 << minWidth
    const d = Math.floor((bits + minWidth - 1) / minWidth)

    const pow2Table = new Array(minWidth + 1)
    pow2Table[0] = this
    for (let i = 1; i < minWidth; ++i)
      pow2Table[i] = pow2Table[i - 1].timesPow2(d)
    pow2Table[minWidth] = pow2Table[0]._addTrusted(pow2Table[1].negate())
    this.curve.checkPoints(pow2Table, 0, pow2Table.length)

    const preComp = new Array(n)
    preComp[0] = pow2Table[0]
    for (let bit = minWidth - 1; bit >= 0; --bit) {
      const pow2 = pow2Table[bit]
      const step = 1 << bit
      for (let i = step; i < n; i += step << 1) {
        preComp[i] = preComp[i - step]._addTrusted(pow2)
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
    /** Whether these are exactly the SM2 parameters, enabling the fast paths. */
    this._isSm2 = q.equals(SM2_P) && a.equals(SM2_A) && b.equals(SM2_B)
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

  /** The candidate square root of the curve equation at x, for a canonical x. */
  _curveRhsSqrt(x) {
    if (this._isSm2) {
      bigToBytes(x.toBigInteger(), bufA)
      decompressY(bufA, bufB)
      return this.fromBigInteger(bytesToBig(bufB))
    }
    return this.fromBigInteger(
      x
        .multiply(x.square())
        .add(x.multiply(this.a))
        .add(this.b)
        .toBigInteger()
        .modPow(this.q.divide(new BigInteger('4')).add(ONE), this.q),
    )
  }

  /**
   * 解析十六进制串为椭圆曲线点，并完整校验：长度精确、坐标小于 q、点在曲线上。
   * 支持非压缩 (04) 和压缩 (02/03) 格式，不接受无穷远点。
   * @param {string} s
   * @returns {ECPointFp}
   * @throws {Error} 编码不合法
   */
  decodePointHex(s) {
    const bytes = decodeHex(s)
    const size = (this.q.bitLength() + 7) >> 3
    if (bytes === null || bytes.length === 0) throw new Error(INVALID_POINT)
    const tag = bytes[0]
    const compressed = tag === 2 || tag === 3
    if (bytes.length !== (compressed ? 1 + size : 1 + 2 * size)) {
      throw new Error(INVALID_POINT)
    }
    if (!compressed && tag !== 4) throw new Error(INVALID_POINT)

    const xValue = new BigInteger(s.substring(2, 2 + 2 * size), 16)
    if (xValue.compareTo(this.q) >= 0) throw new Error(INVALID_POINT)
    const x = this.fromBigInteger(xValue)
    let y
    if (compressed) {
      y = this._curveRhsSqrt(x)
      if (y.toBigInteger().isEven() === (tag === 3)) y = y.negate()
      if (y.toBigInteger().isEven() === (tag === 3))
        throw new Error(INVALID_POINT)
    } else {
      y = this.fromBigInteger(new BigInteger(s.substring(2 + 2 * size), 16))
    }
    const point = new ECPointFp(this, x, y)
    if (!point.isValid()) throw new Error(INVALID_POINT)
    return point
  }
}
