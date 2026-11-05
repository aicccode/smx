import { SM3, getSM3 } from '../sm3/sm3.js'
import { BigInteger } from './biginteger.js'
import { bigToBytes, bytesToBig } from './bytes.js'
import { generateKeyMaterial } from './keygen.js'
import { verifyCombination } from './point.js'
import {
  isBelowN,
  plusNBelowP,
  scalarAdd,
  scalarMulAdd,
  scalarSub,
  signatureS,
} from './scalar.js'
import * as util from './utils.js'

const ZERO = BigInteger.ZERO
const ONE = BigInteger.ONE
const BITS = 256

const { G, curve, n, w } = util.generateEcparam()

// Z 值中的固定部分：曲线参数 a、b 与基点坐标
const CURVE_A = toBytes(curve.a.toBigInteger())
const CURVE_B = toBytes(curve.b.toBigInteger())
const BASE_X = toBytes(G.getX().toBigInteger())
const BASE_Y = toBytes(G.getY().toBigInteger())

// ---- 内部工具 ----

/** 非负 BigInteger（小于 2^256）→ 新的 32 字节数组 */
function toBytes(value) {
  return bigToBytes(value, new Uint8Array(32))
}

/** 点的仿射坐标 → 32 字节数组。无穷远点会抛出 TypeError */
function coordinateBytes(point) {
  return [
    toBytes(point.getX().toBigInteger()),
    toBytes(point.getY().toBigInteger()),
  ]
}

/** Equal-length strings compare in time independent of where they differ. */
function equalStrings(a, b) {
  if (typeof a !== 'string' || a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/** data ^= KDF(x2 || y2)，SM3 派生，块计数器从 1 开始 */
function kdfXor(x2, y2, data) {
  const sm3 = new SM3()
  const counter = new Uint8Array(4)
  let ct = 1
  for (let offset = 0; offset < data.length; ct++) {
    counter[0] = ct >>> 24
    counter[1] = ct >>> 16
    counter[2] = ct >>> 8
    counter[3] = ct
    const block = sm3
      .update(x2)
      .update(y2)
      .update(counter)
      .finish()
      .getHashBytes()
    const end = Math.min(32, data.length - offset)
    for (let i = 0; i < end; i++) data[offset + i] ^= block[i]
    offset += end
  }
}

/** C3 = SM3(x2 || msg || y2)，小写 hex */
function c3Hex(x2, msg, y2) {
  return new SM3().update(x2).update(msg).update(y2).hexDigest().toLowerCase()
}

/** 消息 → 新的 Uint8Array（元素按字节截断） */
function messageBytes(msg) {
  return typeof msg === 'string'
    ? util.stringToBytes(msg)
    : Uint8Array.from(Array.prototype.slice.call(msg))
}

/** Z = SM3(ENTL || userId || a || b || gx || gy || px || py) */
function computeZ(px, py, userId) {
  const userIdBytes = util.stringToBytes(userId)
  const entl = userIdBytes.length * 8
  return new SM3()
    .update((entl >> 8) & 0xff)
    .update(entl & 0xff)
    .update(userIdBytes)
    .update(CURVE_A)
    .update(CURVE_B)
    .update(BASE_X)
    .update(BASE_Y)
    .update(px)
    .update(py)
    .digest()
}

/** 私钥 → 模 n 的 32 字节表示（BigInteger 已由点乘校验长度） */
function privateScalarBytes(d) {
  if (d.signum() >= 0) return toBytes(d)
  const out = new Uint8Array(32)
  scalarSub(out, new Uint8Array(32), toBytes(d.abs()))
  return out
}

function decodePublicKey(publicKey) {
  return publicKey.length === 128
    ? curve.decodePointHex('04' + publicKey)
    : curve.decodePointHex(publicKey)
}

/**
 * SM2 非对称加密算法
 *
 * 提供：加密、解密、签名、验签、密钥交换
 */
class SM2 {
  // ---- 加密 / 解密 ----

  /**
   * SM2 加密
   * @param {string|number[]} msg - 明文
   * @param {string} publicKey - 公钥 hex (04 开头非压缩)
   * @returns {string} 密文 hex (C1 || C3 || C2)
   */
  sm2Encrypt(msg, publicKey) {
    const data = messageBytes(msg)
    const { d: k, x, y } = generateKeyMaterial()
    const c1 = '04' + util.bytes2hex(x) + util.bytes2hex(y)

    const pubPoint = curve.decodePointHex(publicKey)
    const [x2, y2] = coordinateBytes(pubPoint.multiply(k))

    // C3 = SM3(x2 || msg || y2)
    const c3 = c3Hex(x2, data, y2)
    // C2 = msg XOR KDF(x2 || y2)
    kdfXor(x2, y2, data)

    return c1 + c3 + util.bytes2hex(data)
  }

  /**
   * SM2 解密
   * @param {string} encryptData - 密文 hex
   * @param {string} privateKey - 私钥 hex
   * @returns {string} 明文
   */
  sm2Decrypt(encryptData, privateKey) {
    const privKey = new BigInteger(privateKey, 16)
    const c3 = encryptData.substr(130, 64)
    const data = util.hexToBytes(encryptData.substr(194))

    const c1 = curve.decodePointHex(encryptData.substr(0, 130))
    curve.validatePoint(c1.getX(), c1.getY())

    const [x2, y2] = coordinateBytes(c1.multiply(privKey))

    // 恢复明文
    kdfXor(x2, y2, data)

    // 验证 C3
    const checkC3 = c3Hex(x2, data, y2)
    return equalStrings(checkC3, c3.toLowerCase())
      ? util.bytesToUTF8String(data)
      : ''
  }

  // ---- 签名 / 验签 ----

  /**
   * SM2 签名
   * @param {string} userId - 用户标识
   * @param {string} privatekey - 私钥 hex
   * @param {string} msg - 消息
   * @returns {string} 签名 "r_hex h s_hex"
   */
  sm2Sign(userId, privatekey, msg) {
    const intPrivateKey = new BigInteger(privatekey, 16)
    const [px, py] = coordinateBytes(G.multiply(intPrivateKey))
    const d = privateScalarBytes(intPrivateKey)

    const e = new SM3()
      .update(computeZ(px, py, userId))
      .update(util.stringToBytes(msg))
      .digest()

    const r = new Uint8Array(32)
    const s = new Uint8Array(32)
    const sum = new Uint8Array(32)
    let nonce
    do {
      let rejected
      do {
        nonce = generateKeyMaterial()
        const rNonZero = scalarAdd(r, e, nonce.x)
        rejected =
          rNonZero === 0 ||
          scalarAdd(sum, r, nonce.dBytes) === 0 ||
          // The signature format needs 64 hex digits with no leading zero.
          r[0] < 16 ||
          nonce.x[0] < 16 ||
          nonce.y[0] < 16
      } while (rejected)
    } while (signatureS(s, d, nonce.dBytes, r) === 0 || s[0] < 16)

    nonce.dBytes.fill(0)
    d.fill(0)
    return util.bytes2hex(r) + 'h' + util.bytes2hex(s)
  }

  /**
   * SM2 验签
   * @param {string} userId - 用户标识
   * @param {string} signData - 签名 "r_hex h s_hex"
   * @param {string} message - 消息
   * @param {string} publicKey - 公钥 hex
   * @returns {boolean}
   */
  sm2VerifySign(userId, signData, message, publicKey) {
    const z = this.userSM3Z(publicKey, userId)
    const e = new SM3().update(z).update(util.stringToBytes(message)).digest()

    const [sr, ss] = signData.split('h')
    const r = new BigInteger(sr, 16)
    const s = new BigInteger(ss, 16)
    const t = r.add(s).mod(n)

    if (t.equals(ZERO)) return false

    const userKey = decodePublicKey(publicKey)
    if (s.signum() < 0 || r.signum() < 0 || s.bitLength() > BITS) {
      return this._verifyGeneric(e, r, s, t, userKey)
    }

    const [qx, qy] = coordinateBytes(userKey)
    if (!userKey.isValid()) throw new Error('Invalid point')

    // R = (e + x1) mod n equals r exactly when x1 is (r - e) mod n, or that plus n.
    let candidate = null
    let candidatePlusN = null
    if (r.bitLength() <= BITS) {
      const rBytes = toBytes(r)
      if (isBelowN(rBytes)) {
        candidate = new Uint8Array(32)
        scalarSub(candidate, rBytes, e)
        candidatePlusN = plusNBelowP(candidate)
      }
    }
    const outcome = verifyCombination(
      toBytes(s),
      toBytes(t),
      qx,
      qy,
      candidate,
      candidatePlusN,
    )
    // s*G + t*P at infinity has no x coordinate, and getX reports that by throwing.
    if (outcome < 0) curve.getInfinity().getX()
    return outcome === 1
  }

  /** The point-class route, for negative or oversized signature components. */
  _verifyGeneric(e, r, s, t, userKey) {
    const x1y1 = G.multiply(s).add(userKey.multiply(t))
    const R = bytesToBig(e).add(x1y1.getX().toBigInteger()).mod(n)
    return r.equals(R)
  }

  // ---- 密钥交换 ----

  /**
   * B 侧计算协商密钥和验证值
   */
  getSb(len, pA, Ra, IDa, IDb, dBh, pBh, rbh, Rbh) {
    const dB = new BigInteger(dBh, 16)
    const rb = new BigInteger(rbh, 16)
    const Rb = curve.decodePointHex(Rbh)

    const x2_ = this._calcX(w, Rb.getX().toBigInteger())
    const tb = this._calcT(n, rb, dB, x2_)

    const RaPoint = curve.decodePointHex(Ra)
    if (!RaPoint.isValid()) throw new Error('Ra is not valid')

    const x1_ = this._calcX(w, RaPoint.getX().toBigInteger())
    const V = this._calcPoint(tb, x1_, curve.decodePointHex(pA), RaPoint)

    if (V.isInfinity()) throw new Error('V is invalid point')

    const Za = this.userSM3Z(pA, IDa)
    const Zb = this.userSM3Z(pBh, IDb)
    const Kb = this._KDF(len, V, Za, Zb)
    const Sb = this._createS(0x02, V, Za, Zb, RaPoint, Rb)

    return {
      Sb: util.bytes2hex(Sb),
      Rb,
      Kb: util.bytes2hex(Kb),
      V: V.x.toBigInteger().toRadix(16) + V.y.toBigInteger().toRadix(16),
      Za: util.bytes2hex(Za),
      Zb: util.bytes2hex(Zb),
    }
  }

  /**
   * B 侧检查 Sa
   */
  checkSa(V, Za, Zb, Ra, Rb, Sa) {
    const S2 = this._createS(
      0x03,
      curve.decodePointHex('04' + V),
      util.hexToArray(Za),
      util.hexToArray(Zb),
      curve.decodePointHex(Ra),
      Rb,
    )
    return equalStrings(Sa, util.bytes2hex(S2))
  }

  // ---- 公钥计算 ----

  /**
   * 从私钥计算公钥
   * @param {string} privateKey - 私钥 hex
   * @returns {string} 公钥 hex (04 开头)
   */
  getPublicKeyFromPrivateKey(privateKey) {
    const [x, y] = coordinateBytes(G.multiply(new BigInteger(privateKey, 16)))
    return '04' + util.bytes2hex(x) + util.bytes2hex(y)
  }

  /**
   * 生成随机椭圆曲线点
   */
  getPoint() {
    const keypair = util.generateKeyPairHex()
    const PA = curve.decodePointHex(keypair.publicKey)
    keypair.k = new BigInteger(keypair.privateKey, 16)
    keypair.x1 = PA.getX().toBigInteger()
    return keypair
  }

  // ---- 内部方法 ----

  /**
   * 计算用户标识哈希 Z = SM3(ENTL || userId || a || b || gx || gy || px || py)
   */
  userSM3Z(publicKey, userId = '1234567812345678') {
    const [px, py] = coordinateBytes(decodePublicKey(publicKey))
    return computeZ(px, py, userId)
  }

  _calcX(w, x2) {
    const pow2w = BigInteger.nbv(2).pow(w)
    return pow2w.add(x2.and(pow2w.subtract(ONE)))
  }

  _calcT(order, rb, db, x2_) {
    if (
      order.equals(n) &&
      rb.signum() >= 0 &&
      db.signum() >= 0 &&
      rb.bitLength() <= BITS &&
      db.bitLength() <= BITS &&
      x2_.bitLength() <= BITS
    ) {
      const out = new Uint8Array(32)
      scalarMulAdd(out, toBytes(x2_), toBytes(rb), toBytes(db))
      return bytesToBig(out)
    }
    return db.add(x2_.multiply(rb)).mod(order)
  }

  _calcPoint(t, x, pA, rA) {
    return pA.add(rA._multiplyPublic(x)).multiply(t)
  }

  _createS(tag, vu, Za, Zb, Ra, Rb) {
    const [vx, vy] = coordinateBytes(vu)
    const [rax, ray] = coordinateBytes(Ra)
    const [rbx, rby] = coordinateBytes(Rb)
    const h1 = getSM3()
      .update(vx)
      .update(Za)
      .update(Zb)
      .update(rax)
      .update(ray)
      .update(rbx)
      .update(rby)
      .digest()
    return getSM3().update(tag).update(vy).update(h1).digest()
  }

  _KDF(keylen, vu, Za, Zb) {
    const result = new Array(keylen)
    const iterations = Math.ceil(keylen / 32)
    if (iterations === 0) return result
    const [vx, vy] = coordinateBytes(vu)
    const counter = new Uint8Array(4)
    for (let i = 0; i < iterations; i++) {
      const ct = i + 1
      counter[0] = ct >>> 24
      counter[1] = ct >>> 16
      counter[2] = ct >>> 8
      counter[3] = ct
      const block = getSM3()
        .update(vx)
        .update(vy)
        .update(Za)
        .update(Zb)
        .update(counter)
        .digest()
      const copyLen =
        i === iterations - 1 && keylen % 32 !== 0 ? keylen % 32 : 32
      for (let j = 0; j < copyLen; j++) result[i * 32 + j] = block[j]
    }
    return result
  }
}

export const getSM2 = () => new SM2()
