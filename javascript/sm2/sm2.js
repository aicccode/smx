import { SM3, getSM3 } from '../sm3/sm3.js'
import { BigInteger } from './biginteger.js'
import * as util from './utils.js'

const ZERO = BigInteger.ZERO
const ONE = BigInteger.ONE

const { G, curve, n, w } = util.generateEcparam()

// ---- 内部工具 ----

/** BigInteger → 固定 32 字节数组（左补零） */
function bigIntTo32Bytes(n) {
  if (!n) return null
  const arr = n.toByteArray()
  if (arr.length === 33) return arr.slice(1)
  if (arr.length === 32) return arr
  const out = new Array(32).fill(0)
  const off = 32 - arr.length
  for (let i = 0; i < arr.length; i++) out[off + i] = arr[i]
  return out
}

/** BigInteger → 指定长度无符号字节数组 */
function asUnsignedByteArray(length, value) {
  const bytes = value.toByteArray()
  const start = bytes[0] === 0 ? 1 : 0
  const count = bytes.length - start
  if (count > length) throw new Error('Value too large for byte array length')
  const tmp = new Array(length).fill(0)
  const off = length - count
  for (let i = 0; i < count; i++) tmp[off + i] = bytes[start + i]
  return tmp
}

/** 32 位整数 → 大端序 4 字节 */
function intToBigEndian(n, bs, off) {
  bs[off] = (n >>> 24) & 0xff
  bs[off + 1] = (n >>> 16) & 0xff
  bs[off + 2] = (n >>> 8) & 0xff
  bs[off + 3] = n & 0xff
}

/** KDF 密钥派生流（SM3-based） */
function kdfStream(x2, y2) {
  const z = [].concat(x2, y2)
  let ct = 1
  let t = []
  let offset = 0

  function nextBlock() {
    const sm3 = new SM3()
    const hvData = [...z, (ct >> 24) & 0xff, (ct >> 16) & 0xff, (ct >> 8) & 0xff, ct & 0xff]
    sm3.updateBytes(hvData, 0, hvData.length)
    t = sm3.finish().getHashBytes()
    ct++
    offset = 0
  }

  nextBlock()

  return {
    xorByte(b) {
      if (offset === t.length) nextBlock()
      return b ^ (t[offset++] & 0xff)
    }
  }
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
    msg = typeof msg === 'string' ? Array.from(util.stringToBytes(msg)) : Array.prototype.slice.call(msg)

    const keypair = util.generateKeyPairHex()
    const k = new BigInteger(keypair.privateKey, 16)
    const c1 = keypair.publicKey

    const pubPoint = curve.decodePointHex(publicKey)
    const p = pubPoint.multiply(k)
    const x2 = asUnsignedByteArray(32, p.getX().toBigInteger())
    const y2 = asUnsignedByteArray(32, p.getY().toBigInteger())

    // C3 = SM3(x2 || msg || y2)
    const sm3c3 = new SM3()
    sm3c3.updateBytes([].concat(x2, msg, y2), 0, x2.length + msg.length + y2.length)
    const c3 = sm3c3.finish().getHashCode().toLowerCase()

    // C2 = msg XOR KDF(x2 || y2)
    const stream = kdfStream(x2, y2)
    for (let i = 0; i < msg.length; i++) {
      msg[i] = stream.xorByte(msg[i])
    }
    const c2 = util.arrayToHex(msg)

    return c1 + c3 + c2
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
    const c2 = encryptData.substr(194)

    const msg = util.hexToArray(c2)
    const c1 = curve.decodePointHex(encryptData.substr(0, 130))
    curve.validatePoint(c1.getX(), c1.getY())

    const p = c1.multiply(privKey)
    const x2 = asUnsignedByteArray(32, p.getX().toBigInteger())
    const y2 = asUnsignedByteArray(32, p.getY().toBigInteger())

    // 恢复明文
    const stream = kdfStream(x2, y2)
    for (let i = 0; i < msg.length; i++) {
      msg[i] = stream.xorByte(msg[i])
    }

    // 验证 C3
    const sm3c3 = new SM3()
    sm3c3.updateBytes([].concat(x2, msg, y2), 0, x2.length + msg.length + y2.length)
    const checkC3 = sm3c3.finish().getHashCode().toLowerCase()

    return checkC3 === c3.toLowerCase() ? util.bytesToUTF8String(msg) : ''
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
    const pA = G.multiply(intPrivateKey)
    const pAHex = util.leftPad(pA.getX().toBigInteger().toString(16), 64) +
                  util.leftPad(pA.getY().toBigInteger().toString(16), 64)

    const zA = this.userSM3Z(pAHex, userId)
    const sm3 = getSM3()
    sm3.updateBytes(zA, 0, zA.length)
    const sourceData = util.stringToBytes(msg)
    sm3.updateBytes(sourceData, 0, sourceData.length)
    sm3.finish()
    const e = new BigInteger(sm3.getHashCode(), 16)

    let k, kp, r, s
    do {
      do {
        const keypair = util.generateKeyPairHex()
        k = new BigInteger(keypair.privateKey, 16)
        kp = curve.decodePointHex(keypair.publicKey)
        r = e.add(kp.getX().toBigInteger()).mod(n)
      } while (
        r.equals(ZERO) || r.add(k).equals(n) ||
        r.toRadix(16).length !== 64 ||
        kp.getX().toBigInteger().toRadix(16).length !== 64 ||
        kp.getY().toBigInteger().toRadix(16).length !== 64
      )
      let da1 = intPrivateKey.add(ONE).modInverse(n)
      s = da1.multiply(k.subtract(r.multiply(intPrivateKey)).mod(n)).mod(n)
    } while (s.equals(ZERO) || s.toRadix(16).length !== 64)

    return r.toRadix(16) + 'h' + s.toRadix(16)
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
    const sm3 = getSM3()
    const z = this.userSM3Z(publicKey, userId)
    const sourceData = util.stringToBytes(message)
    sm3.updateBytes(z, 0, z.length)
    sm3.updateBytes(sourceData, 0, sourceData.length)
    sm3.finish()

    const [sr, ss] = signData.split('h')
    const r = new BigInteger(sr, 16)
    const s = new BigInteger(ss, 16)
    const e = new BigInteger(sm3.getHashCode(), 16)
    const t = r.add(s).mod(n)

    if (t.equals(ZERO)) return false

    let x1y1 = G.multiply(s)
    const userKey = publicKey.length === 128
      ? G.curve.decodePointHex('04' + publicKey)
      : G.curve.decodePointHex(publicKey)
    x1y1 = x1y1.add(userKey.multiply(t))
    const R = e.add(x1y1.getX().toBigInteger()).mod(n)

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

    if (!curve.decodePointHex(Ra).isValid()) throw new Error('Ra is not valid')

    const x1_ = this._calcX(w, curve.decodePointHex(Ra).getX().toBigInteger())
    const V = this._calcPoint(tb, x1_, curve.decodePointHex(pA), curve.decodePointHex(Ra))

    if (V.isInfinity()) throw new Error('V is invalid point')

    const Za = this.userSM3Z(pA, IDa)
    const Zb = this.userSM3Z(pBh, IDb)
    const Kb = this._KDF(len, V, Za, Zb)
    const Sb = this._createS(0x02, V, Za, Zb, curve.decodePointHex(Ra), Rb)

    return {
      Sb: util.bytes2hex(Sb),
      Rb,
      Kb: util.bytes2hex(Kb),
      V: V.x.toBigInteger().toRadix(16) + V.y.toBigInteger().toRadix(16),
      Za: util.bytes2hex(Za),
      Zb: util.bytes2hex(Zb)
    }
  }

  /**
   * B 侧检查 Sa
   */
  checkSa(V, Za, Zb, Ra, Rb, Sa) {
    const S2 = this._createS(0x03, curve.decodePointHex('04' + V), util.hexToArray(Za), util.hexToArray(Zb), curve.decodePointHex(Ra), Rb)
    return Sa === util.bytes2hex(S2)
  }

  // ---- 公钥计算 ----

  /**
   * 从私钥计算公钥
   * @param {string} privateKey - 私钥 hex
   * @returns {string} 公钥 hex (04 开头)
   */
  getPublicKeyFromPrivateKey(privateKey) {
    const PA = G.multiply(new BigInteger(privateKey, 16))
    const x = util.leftPad(PA.getX().toBigInteger().toString(16), 64)
    const y = util.leftPad(PA.getY().toBigInteger().toString(16), 64)
    return '04' + x + y
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
    const userIdBytes = Array.from(util.stringToBytes(userId))
    const a = bigIntTo32Bytes(curve.a.toBigInteger())
    const b = bigIntTo32Bytes(curve.b.toBigInteger())
    const gx = bigIntTo32Bytes(G.getX().toBigInteger())
    const gy = bigIntTo32Bytes(G.getY().toBigInteger())

    const point = publicKey.length === 128
      ? G.curve.decodePointHex('04' + publicKey)
      : G.curve.decodePointHex(publicKey)
    const px = bigIntTo32Bytes(point.getX().toBigInteger())
    const py = bigIntTo32Bytes(point.getY().toBigInteger())

    const entl = userIdBytes.length * 8
    const sm3Z = getSM3()
    sm3Z.update((entl >> 8) & 0xff)
    sm3Z.update(entl & 0xff)
    sm3Z.updateBytes(userIdBytes, 0, userIdBytes.length)
    sm3Z.updateBytes(a, 0, a.length)
    sm3Z.updateBytes(b, 0, b.length)
    sm3Z.updateBytes(gx, 0, gx.length)
    sm3Z.updateBytes(gy, 0, gy.length)
    sm3Z.updateBytes(px, 0, px.length)
    sm3Z.updateBytes(py, 0, py.length)
    sm3Z.finish()

    return sm3Z.getHashBytes()
  }

  _calcX(w, x2) {
    const pow2w = BigInteger.nbv(2).pow(w)
    return pow2w.add(x2.and(pow2w.subtract(ONE)))
  }

  _calcT(n, rb, db, x2_) {
    return db.add(x2_.multiply(rb)).mod(n)
  }

  _calcPoint(t, x, pA, rA) {
    return pA.add(rA.multiply(x)).multiply(t)
  }

  _createS(tag, vu, Za, Zb, Ra, Rb) {
    const sm3 = getSM3()
    const bXvu = bigIntTo32Bytes(vu.getX().toBigInteger())
    sm3.updateBytes(bXvu, 0, bXvu.length)
    sm3.updateBytes(Za, 0, Za.length)
    sm3.updateBytes(Zb, 0, Zb.length)
    sm3.updateBytes(bigIntTo32Bytes(Ra.getX().toBigInteger()), 0, 32)
    sm3.updateBytes(bigIntTo32Bytes(Ra.getY().toBigInteger()), 0, 32)
    sm3.updateBytes(bigIntTo32Bytes(Rb.getX().toBigInteger()), 0, 32)
    sm3.updateBytes(bigIntTo32Bytes(Rb.getY().toBigInteger()), 0, 32)
    const h1 = sm3.finish().getHashBytes()

    const hash = getSM3()
    hash.update(tag)
    hash.updateBytes(bigIntTo32Bytes(vu.getY().toBigInteger()), 0, 32)
    hash.updateBytes(h1, 0, h1.length)
    return hash.finish().getHashBytes()
  }

  _KDF(keylen, vu, Za, Zb) {
    const result = new Array(keylen)
    let ct = 1
    const iterations = Math.ceil(keylen / 32)
    for (let i = 0; i < iterations; i++) {
      const sm3 = getSM3()
      sm3.updateBytes(asUnsignedByteArray(32, vu.getX().toBigInteger()), 0, 32)
      sm3.updateBytes(asUnsignedByteArray(32, vu.getY().toBigInteger()), 0, 32)
      sm3.updateBytes(Za, 0, Za.length)
      sm3.updateBytes(Zb, 0, Zb.length)
      const ctBytes = [0, 0, 0, 0]
      intToBigEndian(ct, ctBytes, 0)
      sm3.updateBytes(ctBytes, 0, 4)
      sm3.finish()
      const sm3Bytes = sm3.getHashBytes()
      const copyLen = (i === iterations - 1 && keylen % 32 !== 0) ? keylen % 32 : 32
      for (let j = 0; j < copyLen; j++) {
        result[(ct - 1) * 32 + j] = sm3Bytes[j]
      }
      ct++
    }
    return result
  }
}

export const getSM2 = () => new SM2()
