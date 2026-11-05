import { decodeHex, encodeHex, toByteArray } from '../common/hex.js'
import { SM3, getSM3 } from '../sm3/sm3.js'
import { BigInteger } from './biginteger.js'
import { bigToBytes, bytesToBig } from './bytes.js'
import { generateKeyMaterial } from './keygen.js'
import {
  affineAdd,
  affineDouble,
  mulG,
  mulPoint,
  mulPublic,
  verifyCombination,
} from './point.js'
import {
  isBelowN,
  isInScalarRange,
  isValidPrivateScalar,
  plusNBelowP,
  scalarAdd,
  scalarMulAdd,
  scalarSub,
  signatureS,
} from './scalar.js'
import * as util from './utils.js'

const ONE = BigInteger.ONE
const BITS = 256
const SCALAR_BYTES = 32
const SCALAR_HEX = 2 * SCALAR_BYTES
const MAX_USER_ID_BYTES = 8191
const MAX_KEY_EXCHANGE_BYTES = 1 << 20
const MAX_KDF_BYTES = 0xffffffff * 32
/** Retries on values that a working RNG hits with negligible probability. */
const MAX_ATTEMPTS = 64
const C1_HEX = 130
const C3_HEX = 64
const SIGN_TAG = 0x02
const CONFIRM_TAG = 0x03
const DECRYPT_ERROR = 'SM2 decryption failed'

const { G, curve, n } = util.generateEcparam()

// Z 值中的固定部分：曲线参数 a、b 与基点坐标
const CURVE_A = toBytes(curve.a.toBigInteger())
const CURVE_B = toBytes(curve.b.toBigInteger())
const BASE_X = toBytes(G.getX().toBigInteger())
const BASE_Y = toBytes(G.getY().toBigInteger())

// ---- 内部工具 ----

/** 非负 BigInteger（小于 2^256）→ 新的 32 字节数组 */
function toBytes(value) {
  return bigToBytes(value, new Uint8Array(SCALAR_BYTES))
}

/** 点的仿射坐标 → 32 字节数组。无穷远点会抛出错误 */
function coordinateBytes(point) {
  return [
    toBytes(point.getX().toBigInteger()),
    toBytes(point.getY().toBigInteger()),
  ]
}

/** Strings of equal length compare in time independent of where they differ. */
function equalStrings(a, b) {
  if (typeof a !== 'string' || a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/** Byte arrays of equal length compare in time independent of their contents. */
function equalBytes(a, b) {
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/**
 * data ^= KDF(x2 || y2)，SM3 派生，块计数器从 1 开始
 * @returns {boolean} KDF 输出是否全零。全零时 data 不变，密文等于明文，必须拒绝
 */
function kdfXor(x2, y2, data) {
  if (data.length > MAX_KDF_BYTES)
    throw new RangeError('KDF output is too long')
  const sm3 = new SM3()
  const counter = new Uint8Array(4)
  let ct = 1
  let any = 0
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
    for (let i = 0; i < end; i++) {
      data[offset + i] ^= block[i]
      any |= block[i]
    }
    block.fill(0)
    offset += end
  }
  return any === 0
}

/** C3 = SM3(x2 || msg || y2) */
function computeC3(x2, msg, y2) {
  return new SM3().update(x2).update(msg).update(y2).digest()
}

/** 消息 → 新的 Uint8Array。字符串按 UTF-8，数组元素必须是字节 */
function messageBytes(msg) {
  return typeof msg === 'string'
    ? util.stringToBytes(msg)
    : Uint8Array.from(toByteArray(msg))
}

function userIdBytes(userId) {
  const bytes = util.stringToBytes(userId)
  if (bytes.length > MAX_USER_ID_BYTES)
    throw new RangeError('User ID is too long')
  return bytes
}

/** Z = SM3(ENTL || userId || a || b || gx || gy || px || py) */
function computeZ(px, py, userId) {
  const id = userIdBytes(userId)
  const entl = id.length * 8
  return new SM3()
    .update((entl >> 8) & 0xff)
    .update(entl & 0xff)
    .update(id)
    .update(CURVE_A)
    .update(CURVE_B)
    .update(BASE_X)
    .update(BASE_Y)
    .update(px)
    .update(py)
    .digest()
}

/**
 * Private key hex → 32 bytes in [1, n - 2]. Exactly 64 hex digits. The checks are
 * constant-flow, and the error does not depend on the value.
 */
function parsePrivateKey(hex) {
  const bytes =
    typeof hex === 'string' && hex.length === SCALAR_HEX ? decodeHex(hex) : null
  if (bytes === null || !isValidPrivateScalar(bytes)) {
    if (bytes !== null) bytes.fill(0)
    throw new Error('Invalid private key')
  }
  return bytes
}

function decodePublicKey(publicKey) {
  return curve.decodePointHex(publicKey)
}

function requireKeyLength(len) {
  if (!Number.isInteger(len) || len < 1 || len > MAX_KEY_EXCHANGE_BYTES) {
    throw new RangeError('Key length must be from 1 to 1048576 bytes')
  }
}

/** x̄ = 2^127 + (x & (2^127 - 1)) as 32 bytes, for a public coordinate x. */
function xBar(x) {
  const out = new Uint8Array(SCALAR_BYTES)
  out.set(x.subarray(16), 16)
  out[16] = (out[16] & 0x7f) | 0x80
  return out
}

function hexOfPoint(x, y) {
  return encodeHex(x) + encodeHex(y)
}

/**
 * Shared secret point t * (peerKey + x̄ * peerEphemeral), for a secret t in bytes.
 * Returns its coordinates, or throws if it is the point at infinity.
 */
function sharedPoint(t, peerKey, peerEphemeral) {
  const [px, py] = coordinateBytes(peerKey)
  const [rx, ry] = coordinateBytes(peerEphemeral)
  const scaledX = new Uint8Array(SCALAR_BYTES)
  const scaledY = new Uint8Array(SCALAR_BYTES)
  if (!mulPublic(rx, ry, xBar(rx), scaledX, scaledY)) {
    throw new Error('Key exchange produced the point at infinity')
  }
  const sumX = new Uint8Array(SCALAR_BYTES)
  const sumY = new Uint8Array(SCALAR_BYTES)
  const status = affineAdd(px, py, scaledX, scaledY, sumX, sumY)
  if (status === 0)
    throw new Error('Key exchange produced the point at infinity')
  if (status === 2) affineDouble(px, py, sumX, sumY)
  const x = new Uint8Array(SCALAR_BYTES)
  const y = new Uint8Array(SCALAR_BYTES)
  if (!mulPoint(sumX, sumY, t, x, y)) {
    throw new Error('Key exchange produced the point at infinity')
  }
  return [x, y]
}

/** S = SM3(tag || y || SM3(x || Za || Zb || x1 || y1 || x2 || y2)) */
function confirmationHash(tag, x, y, Za, Zb, ra, rb) {
  const h1 = getSM3()
    .update(x)
    .update(Za)
    .update(Zb)
    .update(ra[0])
    .update(ra[1])
    .update(rb[0])
    .update(rb[1])
    .digest()
  return getSM3().update(tag).update(y).update(h1).digest()
}

/** KDF(x || y || Za || Zb) as keylen bytes */
function exchangeKdf(keylen, x, y, Za, Zb) {
  const result = new Uint8Array(keylen)
  const iterations = Math.ceil(keylen / 32)
  const counter = new Uint8Array(4)
  for (let i = 0; i < iterations; i++) {
    const ct = i + 1
    counter[0] = ct >>> 24
    counter[1] = ct >>> 16
    counter[2] = ct >>> 8
    counter[3] = ct
    const block = getSM3()
      .update(x)
      .update(y)
      .update(Za)
      .update(Zb)
      .update(counter)
      .digest()
    const copyLen = i === iterations - 1 && keylen % 32 !== 0 ? keylen % 32 : 32
    for (let j = 0; j < copyLen; j++) result[i * 32 + j] = block[j]
  }
  return result
}

/**
 * SM2 非对称加密算法
 *
 * 提供：加密、解密、签名、验签、密钥交换
 *
 * 私钥是恰好 64 位十六进制、取值在 [1, n-2] 的字符串。公钥是 04 开头的 130 位十六
 * 进制，或 02/03 开头的 66 位压缩格式，且必须在曲线上。
 * 失败约定：返回布尔值的接口返回 false；其余接口抛出 Error，错误信息不含密钥。
 */
class SM2 {
  // ---- 加密 / 解密 ----

  /**
   * SM2 加密
   * @param {string|number[]|Uint8Array} msg - 明文，不能为空
   * @param {string} publicKey - 公钥 hex
   * @returns {string} 密文 hex (C1 || C3 || C2)
   * @throws {Error} 输入不合法
   */
  sm2Encrypt(msg, publicKey) {
    const data = messageBytes(msg)
    if (data.length === 0)
      throw new Error('SM2 cannot encrypt an empty message')
    const pubPoint = decodePublicKey(publicKey)
    const [px, py] = coordinateBytes(pubPoint)

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const { dBytes: k, x, y } = generateKeyMaterial()
      const x2 = new Uint8Array(SCALAR_BYTES)
      const y2 = new Uint8Array(SCALAR_BYTES)
      mulPoint(px, py, k, x2, y2)
      k.fill(0)
      // C3 = SM3(x2 || msg || y2)
      const c3 = computeC3(x2, data, y2)
      // C2 = msg XOR KDF(x2 || y2)。全零 KDF 时 data 不变，可以直接重试
      const zeroKdf = kdfXor(x2, y2, data)
      x2.fill(0)
      y2.fill(0)
      if (!zeroKdf) {
        return '04' + hexOfPoint(x, y) + encodeHex(c3) + encodeHex(data)
      }
    }
    throw new Error('SM2 encryption failed')
  }

  /**
   * SM2 解密
   * @param {string} encryptData - 密文 hex (C1 || C3 || C2)
   * @param {string} privateKey - 私钥 hex
   * @returns {string} 明文。非法 UTF-8 序列替换为 U+FFFD
   * @throws {Error} 私钥不合法，或密文被拒绝（格式、C1、C3 错误都抛出同一个错误）
   */
  sm2Decrypt(encryptData, privateKey) {
    const bytes = decodeHex(encryptData)
    if (bytes === null || bytes.length < (C1_HEX + C3_HEX) / 2 + 1) {
      throw new Error(DECRYPT_ERROR)
    }
    let c1
    try {
      c1 = curve.decodePointHex(encryptData.substring(0, C1_HEX))
    } catch {
      throw new Error(DECRYPT_ERROR)
    }
    if (bytes[0] !== 4) throw new Error(DECRYPT_ERROR)
    const key = parsePrivateKey(privateKey)
    const c3 = bytes.subarray(C1_HEX / 2, (C1_HEX + C3_HEX) / 2)
    const data = Uint8Array.from(bytes.subarray((C1_HEX + C3_HEX) / 2))

    const [cx, cy] = coordinateBytes(c1)
    const x2 = new Uint8Array(SCALAR_BYTES)
    const y2 = new Uint8Array(SCALAR_BYTES)
    mulPoint(cx, cy, key, x2, y2)
    key.fill(0)

    // 恢复明文，并验证 C3
    const zeroKdf = kdfXor(x2, y2, data)
    const check = computeC3(x2, data, y2)
    x2.fill(0)
    y2.fill(0)
    const valid = equalBytes(check, c3)
    if (zeroKdf || !valid) {
      data.fill(0)
      throw new Error(DECRYPT_ERROR)
    }
    const text = util.bytesToUTF8String(data)
    data.fill(0)
    return text
  }

  // ---- 签名 / 验签 ----

  /**
   * SM2 签名
   * @param {string} userId - 用户标识，最多 8191 字节
   * @param {string} privatekey - 私钥 hex
   * @param {string} msg - 消息
   * @returns {string} 签名 "r_hex h s_hex"，r、s 各固定 64 位
   * @throws {Error} 输入不合法
   */
  sm2Sign(userId, privatekey, msg) {
    const d = parsePrivateKey(privatekey)
    try {
      const px = new Uint8Array(SCALAR_BYTES)
      const py = new Uint8Array(SCALAR_BYTES)
      mulG(d, px, py)

      const e = new SM3()
        .update(computeZ(px, py, userId))
        .update(util.stringToBytes(msg))
        .digest()

      const r = new Uint8Array(SCALAR_BYTES)
      const s = new Uint8Array(SCALAR_BYTES)
      const sum = new Uint8Array(SCALAR_BYTES)
      for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        const { dBytes: k, x } = generateKeyMaterial()
        const rNonZero = scalarAdd(r, e, x)
        const rPlusK = scalarAdd(sum, r, k)
        const accepted =
          rNonZero !== 0 && rPlusK !== 0 && signatureS(s, d, k, r) !== 0
        k.fill(0)
        sum.fill(0)
        if (accepted) return encodeHex(r) + 'h' + encodeHex(s)
      }
      throw new Error('SM2 signing failed')
    } finally {
      d.fill(0)
    }
  }

  /**
   * SM2 验签
   * @param {string} userId - 用户标识
   * @param {string} signData - 签名 "r_hex h s_hex"，r、s 各恰好 64 位且在 [1, n-1]
   * @param {string} message - 消息
   * @param {string} publicKey - 公钥 hex
   * @returns {boolean} 任何不合法的输入都返回 false，不会抛出
   */
  sm2VerifySign(userId, signData, message, publicKey) {
    try {
      return this._verify(userId, signData, message, publicKey)
    } catch {
      return false
    }
  }

  _verify(userId, signData, message, publicKey) {
    if (typeof signData !== 'string') return false
    const parts = signData.split('h')
    if (parts.length !== 2) return false
    if (parts[0].length !== SCALAR_HEX || parts[1].length !== SCALAR_HEX) {
      return false
    }
    const r = decodeHex(parts[0])
    const s = decodeHex(parts[1])
    if (
      r === null ||
      s === null ||
      !isInScalarRange(r) ||
      !isInScalarRange(s)
    ) {
      return false
    }
    const t = new Uint8Array(SCALAR_BYTES)
    if (scalarAdd(t, r, s) === 0) return false

    const userKey = decodePublicKey(publicKey)
    const [qx, qy] = coordinateBytes(userKey)
    const e = new SM3()
      .update(computeZ(qx, qy, userId))
      .update(util.stringToBytes(message))
      .digest()

    // R = (e + x1) mod n equals r exactly when x1 is (r - e) mod n, or that plus n.
    if (!isBelowN(r)) return false
    const candidate = new Uint8Array(SCALAR_BYTES)
    scalarSub(candidate, r, e)
    return (
      verifyCombination(s, t, qx, qy, candidate, plusNBelowP(candidate)) === 1
    )
  }

  // ---- 密钥交换 ----

  /**
   * B 侧计算协商密钥和验证值
   * @param {number} len - 协商密钥字节数，1 到 1048576
   * @returns {{Sb: string, Rb: object, Kb: string, V: string, Za: string, Zb: string}}
   *   V 是 x、y 各 64 位的 128 位十六进制。Kb 和 V 是秘密
   * @throws {Error} 任何密钥、点或长度不合法，或 V 是无穷远点
   */
  getSb(len, pA, Ra, IDa, IDb, dBh, pBh, rbh, Rbh) {
    requireKeyLength(len)
    const pAPoint = decodePublicKey(pA)
    const pBPoint = decodePublicKey(pBh)
    const RaPoint = decodePublicKey(Ra)
    const Rb = decodePublicKey(Rbh)
    const [ax, ay] = coordinateBytes(pAPoint)
    const [bx, by] = coordinateBytes(pBPoint)
    const Za = computeZ(ax, ay, IDa)
    const Zb = computeZ(bx, by, IDb)
    const dB = parsePrivateKey(dBh)
    const rb = parsePrivateKey(rbh)

    const raCoordinates = coordinateBytes(RaPoint)
    const rbCoordinates = coordinateBytes(Rb)
    const t = new Uint8Array(SCALAR_BYTES)
    scalarMulAdd(t, xBar(rbCoordinates[0]), rb, dB)
    dB.fill(0)
    rb.fill(0)
    let vx, vy
    try {
      ;[vx, vy] = sharedPoint(t, pAPoint, RaPoint)
    } finally {
      t.fill(0)
    }

    const Kb = exchangeKdf(len, vx, vy, Za, Zb)
    const Sb = confirmationHash(
      SIGN_TAG,
      vx,
      vy,
      Za,
      Zb,
      raCoordinates,
      rbCoordinates,
    )

    return {
      Sb: encodeHex(Sb),
      Rb,
      Kb: encodeHex(Kb),
      V: hexOfPoint(vx, vy),
      Za: encodeHex(Za),
      Zb: encodeHex(Zb),
    }
  }

  /**
   * B 侧检查 Sa。比较不提前退出
   * @param {string} V - getSb 返回的 128 位十六进制
   * @param {string} Sa - A 侧发来的验证值，恰好 64 位小写十六进制
   * @returns {boolean} 任何不合法的输入都返回 false，不会抛出
   */
  checkSa(V, Za, Zb, Ra, Rb, Sa) {
    try {
      if (typeof Sa !== 'string' || Sa.length !== SCALAR_HEX) return false
      if (typeof V !== 'string' || V.length !== 2 * SCALAR_HEX) return false
      const vPoint = decodePublicKey('04' + V)
      const za = decodeHex(Za)
      const zb = decodeHex(Zb)
      if (za === null || zb === null) return false
      if (za.length !== SCALAR_BYTES || zb.length !== SCALAR_BYTES) return false
      const raPoint = decodePublicKey(Ra)
      if (Rb === null || typeof Rb !== 'object') return false
      Rb._requireUsable()
      const [vx, vy] = coordinateBytes(vPoint)
      const S2 = confirmationHash(
        CONFIRM_TAG,
        vx,
        vy,
        za,
        zb,
        coordinateBytes(raPoint),
        coordinateBytes(Rb),
      )
      return equalStrings(Sa, encodeHex(S2))
    } catch {
      return false
    }
  }

  /**
   * A 侧验证 Sb，并计算 Sa 和协商密钥。比较 Sb 时不提前退出
   * @param {number} len - 协商密钥字节数，1 到 1048576
   * @param {string} pB - B 的公钥 hex
   * @param {string} Rb - B 的临时公钥 hex
   * @param {string} pA - A 的公钥 hex
   * @param {string} Ra - A 的临时公钥 hex
   * @param {string} IDa - A 的用户标识
   * @param {string} IDb - B 的用户标识
   * @param {string} dAh - A 的私钥 hex
   * @param {string} rah - A 的临时私钥 hex
   * @param {string} Sb - B 发来的验证值
   * @returns {{Sa: string, Ka: string}} Ka 是秘密
   * @throws {Error} 任何输入不合法，或 Sb 不匹配
   */
  getSa(len, pB, Rb, pA, Ra, IDa, IDb, dAh, rah, Sb) {
    requireKeyLength(len)
    const pAPoint = decodePublicKey(pA)
    const pBPoint = decodePublicKey(pB)
    const RaPoint = decodePublicKey(Ra)
    const RbPoint = decodePublicKey(Rb)
    const [ax, ay] = coordinateBytes(pAPoint)
    const [bx, by] = coordinateBytes(pBPoint)
    const Za = computeZ(ax, ay, IDa)
    const Zb = computeZ(bx, by, IDb)
    const dA = parsePrivateKey(dAh)
    const ra = parsePrivateKey(rah)

    const raCoordinates = coordinateBytes(RaPoint)
    const rbCoordinates = coordinateBytes(RbPoint)
    const t = new Uint8Array(SCALAR_BYTES)
    scalarMulAdd(t, xBar(raCoordinates[0]), ra, dA)
    dA.fill(0)
    ra.fill(0)
    let ux, uy
    try {
      ;[ux, uy] = sharedPoint(t, pBPoint, RbPoint)
    } finally {
      t.fill(0)
    }

    const expected = confirmationHash(
      SIGN_TAG,
      ux,
      uy,
      Za,
      Zb,
      raCoordinates,
      rbCoordinates,
    )
    if (!equalStrings(Sb, encodeHex(expected))) {
      throw new Error('Key exchange confirmation failed')
    }
    const Sa = confirmationHash(
      CONFIRM_TAG,
      ux,
      uy,
      Za,
      Zb,
      raCoordinates,
      rbCoordinates,
    )
    const Ka = exchangeKdf(len, ux, uy, Za, Zb)
    const result = { Sa: encodeHex(Sa), Ka: encodeHex(Ka) }
    Ka.fill(0)
    ux.fill(0)
    uy.fill(0)
    return result
  }

  // ---- 公钥计算 ----

  /**
   * 从私钥计算公钥
   * @param {string} privateKey - 私钥 hex
   * @returns {string} 公钥 hex (04 开头)
   * @throws {Error} 私钥不合法
   */
  getPublicKeyFromPrivateKey(privateKey) {
    const d = parsePrivateKey(privateKey)
    const x = new Uint8Array(SCALAR_BYTES)
    const y = new Uint8Array(SCALAR_BYTES)
    mulG(d, x, y)
    d.fill(0)
    return '04' + hexOfPoint(x, y)
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
   * @throws {Error} 公钥不合法，或 userId 超过 8191 字节
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
      x2_.signum() >= 0 &&
      x2_.bitLength() <= BITS
    ) {
      const out = new Uint8Array(SCALAR_BYTES)
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
    return confirmationHash(
      tag,
      vx,
      vy,
      Za,
      Zb,
      coordinateBytes(Ra),
      coordinateBytes(Rb),
    )
  }

  _KDF(keylen, vu, Za, Zb) {
    requireKeyLength(keylen)
    const [vx, vy] = coordinateBytes(vu)
    return Array.from(exchangeKdf(keylen, vx, vy, Za, Zb))
  }
}

export const getSM2 = () => new SM2()
