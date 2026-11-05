import { BigInteger } from './biginteger.js'
import { ECCurveFp } from './ec.js'
import { generateKeyMaterial } from './keygen.js'
import { encodeHex } from '../common/hex.js'
import {
  bytesToHex,
  hexToBytes,
  stringToBytes,
  bytesToString,
  leftPad,
} from '../common/utils.js'

const { curve } = generateEcparam()

/**
 * 获取公共椭圆曲线
 */
export function getGlobalCurve() {
  return curve
}

/**
 * 生成 SM2 推荐椭圆曲线参数
 */
export function generateEcparam() {
  const p = new BigInteger(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    16,
  )
  const a = new BigInteger(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    16,
  )
  const b = new BigInteger(
    '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
    16,
  )
  const curve = new ECCurveFp(p, a, b)

  const gxHex =
    '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'
  const gyHex =
    'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'
  const G = curve.decodePointHex('04' + gxHex + gyHex)

  const n = new BigInteger(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    16,
  )
  const w = Math.ceil(n.bitLength() / 2.0) - 1

  return { curve, G, n, w }
}

/**
 * 生成密钥对：publicKey = privateKey * G
 * 私钥是 [1, n-2] 内的均匀随机数，hex 固定 64 位
 */
export function generateKeyPairHex() {
  const { dBytes, x, y } = generateKeyMaterial()
  const privateKey = encodeHex(dBytes)
  dBytes.fill(0)
  return {
    privateKey,
    publicKey: '04' + encodeHex(x) + encodeHex(y),
  }
}

/**
 * 生成压缩公钥
 */
export function compressPublicKeyHex(s) {
  if (typeof s !== 'string' || s.length !== 130) {
    throw new Error('Invalid public key to compress')
  }
  const point = curve.decodePointHex(s)
  const prefix = point.y.toBigInteger().isEven() ? '02' : '03'
  return prefix + s.substring(2, 66)
}

/**
 * 验证公钥是否为椭圆曲线上的点
 */
export function verifyPublicKey(publicKey) {
  try {
    curve.decodePointHex(publicKey)
    return true
  } catch {
    return false
  }
}

/**
 * 验证公钥是否等价
 */
export function comparePublicKeyHex(publicKey1, publicKey2) {
  try {
    return curve
      .decodePointHex(publicKey1)
      .equals(curve.decodePointHex(publicKey2))
  } catch {
    return false
  }
}

// ---- 重导出公共工具函数 ----
export {
  bytesToHex as bytes2hex,
  hexToBytes,
  stringToBytes,
  bytesToString as bytesToUTF8String,
  leftPad,
}

/**
 * 十六进制串 → 有符号字节数组（兼容旧 API）
 */
export function hexToArray(hexStr) {
  const bytes = hexToBytes(hexStr)
  const words = new Array(bytes.length)
  for (let i = 0; i < words.length; i++) {
    words[i] = (bytes[i] << 24) >> 24
  }
  return words
}

/**
 * 字节数组 → 十六进制串（兼容旧 API）
 */
export function arrayToHex(arr) {
  return bytesToHex(arr)
}
