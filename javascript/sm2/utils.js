import { BigInteger } from './biginteger.js'
import { ECCurveFp } from './ec.js'
import { generateKeyMaterial } from './keygen.js'
import { HEX_PAIRS, decodeStrictHex, parseHexPair } from '../common/hex.js'
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
 */
export function generateKeyPairHex() {
  const { d, x, y } = generateKeyMaterial()
  return {
    privateKey: d.toRadix(16),
    publicKey: '04' + bytesToHex(x) + bytesToHex(y),
  }
}

/**
 * 生成压缩公钥
 */
export function compressPublicKeyHex(s) {
  if (s.length !== 130) throw new Error('Invalid public key to compress')
  const len = (s.length - 2) / 2
  const xHex = s.substring(2, 2 + len)
  const y = new BigInteger(s.substring(2 + len, 2 + 2 * len), 16)
  const prefix = y.isEven() ? '02' : '03'
  return prefix + xHex
}

/**
 * 验证公钥是否为椭圆曲线上的点
 */
export function verifyPublicKey(publicKey) {
  const point = curve.decodePointHex(publicKey)
  if (!point) return false
  const x = point.getX(),
    y = point.getY()
  return y
    .square()
    .equals(x.multiply(x.square()).add(x.multiply(curve.a)).add(curve.b))
}

/**
 * 验证公钥是否等价
 */
export function comparePublicKeyHex(publicKey1, publicKey2) {
  const point1 = curve.decodePointHex(publicKey1)
  if (!point1) return false
  const point2 = curve.decodePointHex(publicKey2)
  if (!point2) return false
  return point1.equals(point2)
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
  if (hexStr.length % 2 !== 0) hexStr = leftPad(hexStr, hexStr.length + 1)
  const bytes = decodeStrictHex(hexStr)
  const words = new Array(hexStr.length >>> 1)
  for (let i = 0; i < words.length; i++) {
    let b = bytes === null ? parseHexPair(hexStr, i) : bytes[i]
    if (b > 127) b -= 256
    words[i] = b
  }
  return words
}

/**
 * 字节数组 → 十六进制串（兼容旧 API）
 */
export function arrayToHex(arr) {
  return arr.map((item) => HEX_PAIRS[item & 0xff]).join('')
}
