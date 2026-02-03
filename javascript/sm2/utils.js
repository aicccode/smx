/* eslint-disable no-bitwise, no-mixed-operators, no-use-before-define, max-len */
import { BigInteger, SecureRandom } from './biginteger.js'
import { ECCurveFp } from './ec.js'

const rng = new SecureRandom()
const { curve, G, n } = generateEcparam()
const ZERO = new BigInteger('0')
const TWO = new BigInteger('2')
/**
 * 获取公共椭圆曲线
 */
export function getGlobalCurve() {
  return curve
}

/**
 * 生成ecparam
 */
export function generateEcparam() {
  /** 椭圆曲线 国密推荐参数 */
  const p = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
  const a = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
  const b = new BigInteger('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
  const curve = new ECCurveFp(p, a, b)

  // 基点
  const gxHex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'
  const gyHex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'

  const G = curve.decodePointHex('04' + gxHex + gyHex)

  const n = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
  // 密钥交换协议使用  w=[[log2(n)]/2]-1
  const w = Math.ceil(n.bitLength() / 2.0) - 1

  return { curve, G, n, w }

  /** 椭圆曲线 国密测试参数
  const p = new BigInteger('8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3', 16)
  const a = new BigInteger('787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498', 16)
  const b = new BigInteger('63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A', 16)
  const curve = new ECCurveFp(p, a, b)
  // 基点
  const gxHex = '421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D'
  const gyHex = '0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2'
  const G = curve.decodePointHex('04' + gxHex + gyHex)

  const n = new BigInteger('8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7', 16)
  // 密钥交换协议使用  w=[[log2(n)]/2]-1
  const w = Math.ceil(n.bitLength() / 2.0) - 1
  return { curve, G, n, w } */
}

/**
 * 生成密钥对：publicKey = privateKey * G
 */
export function generateKeyPairHex() {
  const minWidth = n.bitLength() >>> 2
  let d
  do {
    d = new BigInteger(n.bitLength(), rng)
  } while (d.compareTo(TWO) < 0 || (d.compareTo(n) >= 0) || getWidth(d) < minWidth)
  const Q = G.multiply(d)

  const Px = bigIntegerToHex(Q.getX().toBigInteger())
  const Py = bigIntegerToHex(Q.getY().toBigInteger())
  const publicKey = '04' + Px + Py
  return {
    privateKey: d.toRadix(16),
    publicKey: publicKey
  }
}

function bigIntegerToHex(n) {
  let tmpd
  if (!n) {
    return null
  }
  const nArray = n.toByteArray()
  if (nArray.length == 33) {
    tmpd = nArray.slice(1)
  } else if (nArray.length == 32) {
    tmpd = nArray
  } else {
    tmpd = new Array(32)
    for (let i = 0; i < 32; i++) {
      if (i < 32 - nArray.length) {
        tmpd[i] = 0
      } else {
        tmpd[i] = nArray[i - (32 - nArray.length)]
      }
    }
  }
  return bytes2hex(tmpd)
}

function getWidth(k) {
  return k.signum() === 0 ? 0 : k.shiftLeft(1).add(k).xor(k).bitCount()
}

/**
 * 生成压缩公钥
 */
export function compressPublicKeyHex(s) {
  if (s.length !== 130) throw new Error('Invalid public key to compress')

  const len = (s.length - 2) / 2
  const xHex = s.substr(2, len)
  const y = new BigInteger(s.substr(len + 2, len), 16)

  let prefix = '03'
  if (y.mod(new BigInteger('2')).equals(ZERO)) prefix = '02'

  return prefix + xHex
}

/**
 * 补全16进制字符串
 */
export function leftPad(input, num) {
  if (input.length >= num) return input

  return (new Array(num - input.length + 1)).join('0') + input
}

/**
 * 转成16进制串
 */
export function arrayToHex(arr) {
  return arr.map(item => {
    item = item.toString(16)
    return item.length === 1 ? '0' + item : item
  }).join('')
}
const HEX_ARRAY = '0123456789ABCDEF'.split('')
export function bytes2hex(bytes, upperCase) {
  const hexChars = new Array(bytes.length * 2)
  for (let j = 0; j < bytes.length; j++) {
    const v = bytes[j] & 0xFF
    hexChars[j * 2] = HEX_ARRAY[v >>> 4]
    hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F]
  }
  return upperCase ? hexChars.join('').toUpperCase() : hexChars.join('').toLowerCase()
}
export function bytesToUTF8String(bytes) {
  const uint8Array = new Uint8Array(bytes.length)
  for (let i = 0; i < bytes.length; i++) {
    uint8Array[i] = bytes[i] < 0 ? bytes[i] + 256 : bytes[i]
  }
  bytes = uint8Array
  const decoder = new TextDecoder('utf-8')
  return decoder.decode(bytes)
}

export function stringToBytes(text) {
  const code = encodeURIComponent(text)
  const bytes = []
  for (let i = 0; i < code.length; i++) {
    const c = code.charAt(i)
    if (c === '%') {
      const hex = code.charAt(i + 1) + code.charAt(i + 2)
      const hexVal = parseInt(hex, 16)
      bytes.push(hexVal)
      i += 2
    } else {
      bytes.push(c.charCodeAt(0))
    }
  }
  return bytes
}

/**
 * 转成utf8串
 */
export function arrayToUtf8(arr) {
  const words = []
  let j = 0
  for (let i = 0; i < arr.length * 2; i += 2) {
    words[i >>> 3] |= parseInt(arr[j], 10) << (24 - (i % 8) * 4)
    j++
  }

  try {
    const latin1Chars = []
    for (let i = 0; i < arr.length; i++) {
      const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
      latin1Chars.push(String.fromCharCode(bite))
    }
    return decodeURIComponent(encodeURI(latin1Chars.join('')))
  } catch (e) {
    throw new Error('Malformed UTF-8 data')
  }
}

/**
 * 转成字节数组
 */
export function hexToArray(hexStr) {
  const words = []
  let hexStrLength = hexStr.length

  if (hexStrLength % 2 !== 0) {
    hexStr = leftPad(hexStr, hexStrLength + 1)
  }

  hexStrLength = hexStr.length

  for (let i = 0; i < hexStrLength; i += 2) {
    words.push(limitToSignedByte(parseInt(hexStr.substr(i, 2), 16)))
  }
  return words
}

function limitToSignedByte(i) {
  const b = i & 0xFF
  let c = 0
  if (b >= 128) {
    c = b % 128
    c = -1 * (128 - c)
  } else {
    c = b
  }
  return c
}

/**
 * 验证公钥是否为椭圆曲线上的点
 */
export function verifyPublicKey(publicKey) {
  const point = curve.decodePointHex(publicKey)
  if (!point) return false

  const x = point.getX()
  const y = point.getY()

  // 验证 y^2 是否等于 x^3 + ax + b
  return y.square().equals(x.multiply(x.square()).add(x.multiply(curve.a)).add(curve.b))
}

/**
 * 验证公钥是否等价，等价返回true
 */
export function comparePublicKeyHex(publicKey1, publicKey2) {
  const point1 = curve.decodePointHex(publicKey1)
  if (!point1) return false

  const point2 = curve.decodePointHex(publicKey2)
  if (!point2) return false

  return point1.equals(point2)
}

// ESM named exports are declared above
