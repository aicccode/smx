/**
 * 公共工具函数 —— hex / bytes / string 转换
 * 统一使用 Uint8Array，消除有符号字节的复杂性
 */
import {
  decodeHex,
  encodeHex,
  requireWellFormedString,
  toByteArray,
} from './hex.js'

const encoder = new TextEncoder()
// ignoreBOM keeps a leading U+FEFF, so UTF-8 round trips are exact.
const decoder = new TextDecoder('utf-8', { ignoreBOM: true })

/**
 * 字符串 → UTF-8 字节数组
 * @param {string} str
 * @returns {Uint8Array}
 * @throws {TypeError} 非字符串，或包含未配对的代理项
 */
export function stringToBytes(str) {
  requireWellFormedString(str)
  return encoder.encode(str)
}

/**
 * UTF-8 字节数组 → 字符串。非法序列替换为 U+FFFD
 * @param {Uint8Array|number[]} bytes
 * @returns {string}
 */
export function bytesToString(bytes) {
  return decoder.decode(toByteArray(bytes))
}

/**
 * 字节数组 → 十六进制字符串（小写）
 * @param {Uint8Array|number[]} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return encodeHex(toByteArray(bytes))
}

/**
 * 十六进制字符串 → Uint8Array
 * @param {string} hex - 偶数长度，只含十六进制数字
 * @returns {Uint8Array}
 * @throws {Error} 不是合法的十六进制串
 */
export function hexToBytes(hex) {
  const bytes = decodeHex(hex)
  if (bytes === null) throw new Error('Invalid hex string')
  return bytes
}

/**
 * 32 位整数 → 4 字节大端序
 * @param {number} n
 * @param {Uint8Array} out
 * @param {number} offset
 */
export function intToBytesBE(n, out, offset) {
  out[offset] = (n >>> 24) & 0xff
  out[offset + 1] = (n >>> 16) & 0xff
  out[offset + 2] = (n >>> 8) & 0xff
  out[offset + 3] = n & 0xff
}

/**
 * 4 字节大端序 → 32 位整数
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {number}
 */
export function bytesToIntBE(bytes, offset) {
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0
  )
}

/**
 * 左填充零到指定长度
 * @param {string} str
 * @param {number} len
 * @returns {string}
 */
export function leftPad(str, len) {
  if (typeof str !== 'string') throw new TypeError('Expected a string')
  if (!Number.isSafeInteger(len) || len < 0) {
    throw new RangeError('Invalid pad length')
  }
  if (str.length >= len) return str
  return '0'.repeat(len - str.length) + str
}
