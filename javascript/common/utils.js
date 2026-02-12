/**
 * 公共工具函数 —— hex / bytes / string 转换
 * 统一使用 Uint8Array，消除有符号字节的复杂性
 */

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8')

/**
 * 字符串 → UTF-8 字节数组
 * @param {string} str
 * @returns {Uint8Array}
 */
export function stringToBytes(str) {
  return encoder.encode(str)
}

/**
 * UTF-8 字节数组 → 字符串
 * @param {Uint8Array|number[]} bytes
 * @returns {string}
 */
export function bytesToString(bytes) {
  if (bytes instanceof Uint8Array) return decoder.decode(bytes)
  return decoder.decode(new Uint8Array(bytes))
}

const HEX_CHARS = '0123456789abcdef'

/**
 * 字节数组 → 十六进制字符串（小写）
 * @param {Uint8Array|number[]} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] & 0xff
    hex += HEX_CHARS[b >>> 4] + HEX_CHARS[b & 0x0f]
  }
  return hex
}

/**
 * 十六进制字符串 → Uint8Array
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  if (hex.length & 1) hex = '0' + hex
  const len = hex.length >>> 1
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
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
  return ((bytes[offset] << 24) |
          (bytes[offset + 1] << 16) |
          (bytes[offset + 2] << 8) |
           bytes[offset + 3]) >>> 0
}

/**
 * 左填充零到指定长度
 * @param {string} str
 * @param {number} len
 * @returns {string}
 */
export function leftPad(str, len) {
  if (str.length >= len) return str
  return '0'.repeat(len - str.length) + str
}
