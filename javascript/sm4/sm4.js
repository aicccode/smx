import { SM3 } from '../sm3/sm3.js'
import {
  stringToBytes,
  bytesToString,
  bytesToHex,
  hexToBytes,
  bytesToIntBE,
  intToBytesBE,
} from '../common/utils.js'

// ---- SM4 常量 ----

/** S 盒 */
const SBOX = new Uint8Array([
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28,
  0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44,
  0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98,
  0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9,
  0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6, 0x47,
  0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85,
  0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f,
  0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
  0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f,
  0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf,
  0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15,
  0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
  0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0,
  0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd,
  0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51, 0x8d, 0x1b, 0xaf,
  0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8,
  0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9,
  0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84, 0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d,
  0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
])

/** 系统参数 FK */
const FK = new Uint32Array([0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc])

/** 固定密钥 CK */
const CK = new Uint32Array([
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
  0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
  0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
  0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
  0x484f565d, 0x646b7279,
])

// ---- 内部函数 ----

/** 32 位循环左移 */
function rotl(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0
}

/** 非线性变换 τ：4 字节 S 盒替换（纯位运算，不创建临时数组） */
function tau(a) {
  return (
    ((SBOX[(a >>> 24) & 0xff] << 24) |
      (SBOX[(a >>> 16) & 0xff] << 16) |
      (SBOX[(a >>> 8) & 0xff] << 8) |
      SBOX[a & 0xff]) >>>
    0
  )
}

/** 合成置换 T（加密轮函数） */
function T(a) {
  const b = tau(a)
  return (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) >>> 0
}

/** 合成置换 T'（密钥扩展） */
function TPrime(a) {
  const b = tau(a)
  return (b ^ rotl(b, 13) ^ rotl(b, 23)) >>> 0
}

/**
 * 将密钥/IV 规范化为 16 字节
 * 如果长度不是 16，用 SM3 哈希后取 hex 串的前 16 个 ASCII 字节（保持向后兼容）
 * @param {string} str
 * @returns {Uint8Array}
 */
function normalizeKeyFromString(str) {
  const bytes = stringToBytes(str)
  if (bytes.length === 16) return bytes
  const hexStr = new SM3().updateString(str).hexDigest()
  return stringToBytes(hexStr).subarray(0, 16)
}

/**
 * SM4 对称加密算法（CBC 模式，PKCS7 填充）
 *
 * 用法：
 *   const sm4 = new SM4()
 *   sm4.setKey('key', 'iv')
 *   const cipher = sm4.encrypt('plaintext')   // hex string
 *   const plain  = sm4.decrypt(cipher)         // string
 */
export class SM4 {
  constructor() {
    this._rk = new Uint32Array(32) // 轮密钥
    this._iv = new Uint8Array(16) // 初始向量
  }

  /**
   * 设置密钥和初始向量
   * @param {string} key  - 密钥字符串或 hex
   * @param {string} iv   - IV 字符串或 hex
   * @param {boolean} [hex=false] - 是否为十六进制输入
   * @returns {SM4}
   */
  setKey(key, iv, hex) {
    const keyBytes = hex ? hexToBytes(key) : normalizeKeyFromString(key)
    const ivBytes = hex ? hexToBytes(iv) : normalizeKeyFromString(iv)
    this._expandKey(keyBytes)
    this._iv.set(ivBytes.subarray(0, 16))
    return this
  }

  /**
   * CBC 加密
   * @param {string} text - 明文字符串
   * @returns {string} 密文 hex
   */
  encrypt(text) {
    const input = pkcs7Pad(stringToBytes(text))
    const output = new Uint8Array(input.length)
    const cbcIV = new Uint8Array(this._iv)
    const block = new Uint8Array(16)

    for (let off = 0; off < input.length; off += 16) {
      // XOR with CBC IV
      for (let i = 0; i < 16; i++) block[i] = input[off + i] ^ cbcIV[i]
      // 加密一个块
      this._encryptBlock(block, output, off)
      // 更新 CBC IV
      cbcIV.set(output.subarray(off, off + 16))
    }

    return bytesToHex(output)
  }

  /**
   * CBC 解密
   * @param {string} cipherHex - 密文 hex
   * @returns {string} 明文字符串
   */
  decrypt(cipherHex) {
    const input = hexToBytes(cipherHex)
    const output = new Uint8Array(input.length)
    const cbcIV = new Uint8Array(this._iv)

    for (let off = 0; off < input.length; off += 16) {
      // 解密一个块
      this._decryptBlock(input, off, output, off)
      // XOR with CBC IV
      for (let i = 0; i < 16; i++) output[off + i] ^= cbcIV[i]
      // 更新 CBC IV = 当前密文块
      cbcIV.set(input.subarray(off, off + 16))
    }

    return bytesToString(pkcs7Unpad(output))
  }

  // ---- 内部方法 ----

  /** 密钥扩展 */
  _expandKey(key) {
    const K = new Uint32Array(36)
    K[0] = bytesToIntBE(key, 0) ^ FK[0]
    K[1] = bytesToIntBE(key, 4) ^ FK[1]
    K[2] = bytesToIntBE(key, 8) ^ FK[2]
    K[3] = bytesToIntBE(key, 12) ^ FK[3]
    for (let i = 0; i < 32; i++) {
      K[i + 4] = (K[i] ^ TPrime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i])) >>> 0
      this._rk[i] = K[i + 4]
    }
  }

  /** 加密单块 (16 bytes) */
  _encryptBlock(input, output, outOff) {
    this._processBlock(input, 0, output, outOff, false)
  }

  /** 解密单块 (16 bytes) */
  _decryptBlock(input, inOff, output, outOff) {
    this._processBlock(input, inOff, output, outOff, true)
  }

  /** 处理单块（加密/解密共用） */
  _processBlock(input, inOff, output, outOff, decrypt) {
    const X = new Uint32Array(36)
    X[0] = bytesToIntBE(input, inOff)
    X[1] = bytesToIntBE(input, inOff + 4)
    X[2] = bytesToIntBE(input, inOff + 8)
    X[3] = bytesToIntBE(input, inOff + 12)

    for (let i = 0; i < 32; i++) {
      const rk = decrypt ? this._rk[31 - i] : this._rk[i]
      X[i + 4] = (X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk)) >>> 0
    }

    // 反序变换 R
    intToBytesBE(X[35], output, outOff)
    intToBytesBE(X[34], output, outOff + 4)
    intToBytesBE(X[33], output, outOff + 8)
    intToBytesBE(X[32], output, outOff + 12)
  }
}

// ---- PKCS7 填充 ----

function pkcs7Pad(data) {
  const padLen = 16 - (data.length % 16)
  const out = new Uint8Array(data.length + padLen)
  out.set(data)
  for (let i = data.length; i < out.length; i++) out[i] = padLen
  return out
}

function pkcs7Unpad(data) {
  const padLen = data[data.length - 1]
  return data.subarray(0, data.length - padLen)
}

/** @deprecated 使用 new SM4() */
export const getSM4 = () => new SM4()
