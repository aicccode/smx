import {
  stringToBytes,
  bytesToHex,
  bytesToIntBE,
  intToBytesBE,
} from '../common/utils.js'

/** SM3 初始向量 */
const IV = new Uint32Array([
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa,
  0xe38dee4d, 0xb0fb0e4e,
])

/** 32 位循环左移 */
function rotl(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0
}

/** 置换函数 P0 */
function P0(x) {
  return x ^ rotl(x, 9) ^ rotl(x, 17)
}

/** 置换函数 P1 */
function P1(x) {
  return x ^ rotl(x, 15) ^ rotl(x, 23)
}

/** 布尔函数 FF (j >= 16) */
function FF1(x, y, z) {
  return (x & y) | (x & z) | (y & z)
}

/** 布尔函数 GG (j >= 16) */
function GG1(x, y, z) {
  return (x & y) | (~x & z)
}

/**
 * SM3 哈希算法
 *
 * 用法：
 *   const h = new SM3()
 *   h.update(bytes).update(moreBytes)
 *   const hash = h.digest()       // Uint8Array(32)
 *   const hex  = h.hexDigest()    // string
 *
 * 便捷方法：
 *   SM3.hash('abc')               // Uint8Array(32)
 *   SM3.hashHex('abc')            // 大写 hex string
 */
export class SM3 {
  constructor() {
    this._buf = new Uint8Array(64) // 512-bit 块缓冲
    this._pos = 0 // 缓冲区写入位置
    this._len = 0 // 已处理字节总长度
    this._V = new Uint32Array(IV) // 当前哈希状态
    this._finished = false
  }

  /**
   * 输入数据（支持单个字节或字节数组）
   * @param {number|Uint8Array|number[]} data - 单个字节 (0-255) 或字节数组
   * @returns {SM3}
   */
  update(data) {
    if (typeof data === 'number') {
      this._buf[this._pos++] = data & 0xff
      this._len++
      if (this._pos === 64) {
        this._compress(this._buf)
        this._pos = 0
      }
      return this
    }
    for (let i = 0; i < data.length; i++) {
      this._buf[this._pos++] = data[i] & 0xff
      this._len++
      if (this._pos === 64) {
        this._compress(this._buf)
        this._pos = 0
      }
    }
    return this
  }

  /**
   * 输入字符串（UTF-8 编码）
   * @param {string} text
   * @returns {SM3}
   */
  updateString(text) {
    return this.update(stringToBytes(text))
  }

  /**
   * 输入字节数组的指定区间（兼容旧 API）
   * @param {Uint8Array|number[]} data
   * @param {number} offset
   * @param {number} length
   * @returns {SM3}
   */
  updateBytes(data, offset, length) {
    for (let i = 0; i < length; i++) {
      this._buf[this._pos++] = data[offset + i] & 0xff
      this._len++
      if (this._pos === 64) {
        this._compress(this._buf)
        this._pos = 0
      }
    }
    return this
  }

  /**
   * 完成哈希计算，返回 32 字节摘要
   * @returns {Uint8Array}
   */
  digest() {
    if (!this._finished) {
      this._pad()
      this._finished = true
    }
    const out = new Uint8Array(32)
    for (let i = 0; i < 8; i++) {
      intToBytesBE(this._V[i], out, i * 4)
    }
    return out
  }

  /**
   * 完成哈希计算，返回大写十六进制字符串
   * @returns {string}
   */
  hexDigest() {
    return bytesToHex(this.digest()).toUpperCase()
  }

  // ---- 兼容旧 API ----

  /** @deprecated 使用 digest() / hexDigest() */
  finish() {
    this._hashBytes = this.digest()
    this._hashValue = bytesToHex(this._hashBytes).toUpperCase()
    // 重置状态以支持复用
    this._V = new Uint32Array(IV)
    this._pos = 0
    this._len = 0
    this._finished = false
    return this
  }

  /** @deprecated 使用 hexDigest() */
  getHashCode() {
    return this._hashValue
  }

  /** @deprecated 使用 digest() */
  getHashBytes() {
    return this._hashBytes
  }

  // ---- 内部方法 ----

  /** 消息填充 */
  _pad() {
    const bitLen = this._len * 8

    // 追加 0x80
    this._buf[this._pos++] = 0x80
    // 如果剩余空间不够放 8 字节长度，先填满当前块
    if (this._pos > 56) {
      while (this._pos < 64) this._buf[this._pos++] = 0
      this._compress(this._buf)
      this._pos = 0
    }
    // 填充零
    while (this._pos < 56) this._buf[this._pos++] = 0
    // 追加 64 位大端序消息长度（JS 安全整数范围内用两个 32 位写入）
    intToBytesBE(Math.floor(bitLen / 0x100000000), this._buf, 56)
    intToBytesBE(bitLen >>> 0, this._buf, 60)
    this._compress(this._buf)
  }

  /** 压缩函数：处理一个 64 字节块 */
  _compress(block) {
    // 消息扩展
    const w = new Int32Array(68)
    for (let j = 0; j < 16; j++) {
      w[j] = bytesToIntBE(block, j * 4)
    }
    for (let j = 16; j < 68; j++) {
      w[j] =
        P1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^
        rotl(w[j - 13], 7) ^
        w[j - 6]
    }

    const w2 = new Int32Array(64)
    for (let j = 0; j < 64; j++) {
      w2[j] = w[j] ^ w[j + 4]
    }

    // 压缩
    let A = this._V[0],
      B = this._V[1],
      C = this._V[2],
      D = this._V[3]
    let E = this._V[4],
      F = this._V[5],
      G = this._V[6],
      H = this._V[7]

    for (let j = 0; j < 64; j++) {
      const A12 = rotl(A, 12)
      const Tj = j < 16 ? rotl(0x79cc4519, j) : rotl(0x7a879d8a, j % 32)
      const SS1 = rotl((A12 + E + Tj) | 0, 7)
      const SS2 = SS1 ^ A12

      const TT1 =
        j < 16
          ? ((A ^ B ^ C) + D + SS2 + w2[j]) | 0
          : (FF1(A, B, C) + D + SS2 + w2[j]) | 0
      const TT2 =
        j < 16
          ? ((E ^ F ^ G) + H + SS1 + w[j]) | 0
          : (GG1(E, F, G) + H + SS1 + w[j]) | 0

      D = C
      C = rotl(B, 9)
      B = A
      A = TT1
      H = G
      G = rotl(F, 19)
      F = E
      E = P0(TT2)
    }

    this._V[0] ^= A
    this._V[1] ^= B
    this._V[2] ^= C
    this._V[3] ^= D
    this._V[4] ^= E
    this._V[5] ^= F
    this._V[6] ^= G
    this._V[7] ^= H
  }

  // ---- 静态便捷方法 ----

  /**
   * 一次性计算字符串的 SM3 哈希
   * @param {string} str
   * @returns {Uint8Array}
   */
  static hash(str) {
    return new SM3().updateString(str).digest()
  }

  /**
   * 一次性计算字符串的 SM3 哈希（大写 hex）
   * @param {string} str
   * @returns {string}
   */
  static hashHex(str) {
    return new SM3().updateString(str).hexDigest()
  }
}

/** @deprecated 使用 new SM3() */
export const getSM3 = () => new SM3()
