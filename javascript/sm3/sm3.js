import { stringToBytes, bytesToHex, intToBytesBE } from '../common/utils.js'

/** SM3 初始向量 */
const IV = new Int32Array([
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa,
  0xe38dee4d, 0xb0fb0e4e,
])

/** 轮常量 T_j <<< j，预先计算 */
const T = new Int32Array(64)
for (let j = 0; j < 64; j++) {
  const t = j < 16 ? 0x79cc4519 : 0x7a879d8a
  const n = j % 32
  T[j] = n === 0 ? t : (t << n) | (t >>> (32 - n))
}

/** 消息扩展缓冲区：可复用，因为压缩函数不会重入 */
const W = new Int32Array(68)

/**
 * 压缩函数：依次处理 data 中从 offset 开始的 blocks 个 64 字节块
 * @param {Int32Array} V - 哈希状态，原地更新
 * @param {Uint8Array} data
 * @param {number} offset
 * @param {number} blocks
 */
function compress(V, data, offset, blocks) {
  const w = W
  const t = T
  let v0 = V[0]
  let v1 = V[1]
  let v2 = V[2]
  let v3 = V[3]
  let v4 = V[4]
  let v5 = V[5]
  let v6 = V[6]
  let v7 = V[7]

  for (let block = 0; block < blocks; block++, offset += 64) {
    for (let j = 0; j < 16; j++) {
      const o = offset + 4 * j
      w[j] =
        (data[o] << 24) | (data[o + 1] << 16) | (data[o + 2] << 8) | data[o + 3]
    }
    for (let j = 16; j < 68; j++) {
      const a = w[j - 3]
      const x = w[j - 16] ^ w[j - 9] ^ ((a << 15) | (a >>> 17))
      const b = w[j - 13]
      w[j] =
        x ^
        ((x << 15) | (x >>> 17)) ^
        ((x << 23) | (x >>> 9)) ^
        ((b << 7) | (b >>> 25)) ^
        w[j - 6]
    }

    let A = v0
    let B = v1
    let C = v2
    let D = v3
    let E = v4
    let F = v5
    let G = v6
    let H = v7

    for (let j = 0; j < 16; j++) {
      const a12 = (A << 12) | (A >>> 20)
      const s = (a12 + E + t[j]) | 0
      const ss1 = (s << 7) | (s >>> 25)
      const wj = w[j]
      const tt1 = ((A ^ B ^ C) + D + (ss1 ^ a12) + (wj ^ w[j + 4])) | 0
      const tt2 = ((E ^ F ^ G) + H + ss1 + wj) | 0
      D = C
      C = (B << 9) | (B >>> 23)
      B = A
      A = tt1
      H = G
      G = (F << 19) | (F >>> 13)
      F = E
      E = tt2 ^ ((tt2 << 9) | (tt2 >>> 23)) ^ ((tt2 << 17) | (tt2 >>> 15))
    }
    for (let j = 16; j < 64; j++) {
      const a12 = (A << 12) | (A >>> 20)
      const s = (a12 + E + t[j]) | 0
      const ss1 = (s << 7) | (s >>> 25)
      const wj = w[j]
      const ff = (A & B) | (C & (A | B))
      const gg = ((F ^ G) & E) ^ G
      const tt1 = (ff + D + (ss1 ^ a12) + (wj ^ w[j + 4])) | 0
      const tt2 = (gg + H + ss1 + wj) | 0
      D = C
      C = (B << 9) | (B >>> 23)
      B = A
      A = tt1
      H = G
      G = (F << 19) | (F >>> 13)
      F = E
      E = tt2 ^ ((tt2 << 9) | (tt2 >>> 23)) ^ ((tt2 << 17) | (tt2 >>> 15))
    }

    v0 ^= A
    v1 ^= B
    v2 ^= C
    v3 ^= D
    v4 ^= E
    v5 ^= F
    v6 ^= G
    v7 ^= H
  }

  V[0] = v0
  V[1] = v1
  V[2] = v2
  V[3] = v3
  V[4] = v4
  V[5] = v5
  V[6] = v6
  V[7] = v7
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
    this._V = new Int32Array(IV) // 当前哈希状态
    this._finished = false
    this._hashBytes = null // finish() 的结果
    this._hashValue = null // 由 _hashBytes 按需生成
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
        compress(this._V, this._buf, 0, 1)
        this._pos = 0
      }
      return this
    }
    if (data instanceof Uint8Array) {
      this._absorb(data, 0, data.length)
      return this
    }
    this._absorbGeneric(data, 0, data.length)
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
    if (
      data instanceof Uint8Array &&
      offset >= 0 &&
      length >= 0 &&
      offset + length <= data.length
    ) {
      this._absorb(data, offset, length)
    } else {
      this._absorbGeneric(data, offset, length)
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
    this._hashValue = null
    // 重置状态以支持复用
    this._V.set(IV)
    this._pos = 0
    this._len = 0
    this._finished = false
    return this
  }

  /** @deprecated 使用 hexDigest() */
  getHashCode() {
    if (this._hashBytes === null) return undefined
    if (this._hashValue === null) {
      this._hashValue = bytesToHex(this._hashBytes).toUpperCase()
    }
    return this._hashValue
  }

  /** @deprecated 使用 digest() */
  getHashBytes() {
    return this._hashBytes === null ? undefined : this._hashBytes
  }

  // ---- 内部方法 ----

  /** 整块直接在输入上压缩，只把不足一块的部分放入缓冲区 */
  _absorb(data, offset, length) {
    this._len += length
    const buf = this._buf
    let pos = this._pos
    let remaining = length
    if (pos > 0) {
      const take = Math.min(64 - pos, remaining)
      for (let i = 0; i < take; i++) buf[pos + i] = data[offset + i]
      pos += take
      offset += take
      remaining -= take
      if (pos === 64) {
        compress(this._V, buf, 0, 1)
        pos = 0
      }
    }
    if (remaining >= 64) {
      const blocks = remaining >>> 6
      compress(this._V, data, offset, blocks)
      const consumed = blocks << 6
      offset += consumed
      remaining -= consumed
    }
    for (let i = 0; i < remaining; i++) buf[pos + i] = data[offset + i]
    this._pos = pos + remaining
  }

  /** 普通数组等输入：逐字节截断为 0-255 */
  _absorbGeneric(data, offset, length) {
    for (let i = 0; i < length; i++) {
      this._buf[this._pos++] = data[offset + i] & 0xff
      this._len++
      if (this._pos === 64) {
        compress(this._V, this._buf, 0, 1)
        this._pos = 0
      }
    }
  }

  /** 消息填充 */
  _pad() {
    const bitLen = this._len * 8

    // 追加 0x80
    this._buf[this._pos++] = 0x80
    // 如果剩余空间不够放 8 字节长度，先填满当前块
    if (this._pos > 56) {
      this._buf.fill(0, this._pos, 64)
      compress(this._V, this._buf, 0, 1)
      this._pos = 0
    }
    // 填充零
    this._buf.fill(0, this._pos, 56)
    this._pos = 56
    // 追加 64 位大端序消息长度（JS 安全整数范围内用两个 32 位写入）
    intToBytesBE(Math.floor(bitLen / 0x100000000), this._buf, 56)
    intToBytesBE(bitLen >>> 0, this._buf, 60)
    compress(this._V, this._buf, 0, 1)
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
