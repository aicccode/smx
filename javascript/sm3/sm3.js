import { toByteArray } from '../common/hex.js'
import { compress } from './compress.js'
import { stringToBytes, bytesToHex, intToBytesBE } from '../common/utils.js'

/** 超过这个长度 _len 不再是精确整数，所以限制更严，仍低于标准上限 2^61 - 1 */
const MAX_TRACKED_BYTES = Number.MAX_SAFE_INTEGER

const INSPECT = Symbol.for('nodejs.util.inspect.custom')

/** SM3 初始向量 */
const IV = new Int32Array([
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa,
  0xe38dee4d, 0xb0fb0e4e,
])

const SINGLE_BYTE = new Uint8Array(1)

/**
 * V8 keeps typed arrays of up to 64 bytes inside the object itself, and reading
 * `.buffer` of one moves its storage off the heap, which costs more than hashing it.
 * Blocks of such arrays, including each instance's own buffer, are copied to this
 * staging block instead. Larger arrays already live off the heap and are read in
 * place. Not reentrant, which is fine: compress never calls back into user code.
 */
const ON_HEAP_MAX_BYTES = 64
const STAGE = new Uint8Array(64)
const STAGE_VIEW = new DataView(STAGE.buffer)

/** Compresses whole blocks of `data` starting at `offset`. */
function compressBlocks(V, data, offset, blocks) {
  if (data.length > ON_HEAP_MAX_BYTES) {
    compress(
      V,
      new DataView(data.buffer, data.byteOffset, data.length),
      offset,
      blocks,
    )
    return
  }
  // A short array holds at most one block. A plain loop: subarray() would allocate.
  for (let i = 0; i < 64; i++) STAGE[i] = data[offset + i]
  compress(V, STAGE_VIEW, 0, 1)
  STAGE.fill(0)
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
    this._hashValue = null
  }

  /**
   * 输入数据（支持单个字节或字节数组）
   * @param {number|Uint8Array|number[]} data - 单个字节 (-128 到 255) 或字节数组
   * @returns {SM3}
   * @throws {TypeError} 不是字节数据，或 digest() 之后继续输入
   */
  update(data) {
    this._requireOpen()
    this._clearFinishResult()
    if (typeof data === 'number') {
      if (!Number.isInteger(data) || data < -128 || data > 255) {
        throw new TypeError('Expected a byte value')
      }
      SINGLE_BYTE[0] = data
      this._absorb(SINGLE_BYTE, 0, 1)
      return this
    }
    const bytes = toByteArray(data)
    this._absorb(bytes, 0, bytes.length)
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
   * @throws {TypeError|RangeError} 不是字节数据，或区间超出数组范围
   */
  updateBytes(data, offset, length) {
    this._requireOpen()
    this._clearFinishResult()
    const bytes = toByteArray(data)
    if (
      !Number.isSafeInteger(offset) ||
      !Number.isSafeInteger(length) ||
      offset < 0 ||
      length < 0 ||
      offset + length > bytes.length
    ) {
      throw new RangeError('Range is outside the input')
    }
    this._absorb(bytes, offset, length)
    return this
  }

  /**
   * 完成哈希计算，返回 32 字节摘要
   * @returns {Uint8Array}
   */
  digest() {
    // After finish() with no new input, this is the digest that finish() computed,
    // not the digest of an empty message.
    if (this._hashBytes !== null) return Uint8Array.from(this._hashBytes)
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
    // Calling finish() again with no new input keeps the same result.
    if (this._hashBytes !== null) return this
    this._hashBytes = this.digest()
    // Computed now: getHashBytes hands out this array, and the caller may change it.
    this._hashValue = bytesToHex(this._hashBytes).toUpperCase()
    // 重置状态以支持复用
    this._V.set(IV)
    this._pos = 0
    this._len = 0
    this._finished = false
    return this
  }

  /** @deprecated 使用 hexDigest() */
  getHashCode() {
    return this._hashValue === null ? undefined : this._hashValue
  }

  /** @deprecated 使用 digest() */
  getHashBytes() {
    return this._hashBytes === null ? undefined : this._hashBytes
  }

  // ---- 内部方法 ----

  /** 整块直接在输入上压缩，只把不足一块的部分放入缓冲区 */
  _absorb(data, offset, length) {
    if (this._len + length > MAX_TRACKED_BYTES) {
      throw new RangeError('SM3 input is too long')
    }
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
        compressBlocks(this._V, buf, 0, 1)
        pos = 0
      }
    }
    if (remaining >= 64) {
      // Plain division: lengths can exceed the 32-bit range of shift operators.
      const blocks = Math.floor(remaining / 64)
      compressBlocks(this._V, data, offset, blocks)
      const consumed = blocks * 64
      offset += consumed
      remaining -= consumed
    }
    for (let i = 0; i < remaining; i++) buf[pos + i] = data[offset + i]
    this._pos = pos + remaining
  }

  /**
   * Makes this instance continue from the state of `other`, which must have no
   * finished result. Used to hash many messages that share a prefix, such as the
   * KDF blocks, without hashing the prefix again.
   */
  _copyStateFrom(other) {
    this._V.set(other._V)
    this._buf.set(other._buf)
    this._pos = other._pos
    this._len = other._len
    this._finished = false
    this._hashBytes = null
    this._hashValue = null
    return this
  }

  /** New input starts a new message, so the previous result must not be readable. */
  _clearFinishResult() {
    this._hashBytes = null
    this._hashValue = null
  }

  /** Best-effort erasure when this instance held secret input. Ends its use. */
  _wipe() {
    this._buf.fill(0)
    this._V.fill(0)
    if (this._hashBytes !== null) this._hashBytes.fill(0)
    this._hashBytes = null
    this._hashValue = null
    this._finished = true
  }

  /** Keeps buffered input and hash state out of JSON and console output. */
  toJSON() {
    return '[SM3]'
  }

  [INSPECT]() {
    return '[SM3]'
  }

  _requireOpen() {
    if (this._finished) {
      throw new TypeError('SM3 cannot accept input after digest()')
    }
  }

  /** 消息填充 */
  _pad() {
    // 位长度是 64 位：分别计算高低 32 位，避免浮点精度损失
    const lengthHigh = Math.floor(this._len / 0x20000000)
    const lengthLow = ((this._len % 0x20000000) * 8) >>> 0

    // 追加 0x80
    this._buf[this._pos++] = 0x80
    // 如果剩余空间不够放 8 字节长度，先填满当前块
    if (this._pos > 56) {
      this._buf.fill(0, this._pos, 64)
      compressBlocks(this._V, this._buf, 0, 1)
      this._pos = 0
    }
    // 填充零
    this._buf.fill(0, this._pos, 56)
    this._pos = 56
    // 追加 64 位大端序消息长度（JS 安全整数范围内用两个 32 位写入）
    intToBytesBE(lengthHigh, this._buf, 56)
    intToBytesBE(lengthLow, this._buf, 60)
    compressBlocks(this._V, this._buf, 0, 1)
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
