import { decodeHex, requireWellFormedString } from '../common/hex.js'
import { bytesToString, bytesToHex, stringToBytes } from '../common/utils.js'
import { sboxPlanes, sboxWord } from './sbox-circuit.js'

// ---- SM4 常量 ----

/** 系统参数 FK */
const FK = new Int32Array([0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc])

/** 固定密钥 CK */
const CK = new Int32Array([
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
  0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
  0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
  0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
  0x484f565d, 0x646b7279,
])

const BLOCK_BYTES = 16
const KEY_BYTES = 16
const LANES = 8
const LANE_BYTES = LANES * BLOCK_BYTES
const DECRYPT_ERROR = 'SM4 decryption failed'

// ---- 内部函数 ----

/** 32 位大端读取 */
function readWord(b, o) {
  return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]
}

function writeWord(out, o, x) {
  out[o] = x >>> 24
  out[o + 1] = x >>> 16
  out[o + 2] = x >>> 8
  out[o + 3] = x
}

/** 合成置换 T（加解密轮函数）：S 盒电路后接线性变换 L */
function roundT(a) {
  const b = sboxWord(a)
  return (
    b ^
    ((b << 2) | (b >>> 30)) ^
    ((b << 10) | (b >>> 22)) ^
    ((b << 18) | (b >>> 14)) ^
    ((b << 24) | (b >>> 8))
  )
}

/** 合成置换 T'（密钥扩展）：S 盒电路后接 L' */
function keyT(a) {
  const b = sboxWord(a)
  return b ^ ((b << 13) | (b >>> 19)) ^ ((b << 23) | (b >>> 9))
}

/**
 * 处理一个块。step 为 +1 时按 rk[0..31] 使用轮密钥（加密），为 -1 时反向（解密）。
 * 输入和输出可以是同一缓冲区。
 */
function processBlock(rk, first, step, x0, x1, x2, x3, out, outOff) {
  let k = first
  for (let round = 0; round < 8; round++) {
    x0 ^= roundT(x1 ^ x2 ^ x3 ^ rk[k])
    k += step
    x1 ^= roundT(x2 ^ x3 ^ x0 ^ rk[k])
    k += step
    x2 ^= roundT(x3 ^ x0 ^ x1 ^ rk[k])
    k += step
    x3 ^= roundT(x0 ^ x1 ^ x2 ^ rk[k])
    k += step
  }
  // 反序变换 R
  writeWord(out, outOff, x3)
  writeWord(out, outOff + 4, x2)
  writeWord(out, outOff + 8, x1)
  writeWord(out, outOff + 12, x0)
}

/** Swaps bit groups between two words of the buffer, for the 8x8 transpose. */
function transposeBits(w) {
  for (let shift = 4, mask = 0x0f0f0f0f; shift > 0;) {
    for (let i = 0; i < LANES; i = (i + shift + 1) & ~shift) {
      const j = i + shift
      const t = ((w[i] >>> shift) ^ w[j]) & mask
      w[j] ^= t
      w[i] ^= t << shift
    }
    shift >>>= 1
    mask = shift === 2 ? 0x33333333 : 0x55555555
  }
}

const laneState = [
  new Int32Array(LANES),
  new Int32Array(LANES),
  new Int32Array(LANES),
  new Int32Array(LANES),
]
const lanePlanes = new Int32Array(LANES)

/**
 * Decrypts eight blocks in parallel: the Boolean S-box evaluates 32 bytes at once
 * on bit planes, so one round costs about a quarter of eight separate rounds.
 */
function decryptEightBlocks(rk, input, inOff, out, outOff) {
  const [a, b, c, d] = laneState
  const p = lanePlanes
  for (let lane = 0; lane < LANES; lane++) {
    const o = inOff + lane * BLOCK_BYTES
    a[lane] = readWord(input, o)
    b[lane] = readWord(input, o + 4)
    c[lane] = readWord(input, o + 8)
    d[lane] = readWord(input, o + 12)
  }
  let k = 31
  for (let round = 0; round < 32; round++, k--) {
    const target = laneState[round & 3]
    const x1 = laneState[(round + 1) & 3]
    const x2 = laneState[(round + 2) & 3]
    const x3 = laneState[(round + 3) & 3]
    const key = rk[k]
    for (let i = 0; i < LANES; i++) p[i] = x1[i] ^ x2[i] ^ x3[i] ^ key
    transposeBits(p)
    sboxPlanes(p)
    transposeBits(p)
    for (let i = 0; i < LANES; i++) {
      const v = p[i]
      target[i] ^=
        v ^
        ((v << 2) | (v >>> 30)) ^
        ((v << 10) | (v >>> 22)) ^
        ((v << 18) | (v >>> 14)) ^
        ((v << 24) | (v >>> 8))
    }
  }
  for (let lane = 0; lane < LANES; lane++) {
    const o = outOff + lane * BLOCK_BYTES
    writeWord(out, o, d[lane])
    writeWord(out, o + 4, c[lane])
    writeWord(out, o + 8, b[lane])
    writeWord(out, o + 12, a[lane])
  }
  p.fill(0)
  for (const s of laneState) s.fill(0)
}

/**
 * SM4 对称加密算法（CBC 模式，PKCS7 填充）
 *
 * 用法：
 *   const sm4 = new SM4()
 *   sm4.setKey('16-byte-key-here', '16-byte-iv-value')
 *   const cipher = sm4.encrypt('plaintext')   // hex string
 *   const plain  = sm4.decrypt(cipher)         // string
 *
 * 安全说明：
 * - CBC 只提供机密性，不提供完整性。密文可被篡改，调用方必须另行认证（如
 *   encrypt-then-MAC）。如果未经认证的解密结果或错误对攻击者可见，还会形成填充
 *   预言机。
 * - 同一实例的每次 encrypt 都重用 setKey 给定的 IV，相同明文产生相同密文。CBC 要求
 *   每条消息使用新的不可预测 IV：请为每条消息调用 setKey。
 * - 字符串密钥必须恰好 16 字节，且应当是随机值；可读文本的熵很低。
 * - S 盒是布尔电路，没有依赖秘密的查表或分支。JavaScript 引擎不提供常数时间保证。
 */
export class SM4 {
  constructor() {
    this._rk = new Int32Array(32) // 轮密钥
    this._iv = new Uint8Array(BLOCK_BYTES) // 初始向量
    this._keyed = false
  }

  /**
   * 设置密钥和初始向量。两者都必须恰好 16 字节
   * @param {string} key  - 16 字节字符串（UTF-8），或 hex 为 true 时的 32 位十六进制
   * @param {string} iv   - 与 key 相同的格式
   * @param {boolean} [hex=false] - 是否为十六进制输入
   * @returns {SM4}
   * @throws {Error} 长度或格式不符
   */
  setKey(key, iv, hex) {
    const keyBytes = parseKeyMaterial(key, hex)
    const ivBytes = parseKeyMaterial(iv, hex)
    if (keyBytes === null || ivBytes === null) {
      if (keyBytes !== null) keyBytes.fill(0)
      throw new Error('SM4 key and IV must each be exactly 16 bytes')
    }
    this._expandKey(keyBytes)
    this._iv.set(ivBytes)
    keyBytes.fill(0)
    this._keyed = true
    return this
  }

  /**
   * CBC 加密。不提供完整性，见类注释
   * @param {string} text - 明文字符串
   * @returns {string} 密文 hex
   */
  encrypt(text) {
    this._requireKey()
    const input = pkcs7Pad(stringToBytes(text))
    const output = new Uint8Array(input.length)
    const rk = this._rk
    let iv0 = readWord(this._iv, 0)
    let iv1 = readWord(this._iv, 4)
    let iv2 = readWord(this._iv, 8)
    let iv3 = readWord(this._iv, 12)

    for (let off = 0; off < input.length; off += BLOCK_BYTES) {
      processBlock(
        rk,
        0,
        1,
        readWord(input, off) ^ iv0,
        readWord(input, off + 4) ^ iv1,
        readWord(input, off + 8) ^ iv2,
        readWord(input, off + 12) ^ iv3,
        output,
        off,
      )
      iv0 = readWord(output, off)
      iv1 = readWord(output, off + 4)
      iv2 = readWord(output, off + 8)
      iv3 = readWord(output, off + 12)
    }

    input.fill(0)
    return bytesToHex(output)
  }

  /**
   * CBC 解密。任何长度、格式或填充错误都抛出同一个错误。
   * CBC 不提供完整性，未经认证的密文解密成功并不代表其真实，见类注释
   * @param {string} cipherHex - 密文 hex
   * @returns {string} 明文字符串。非法 UTF-8 序列替换为 U+FFFD
   * @throws {Error} 解密失败
   */
  decrypt(cipherHex) {
    this._requireKey()
    const input = decodeHex(cipherHex)
    if (
      input === null ||
      input.length === 0 ||
      input.length % BLOCK_BYTES !== 0
    ) {
      throw new Error(DECRYPT_ERROR)
    }
    const output = new Uint8Array(input.length)
    const rk = this._rk
    const iv = this._iv

    let off = 0
    for (; off + LANE_BYTES <= input.length; off += LANE_BYTES) {
      decryptEightBlocks(rk, input, off, output, off)
    }
    for (; off < input.length; off += BLOCK_BYTES) {
      processBlock(
        rk,
        31,
        -1,
        readWord(input, off),
        readWord(input, off + 4),
        readWord(input, off + 8),
        readWord(input, off + 12),
        output,
        off,
      )
    }
    for (let i = 0; i < BLOCK_BYTES; i++) output[i] ^= iv[i]
    for (let i = BLOCK_BYTES; i < input.length; i++) {
      output[i] ^= input[i - BLOCK_BYTES]
    }

    const length = pkcs7UnpaddedLength(output)
    if (length < 0) {
      output.fill(0)
      throw new Error(DECRYPT_ERROR)
    }
    const text = bytesToString(output.subarray(0, length))
    output.fill(0)
    return text
  }

  // ---- 内部方法 ----

  _requireKey() {
    if (!this._keyed) throw new Error('SM4 key has not been set')
  }

  /** 密钥扩展 */
  _expandKey(key) {
    const rk = this._rk
    let k0 = readWord(key, 0) ^ FK[0]
    let k1 = readWord(key, 4) ^ FK[1]
    let k2 = readWord(key, 8) ^ FK[2]
    let k3 = readWord(key, 12) ^ FK[3]
    for (let i = 0; i < 32; i += 4) {
      k0 ^= keyT(k1 ^ k2 ^ k3 ^ CK[i])
      rk[i] = k0
      k1 ^= keyT(k2 ^ k3 ^ k0 ^ CK[i + 1])
      rk[i + 1] = k1
      k2 ^= keyT(k3 ^ k0 ^ k1 ^ CK[i + 2])
      rk[i + 2] = k2
      k3 ^= keyT(k0 ^ k1 ^ k2 ^ CK[i + 3])
      rk[i + 3] = k3
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
    this._requireKey()
    processBlock(
      this._rk,
      decrypt ? 31 : 0,
      decrypt ? -1 : 1,
      readWord(input, inOff),
      readWord(input, inOff + 4),
      readWord(input, inOff + 8),
      readWord(input, inOff + 12),
      output,
      outOff,
    )
  }
}

/** 16 字节字符串或 32 位十六进制 → 字节；其他输入返回 null，不做任何派生或截断 */
function parseKeyMaterial(value, hex) {
  if (typeof value !== 'string') return null
  if (hex) return value.length === 2 * KEY_BYTES ? decodeHex(value) : null
  requireWellFormedString(value)
  const bytes = stringToBytes(value)
  return bytes.length === KEY_BYTES ? bytes : null
}

// ---- PKCS7 填充 ----

function pkcs7Pad(data) {
  const padLen = BLOCK_BYTES - (data.length % BLOCK_BYTES)
  const out = new Uint8Array(data.length + padLen)
  out.set(data)
  out.fill(padLen, data.length)
  return out
}

/**
 * Plaintext length after removing the padding, or -1 if it is invalid. Always reads
 * the last 16 bytes and combines the result with masks, so it does not reveal how
 * much of the padding was correct. data.length is a nonzero multiple of 16.
 */
function pkcs7UnpaddedLength(data) {
  const n = data.length
  const pad = data[n - 1]
  // bad < 0 when pad is outside [1, 16]
  let bad = (pad - 1) | (BLOCK_BYTES - pad)
  for (let i = 1; i <= BLOCK_BYTES; i++) {
    const inPadding = (i - pad - 1) >> 31 // -1 when i <= pad
    const diff = data[n - i] ^ pad
    bad |= inPadding & -diff
  }
  return bad < 0 ? -1 : n - pad
}

/** @deprecated 使用 new SM4() */
export const getSM4 = () => new SM4()
