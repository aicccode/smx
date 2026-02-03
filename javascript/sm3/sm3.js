class Sm3Impl {
  // 初始IV常量
  static IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]

  constructor() {
    this.buff512Bit = new Int8Array(64)
    this.buffPoint = 0
    this.dataLength = 0
    this.V = Sm3Impl.IV.slice()
  }

  /**
   * 输入单个字节
   *
   * @param {number} data
   * @return {Sm3Impl}
   */
  update(data) {
    this.buff512Bit[this.buffPoint++] = data
    this.dataLength += 8
    // 够一个块，立即处理
    if (this.buffPoint === 64) {
      // 迭代压缩
      this.processFullBuff(this.buff512Bit)
      this.buffPoint = 0
    }
    return this
  }
  /**
   * 输入字符串
   *
   * @param {String} text
   * @return {Sm3Impl}
   */

  updateString(text) {
    const code = encodeURIComponent(text)
    const bytes = []
    for (let i = 0; i < code.length; i++) {
      const c = code.charAt(i)
      if (c === '%') {
        const hex = code.charAt(i + 1) + code.charAt(i + 2)
        const hexVal = parseInt(hex, 16)
        bytes.push(hexVal)
        i += 2
      } else bytes.push(c.charCodeAt(0))
    }
    return this.updateBytes(bytes, 0, bytes.length)
  }

  /**
   * 输入字节数组
   *
   * @param {Int8Array} data
   * @param {number} inOffset
   * @param {number} length
   * @return {Sm3Impl}
   */
  updateBytes(data, inOffset, length) {
    for (let i = 0; i < length; i++) {
      this.buff512Bit[this.buffPoint++] = data[inOffset + i]
      this.dataLength += 8
      // 够一个块，立即处理
      if (this.buffPoint === 64) {
        // 迭代压缩
        this.processFullBuff(this.buff512Bit)
        this.buffPoint = 0
      }
    }
    return this
  }

  /**
   * 获取最终的杂凑值，获取之前必须先调用finish
   *
   * @return {string} 杂凑值 hexString
   */
  getHashCode() {
    return this.hashValue
  }

  /**
   * 获取最终的杂凑值，获取之前必须先调用finish
   *
   * @return {Int8Array} 杂凑值 byte数组
   */
  getHashBytes() {
    return this.hashBytes
  }

  /**
   * 结束输入，处理最终块
   *
   * @return {Sm3Impl}
   */
  finish() {
    // 最后一个块处理
    const end = this.buff512Bit.slice(0, this.buffPoint)
    const blockLen = end.length * 8
    // 1
    const one = this.limitToSignedByte(128)
    // 需填0长度
    const fillZeroLen = (512 - (blockLen + 65) % 512) - 7
    // 总长度Bit
    const allLen = fillZeroLen + blockLen + 65 + 7
    // 总长度Byte
    const allByteLen = allLen / 8
    //
    const buff = new Int8Array(allByteLen)
    // 填充数据
    for (let i = 0; i < allByteLen; i++) {
      if (i < end.length) {
        // 填充消息
        buff[i] = end[i]
      } else if (i === end.length) {
        // 填充1
        buff[i] = one
      } else if (i > allByteLen - 5) {
        // 最后四字节填充全部数据的总长度
        buff[i] = (this.dataLength >> ((allByteLen - i - 1) * 8)) & 0xFF
      } else {
        // 填充0
        buff[i] = 0
      }
    }
    // 当剩余缓存中内容大于等于448位时，这里会有两个块
    for (let i = 0; i < allLen / 512; i++) {
      const block = buff.slice(i * 512 / 8, (i + 1) * 512 / 8)
      // 迭代压缩
      this.processFullBuff(block)
    }
    // 记录杂凑值，重置本实例
    this.generatorHashString()
    this.reset()
    return this
  }
  limitToSignedByte(i) {
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
  generatorHashString() {
    this.hashBytes = new Int8Array(32)
    let off = 0
    for (const element of this.V) {
      this.hashBytes[off] = this.limitToSignedByte((element >>> 24) & 0xff)
      this.hashBytes[++off] = this.limitToSignedByte((element >>> 16) & 0xff)
      this.hashBytes[++off] = this.limitToSignedByte((element >>> 8) & 0xff)
      this.hashBytes[++off] = this.limitToSignedByte(element & 0xff)
      off++
    }
    // 转16进制大写串
    let result = ''
    for (const element of this.hashBytes) {
      result += (element & 0xff).toString(16).padStart(2, '0')
    }
    this.hashValue = result.toUpperCase()
  }

  reset() {
    this.V = Sm3Impl.IV.slice()
    this.buffPoint = 0
    this.dataLength = 0
  }

  processFullBuff(block) {
    // 消息扩展至132个字
    const w = new Array(68)
    let offset = 0
    // w0 ~ w15
    for (let j = 0; j < 16; j++) {
      w[j] = ((block[offset] & 0xff) << 24) | ((block[++offset] & 0xff) << 16) | ((block[++offset] & 0xff) << 8) | ((block[++offset] & 0xff))
      offset++
    }
    // w16 ~ w67
    for (let j = 16; j < 68; j++) {
      const wj3 = w[j - 3]
      const r15 = ((wj3 << 15) | (wj3 >>> (32 - 15)))
      const wj13 = w[j - 13]
      const r7 = ((wj13 << 7) | (wj13 >>> (32 - 7)))
      w[j] = this.P1(w[j - 16] ^ w[j - 9] ^ r15) ^ r7 ^ w[j - 6]
    }
    // w'0 ~ w'63
    const w2 = new Array(64)
    for (let j = 0; j < w2.length; j++) {
      w2[j] = w[j] ^ w[j + 4]
    }

    // 压缩函数
    let A = this.V[0]
    let B = this.V[1]
    let C = this.V[2]
    let D = this.V[3]
    let E = this.V[4]
    let F = this.V[5]
    let G = this.V[6]
    let H = this.V[7]
    for (let j = 0; j < 64; j++) {
      const A12 = ((A << 12) | (A >>> (32 - 12)))
      // 常量 Tj
      const T_j = j < 16 ? ((0x79CC4519 << j) | (0x79CC4519 >>> (32 - j))) : ((0x7A879D8A << (j % 32)) | (0x7A879D8A >>> (32 - (j % 32))))
      const S_S = A12 + E + T_j
      const SS1 = ((S_S << 7) | (S_S >>> (32 - 7)))
      const SS2 = SS1 ^ A12
      const TT1 = j < 16 ? ((A ^ B ^ C) + D + SS2 + w2[j]) : (this.FF1(A, B, C) + D + SS2 + w2[j])
      const TT2 = j < 16 ? ((E ^ F ^ G) + H + SS1 + w[j]) : (this.GG1(E, F, G) + H + SS1 + w[j])
      D = C
      C = ((B << 9) | (B >>> (32 - 9)))
      B = A
      A = TT1
      H = G
      G = ((F << 19) | (F >>> (32 - 19)))
      F = E
      E = this.P0(TT2)
    }
    this.V[0] ^= A
    this.V[1] ^= B
    this.V[2] ^= C
    this.V[3] ^= D
    this.V[4] ^= E
    this.V[5] ^= F
    this.V[6] ^= G
    this.V[7] ^= H
  }

  FF1(X, Y, Z) {
    return (X & Y) | (X & Z) | (Y & Z)
  }

  GG1(x, y, z) {
    return (x & y) | ((~x) & z)
  }

  P0(x) {
    const x9 = (x << 9) | (x >>> (32 - 9))
    const x17 = (x << 17) | (x >>> (32 - 17))
    return x ^ x9 ^ x17
  }

  P1(x) {
    const x15 = (x << 15) | (x >>> (32 - 15))
    const x23 = (x << 23) | (x >>> (32 - 23))
    return x ^ x15 ^ x23
  }
}

export const getSM3 = () => {
  return new Sm3Impl()
}
