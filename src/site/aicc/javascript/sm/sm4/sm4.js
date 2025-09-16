import { getSM3 } from '../sm3/sm3'

class Sm4Impl {
  constructor() {
    // S 盒
    this.STable = [
      0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
      0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
      0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
      0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
      0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
      0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
      0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
      0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
      0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
      0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
      0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
      0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
      0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
      0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
      0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
      0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ]

    this.FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

    this.CK = [
      0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
      0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
      0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
      0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
      0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
      0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
      0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
      0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]


    this.rk = new Array(32)
    this.iv = new Array(16)
  }

  Sbox(input) {
    const output = this.STable[input & 0xFF]
    return output
  }

  setKey(key, iv, hex) {
    if (hex) {
      this.setKeyBytes(hex2Bytes(key), hex2Bytes(iv))
    } else {
      this.setKeyString(key, iv)
    }
    return this
  }

  setKeyBytes(keyBytes, ivBytes) {
    this.initKey(keyBytes, ivBytes)
  }

  setKeyString(keyString, ivString) {
    let key = stringToBytes(keyString)
    const sm3 = getSM3()
    if (key.length !== 16) {
      key = new Array(16)
      const hashKey = sm3.updateString(keyString).finish().getHashCode()
      const sm3Bytes = stringToBytes(hashKey)
      for (let i = 0; i < sm3Bytes.length; i++) {
        key[i] = sm3Bytes[i]
      }
    }

    let iv = stringToBytes(ivString)
    if (iv.length !== 16) {
      iv = new Array(16)
      const hashIv = sm3.updateString(ivString).finish().getHashCode()
      const sm3Bytes = stringToBytes(hashIv)
      for (let i = 0; i < sm3Bytes.length; i++) {
        iv[i] = sm3Bytes[i]
      }
    }
    this.initKey(key, iv)
  }

  initKey(key, iv) {
    const MK = new Array(4)
    let offset = 0
    for (let i = 0; i < key.length / 4; i++) {
      MK[i] = (((key[offset] & 0xff) << 24) | ((key[++offset] & 0xff) << 16) | ((key[++offset] & 0xff) << 8) | (key[++offset] & 0xff))
      offset++
    }

    const K = new Array(36)
    K[0] = MK[0] ^ this.FK[0]
    K[1] = MK[1] ^ this.FK[1]
    K[2] = MK[2] ^ this.FK[2]
    K[3] = MK[3] ^ this.FK[3]
    for (let i = 0; i < 32; i++) {
      K[i + 4] = (K[i] ^ this.T_(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ this.CK[i]))
      this.rk[i] = K[i + 4]
    }
    this.iv = iv.slice(0, 16)
  }

  /**
     * 加密方法
     * @param text
     * @return
     */
  encrypt(text) {
    return this.doCrypt(stringToBytes(text), this.iv.slice(), true)
  }
  /**
     * 解密方法
     * @param text
     * @return
     */
  decrypt(text) {
    // 解密
    return this.doCrypt(hex2Bytes(text), this.iv.slice(), false)
  }

  doCrypt(input, cbcIV, encrypt) {
    if (encrypt) {
      input = this.fixInput(input)
    }
    const out = []
    let offset = 0
    for (let j = 0; j < input.length / 16; j++) {
      const X = new Array(36)
      const nextiv = input.slice(offset, offset + 16)
      for (let i = 0; i < 4; i++) {
        if (encrypt) {
          X[i] = ((((input[offset] ^ cbcIV[offset % 16]) & 0xff) << 24) | (((input[++offset] ^ cbcIV[offset % 16]) & 0xff) << 16) | (((input[++offset] ^ cbcIV[offset % 16]) & 0xff) << 8) |
                      (((input[++offset] ^ cbcIV[offset % 16]) & 0xff)))
        } else {
          X[i] = (((input[offset] & 0xff) << 24) | ((input[++offset] & 0xff) << 16) | ((input[++offset] & 0xff) << 8) | ((input[++offset] & 0xff)))
        }

        offset++
      }
      for (let i = 0; i < 32; i++) {
        X[i + 4] = this.F(X[i], X[i + 1], X[i + 2], X[i + 3], encrypt ? this.rk[i] : this.rk[31 - i])
      }
      const XO = X.slice(32, 36)
      const XRO = this.R(XO)
      const XBO = []
      let index = 0
      for (let i = 0; i < 4; i++) {
        XBO[index] = limitToSignedByte((XRO[i] >>> 24) & 0xff)
        XBO[++index] = limitToSignedByte((XRO[i] >>> 16) & 0xff)
        XBO[++index] = limitToSignedByte((XRO[i] >>> 8) & 0xff)
        XBO[++index] = limitToSignedByte(XRO[i] & 0xff)
        index++
      }
      if (encrypt) {
        cbcIV = XBO.slice(0, 16)
      } else {
        for (let i = 0; i < XBO.length; i++) {
          XBO[i] ^= cbcIV[i]
        }
        cbcIV = nextiv.slice(0, 16)
      }
      out.push(...XBO)
    }
    if (encrypt) {
      return bytes2Hex(out, false)
    } else {
      const bs = out
      return bytesToUTF8String(bs.slice(0, bs.length - bs[bs.length - 1]))
    }
  }

  F(x0, x1, x2, x3, rk) {
    return x0 ^ this.T(x1 ^ x2 ^ x3 ^ rk)
  }

  T(a) {
    const abs = int2Bytes(a)
    for (let i = 0; i < abs.length; i++) {
      abs[i] = this.Sbox(abs[i])
    }
    const b = bytes2Int(abs)
    return b ^ ((b << 2) | (b >>> (32 - 2))) ^ ((b << 10) | (b >>> (32 - 10))) ^ ((b << 18) | (b >>> (32 - 18))) ^ ((b << 24) | (b >>> (32 - 24)))
  }

  T_(a) {
    const abs = int2Bytes(a)
    for (let i = 0; i < abs.length; i++) {
      abs[i] = this.Sbox(abs[i])
    }
    const b = bytes2Int(abs)
    return b ^ ((b << 13) | (b >>> (32 - 13))) ^ ((b << 23) | (b >>> (32 - 23)))
  }

  R(A) {
    A[0] = A[0] ^ A[3]
    A[3] = A[0] ^ A[3]
    A[0] = A[0] ^ A[3]
    A[1] = A[1] ^ A[2]
    A[2] = A[1] ^ A[2]
    A[1] = A[1] ^ A[2]
    return A
  }

  fixInput(input) {
    const t = 16 - input.length % 16
    const out = new Array(t)
    for (let i = 0; i < t; i++) {
      out[i] = t
    }
    return input.concat(out)
  }
}

function bytesToUTF8String(bytes) {
  const uint8Array = new Uint8Array(bytes.length)
  for (let i = 0; i < bytes.length; i++) {
    uint8Array[i] = bytes[i] < 0 ? bytes[i] + 256 : bytes[i]
  }
  bytes = uint8Array
  const decoder = new TextDecoder('utf-8')
  return decoder.decode(bytes)
}

function stringToBytes(text) {
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
  return bytes
}

const HEX_ARRAY = '0123456789ABCDEF'.split('')

function bytes2Hex(bytes, upperCase) {
  const hexChars = []
  for (let j = 0; j < bytes.length; j++) {
    const v = bytes[j] & 0xFF
    hexChars[j * 2] = HEX_ARRAY[v >>> 4]
    hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F]
  }
  return upperCase ? hexChars.join('').toUpperCase() : hexChars.join('').toLowerCase()
}

function hex2Bytes(hex) {
  const chars = hex.split('')
  const bs = new Array(chars.length / 2)
  let point = 0
  for (let i = 0; i < hex.length; i++) {
    bs[point++] = limitToSignedByte(parseInt(chars[i++] + chars[i], 16) & 0xFF)
  }
  return bs
}

function bytes2Int(b) {
  const n = (b[0] & 0xff) << 24 | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff)
  return n
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

function int2Bytes(n) {
  const b = new Array(4)
  b[0] = (0xFF & n >> 24)
  b[1] = (0xFF & n >> 16)
  b[2] = (0xFF & n >> 8)
  b[3] = (0xFF & n)
  return b
}
export const getSM4 = () => {
  return new Sm4Impl()
}
