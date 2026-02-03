import { getSM3 } from '../sm3/sm3.js'

/* eslint-disable no-use-before-define */
import { BigInteger } from './biginteger.js'
import * as util from './utils.js'

const ZERO = new BigInteger('0')
const ONE = new BigInteger('1')

const { G, curve, n, w } = util.generateEcparam()

class Sm2Impl {
// B侧计算，获得协商密钥Kb，验证结果Sb
  getSb(len, pA, Ra, IDa, IDb, dBh, pBh, rbh, Rbh) {
    const dB = new BigInteger(dBh, 16)
    const rb = new BigInteger(rbh, 16)
    const Rb = curve.decodePointHex(Rbh)
    const x2_ = this.calcX(w, Rb.getX().toBigInteger())
    const tb = this.calcT(n, rb, dB, x2_)
    if (!curve.decodePointHex(Ra).isValid()) {
      throw new Error('Ra is not valid')
    }
    const x1_ = this.calcX(w, curve.decodePointHex(Ra).getX().toBigInteger())
    const V = this.calcPoint(tb, x1_, curve.decodePointHex(pA), curve.decodePointHex(Ra))
    if (V.isInfinity()) {
      throw new Error('V is invalid point')
    }
    const Za = this.userSM3Z(pA, IDa)
    const Zb = this.userSM3Z(pBh, IDb)
    const Kb = this.KDF(len, V, Za, Zb)
    const Sb = this.createS(0x02, V, Za, Zb, curve.decodePointHex(Ra), Rb)
    return { 'Sb': util.bytes2hex(Sb), 'Rb': Rb, 'Kb': util.bytes2hex(Kb), 'V': V.x.toBigInteger().toRadix(16) + V.y.toBigInteger().toRadix(16), 'Za': util.bytes2hex(Za), 'Zb': util.bytes2hex(Zb) }
  }
  // B侧检查Sa
  checkSa(V, Za, Zb, Ra, Rb, Sa) {
    const S2 = this.createS(0x03, curve.decodePointHex('04' + V), util.hexToArray(Za), util.hexToArray(Zb), curve.decodePointHex(Ra), Rb)
    return Sa === util.bytes2hex(S2)
  }
  // byte tag, AbstractECPoint vu, byte[] Za, byte[] Zb, AbstractECPoint Ra, AbstractECPoint Rb
  createS(tag, vu, Za, Zb, Ra, Rb) {
    const sm3 = getSM3()
    const bXvu = this.bigIntegerTo32Bytes(vu.getX().toBigInteger())
    sm3.updateBytes(bXvu, 0, bXvu.length)
    sm3.updateBytes(Za, 0, Za.length)
    sm3.updateBytes(Zb, 0, Zb.length)
    const bRax = this.bigIntegerTo32Bytes(Ra.getX().toBigInteger())
    const bRay = this.bigIntegerTo32Bytes(Ra.getY().toBigInteger())
    const bRbx = this.bigIntegerTo32Bytes(Rb.getX().toBigInteger())
    const bRby = this.bigIntegerTo32Bytes(Rb.getY().toBigInteger())
    sm3.updateBytes(bRax, 0, bRax.length)
    sm3.updateBytes(bRay, 0, bRay.length)
    sm3.updateBytes(bRbx, 0, bRbx.length)
    sm3.updateBytes(bRby, 0, bRby.length)
    const h1 = sm3.finish().getHashBytes()
    const hash = getSM3()
    hash.update(tag)
    const bYvu = this.bigIntegerTo32Bytes(vu.getY().toBigInteger())
    hash.updateBytes(bYvu, 0, bYvu.length)
    hash.updateBytes(h1, 0, h1.length)
    return hash.finish().getHashBytes()
  }

  // int keylen, AbstractECPoint vu, byte[] Za, byte[] Zb
  KDF(keylen, vu, Za, Zb) {
    const result = new Array(keylen)
    let ct = 0x00000001
    for (let i = 0; i < Math.floor((keylen + 31) / 32); i++) {
      const sm3 = getSM3()
      const p2x = this.asUnsignedByteArray(32, vu.getX().toBigInteger())
      sm3.updateBytes(p2x, 0, p2x.length)
      const p2y = this.asUnsignedByteArray(32, vu.getY().toBigInteger())
      sm3.updateBytes(p2y, 0, p2y.length)
      sm3.updateBytes(Za, 0, Za.length)
      sm3.updateBytes(Zb, 0, Zb.length)
      const ctBytes = new Array(4)
      this.intToBigEndian(ct, ctBytes, 0)
      sm3.updateBytes(ctBytes, 0, 4)
      sm3.finish()
      // 最后一段
      const sm3Bytes = sm3.getHashBytes()
      if (i === (Math.floor((keylen + 31) / 32) - 1) && (keylen % 32) != 0) {
        for (let j = 0; j < (keylen % 32); j++) {
          result[32 * ct - 32 + j] = sm3Bytes[j]
        }
      } else {
        for (let j = 0; j < 32; j++) {
          result[32 * ct - 32 + j] = sm3Bytes[j]
        }
      }
      ct++
    }
    return result
  }

  calcX(w, x2) {
    const _2PowW = new BigInteger('2', 10).pow(w)
    return _2PowW.add(x2.and(_2PowW.subtract(ONE)))
  }

  calcT(n, rb, db, x2_) {
    return db.add(x2_.multiply(rb)).mod(n)
  }

  calcPoint(t, x, pA, rA) {
    return pA.add(rA.multiply(x)).multiply(t)
  }
  /**
 * 加密
 */
  sm2Encrypt(msg, publicKey) {
    msg = typeof msg === 'string' ? util.stringToBytes(msg) : Array.prototype.slice.call(msg)


    const keypair = util.generateKeyPairHex()
    // 随机数 k
    const k = new BigInteger(keypair.privateKey, 16)
    // 国密测试参数
    // const k = new BigInteger('4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F', 16)

    // c1 = k * G
    const c1 = keypair.publicKey
    // let c1 = G.multiply(k)

    publicKey = curve.decodePointHex(publicKey)
    // 先将公钥转成点
    // (x2, y2) = k * publicKey
    const p = publicKey.multiply(k)
    const x2 = this.asUnsignedByteArray(32, p.getX().toBigInteger())
    const y2 = this.asUnsignedByteArray(32, p.getY().toBigInteger())

    // c3 = hash(x2 || msg || y2)
    const sm3c3 = getSM3()
    const c3data = [].concat(x2, msg, y2)
    sm3c3.updateBytes(c3data, 0, c3data.length)
    sm3c3.finish()
    const c3 = sm3c3.getHashCode().toLowerCase()

    let ct = 1
    let offset = 0
    let t = [] // 256 位
    const z = [].concat(x2, y2)
    const nextT = () => {
    // (1) Hai = hash(z || ct)
    // (2) ct++
      const sm3Hv = getSM3()
      const hvData = [...z, this.limitToSignedByte(ct >> 24 & 0x00ff), this.limitToSignedByte(ct >> 16 & 0x00ff), this.limitToSignedByte(ct >> 8 & 0x00ff), this.limitToSignedByte(ct & 0x00ff)]
      sm3Hv.updateBytes(hvData, 0, hvData.length)
      sm3Hv.finish()
      t = sm3Hv.getHashBytes()
      ct++
      offset = 0
    }
    nextT() // 先生成 Ha1

    for (let i = 0, len = msg.length; i < len; i++) {
    // t = Ha1 || Ha2 || Ha3 || Ha4
      if (offset === t.length) nextT()

      // c2 = msg ^ t
      msg[i] ^= t[offset++] & 0xff
    }
    const c2 = util.arrayToHex(msg)

    return c1 + c3 + c2
  }

  /**
 * 解密
 */
  sm2Decrypt(encryptData, privateKey) {
    privateKey = new BigInteger(privateKey, 16)

    const c3 = encryptData.substr(130, 64)
    const c2 = encryptData.substr(130 + 64)

    const msg = util.hexToArray(c2)
    const c1 = curve.decodePointHex(encryptData.substr(0, 130))
    curve.validatePoint(c1.getX(), c1.getY())

    const p = c1.multiply(privateKey)
    const x2 = this.asUnsignedByteArray(32, p.getX().toBigInteger())
    const y2 = this.asUnsignedByteArray(32, p.getY().toBigInteger())

    let ct = 1
    let offset = 0
    let t = [] // 256 位
    const z = [].concat(x2, y2)
    const nextT = () => {
    // (1) Hai = hash(z || ct)
    // (2) ct++
      const sm3Hv = getSM3()
      const hvdata = [...z, this.limitToSignedByte(ct >> 24 & 0x00ff), this.limitToSignedByte(ct >> 16 & 0x00ff), this.limitToSignedByte(ct >> 8 & 0x00ff), this.limitToSignedByte(ct & 0x00ff)]
      sm3Hv.updateBytes(hvdata, 0, hvdata.length)
      sm3Hv.finish()
      t = sm3Hv.getHashBytes()
      ct++
      offset = 0
    }
    nextT() // 先生成 Ha1

    for (let i = 0, len = msg.length; i < len; i++) {
    // t = Ha1 || Ha2 || Ha3 || Ha4
      if (offset === t.length) nextT()

      // c2 = msg ^ t
      msg[i] ^= t[offset++] & 0xff
    }

    // c3 = hash(x2 || msg || y2)

    const sm3c3 = getSM3()
    const c3data = [].concat(x2, msg, y2)
    sm3c3.updateBytes(c3data, 0, c3data.length)
    sm3c3.finish()
    const checkC3 = sm3c3.getHashCode().toLowerCase()
    // 验证v与c3相等
    if (checkC3 === c3.toLowerCase()) {
      return util.bytesToUTF8String(msg)
    } else {
      return ''
    }
  }


  /**
 * 签名
 */
  sm2Sign(userId, privatekey, msg,) {
    const intPrivateKey = new BigInteger(privatekey, 16)
    const pA = G.multiply(intPrivateKey)
    const zA = this.userSM3Z(util.leftPad(pA.getX().toBigInteger().toString(16), 64) + util.leftPad(pA.getY().toBigInteger().toString(16), 64), userId)
    const sm3 = getSM3()
    sm3.updateBytes(zA, 0, zA.length)
    const sourceData = util.stringToBytes(msg)
    sm3.updateBytes(sourceData, 0, sourceData.length)
    sm3.finish()
    const e = new BigInteger(sm3.getHashCode(), 16)
    // 计算签名
    let k = null
    let kp = null
    let r = null
    let s = null
    do {
    // 生成随机数k
      do {
      // 国密测试参数
        // k = new BigInteger('6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F', 16)
        // kp = curve.decodePointHex('04' + '110FCDA57615705D5E7B9324AC4B856D23E6D9188B2AE47759514657CE25D112' + '1C65D68A4A08601DF24B431E0CAB4EBE084772B3817E85811A8510B2DF7ECA1A')

        const keypair = util.generateKeyPairHex()
        k = new BigInteger(keypair.privateKey, 16)
        kp = curve.decodePointHex(keypair.publicKey)

        r = e.add(kp.getX().toBigInteger())
        r = r.mod(n)
      } while (r.equals(ZERO) || r.add(k).equals(n) || r.toRadix(16).length != 64 || kp.getX().toBigInteger().toRadix(16).length != 64 || kp.getY().toBigInteger().toRadix(16).length != 64)
      // 计算s
      let da1 = intPrivateKey.add(ONE)
      da1 = da1.modInverse(n)
      s = r.multiply(intPrivateKey)
      s = k.subtract(s).mod(n)
      s = da1.multiply(s).mod(n)
    } while (s.equals(ZERO) || (s.toRadix(16).length != 64))
    return (r.toRadix(16) + 'h' + s.toRadix(16))
  }

  /**
 * 验签
 */
  sm2VerifySign(userId, signData, message, publicKey) {
    const sm3 = getSM3()
    const z = this.userSM3Z(publicKey, userId)
    const sourceData = util.stringToBytes(message)
    sm3.updateBytes(z, 0, z.length)
    sm3.updateBytes(sourceData, 0, sourceData.length)
    sm3.finish()
    const sr = signData.split('h')[0]
    const ss = signData.split('h')[1]
    const r = new BigInteger(sr, 16)
    const s = new BigInteger(ss, 16)
    const e = new BigInteger(sm3.getHashCode(), 16)
    const t = r.add(s).mod(n)
    let R = null
    if (!t.equals(ZERO)) {
      let x1y1 = G.multiply(s)
      let userKey
      if (publicKey.length === 128) {
        userKey = G.curve.decodePointHex('04' + publicKey)
      } else {
        userKey = G.curve.decodePointHex(publicKey)
      }
      x1y1 = x1y1.add(userKey.multiply(t))
      R = e.add(x1y1.getX().toBigInteger()).mod(n)
    }
    return r.equals(R)
  }
  userSM3Z(publicKey, userId = '1234567812345678') {
  // z = hash(entl || userId || a || b || gx || gy || px || py)
    userId = util.stringToBytes(userId)
    const a = this.bigIntegerTo32Bytes(curve.a.toBigInteger())
    const b = this.bigIntegerTo32Bytes(curve.b.toBigInteger())
    const gx = this.bigIntegerTo32Bytes(G.getX().toBigInteger())
    const gy = this.bigIntegerTo32Bytes(G.getY().toBigInteger())
    let px
    let py
    if (publicKey.length === 128) {
      const point = G.curve.decodePointHex('04' + publicKey)
      px = this.bigIntegerTo32Bytes(point.getX().toBigInteger())
      py = this.bigIntegerTo32Bytes(point.getY().toBigInteger())
    } else {
      const point = G.curve.decodePointHex(publicKey)
      px = this.bigIntegerTo32Bytes(point.getX().toBigInteger())
      py = this.bigIntegerTo32Bytes(point.getY().toBigInteger())
    }
    const entl = userId.length * 8
    const sm3Z = getSM3()
    sm3Z.update(this.limitToSignedByte(entl >> 8 & 0x00ff))
    sm3Z.update(this.limitToSignedByte(entl & 0x00ff))
    sm3Z.updateBytes(userId, 0, userId.length)
    sm3Z.updateBytes(a, 0, a.length)
    sm3Z.updateBytes(b, 0, b.length)
    sm3Z.updateBytes(gx, 0, gx.length)
    sm3Z.updateBytes(gy, 0, gy.length)
    sm3Z.updateBytes(px, 0, px.length)
    sm3Z.updateBytes(py, 0, py.length)

    sm3Z.finish()
    return sm3Z.getHashBytes()
  }

  /**
 * 计算公钥
 */
  getPublicKeyFromPrivateKey(privateKey) {
    const PA = G.multiply(new BigInteger(privateKey, 16))
    const x = util.leftPad(PA.getX().toBigInteger().toString(16), 64)
    const y = util.leftPad(PA.getY().toBigInteger().toString(16), 64)
    return '04' + x + y
  }

  intToBigEndian(n, bs, off) {
    bs[off] = this.limitToSignedByte(n >>> 24)
    bs[++off] = this.limitToSignedByte(n >>> 16)
    bs[++off] = this.limitToSignedByte(n >>> 8)
    bs[++off] = this.limitToSignedByte(n)
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

  /**
 * 获取椭圆曲线点
 */
  getPoint() {
    const keypair = util.generateKeyPairHex()
    const PA = curve.decodePointHex(keypair.publicKey)

    keypair.k = new BigInteger(keypair.privateKey, 16)
    keypair.x1 = PA.getX().toBigInteger()

    return keypair
  }

  asUnsignedByteArray(length, value) {
    const bytes = value.toByteArray()
    if (bytes.length === length) {
      return bytes
    }
    const start = bytes[0] == 0 ? 1 : 0
    const count = bytes.length - start
    if (count > length) {
      throw new Error('长度length无法表示value!')
    }
    const tmp = new Array(length)
    for (let i = 0; i < tmp.length; i++) {
      if (i >= tmp.length - count) {
        tmp[i] = bytes[start + i - (tmp.length - count)]
      } else {
        tmp[i] = 0
      }
    }
    return tmp
  }

  fromUnsignedByteArray(buf, off, length) {
    let mag = buf
    if (off != 0 || length != buf.length) {
      mag = new Array(length)
      for (let i = 0; i < length; i++) {
        if (i >= buf.length - off) {
          mag[i] = buf[i - (buf.length - off)]
        } else {
          mag[i] = 0
        }
      }
    }
    return new BigInteger(util.bytes2hex(mag), 16)
  }

  bigIntegerTo32Bytes(n) {
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
    return tmpd
  }
}

export const getSM2 = () => {
  return new Sm2Impl()
}
