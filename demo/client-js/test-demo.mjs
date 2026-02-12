/**
 * SM2 密钥交换Demo客户端 - JavaScript版
 * 作为A侧与Java服务端(B侧)进行密钥交换
 */

import { SM3 } from '../../javascript/sm3/sm3.js'
import { SM4 } from '../../javascript/sm4/sm4.js'
import { BigInteger } from '../../javascript/sm2/biginteger.js'
import * as util from '../../javascript/sm2/utils.js'

const SERVER_URL = 'http://localhost:8080'
const IDa = 'client@demo.aicc'

// 椭圆曲线参数
const { G, curve, n, w } = util.generateEcparam()
const ONE = new BigInteger('1')

/**
 * 将BigInteger转为32字节数组
 */
function bigIntegerTo32Bytes(n) {
  const bytes = n.toByteArray()
  if (bytes.length === 33) return bytes.slice(1)
  if (bytes.length === 32) return bytes
  const result = new Array(32).fill(0)
  for (let i = 0; i < bytes.length; i++) {
    result[32 - bytes.length + i] = bytes[i]
  }
  return result
}

/**
 * 将BigInteger转为无符号字节数组
 */
function asUnsignedByteArray(length, value) {
  const bytes = value.toByteArray()
  const start = bytes[0] === 0 ? 1 : 0
  const count = bytes.length - start
  if (count > length) throw new Error('length cannot represent value')
  const tmp = new Array(length).fill(0)
  for (let i = 0; i < count; i++) {
    tmp[length - count + i] = bytes[start + i]
  }
  return tmp
}

/**
 * int转大端字节数组
 */
function intToBigEndian(n, bs, off) {
  bs[off] = (n >>> 24) & 0xff
  bs[off + 1] = (n >>> 16) & 0xff
  bs[off + 2] = (n >>> 8) & 0xff
  bs[off + 3] = n & 0xff
}

/**
 * 计算用户身份标识值Z
 */
function userSM3Z(publicKey, userId) {
  const sm3 = new SM3()
  const userIdBytes = new TextEncoder().encode(userId)
  const entla = userIdBytes.length * 8
  sm3.update((entla >> 8) & 0xff)
  sm3.update(entla & 0xff)
  sm3.updateBytes(Array.from(userIdBytes), 0, userIdBytes.length)

  // 曲线参数 a, b
  const a = new BigInteger(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    16,
  )
  const b = new BigInteger(
    '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
    16,
  )
  const aBytes = asUnsignedByteArray(32, a)
  const bBytes = asUnsignedByteArray(32, b)
  sm3.updateBytes(aBytes, 0, 32)
  sm3.updateBytes(bBytes, 0, 32)

  // 基点G坐标
  const gxBytes = asUnsignedByteArray(32, G.getX().toBigInteger())
  const gyBytes = asUnsignedByteArray(32, G.getY().toBigInteger())
  sm3.updateBytes(gxBytes, 0, 32)
  sm3.updateBytes(gyBytes, 0, 32)

  // 公钥坐标
  const point = curve.decodePointHex(publicKey)
  const xBytes = asUnsignedByteArray(32, point.getX().toBigInteger())
  const yBytes = asUnsignedByteArray(32, point.getY().toBigInteger())
  sm3.updateBytes(xBytes, 0, 32)
  sm3.updateBytes(yBytes, 0, 32)

  return Array.from(sm3.digest())
}

/**
 * 计算x_的值
 */
function calcX(w, x) {
  const _2PowW = new BigInteger('2', 10).pow(w)
  return _2PowW.add(x.and(_2PowW.subtract(ONE)))
}

/**
 * 计算t值
 */
function calcT(n, r, d, x_) {
  return d.add(x_.multiply(r)).mod(n)
}

/**
 * KDF密钥派生函数
 */
function KDF(keylen, vu, Za, Zb) {
  const result = new Array(keylen)
  let ct = 0x00000001
  for (let i = 0; i < Math.floor((keylen + 31) / 32); i++) {
    const sm3 = new SM3()
    const p2x = asUnsignedByteArray(32, vu.getX().toBigInteger())
    sm3.updateBytes(p2x, 0, p2x.length)
    const p2y = asUnsignedByteArray(32, vu.getY().toBigInteger())
    sm3.updateBytes(p2y, 0, p2y.length)
    sm3.updateBytes(Za, 0, Za.length)
    sm3.updateBytes(Zb, 0, Zb.length)
    const ctBytes = new Array(4)
    intToBigEndian(ct, ctBytes, 0)
    sm3.updateBytes(ctBytes, 0, 4)
    const sm3Bytes = Array.from(sm3.digest())
    if (i === Math.floor((keylen + 31) / 32) - 1 && keylen % 32 !== 0) {
      for (let j = 0; j < keylen % 32; j++) {
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

/**
 * 创建验证值S
 */
function createS(tag, vu, Za, Zb, Ra, Rb) {
  const sm3 = new SM3()
  const bXvu = bigIntegerTo32Bytes(vu.getX().toBigInteger())
  sm3.updateBytes(bXvu, 0, bXvu.length)
  sm3.updateBytes(Za, 0, Za.length)
  sm3.updateBytes(Zb, 0, Zb.length)
  const bRax = bigIntegerTo32Bytes(Ra.getX().toBigInteger())
  const bRay = bigIntegerTo32Bytes(Ra.getY().toBigInteger())
  const bRbx = bigIntegerTo32Bytes(Rb.getX().toBigInteger())
  const bRby = bigIntegerTo32Bytes(Rb.getY().toBigInteger())
  sm3.updateBytes(bRax, 0, bRax.length)
  sm3.updateBytes(bRay, 0, bRay.length)
  sm3.updateBytes(bRbx, 0, bRbx.length)
  sm3.updateBytes(bRby, 0, bRby.length)
  const h1 = Array.from(sm3.digest())

  const hash = new SM3()
  hash.update(tag)
  const bYvu = bigIntegerTo32Bytes(vu.getY().toBigInteger())
  hash.updateBytes(bYvu, 0, bYvu.length)
  hash.updateBytes(h1, 0, h1.length)
  return Array.from(hash.digest())
}

/**
 * A侧计算getSa - 验证Sb并计算Sa和Ka
 */
function getSa(len, pB, Rb, pA, dA, Ra, ra, IDa, IDb, Sb) {
  try {
    const dABig = new BigInteger(dA, 16)
    const raBig = new BigInteger(ra, 16)
    const RaPoint = curve.decodePointHex(Ra)
    const RbPoint = curve.decodePointHex(Rb)
    const pBPoint = curve.decodePointHex(pB)

    const x1_ = calcX(w, RaPoint.getX().toBigInteger())
    const tA = calcT(n, raBig, dABig, x1_)
    const x2_ = calcX(w, RbPoint.getX().toBigInteger())
    const U = pBPoint.add(RbPoint.multiply(x2_)).multiply(tA)

    if (U.isInfinity()) {
      return { success: false, message: 'U is invalid point' }
    }

    const Za = userSM3Z(pA, IDa)
    const Zb = userSM3Z(pB, IDb)
    const Ka = KDF(len, U, Za, Zb)
    const S1 = createS(0x02, U, Za, Zb, RaPoint, RbPoint)
    const SbBytes = Array.from(util.hexToBytes(Sb))

    let sbMatch = true
    for (let i = 0; i < S1.length; i++) {
      if (S1[i] !== SbBytes[i]) {
        sbMatch = false
        break
      }
    }

    if (!sbMatch) {
      return { success: false, message: 'Sb verification failed' }
    }

    const Sa = createS(0x03, U, Za, Zb, RaPoint, RbPoint)

    return {
      success: true,
      Sa: util.bytes2hex(Sa),
      Ka: util.bytes2hex(Ka),
    }
  } catch (e) {
    return { success: false, message: e.message }
  }
}

/**
 * 主测试流程
 */
async function main() {
  console.log('=== SM2 Key Exchange Demo (JavaScript Client) ===\n')

  // 生成A侧(客户端)证书密钥对
  const certKeyPair = util.generateKeyPairHex()
  console.log('Generated A certificate keypair:')
  console.log('  Private key (dA):', certKeyPair.privateKey)
  console.log('  Public key (pA):', certKeyPair.publicKey)

  // 生成A侧随机密钥对
  const randomKeyPair = util.generateKeyPairHex()
  console.log('\nGenerated A random keypair:')
  console.log('  Private key (ra):', randomKeyPair.privateKey)
  console.log('  Public key (Ra):', randomKeyPair.publicKey)

  const keyLen = 16

  // Step 1: 发起密钥交换
  console.log('\n--- Step 1: Key Exchange Init ---')
  const initRequest = {
    IDa: IDa,
    pA: certKeyPair.publicKey,
    Ra: randomKeyPair.publicKey,
    keyLen: keyLen,
  }
  console.log('Request:', JSON.stringify(initRequest, null, 2))

  let initResponse
  try {
    const res = await fetch(`${SERVER_URL}/api/keyswap/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(initRequest),
    })
    initResponse = await res.json()
    console.log('Response:', JSON.stringify(initResponse, null, 2))
  } catch (e) {
    console.error('Failed to connect to server:', e.message)
    console.error('Make sure the Java server is running on port 8080')
    process.exit(1)
  }

  // Step 2: 计算Sa和Ka
  console.log('\n--- Step 2: Calculate Sa and Ka ---')
  const result = getSa(
    keyLen,
    initResponse.pB,
    initResponse.Rb,
    certKeyPair.publicKey,
    certKeyPair.privateKey,
    randomKeyPair.publicKey,
    randomKeyPair.privateKey,
    IDa,
    initResponse.IDb,
    initResponse.Sb,
  )

  if (!result.success) {
    console.error('getSa failed:', result.message)
    process.exit(1)
  }

  console.log('Sa:', result.Sa)
  console.log('Ka (negotiated key):', result.Ka)

  // Step 3: 确认密钥交换
  console.log('\n--- Step 3: Key Exchange Confirm ---')
  const confirmRequest = {
    sessionId: initResponse.sessionId,
    Sa: result.Sa,
  }
  console.log('Request:', JSON.stringify(confirmRequest, null, 2))

  const confirmRes = await fetch(`${SERVER_URL}/api/keyswap/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(confirmRequest),
  })
  const confirmResponse = await confirmRes.json()
  console.log('Response:', JSON.stringify(confirmResponse, null, 2))

  if (!confirmResponse.success) {
    console.error('Key exchange confirmation failed')
    process.exit(1)
  }

  console.log('\nKey exchange completed successfully!')
  console.log('Negotiated key (Ka):', result.Ka)

  // Step 4: 双向加密通信测试
  console.log('\n--- Step 4: Bidirectional Crypto Test ---')

  // 初始化SM4
  const iv = '00000000000000000000000000000000'
  const sm4 = new SM4()
  sm4.setKey(result.Ka, iv, true)

  // 客户端加密消息
  const clientPlaintext = 'Hello from JavaScript Client!'
  const clientCiphertext = sm4.encrypt(clientPlaintext)
  console.log('Client plaintext:', clientPlaintext)
  console.log('Client ciphertext:', clientCiphertext)

  // 发送给服务端
  const cryptoRequest = {
    sessionId: initResponse.sessionId,
    clientCiphertext: clientCiphertext,
    clientPlaintext: clientPlaintext,
  }
  console.log('\nRequest:', JSON.stringify(cryptoRequest, null, 2))

  const cryptoRes = await fetch(`${SERVER_URL}/api/crypto/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cryptoRequest),
  })
  const cryptoResponse = await cryptoRes.json()
  console.log('Response:', JSON.stringify(cryptoResponse, null, 2))

  // 验证服务端是否正确解密了客户端的消息
  const serverDecryptOk = cryptoResponse.clientDecryptMatch
  console.log(
    '\n[Server decrypted client message]:',
    serverDecryptOk ? 'PASS' : 'FAIL',
  )

  // 客户端解密服务端的消息
  const serverDecrypted = sm4.decrypt(cryptoResponse.serverCiphertext)
  const clientDecryptOk = serverDecrypted === cryptoResponse.serverPlaintext
  console.log(
    '[Client decrypted server message]:',
    clientDecryptOk ? 'PASS' : 'FAIL',
  )
  console.log('  Server plaintext:', cryptoResponse.serverPlaintext)
  console.log('  Client decrypted:', serverDecrypted)

  if (serverDecryptOk && clientDecryptOk) {
    console.log('\nBidirectional Crypto test PASSED!')
  } else {
    console.error('\nBidirectional Crypto test FAILED!')
  }

  console.log('\n=== Demo Complete ===')
}

main().catch(console.error)
