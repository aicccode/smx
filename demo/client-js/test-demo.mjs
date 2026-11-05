/**
 * SM2 密钥交换Demo客户端 - JavaScript版
 * 作为A侧与Java服务端(B侧)进行密钥交换
 *
 * 这是演示代码。它使用明文 HTTP，网络上的攻击者可以读取和篡改所有消息；真实系统必须
 * 使用 TLS 和可信的公钥。它也不打印私钥和协商密钥：日志不是存放秘密的地方。
 */

import { getSM2 } from '../../javascript/sm2/sm2.js'
import { SM4 } from '../../javascript/sm4/sm4.js'
import * as util from '../../javascript/sm2/utils.js'

const SERVER_URL = 'http://localhost:8080'
const IDa = 'client@demo.aicc'
const KEY_LENGTH_BYTES = 16
const ZERO_IV = '00000000000000000000000000000000'
const REQUEST_TIMEOUT_MS = 10000
const MAX_RESPONSE_BYTES = 64 * 1024

/**
 * POST JSON and parse the reply. Replies are untrusted: their size is bounded, a
 * bad status or malformed JSON is an error, and only an object is accepted.
 */
async function postJson(path, body) {
  const res = await fetch(`${SERVER_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  })
  const text = await readBounded(res)
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`)
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error(`${path}: the reply is not valid JSON`)
  }
  if (parsed === null || typeof parsed !== 'object') {
    throw new Error(`${path}: the reply is not a JSON object`)
  }
  return parsed
}

async function readBounded(res) {
  const chunks = []
  let total = 0
  for await (const chunk of res.body) {
    total += chunk.length
    if (total > MAX_RESPONSE_BYTES) throw new Error('The reply is too large')
    chunks.push(chunk)
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.length
  }
  return new TextDecoder().decode(bytes)
}

/**
 * 主测试流程
 */
async function main() {
  console.log('=== SM2 Key Exchange Demo (JavaScript Client) ===\n')

  const sm2 = getSM2()

  // 生成A侧(客户端)证书密钥对和随机密钥对
  const certKeyPair = util.generateKeyPairHex()
  const randomKeyPair = util.generateKeyPairHex()
  console.log('Public key (pA):', certKeyPair.publicKey)
  console.log('Public key (Ra):', randomKeyPair.publicKey)

  // Step 1: 发起密钥交换
  console.log('\n--- Step 1: Key Exchange Init ---')
  const initRequest = {
    IDa: IDa,
    pA: certKeyPair.publicKey,
    Ra: randomKeyPair.publicKey,
    keyLen: KEY_LENGTH_BYTES,
  }
  console.log('Request:', JSON.stringify(initRequest, null, 2))
  const initResponse = await postJson('/api/keyswap/init', initRequest)
  console.log('Response:', JSON.stringify(initResponse, null, 2))

  // Step 2: 校验服务端的所有值和 Sb，然后计算 Sa 和 Ka
  console.log('\n--- Step 2: Calculate Sa and Ka ---')
  const { Sa, Ka } = sm2.getSa(
    KEY_LENGTH_BYTES,
    initResponse.pB,
    initResponse.Rb,
    certKeyPair.publicKey,
    randomKeyPair.publicKey,
    IDa,
    initResponse.IDb,
    certKeyPair.privateKey,
    randomKeyPair.privateKey,
    initResponse.Sb,
  )
  console.log('Sb verified. Sa:', Sa)

  // Step 3: 确认密钥交换
  console.log('\n--- Step 3: Key Exchange Confirm ---')
  const confirmRequest = {
    sessionId: initResponse.sessionId,
    Sa,
  }
  console.log('Request:', JSON.stringify(confirmRequest, null, 2))
  const confirmResponse = await postJson('/api/keyswap/confirm', confirmRequest)
  console.log('Response:', JSON.stringify(confirmResponse, null, 2))

  if (confirmResponse.success !== true) {
    throw new Error('Key exchange confirmation failed')
  }
  console.log('\nKey exchange completed successfully!')

  // Step 4: 双向加密通信测试
  console.log('\n--- Step 4: Bidirectional Crypto Test ---')

  // 固定全零 IV 只是为了与其他语言的 Demo 互通。真实系统必须为每条消息使用新的随机
  // IV，并认证密文：CBC 本身不提供完整性
  const sm4 = new SM4()
  sm4.setKey(Ka, ZERO_IV, true)

  // 客户端加密消息
  const clientPlaintext = 'Hello from JavaScript Client!'
  const clientCiphertext = sm4.encrypt(clientPlaintext)
  console.log('Client plaintext:', clientPlaintext)
  console.log('Client ciphertext:', clientCiphertext)

  // 发送给服务端
  const cryptoRequest = {
    sessionId: initResponse.sessionId,
    clientCiphertext,
    clientPlaintext,
  }
  console.log('\nRequest:', JSON.stringify(cryptoRequest, null, 2))
  const cryptoResponse = await postJson('/api/crypto/test', cryptoRequest)
  console.log('Response:', JSON.stringify(cryptoResponse, null, 2))

  // 验证服务端是否正确解密了客户端的消息
  const serverDecryptOk = cryptoResponse.clientDecryptMatch === true
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

  if (!serverDecryptOk || !clientDecryptOk) {
    throw new Error('Bidirectional Crypto test FAILED!')
  }
  console.log('\nBidirectional Crypto test PASSED!')
  console.log('\n=== Demo Complete ===')
}

main().catch((e) => {
  console.error('Demo failed:', e.message)
  process.exit(1)
})
