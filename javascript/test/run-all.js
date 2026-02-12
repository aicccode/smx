import { getSM3, SM3 } from '../sm3/sm3.js'
import { getSM4, SM4 } from '../sm4/sm4.js'
import { getSM2 } from '../sm2/sm2.js'

let passed = 0, failed = 0

function assertEqual(name, a, b) {
  if (a !== b) {
    console.error(`[FAIL] ${name}`)
    console.error(`  expected: ${b}`)
    console.error(`  got:      ${a}`)
    failed++
  } else {
    console.log(`[ OK ] ${name}`)
    passed++
  }
}

function assertTrue(name, val) {
  if (!val) {
    console.error(`[FAIL] ${name}: expected true, got ${val}`)
    failed++
  } else {
    console.log(`[ OK ] ${name}`)
    passed++
  }
}

// ---- SM3 tests ----
console.log('\n=== SM3 ===')
{
  // 旧 API
  const sm3 = getSM3()
  sm3.finish()
  assertEqual('SM3("") via getSM3', sm3.getHashCode(), '1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B')
}
{
  const sm3 = getSM3()
  sm3.updateString('abc').finish()
  assertEqual('SM3("abc") via getSM3', sm3.getHashCode(), '66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0')
}
{
  // 新 API
  assertEqual('SM3.hashHex("")', SM3.hashHex(''), '1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B')
  assertEqual('SM3.hashHex("abc")', SM3.hashHex('abc'), '66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0')
}

// ---- SM4 tests ----
console.log('\n=== SM4 ===')
{
  // 旧 API
  const sm4 = getSM4()
  sm4.setKey('this is the key', 'this is the iv', false)
  const msg = '国密SM4对称加密算法'
  const c = sm4.encrypt(msg)
  assertEqual('SM4 encrypt', c, '09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc')
  const p = sm4.decrypt(c)
  assertEqual('SM4 round-trip', p, msg)
}
{
  // 新 API
  const sm4 = new SM4()
  sm4.setKey('this is the key', 'this is the iv')
  const msg = '国密SM4对称加密算法'
  const c = sm4.encrypt(msg)
  assertEqual('SM4 new API encrypt', c, '09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc')
  assertEqual('SM4 new API decrypt', sm4.decrypt(c), msg)
}

// ---- SM2 tests ----
console.log('\n=== SM2 ===')
{
  const sm2 = getSM2()
  // 生成密钥对
  const keypair = sm2.getPoint()
  assertTrue('SM2 getPoint has privateKey', !!keypair.privateKey)
  assertTrue('SM2 getPoint has publicKey', !!keypair.publicKey)

  // 从私钥推导公钥
  const pubKey = sm2.getPublicKeyFromPrivateKey(keypair.privateKey)
  assertTrue('SM2 getPublicKeyFromPrivateKey starts with 04', pubKey.startsWith('04'))
  assertEqual('SM2 pubKey length', pubKey.length, 130)

  // 加密解密
  const msg = 'hello SM2!'
  const cipher = sm2.sm2Encrypt(msg, pubKey)
  const plain = sm2.sm2Decrypt(cipher, keypair.privateKey)
  assertEqual('SM2 encrypt/decrypt', plain, msg)

  // 签名验签
  const userId = '1234567812345678'
  const sign = sm2.sm2Sign(userId, keypair.privateKey, msg)
  assertTrue('SM2 sign contains h separator', sign.includes('h'))
  const verified = sm2.sm2VerifySign(userId, sign, msg, pubKey)
  assertTrue('SM2 verify', verified)
}

// ---- 结果 ----
console.log(`\n${passed} passed, ${failed} failed`)
if (failed > 0) process.exit(1)
console.log('All JavaScript SM2/SM3/SM4 tests passed.')
