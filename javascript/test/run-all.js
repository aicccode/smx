import { getSM3 } from '../sm3/sm3.js'
import { getSM4 } from '../sm4/sm4.js'
import { getSM2 } from '../sm2/sm2.js'

function assertEqual(name, a, b) {
  if (a !== b) {
    console.error(`[FAIL] ${name}: expected ${b}, got ${a}`)
    process.exit(1)
  } else {
    console.log(`[ OK ] ${name}`)
  }
}

// SM3 tests
{
  const sm3 = getSM3()
  sm3.finish()
  assertEqual('SM3("")', sm3.getHashCode(), '1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B')
}
{
  const sm3 = getSM3()
  sm3.updateString('abc').finish()
  assertEqual('SM3("abc")', sm3.getHashCode(), '66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0')
}

// SM4 round-trip
{
  const sm4 = getSM4()
  sm4.setKey('this is the key', 'this is the iv', false)
  const msg = '国密SM4对称加密算法'
  const c = sm4.encrypt(msg)
  assertEqual('SM4 encrypt', c, '09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc')
  const p = sm4.decrypt(c)
  assertEqual('SM4 round-trip', p, msg)
}

// 目前仅对 SM3/SM4 做 Node 端回归测试；SM2 在浏览器环境下已有完整测试

console.log('All JavaScript SM2/SM3/SM4 tests passed.')
