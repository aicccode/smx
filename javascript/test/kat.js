/**
 * Known-answer and byte-compatibility tests.
 *
 * The answers in kat-vectors.json were captured from the original (pre-
 * optimization) implementation at commit 3397c6d, including its quirks and
 * its error behaviour. The RNG inputs are stubbed before the library loads, so
 * key generation, signing and encryption are reproducible byte for byte.
 *
 *   node test/kat.js                     compare this library to the vectors
 *   node test/kat.js --capture <root>    regenerate from the library at <root>
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const VECTORS = resolve(here, 'kat-vectors.json')
const captureAt = process.argv.indexOf('--capture')
const root =
  captureAt >= 0 ? resolve(process.argv[captureAt + 1]) : resolve(here, '..')

// ---- deterministic RNG inputs, installed before the library is imported ----
let seed = 0x12345678
const prng = () => {
  seed ^= seed << 13
  seed ^= seed >>> 17
  seed ^= seed << 5
  return (seed >>> 0) / 4294967296
}
Math.random = prng
Date.now = () => 1700000000000
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: {
    getRandomValues(a) {
      for (let i = 0; i < a.length; i++) a[i] = (i * 37 + 11) & 0xff
      return a
    },
  },
})

const load = (p) => import(pathToFileURL(resolve(root, p)).href)
const { SM3, getSM3 } = await load('sm3/sm3.js')
const { SM4 } = await load('sm4/sm4.js')
const { getSM2 } = await load('sm2/sm2.js')
const { BigInteger } = await load('sm2/biginteger.js')
const { ECCurveFp, ECPointFp } = await load('sm2/ec.js')
const util = await load('sm2/utils.js')
const common = await load('common/utils.js')

// ---- helpers ----
const out = {}
const hex = (b) =>
  Array.from(b, (x) => (x & 0xff).toString(16).padStart(2, '0')).join('')

/** Record the result, or the error type/message. TypeError text varies by V8. */
function rec(name, fn) {
  let v
  try {
    v = fn()
  } catch (e) {
    v = e instanceof TypeError ? { thrown: 'TypeError' } : { thrown: e.message }
  }
  if (name in out) throw new Error(`duplicate case ${name}`)
  out[name] = norm(v)
}
function norm(v) {
  if (v === undefined) return { undefined: true }
  if (v === null || typeof v !== 'object') return v
  if (v instanceof BigInteger) return { big: v.toString(16) }
  if (v instanceof ECPointFp) {
    return v.isInfinity()
      ? { inf: true }
      : {
          x: v.getX().toBigInteger().toString(16),
          y: v.getY().toBigInteger().toString(16),
        }
  }
  if (ArrayBuffer.isView(v)) return { bytes: hex(v) }
  if (Array.isArray(v)) return v.map(norm)
  const o = {}
  for (const k of Object.keys(v)) o[k] = norm(v[k])
  return o
}

const rndHex = (n) => {
  let s = ''
  for (let i = 0; i < n; i++) s += Math.floor(prng() * 16).toString(16)
  return s
}

const P_HEX = 'fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff'
const N_HEX = 'fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123'
const big = (s) => new BigInteger(s, 16)
const nBI = big(N_HEX)
const pBI = big(P_HEX)

const SCALARS = [
  '0',
  '1',
  '2',
  '3',
  '4',
  '1f',
  '20',
  '21',
  'ff',
  '100',
  nBI.subtract(BigInteger.ONE).toString(16),
  nBI.subtract(big('2')).toString(16),
  nBI.subtract(big('3')).toString(16),
  nBI.subtract(big('10')).toString(16),
  nBI.subtract(big('20')).toString(16),
  N_HEX,
  nBI.add(BigInteger.ONE).toString(16),
  nBI.add(big('2')).toString(16),
  'f'.repeat(64),
  '8' + '0'.repeat(63),
  '7' + 'f'.repeat(63),
  '1' + '0'.repeat(63),
  '1' + '0'.repeat(52),
  'f'.repeat(32),
  '1' + '0'.repeat(32),
  '5'.repeat(64),
  'a'.repeat(64),
  P_HEX,
  '0'.repeat(64),
  '0'.repeat(63) + '7',
]
for (let i = 0; i < 12; i++) SCALARS.push(rndHex(64))
for (let i = 0; i < 4; i++) SCALARS.push(rndHex(8 + i * 11))

const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8'

// ---- SM3 ----
function sm3Cases() {
  for (const n of [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000]) {
    const data = Uint8Array.from({ length: n }, (_, i) => (i * 7 + n) & 0xff)
    rec(`sm3/${n}`, () => new SM3().update(data).digest())
    rec(`sm3/${n}/array`, () => new SM3().update(Array.from(data)).hexDigest())
    rec(`sm3/${n}/split`, () => {
      const h = new SM3()
      for (let i = 0; i < n; i += 5) h.update(data.subarray(i, i + 5))
      return h.digest()
    })
    rec(`sm3/${n}/bytes`, () => {
      const h = new SM3()
      for (const b of data) h.update(b)
      return h.digest()
    })
    rec(`sm3/${n}/updateBytes`, () =>
      getSM3().updateBytes(data, 0, n).finish().getHashCode(),
    )
    rec(`sm3/${n}/offset`, () =>
      new SM3().updateBytes(data, 1, Math.max(0, n - 2)).digest(),
    )
  }
  rec('sm3/signed', () => new SM3().update([-1, -128, 127, 300, 1.5]).digest())
  rec('sm3/signedBytes', () =>
    new SM3().updateBytes([-1, -128, 127, 300, 1.5], 0, 5).digest(),
  )
  rec('sm3/pastEnd', () => new SM3().updateBytes([1, 2], 0, 5).digest())
  rec('sm3/number', () => new SM3().update(0x1ff).update(-1).digest())
  rec('sm3/string', () => new SM3().updateString('国密 SM3 🚀').hexDigest())
  rec('sm3/hash', () => SM3.hash('abc'))
  rec('sm3/hashHex', () => SM3.hashHex('abc'))
  rec('sm3/1m', () => new SM3().update(new Uint8Array(1000000)).hexDigest())
  rec('sm3/digestTwice', () => {
    const h = new SM3().update([1, 2, 3])
    return [h.digest(), h.digest(), h.hexDigest()]
  })
  rec('sm3/updateAfterDigest', () => {
    const h = new SM3().update([1, 2, 3])
    const a = h.digest()
    h.update([4, 5, 6])
    const b = h.digest()
    h.update(new Uint8Array(200))
    return [a, b, h.digest()]
  })
  rec('sm3/finishReuse', () => {
    const h = new SM3().update([1, 2, 3]).finish()
    const a = [h.getHashCode(), h.getHashBytes()]
    h.update([9])
    h.finish()
    return [a, h.getHashCode(), h.getHashBytes()]
  })
  rec('sm3/finishAfterDigest', () => {
    const h = new SM3().update([1]).update([2])
    const a = h.digest()
    h.finish()
    return [a, h.getHashCode()]
  })
  rec('sm3/hashBytesDistinct', () => {
    const h = new SM3().update([1]).finish()
    const first = h.getHashBytes()
    h.update([2]).finish()
    return [first, h.getHashBytes(), first === h.getHashBytes()]
  })
}

// ---- SM4 ----
function sm4Cases() {
  const hk = '0123456789abcdeffedcba9876543210'
  const iv = '000102030405060708090a0b0c0d0e0f'
  const msgs = ['', 'a', 'a'.repeat(15), 'a'.repeat(16), 'a'.repeat(17)]
  msgs.push('国密SM4对称加密算法 🚀', 'x'.repeat(1000))
  for (const [i, m] of msgs.entries()) {
    rec(`sm4/hexkey/${i}`, () => {
      const s = new SM4().setKey(hk, iv, true)
      const c = s.encrypt(m)
      return [c, s.decrypt(c) === m, s.encrypt(m) === c]
    })
    rec(`sm4/strkey/${i}`, () => {
      const s = new SM4().setKey('this is the key', 'this is the iv')
      const c = s.encrypt(m)
      return [c, s.decrypt(c) === m]
    })
  }
  rec('sm4/key16', () =>
    new SM4().setKey('1234567890abcdef', 'fedcba0987654321').encrypt('hi'),
  )
  rec('sm4/shortHexKey', () =>
    new SM4().setKey('0102', '03', true).encrypt('x'),
  )
  rec('sm4/longHexKey', () =>
    new SM4().setKey(hk + 'ff', iv + 'ff', true).encrypt('x'),
  )
  rec('sm4/oddHexKey', () => new SM4().setKey('abc', 'def', true).encrypt('x'))
  rec('sm4/junkHexKey', () =>
    new SM4().setKey('zz1z z1+1-1 10x', 'gg', true).encrypt('x'),
  )
  rec('sm4/rekey', () => {
    const s = new SM4().setKey(hk, iv, true)
    s.encrypt('x')
    s.setKey('0'.repeat(32), '1', true)
    return s.encrypt('x')
  })
  rec('sm4/noKey', () => new SM4().encrypt('x'))
  const s = new SM4().setKey(hk, iv, true)
  const c = s.encrypt('hello world, hello world, hello world')
  rec('sm4/dec/empty', () => s.decrypt(''))
  rec('sm4/dec/partial', () => s.decrypt(c.slice(0, 40)))
  rec('sm4/dec/oneByte', () => s.decrypt('ab'))
  rec('sm4/dec/odd', () => s.decrypt(c.slice(0, 33)))
  rec('sm4/dec/upper', () => s.decrypt(c.toUpperCase()))
  rec('sm4/dec/junk', () => s.decrypt('zz' + c.slice(2)))
  rec('sm4/dec/badPad', () => s.decrypt(c.slice(0, -2) + 'ff'))
  rec('sm4/dec/tamper', () => s.decrypt('00' + c.slice(2)))
  rec('sm4/internals', () => {
    const o = new Uint8Array(32)
    const p = common.hexToBytes(hk)
    const t = new SM4().setKey(hk, iv, true)
    t._encryptBlock(p, o, 16)
    const d = new Uint8Array(16)
    t._decryptBlock(o, 16, d, 0)
    return [o, d]
  })
}

// ---- utilities ----
function utilCases() {
  for (const s of ['', 'a', 'ab', 'AB', 'abc', '0x', 'zz', '1z', 'z1', ' 1']) {
    rec(`util/hexToBytes/${s}`, () => common.hexToBytes(s))
    rec(`util/hexToArray/${s}`, () => util.hexToArray(s))
  }
  rec('util/hexToBytes/sym', () => common.hexToBytes('+1-1 2'))
  rec('util/hexToBytes/nonLatin', () => common.hexToBytes('国密ab'))
  rec('util/hexToArray/high', () => util.hexToArray('ff80007f'))
  rec('util/bytesToHex', () => common.bytesToHex([0, 1, 255, -1, 256, 1.5]))
  rec('util/bytesToHex/u8', () =>
    common.bytesToHex(new Uint8Array(300).map((_, i) => i)),
  )
  rec('util/bytesToHex/big', () =>
    new SM3()
      .updateString(common.bytesToHex(new Uint8Array(100000).fill(171)))
      .hexDigest(),
  )
  rec('util/arrayToHex', () => util.arrayToHex([0, 1, 255, -1, 256, -128]))
  rec('util/bytes2hex', () => util.bytes2hex([0, -1]))
  rec('util/bytesToString', () => [
    common.bytesToString(common.stringToBytes('国密')),
    common.bytesToString([0xe5, 0x9b, 0xbd]),
    common.bytesToString(new Uint8Array([0xef, 0xbb, 0xbf, 0x41])),
    common.bytesToString(new Uint8Array([0xff, 0x41])),
  ])
  rec('util/leftPad', () => [
    util.leftPad('a', 3),
    util.leftPad('abc', 2),
    util.leftPad('', 0),
  ])
  rec('util/intBE', () => {
    const o = new Uint8Array(4)
    common.intToBytesBE(0xdeadbeef, o, 0)
    return [o, common.bytesToIntBE(o, 0), common.bytesToIntBE([1], 0)]
  })
}

// ---- curve, points, field elements ----
function curveCases() {
  const { curve, G, n, w } = util.generateEcparam()
  rec('ec/params', () => [
    n,
    w,
    curve.q,
    curve.a.toBigInteger(),
    curve.b.toBigInteger(),
    G,
    curve.equals(util.getGlobalCurve()),
    util.getGlobalCurve().equals(curve),
  ])
  const P = G.multiply(big(D))
  const Q = G.multiply(big('abcdef'))
  for (const k of SCALARS) {
    rec(`ec/G*${k}`, () => G.multiply(big(k)))
    rec(`ec/P*${k}`, () => P.multiply(big(k)))
    rec(`sm2/pub/${k}`, () => getSM2().getPublicKeyFromPrivateKey(k))
  }
  rec('ec/G*-5', () => G.multiply(big('-5')))
  rec('ec/P*-5', () => P.multiply(big('-5')))
  rec('ec/G*tooLarge', () => G.multiply(big('1' + '0'.repeat(64))))
  rec('ec/P*tooLarge', () => P.multiply(big('1' + '0'.repeat(64))))
  rec('ec/inf*k', () => curve.getInfinity().multiply(big('5')))
  rec('ec/P+Q', () => P.add(Q))
  rec('ec/Q+P', () => Q.add(P))
  rec('ec/P+P', () => P.add(P))
  rec('ec/P+Pcopy', () => P.add(new ECPointFp(curve, P.getX(), P.getY())))
  rec('ec/P-P', () => P.subtract(P))
  rec('ec/P+-P', () => P.add(P.negate()))
  rec('ec/P+inf', () => P.add(curve.getInfinity()))
  rec('ec/inf+P', () => curve.getInfinity().add(P))
  rec('ec/inf+inf', () => curve.getInfinity().add(curve.getInfinity()))
  rec('ec/twice', () => P.twice())
  rec('ec/twiceInf', () => curve.getInfinity().twice())
  rec('ec/neg', () => P.negate())
  rec('ec/subQ', () => P.subtract(Q))
  rec('ec/subInf', () => P.subtract(curve.getInfinity()))
  rec('ec/pow2', () => P.timesPow2(5))
  rec('ec/pow2/0', () => P.timesPow2(0))
  rec('ec/pow2/-1', () => P.timesPow2(-1))
  rec('ec/equals', () => [
    P.equals(P),
    P.equals(Q),
    P.equals(new ECPointFp(curve, P.getX(), P.getY())),
    P.equals(curve.getInfinity()),
    curve.getInfinity().equals(P),
    curve.getInfinity().equals(curve.getInfinity()),
  ])
  rec('ec/isValid', () => [P.isValid(), G.isValid(), curve.infinity.isValid()])
  rec('ec/isInfinity', () => [P.isInfinity(), curve.infinity.isInfinity()])
  rec('ec/validatePoint', () => curve.validatePoint(P.getX(), P.getY()))

  // Non-canonical, off-curve and malformed encodings
  const xh = P.getX().toBigInteger().toString(16).padStart(64, '0')
  const yh = P.getY().toBigInteger().toString(16).padStart(64, '0')
  const enc = '04' + xh + yh
  const evenY = P.getY().toBigInteger().isEven()
  rec('dec/04', () => curve.decodePointHex(enc))
  rec('dec/06', () => curve.decodePointHex('06' + xh + yh))
  rec('dec/07', () => curve.decodePointHex('07' + xh + yh))
  rec('dec/upper', () => curve.decodePointHex(enc.toUpperCase()))
  rec('dec/02', () => curve.decodePointHex((evenY ? '02' : '03') + xh))
  rec('dec/03', () => curve.decodePointHex((evenY ? '03' : '02') + xh))
  rec('dec/00', () => curve.decodePointHex('00'))
  rec('dec/05', () => curve.decodePointHex('05' + xh + yh))
  rec('dec/garbage', () => curve.decodePointHex('zz'))
  rec('dec/empty', () => curve.decodePointHex(''))
  const sx = 'b'.repeat(64)
  rec('dec/compressedNotOnCurve', () => [
    curve.decodePointHex('02' + sx),
    curve.decodePointHex('03' + sx),
    curve.decodePointHex('02' + sx).isValid(),
  ])
  const offX = P.getX().toBigInteger().add(pBI).toString(16)
  const offCurve = '04' + xh + yh.slice(0, -1) + (yh.endsWith('0') ? '1' : '0')
  rec('dec/offCurve', () => curve.decodePointHex(offCurve).isValid())
  for (const k of ['0', '1', '5', D, N_HEX]) {
    rec(`dec/offCurve*${k}`, () =>
      curve.decodePointHex(offCurve).multiply(big(k)),
    )
  }
  rec('dec/offCurve+Q', () => curve.decodePointHex(offCurve).add(Q))
  rec('dec/offCurve+self', () => {
    const O = curve.decodePointHex(offCurve)
    return [O.add(O), O.twice()]
  })
  rec('dec/xPlusP', () => {
    const NC = new ECPointFp(
      curve,
      curve.fromBigInteger(big(offX)),
      curve.fromBigInteger(big(yh)),
    )
    return [
      NC.isValid(),
      NC.multiply(big('5')),
      NC.add(Q),
      NC.twice(),
      NC.equals(P),
      NC.x.toBigInteger(),
      NC.getX().toBigInteger(),
    ]
  })
  rec('dec/negCoord', () => {
    const NC = new ECPointFp(
      curve,
      curve.fromBigInteger(P.getX().toBigInteger().subtract(pBI)),
      curve.fromBigInteger(P.getY().toBigInteger()),
    )
    return [NC.isValid(), NC.multiply(big('5')), NC.add(Q)]
  })
  rec('ec/z2', () => {
    const Z = new ECPointFp(curve, P.getX(), P.getY(), big('2'))
    return [Z.getX().toBigInteger(), Z.twice(), Z.multiply(big('3')), Z.add(Q)]
  })
  rec('ec/zZero', () =>
    new ECPointFp(curve, P.getX(), P.getY(), BigInteger.ZERO).isInfinity(),
  )
  rec('ec/twiceY0', () =>
    new ECPointFp(
      curve,
      P.getX(),
      curve.fromBigInteger(BigInteger.ZERO),
    ).twice(),
  )

  // Field elements
  const a = curve.fromBigInteger(big(rndHex(64)))
  const b = curve.fromBigInteger(big(rndHex(64)))
  const zero = curve.fromBigInteger(BigInteger.ZERO)
  const huge = curve.fromBigInteger(big(rndHex(100)))
  const neg = curve.fromBigInteger(big('-' + rndHex(70)))
  for (const [nm, x, y] of [
    ['ab', a, b],
    ['zero', a, zero],
    ['zero2', zero, a],
    ['huge', huge, a],
    ['neg', neg, a],
    ['negneg', neg, neg],
    ['self', a, a],
  ]) {
    rec(`fe/${nm}`, () => [
      x.add(y).toBigInteger(),
      x.subtract(y).toBigInteger(),
      x.multiply(y).toBigInteger(),
      x.square().toBigInteger(),
      x.negate().toBigInteger(),
      x.isZero(),
      x.equals(y),
      x.equals(x),
    ])
    // The baseline hangs in modInverse on a zero or negative divisor, so those
    // inputs have no captured answer.
    if (y.toBigInteger().signum() > 0) {
      rec(`fe/${nm}/div`, () => x.divide(y).toBigInteger())
    }
  }

  // Other curves must keep working: a small prime and a 192-bit curve
  rec('other/small', () => {
    const c = new ECCurveFp(big('61'), big('2'), big('3'))
    const pt = new ECPointFp(
      c,
      c.fromBigInteger(big('3')),
      c.fromBigInteger(big('6')),
    )
    return [pt.isValid(), pt.twice(), pt.add(pt.twice()), c.equals(curve)]
  })
  rec('other/p192', () => {
    const q = big('fffffffffffffffffffffffffffffffeffffffffffffffff')
    const c = new ECCurveFp(
      q,
      q.subtract(big('3')),
      big('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
    )
    const pt = c.decodePointHex(
      '04188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012' +
        '07192b95ffc8da78631011ed6b24cdd573f977a11e794811',
    )
    return [
      pt.isValid(),
      pt.multiply(big('abcdef0123456789')),
      pt.add(pt),
      pt.twice(),
    ]
  })
  rec('other/sm2pDifferentB', () => {
    const c = new ECCurveFp(pBI, pBI.subtract(big('3')), big('7'))
    const pt = new ECPointFp(c, P.getX(), P.getY())
    return [pt.isValid(), c.equals(curve), curve.equals(c)]
  })
}

// ---- SM2 ----
function sm2Cases() {
  const sm2 = getSM2()
  const pub = sm2.getPublicKeyFromPrivateKey(D)
  const bare = pub.slice(2)
  const Y_ODD = BigInt('0x' + pub.slice(-64)) & 1n
  const comp = (Y_ODD ? '03' : '02') + pub.slice(2, 66)
  const ID = '1234567812345678'

  rec('sm2/keygen', () => {
    const r = []
    for (let i = 0; i < 8; i++) r.push(util.generateKeyPairHex())
    return r
  })
  rec('sm2/getPoint', () => sm2.getPoint())
  rec('sm2/compress', () => [
    util.compressPublicKeyHex(pub),
    util.compressPublicKeyHex(
      '04' + 'a'.repeat(63) + '1' + 'b'.repeat(63) + '2',
    ),
  ])
  rec('sm2/compress/bad', () => util.compressPublicKeyHex('04ab'))
  rec('sm2/verifyPublicKey', () => [
    util.verifyPublicKey(pub),
    util.verifyPublicKey(comp),
    util.verifyPublicKey('04' + 'a'.repeat(128)),
    util.verifyPublicKey('09' + 'a'.repeat(128)),
    util.comparePublicKeyHex(pub, pub),
    util.comparePublicKeyHex(pub, comp),
    util.comparePublicKeyHex(pub, '04' + 'a'.repeat(128)),
    util.comparePublicKeyHex('09', pub),
    util.comparePublicKeyHex(pub, '09'),
  ])
  rec('sm2/verifyPublicKey/inf', () => util.verifyPublicKey('00'))

  // Z values
  for (const [nm, k, id] of [
    ['default', pub, undefined],
    ['bare', bare, ID],
    ['compressed', comp, ID],
    ['emptyId', pub, ''],
    ['unicode', pub, '国密用户'],
    ['longId', pub, 'x'.repeat(300)],
  ]) {
    rec(`sm2/z/${nm}`, () => sm2.userSM3Z(k, id))
  }
  rec('sm2/z/badTag', () => sm2.userSM3Z('09' + bare, ID))
  rec('sm2/z/inf', () => sm2.userSM3Z('00', ID))

  // Signing (deterministic because the RNG inputs are stubbed)
  const msgs = ['message digest', '', '国密 🚀', 'm'.repeat(1000)]
  const sigs = []
  for (const [i, m] of msgs.entries()) {
    for (const id of [ID, '', 'alice']) {
      rec(`sm2/sign/${i}/${id}`, () => {
        const sig = sm2.sm2Sign(id, D, m)
        sigs.push([id, sig, m])
        return [sig, sm2.sm2VerifySign(id, sig, m, pub)]
      })
    }
  }
  for (const k of ['1', '2', 'ff', 'f'.repeat(64), N_HEX, D.toUpperCase()]) {
    rec(`sm2/sign/key/${k}`, () => sm2.sm2Sign(ID, k, 'x'))
  }
  rec('sm2/sign/key0', () => sm2.sm2Sign(ID, '0', 'x'))
  rec('sm2/sign/tooLarge', () => sm2.sm2Sign(ID, '1' + '0'.repeat(64), 'x'))
  // A negative key hangs the baseline in modInverse, so it has no captured answer.

  // Standard vector, GB/T 32918.5 Annex A
  const stdPub =
    '0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020' +
    'ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13'
  const stdSig =
    'f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3' +
    'h' +
    'b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa'
  rec('sm2/std/pub', () => sm2.getPublicKeyFromPrivateKey(D) === stdPub)
  rec('sm2/std/verify', () =>
    sm2.sm2VerifySign(ID, stdSig, 'message digest', stdPub),
  )

  // Verify edge cases
  const [, sig0, m0] = sigs[0]
  const [r0, s0] = sig0.split('h')
  const v = (nm, sig, msg = m0, id = ID, key = pub) =>
    rec(`sm2/verify/${nm}`, () => sm2.sm2VerifySign(id, sig, msg, key))
  v('ok', sig0)
  v('upper', sig0.toUpperCase().replace('H', 'h'))
  v('bareKey', sig0, m0, ID, bare)
  v('compressedKey', sig0, m0, ID, comp)
  v('wrongMsg', sig0, m0 + 'x')
  v('wrongId', sig0, m0, 'other')
  v('wrongKey', sig0, m0, ID, sm2.getPublicKeyFromPrivateKey('5'))
  v('offCurveKey', sig0, m0, ID, '04' + 'a'.repeat(128))
  v('badTagKey', sig0, m0, ID, '09' + bare)
  v('infKey', sig0, m0, ID, '00')
  v('r+1', big(r0).add(BigInteger.ONE).toString(16) + 'h' + s0)
  v('s+1', r0 + 'h' + big(s0).add(BigInteger.ONE).toString(16))
  v('r0', '0h' + s0)
  v('s0', r0 + 'h0')
  v('r0s0', '0h0')
  v('rN', N_HEX + 'h' + s0)
  v('sN', r0 + 'h' + N_HEX)
  v('rEqN-s', big(N_HEX).subtract(big(s0)).toString(16) + 'h' + s0)
  v('r+n', big(r0).add(nBI).toString(16) + 'h' + s0)
  v('s+n', r0 + 'h' + big(s0).add(nBI).toString(16))
  v('tooLong', r0 + 'h' + '1' + '0'.repeat(64))
  v('rTooLong', '1' + '0'.repeat(64) + 'h' + s0)
  v('neg', '-' + r0 + 'h' + s0)
  v('negS', r0 + 'h-' + s0)
  v('noSep', r0 + s0)
  v('empty', '')
  v('junk', 'zzhzz')
  v('extraSep', r0 + 'h' + s0 + 'hff')
  v('prefixZero', '00' + r0 + 'h00' + s0)

  // s*G + t*P = infinity: for d=1, s + t = 0 (mod n), i.e. 2s + r = 0
  rec('sm2/verify/infinity', () => {
    const r = big('5')
    const s = nBI
      .subtract(r)
      .multiply(nBI.add(BigInteger.ONE).shiftRight(1))
      .mod(nBI)
    return sm2.sm2VerifySign(
      ID,
      r.toString(16) + 'h' + s.toString(16),
      'x',
      sm2.getPublicKeyFromPrivateKey('1'),
    )
  })

  // Encrypt / decrypt
  const plain = [
    'hello SM2!',
    '国密 🚀',
    'a',
    'k'.repeat(31),
    'k'.repeat(32),
    'k'.repeat(33),
    'k'.repeat(1000),
  ]
  const ciphers = []
  for (const [i, m] of plain.entries()) {
    rec(`sm2/enc/${i}`, () => {
      const c = sm2.sm2Encrypt(m, pub)
      ciphers.push(c)
      return [c, sm2.sm2Decrypt(c, D) === m]
    })
  }
  rec('sm2/enc/empty', () => {
    const c = sm2.sm2Encrypt('', pub)
    return [c, sm2.sm2Decrypt(c, D)]
  })
  rec('sm2/enc/array', () => sm2.sm2Encrypt([1, 2, 255, -1, 300, 1.5], pub))
  rec('sm2/enc/u8', () => sm2.sm2Encrypt(new Uint8Array([1, 2, 255]), pub))
  rec('sm2/enc/compressedKey', () => sm2.sm2Encrypt('x', comp))
  rec('sm2/enc/offCurveKey', () => sm2.sm2Encrypt('x', '04' + 'a'.repeat(128)))
  rec('sm2/enc/badTagKey', () => sm2.sm2Encrypt('x', '09' + bare))
  rec('sm2/enc/infKey', () => sm2.sm2Encrypt('x', '00'))
  rec('sm2/enc/inputKept', () => {
    const a = [1, 2, 3]
    sm2.sm2Encrypt(a, pub)
    return a
  })
  const c0 = ciphers[0]
  const dec = (nm, c, k = D) => rec(`sm2/dec/${nm}`, () => sm2.sm2Decrypt(c, k))
  dec('ok', c0)
  dec('upper', c0.toUpperCase())
  dec(
    'upperC3',
    c0.slice(0, 130) + c0.slice(130, 194).toUpperCase() + c0.slice(194),
  )
  dec('wrongKey', c0, '5')
  dec('badC3', c0.slice(0, 130) + '00' + c0.slice(132))
  dec('badC2', c0.slice(0, -2) + '00')
  dec('badC1', '04' + 'a'.repeat(128) + c0.slice(130))
  dec('badTag', '09' + c0.slice(2))
  dec('inf', '00' + c0.slice(2))
  dec('truncated', c0.slice(0, 150))
  dec('c3Only', c0.slice(0, 194))
  dec('empty', '')
  dec('key0', c0, '0')
  dec('keyTooLarge', c0, '1' + '0'.repeat(64))
  dec('oddC2', c0.slice(0, -1))
  dec(
    'compressedC1',
    util.compressPublicKeyHex(c0.slice(0, 130)) + c0.slice(130),
  )

  // Key exchange
  const db = '7fb1f3a6c7a4d3d94cfa6c2a0d6c0e5a48e6e5a1b5f3c9d27a6e0f1b3c4d5e6f'
  const ra = '81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029'
  const rb = '2a4e0f1b3c4d5e6f7fb1f3a6c7a4d3d94cfa6c2a0d6c0e5a48e6e5a1b5f3c9d2'
  const pA = pub
  const pB = sm2.getPublicKeyFromPrivateKey(db)
  const Ra = sm2.getPublicKeyFromPrivateKey(ra)
  const Rb = sm2.getPublicKeyFromPrivateKey(rb)
  for (const len of [0, 1, 16, 32, 33, 64, 100]) {
    rec(`kx/getSb/${len}`, () =>
      sm2.getSb(len, pA, Ra, 'alice@x', 'bob@x', db, pB, rb, Rb),
    )
  }
  // Coordinates with leading zeros exercise the unpadded V output
  for (let i = 1; i <= 40; i++) {
    rec(`kx/many/${i}`, () => {
      const rbi = rndHex(64)
      const Rbi = sm2.getPublicKeyFromPrivateKey(rbi)
      const r = sm2.getSb(16, pA, Ra, 'a', 'b', db, pB, rbi, Rbi)
      const S2 = sm2._createS(
        0x03,
        util.getGlobalCurve().decodePointHex('04' + r.V),
        util.hexToArray(r.Za),
        util.hexToArray(r.Zb),
        util.getGlobalCurve().decodePointHex(Ra),
        r.Rb,
      )
      return [
        r,
        sm2.checkSa(r.V, r.Za, r.Zb, Ra, r.Rb, util.bytes2hex(S2)),
        sm2.checkSa(r.V, r.Za, r.Zb, Ra, r.Rb, 'wrong'),
      ]
    })
  }
  rec('kx/badRa', () =>
    sm2.getSb(16, pA, '04' + 'a'.repeat(128), 'a', 'b', db, pB, rb, Rb),
  )
  rec('kx/badPa', () =>
    sm2.getSb(16, '04' + 'a'.repeat(128), Ra, 'a', 'b', db, pB, rb, Rb),
  )
  rec('kx/internals', () => {
    const { curve, n, w } = util.generateEcparam()
    const x = sm2._calcX(w, big('abcdef' + '0'.repeat(58)))
    const t = sm2._calcT(n, big(rb), big(db), x)
    const pt = sm2._calcPoint(
      t,
      x,
      curve.decodePointHex(pA),
      curve.decodePointHex(Ra),
    )
    return [x, t, pt, sm2._KDF(40, pt, [1, 2], [3])]
  })
}

// ---- BigInteger public behaviour (values, sign handling, quirks) ----
function bigIntegerCases() {
  const vals = ['0', '1', '-1', 'ff', '-ff', '10000000', 'fffffff', N_HEX]
  vals.push('-' + P_HEX, 'abc' + '0'.repeat(60), '7f', '80', '-80', '-81')
  const b16 = (s) => new BigInteger(s, 16)
  for (const s of vals) {
    rec(`bi/str/${s}`, () => {
      const x = b16(s)
      return [
        x.toString(16),
        x.toString(2).length,
        x.toString(8),
        x.toString(32),
        x.toString(10),
        x.toRadix(16),
        x.toRadix(10),
        x.toRadix(36),
        x.toRadix(2).length,
        x.toRadix(1),
        x.toByteArray(),
        x.signum(),
        x.bitLength(),
        x.bitCount(),
        x.intValue(),
        x.byteValue(),
        x.shortValue(),
        x.isEven(),
        x.getLowestSetBit(),
        x.negate().toString(16),
        x.abs().toString(16),
        x.square().toString(16),
        x.shiftLeft(13).toString(16),
        x.shiftRight(13).toString(16),
        x.not().toString(16),
      ]
    })
  }
  rec('bi/parse', () => [
    new BigInteger('123456789012345678901234567890').toString(16),
    new BigInteger('123456789012345678901234567890', 10).toString(10),
    new BigInteger('zz', 36).toString(10),
    new BigInteger('-ff', 16).toString(10),
    new BigInteger('a b-c', 16).toString(16),
    new BigInteger('xyz', 16).toString(16),
    new BigInteger('', 16).toString(16),
    new BigInteger([1, 2, 3]).toString(16),
    new BigInteger([255, 2, 3]).toString(16),
    new BigInteger('777', 8).toString(16),
    new BigInteger('1010', 2).toString(16),
    new BigInteger('1v', 32).toString(16),
    new BigInteger('33', 4).toString(16),
    new BigInteger(100, { nextBytes: (b) => b.fill(0xab) }).toString(16),
    new BigInteger(8, { nextBytes: (b) => b.fill(0xab) }).toString(16),
    new BigInteger(64, 20, { nextBytes: (b) => b.fill(0xab) }).toString(16),
    new BigInteger(1, 20, { nextBytes: (b) => b.fill(0xab) }).toString(16),
  ])
  const pairs = [
    ['abcdef0123456789', '123456789'],
    [N_HEX, P_HEX],
    ['-' + N_HEX, P_HEX],
    [N_HEX, '-' + P_HEX],
    ['-abcdef', '-12'],
    ['0', '5'],
    ['1000000000', '10000000'],
    ['f'.repeat(128), 'f'.repeat(64)],
  ]
  for (const [p, q] of pairs) {
    rec(`bi/op/${p}/${q}`, () => {
      const a = b16(p)
      const b = b16(q)
      return [
        a.add(b),
        a.subtract(b),
        a.multiply(b),
        a.divide(b),
        a.remainder(b),
        a.divideAndRemainder(b),
        a.mod(b),
        a.and(b),
        a.or(b),
        a.xor(b),
        a.andNot(b),
        a.compareTo(b),
        a.equals(b),
        a.min(b),
        a.max(b),
        a.gcd(b),
      ]
    })
  }
  rec('bi/modular', () => {
    const a = b16('abcdef0123456789abcdef')
    return [
      a.modInverse(pBI),
      a.modInverse(big('100')),
      big('10').modInverse(big('100')),
      a.modPow(big('10001'), pBI),
      a.modPow(big('10001'), big('100')),
      a.modPow(big('3'), pBI),
      a.modPow(BigInteger.ZERO, pBI),
      a.modPow(nBI, pBI),
      a.modPowInt(3, pBI),
      a.modPowInt(65537, pBI),
      a.modPowInt(65537, big('100')),
      a.pow(3),
      a.pow(0),
      a.modInt(97),
      a.modInt(16),
      a.modInt(0),
      big('-ab').modInt(7),
    ]
  })
  rec('bi/bits', () => {
    const a = b16('abcdef')
    return [
      a.testBit(0),
      a.testBit(5),
      a.testBit(500),
      a.setBit(40),
      a.clearBit(0),
      a.flipBit(1),
      a.clone(),
      BigInteger.ZERO,
      BigInteger.ONE,
      BigInteger.nbv(-5),
      BigInteger.nbv(5),
      BigInteger.nbi() instanceof BigInteger,
      a.DV,
      a.DM,
      a.DB,
    ]
  })
  rec('bi/prime', () => [
    pBI.isProbablePrime(20),
    nBI.isProbablePrime(20),
    big('61').isProbablePrime(5),
    big('60').isProbablePrime(5),
    pBI.add(big('2')).isProbablePrime(20),
  ])
}

sm3Cases()
sm4Cases()
utilCases()
curveCases()
sm2Cases()
bigIntegerCases()

// ---- standard vectors (independent of the captured baseline) ----
const STANDARD = [
  [
    'GB/T 32905 SM3("abc")',
    () => new SM3().updateString('abc').hexDigest(),
    '66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0',
  ],
  [
    'GB/T 32905 SM3("abcd"x16)',
    () => new SM3().updateString('abcd'.repeat(16)).hexDigest(),
    'DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732',
  ],
  [
    'GB/T 32907 SM4 one block',
    () => {
      const key = common.hexToBytes('0123456789abcdeffedcba9876543210')
      const s = new SM4().setKey(
        '0123456789abcdeffedcba9876543210',
        '00'.repeat(16),
        true,
      )
      const o = new Uint8Array(16)
      s._encryptBlock(key, o, 0)
      return common.bytesToHex(o)
    },
    '681edf34d206965e86b3e94f536e4246',
  ],
  [
    'GB/T 32907 SM4 decrypt one block',
    () => {
      const s = new SM4().setKey(
        '0123456789abcdeffedcba9876543210',
        '00'.repeat(16),
        true,
      )
      const c = common.hexToBytes('681edf34d206965e86b3e94f536e4246')
      const o = new Uint8Array(16)
      s._decryptBlock(c, 0, o, 0)
      return common.bytesToHex(o)
    },
    '0123456789abcdeffedcba9876543210',
  ],
  [
    'GB/T 32907 SM4 1,000,000 iterations',
    () => {
      const s = new SM4().setKey(
        '0123456789abcdeffedcba9876543210',
        '00'.repeat(16),
        true,
      )
      const b = common.hexToBytes('0123456789abcdeffedcba9876543210')
      for (let i = 0; i < 1000000; i++) s._encryptBlock(b, b, 0)
      return common.bytesToHex(b)
    },
    '595298c7c6fd271f0402f804c33d3f66',
  ],
]
STANDARD.push([
  'GB/T 32918.5 SM2 signature verifies',
  () =>
    String(
      getSM2().sm2VerifySign(
        '1234567812345678',
        'f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3h' +
          'b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa',
        'message digest',
        '0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020' +
          'ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13',
      ),
    ),
  'true',
])
const standard = {}
for (const [name, fn] of STANDARD) standard[name] = fn()

// ---- capture or compare ----
if (captureAt >= 0) {
  writeFileSync(VECTORS, JSON.stringify(out, null, 0) + '\n')
  let bad = 0
  for (const [name, , want] of STANDARD) {
    if (standard[name] !== want) {
      console.error(`[FAIL] ${name}: ${standard[name]}`)
      bad++
    }
  }
  console.log(`captured ${Object.keys(out).length} cases, ${bad} std failures`)
  process.exit(bad ? 1 : 0)
}

let failed = 0
for (const [name, , want] of STANDARD) {
  if (standard[name] !== want) {
    console.error(`[FAIL] ${name}\n  want ${want}\n  got  ${standard[name]}`)
    failed++
  }
}
const expected = JSON.parse(readFileSync(VECTORS, 'utf8'))
const names = Object.keys(expected)
for (const name of names) {
  const a = JSON.stringify(out[name])
  const b = JSON.stringify(expected[name])
  if (a !== b) {
    console.error(`[FAIL] ${name}\n  want ${b}\n  got  ${a}`)
    failed++
  }
}
const extra = Object.keys(out).filter((k) => !(k in expected))
for (const name of extra) {
  console.error(`[FAIL] ${name}: no captured answer`)
  failed++
}
const total = names.length + STANDARD.length
console.log(`KAT: ${total - failed} passed, ${failed} failed of ${total}`)
process.exit(failed ? 1 : 0)
