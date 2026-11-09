/**
 * Seeded malformed-input harness for every public function.
 *
 *   node test/fuzz.js [--cases=N] [--seed=N] [--shard=I/M] [--only=regex]
 *
 * A worker runs the cases while the main thread watches a heartbeat, so a hang is
 * reported with its function and case number instead of stalling forever. Every call
 * must return or throw an Error, boolean-returning functions must not throw at all,
 * and after each batch the library must still produce correct results. A case can
 * be replayed exactly from its function name, seed and case number.
 */
import {
  Worker,
  isMainThread,
  parentPort,
  workerData,
} from 'node:worker_threads'
import { fileURLToPath } from 'node:url'

const HEARTBEAT_LIMIT_MS = Number(process.env.FUZZ_HANG_MS ?? 120000)
const SANITY_EVERY = 2000

function parseArgs() {
  const flag = (name, dflt) => {
    const hit = process.argv.find((a) => a.startsWith(`--${name}=`))
    return hit ? hit.split('=')[1] : dflt
  }
  const [shard, shards] = flag('shard', '0/1').split('/').map(Number)
  return {
    cases: Number(flag('cases', 2000)),
    seed: Number(flag('seed', 1)),
    shard,
    shards,
    only: flag('only', ''),
  }
}

if (isMainThread) {
  const options = parseArgs()
  const shared = new Int32Array(new SharedArrayBuffer(16))
  const worker = new Worker(fileURLToPath(import.meta.url), {
    workerData: { ...options, shared },
    resourceLimits: { maxOldGenerationSizeMb: 4096 },
  })
  let last = -1
  let current = ''
  let lastChange = Date.now()
  const start = Date.now()
  const finish = (code) => {
    clearInterval(timer)
    worker.terminate().then(() => process.exit(code))
  }
  const timer = setInterval(() => {
    const beat = Atomics.load(shared, 0)
    if (beat !== last) {
      last = beat
      lastChange = Date.now()
    } else if (Date.now() - lastChange > HEARTBEAT_LIMIT_MS) {
      console.error(
        `[HANG] ${current} case ${Atomics.load(shared, 2)} seed ${options.seed}`,
      )
      finish(2)
    }
  }, 1000)
  worker.on('message', (m) => {
    if (m.current) current = m.current
    if (m.log) console.log(m.log)
    if (m.done) {
      const s = ((Date.now() - start) / 1000).toFixed(1)
      console.log(`fuzz: ${m.calls} calls, ${m.failures} failures, ${s} s`)
      finish(m.failures ? 1 : 0)
    }
  })
  worker.on('error', (e) => {
    console.error(
      `[CRASH] function #${Atomics.load(shared, 1)} case ${Atomics.load(shared, 2)}:`,
      e,
    )
    finish(3)
  })
} else {
  await runWorker(workerData)
}

async function runWorker({ cases, seed, shard, shards, only, shared }) {
  const { getSM2 } = await import('../sm2/sm2.js')
  const { getSM9 } = await import('../sm9/sm9.js')
  const { SM3, getSM3 } = await import('../sm3/sm3.js')
  const { SM4, getSM4 } = await import('../sm4/sm4.js')
  const { BigInteger, SecureRandom } = await import('../sm2/biginteger.js')
  const { ECCurveFp, ECPointFp } = await import('../sm2/ec.js')
  const util = await import('../sm2/utils.js')
  const common = await import('../common/utils.js')

  // ---- seeded generator, independent of the library's RNG ----
  let state = 1
  const reseed = (name, i) => {
    let h = (seed ^ 0x811c9dc5) >>> 0
    for (let c = 0; c < name.length; c++) {
      h = Math.imul(h ^ name.charCodeAt(c), 16777619)
    }
    state = (h ^ Math.imul(i + 1, 0x9e3779b1)) >>> 0 || 1
  }
  const next = () => {
    state ^= state << 13
    state ^= state >>> 17
    state ^= state << 5
    state >>>= 0
    return state
  }
  const below = (n) => next() % n
  const chance = (percent) => below(100) < percent
  const pick = (list) => list[below(list.length)]
  const randomHex = (n) => {
    let s = ''
    for (let i = 0; i < n; i++) s += (next() & 15).toString(16)
    return s
  }

  // ---- valid material to mutate ----
  const sm2 = getSM2()
  const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8'
  const D2 = '7fb1f3a6c7a4d3d94cfa6c2a0d6c0e5a48e6e5a1b5f3c9d27a6e0f1b3c4d5e6f'
  const PUB = sm2.getPublicKeyFromPrivateKey(D)
  const PUB2 = sm2.getPublicKeyFromPrivateKey(D2)
  const COMPRESSED = util.compressPublicKeyHex(PUB)
  const SIG = sm2.sm2Sign('id', D, 'message')
  const CIPHER = sm2.sm2Encrypt('plaintext', PUB)
  const { curve, G, n, w } = util.generateEcparam()
  const EX = sm2.getSb(16, PUB, PUB2, 'a', 'b', D2, PUB2, D2, PUB2)
  const SM4_KEY = '0123456789abcdeffedcba9876543210'
  const SM4_CIPHER = new SM4().setKey(SM4_KEY, SM4_KEY, true).encrypt('hello')
  const NEAR_N =
    'fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d541'
  const VALID_HEX = [
    D,
    D2,
    PUB,
    PUB2,
    COMPRESSED,
    SIG,
    CIPHER,
    SM4_KEY,
    SM4_CIPHER,
    EX.V,
    EX.Sb,
    EX.Za,
  ]

  function mutateHex(s) {
    switch (below(8)) {
      case 0:
        return s.slice(0, below(s.length + 1))
      case 1:
        return s + randomHex(below(4) + 1)
      case 2: {
        const at = below(s.length || 1)
        return s.slice(0, at) + (next() & 15).toString(16) + s.slice(at + 1)
      }
      case 3:
        return s.toUpperCase()
      case 4: {
        const at = below(s.length || 1)
        return (
          s.slice(0, at) +
          pick(['z', ' ', '-', '١', '\ud800', 'é', 'h', '\0']) +
          s.slice(at + 1)
        )
      }
      case 5:
        return (
          pick(['00', '02', '03', '04', '05', '06', '07', 'ff']) + s.slice(2)
        )
      case 6:
        return NEAR_N + pick(['00', '20', '21', '22', '23', '24', 'ff'])
      default:
        return '0'.repeat(below(4) * 16) + s
    }
  }

  const newBig = () =>
    pick([
      () => new BigInteger('0', 16),
      () => new BigInteger('1', 16),
      () => new BigInteger('-1', 16),
      () => new BigInteger('2', 16),
      () => new BigInteger(randomHex(1 + below(70)), 16),
      () => new BigInteger('-' + randomHex(1 + below(70)), 16),
      () => n.clone(),
      () => curve.q.clone(),
      () => n.subtract(BigInteger.ONE),
      () => new BigInteger(randomHex(1 + below(600)), 16),
      () => BigInteger.nbi(),
    ])()

  const newPoint = () =>
    pick([
      () => G.multiply(new BigInteger(randomHex(8) + '1', 16)),
      () => curve.getInfinity(),
      () => G,
      () =>
        new ECPointFp(
          curve,
          curve.fromBigInteger(newBig()),
          curve.fromBigInteger(newBig()),
        ),
      () =>
        new ECPointFp(
          curve,
          curve.fromBigInteger(newBig()),
          curve.fromBigInteger(newBig()),
          newBig(),
        ),
      () => new ECPointFp(curve, null, curve.fromBigInteger(newBig())),
    ])()

  const hostile = () =>
    pick([
      () => ({
        get length() {
          throw new Error('hostile length')
        },
      }),
      () => ({
        toString() {
          throw new Error('hostile toString')
        },
      }),
      () =>
        new Proxy([], {
          get() {
            throw new Error('hostile get')
          },
        }),
      () => ({ length: 1e9 }),
      () => ({ length: -1 }),
      () => new Array(2 ** 31),
      () => Symbol('s'),
      () => 1n,
      () => () => 1,
      () => new Date(0),
      () => ({ t: 1e12, s: 0 }),
      () => ({ valueOf: () => 1e12 }),
      () => Object.create(null),
      () => [[1]],
      () => new Float64Array(3),
      () => new ArrayBuffer(4),
    ])()

  function junk() {
    switch (below(14)) {
      case 0:
        return pick([undefined, null, true, false])
      case 1:
        return pick([
          0,
          -1,
          1,
          2,
          1.5,
          -1.5,
          NaN,
          Infinity,
          -Infinity,
          255,
          256,
        ])
      case 2:
        return pick([
          2 ** 28,
          2 ** 31,
          2 ** 32,
          2 ** 53,
          1e15,
          1e300,
          -(2 ** 31),
          1 << 17,
          8191,
          8192,
        ])
      case 3:
        return randomHex(below(140))
      case 4:
        return mutateHex(pick(VALID_HEX))
      case 5:
        return pick(VALID_HEX)
      case 6:
        return pick([
          '',
          'h',
          'hh',
          'abc',
          '国密',
          '\ud800',
          '\udc00a',
          '﻿',
          '-',
          '0x10',
          ' 1 ',
        ])
      case 7:
        return Array.from({ length: below(40) }, () =>
          pick([0, 1, 255, -1, -128, 300, 1.5, NaN, '1', null]),
        )
      case 8:
        return new Uint8Array(below(70)).map(() => next())
      case 9:
        return new Int8Array(below(5))
      case 10:
        return newBig()
      case 11:
        return newPoint()
      case 12:
        return chance(5) ? 'x'.repeat(pick([8191, 8192, 70000])) : hostile()
      default:
        return hostile()
    }
  }

  const keyArg = () =>
    chance(40) ? pick([D, D2]) : chance(50) ? mutateHex(pick([D, D2])) : junk()
  const pubArg = () =>
    chance(40)
      ? pick([PUB, PUB2, COMPRESSED])
      : chance(50)
        ? mutateHex(pick([PUB, PUB2, COMPRESSED]))
        : junk()
  const idArg = () =>
    chance(50) ? pick(['id', '', 'alice', 'x'.repeat(8191)]) : junk()
  const msgArg = () => (chance(50) ? pick(['message', '', '国密']) : junk())
  const bigArg = () => (chance(70) ? newBig() : junk())
  const intArg = () => (chance(60) ? below(64) : junk())
  const anyArgs = (count) => () =>
    Array.from({ length: below(count + 2) }, junk)
  const rngArg = () => (chance(70) ? new SecureRandom() : junk())

  const fe = (v) => curve.fromBigInteger(v)
  const feArg = () => (chance(80) ? fe(newBig()) : junk())
  const makeSm3 = () => {
    const h = new SM3()
    if (chance(30)) h.update([1, 2, 3])
    if (chance(10)) h.digest()
    if (chance(10)) h.finish()
    return h
  }
  const makeSm4 = () => {
    const s = new SM4()
    if (chance(90)) s.setKey(SM4_KEY, SM4_KEY, true)
    return s
  }

  // [name, target factory, method or function, arguments, returns boolean]
  const F = []
  const fn = (name, f, args, boolean = false) =>
    F.push({ name, call: () => f(...args()), boolean })
  const method = (name, make, m, args, boolean = false) =>
    F.push({ name, call: () => make()[m](...args()), boolean })

  // ---- SM2 ----
  const S = 'SM2.'
  const sigArg = () => (chance(40) ? SIG : chance(50) ? mutateHex(SIG) : junk())
  const cipherArg = () =>
    chance(30) ? CIPHER : chance(60) ? mutateHex(CIPHER) : junk()
  method(
    S + 'sm2Encrypt',
    () => sm2,
    'sm2Encrypt',
    () => [msgArg(), pubArg()],
  )
  method(
    S + 'sm2Decrypt',
    () => sm2,
    'sm2Decrypt',
    () => [cipherArg(), keyArg()],
  )
  method(
    S + 'sm2DecryptBytes',
    () => sm2,
    'sm2DecryptBytes',
    () => [cipherArg(), keyArg()],
  )
  method(
    S + 'sm2Sign',
    () => sm2,
    'sm2Sign',
    () => [idArg(), keyArg(), msgArg()],
  )
  method(
    S + 'sm2VerifySign',
    () => sm2,
    'sm2VerifySign',
    () => [idArg(), sigArg(), msgArg(), pubArg()],
    true,
  )
  const lenArg = () => (chance(60) ? pick([1, 16, 33]) : junk())
  method(
    S + 'getSb',
    () => sm2,
    'getSb',
    () => [
      lenArg(),
      pubArg(),
      pubArg(),
      idArg(),
      idArg(),
      keyArg(),
      pubArg(),
      keyArg(),
      pubArg(),
    ],
  )
  const sbArg = () =>
    chance(50) ? EX.Sb : chance(50) ? mutateHex(EX.Sb) : junk()
  method(
    S + 'getSa',
    () => sm2,
    'getSa',
    () => [
      lenArg(),
      pubArg(),
      pubArg(),
      pubArg(),
      pubArg(),
      idArg(),
      idArg(),
      keyArg(),
      keyArg(),
      sbArg(),
    ],
  )
  method(
    S + 'checkSa',
    () => sm2,
    'checkSa',
    () => [
      chance(50) ? EX.V : mutateHex(EX.V),
      chance(50) ? EX.Za : junk(),
      chance(50) ? EX.Zb : junk(),
      pubArg(),
      chance(50) ? EX.Rb : junk(),
      sbArg(),
    ],
    true,
  )
  method(
    S + 'getPublicKeyFromPrivateKey',
    () => sm2,
    'getPublicKeyFromPrivateKey',
    () => [keyArg()],
  )
  method(
    S + 'getPoint',
    () => sm2,
    'getPoint',
    () => [],
  )
  method(
    S + 'userSM3Z',
    () => sm2,
    'userSM3Z',
    () => [pubArg(), idArg()],
  )
  method(
    S + '_calcX',
    () => sm2,
    '_calcX',
    () => [intArg(), bigArg()],
  )
  method(
    S + '_calcT',
    () => sm2,
    '_calcT',
    () => [chance(50) ? n : bigArg(), bigArg(), bigArg(), bigArg()],
  )
  method(
    S + '_calcPoint',
    () => sm2,
    '_calcPoint',
    () => [bigArg(), bigArg(), newPoint(), newPoint()],
  )
  method(
    S + '_createS',
    () => sm2,
    '_createS',
    () => [
      chance(50) ? 2 : junk(),
      newPoint(),
      junk(),
      junk(),
      newPoint(),
      newPoint(),
    ],
  )
  method(
    S + '_KDF',
    () => sm2,
    '_KDF',
    () => [lenArg(), newPoint(), junk(), junk()],
  )

  // ---- SM9 ----
  const sm9 = getSM9()
  const K9S = '1f2e3d4c5b6a79880102030405060708090a0b0c0d0e0f101112131415161718'
  const K9E = '2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819'
  const MPK9S = sm9.sm9SignMasterPublicKey(K9S)
  const MPK9E = sm9.sm9EncMasterPublicKey(K9E)
  const DS9 = sm9.sm9GenSignUserKey(K9S, 'id')
  const DE9 = sm9.sm9GenEncUserKey(K9E, 'id')
  const DX9A = sm9.sm9GenEncUserKey(K9E, 'a', 2)
  const DX9B = sm9.sm9GenEncUserKey(K9E, 'b', 2)
  const SIG9 = sm9.sm9Sign('message', DS9, MPK9S)
  const CT9 = sm9.sm9Encrypt('plaintext', 'id', MPK9E)
  const CT9_SM4 = sm9.sm9Encrypt('plaintext', 'id', MPK9E, 3, 'sm4')
  const KEM9 = sm9.sm9Encapsulate('id', MPK9E, 16)
  const XA9 = sm9.sm9ExchangeInit('b', MPK9E)
  const XB9 = sm9.sm9ExchangeInit('a', MPK9E)
  const XR9 = sm9.sm9ExchangeRespond(
    16,
    'a',
    'b',
    MPK9E,
    DX9B,
    XB9.r,
    XB9.R,
    XA9.R,
  )
  VALID_HEX.push(
    K9S,
    MPK9S,
    MPK9E,
    DS9,
    DE9,
    SIG9,
    CT9,
    KEM9.ciphertext,
    XR9.sB,
  )
  const T9 = 'SM9.'
  const pick9 = (valid) => () =>
    chance(40) ? pick(valid) : chance(50) ? mutateHex(pick(valid)) : junk()
  const mk9 = pick9([K9S, K9E])
  const mpkS9 = pick9([MPK9S])
  const mpkE9 = pick9([MPK9E])
  const ds9 = pick9([DS9])
  const de9 = pick9([DE9, DX9A, DX9B])
  const sig9 = pick9([SIG9])
  const ct9 = pick9([CT9, CT9_SM4])
  const kem9 = pick9([KEM9.ciphertext])
  const g1x9 = pick9([XA9.R, XB9.R, MPK9E])
  const r9 = pick9([XA9.r, XB9.r, K9S])
  const sb9 = pick9([XR9.sB, XR9.s2])
  const hid9 = () => (chance(70) ? pick([1, 2, 3, 0, 255]) : junk())
  const mode9 = () => (chance(70) ? pick(['stream', 'sm4']) : junk())
  const len9 = () => (chance(60) ? pick([1, 16, 33]) : junk())
  const id9 = () => (chance(50) ? pick(['id', 'a', 'b', '']) : idArg())
  const sm9Method = (name, args, boolean = false) =>
    method(T9 + name, () => sm9, name, args, boolean)
  sm9Method('sm9GenSignMasterKey', () => [])
  sm9Method('sm9GenEncMasterKey', () => [])
  sm9Method('sm9SignMasterPublicKey', () => [mk9()])
  sm9Method('sm9EncMasterPublicKey', () => [mk9()])
  sm9Method('sm9GenSignUserKey', () => [mk9(), id9(), hid9()])
  sm9Method('sm9GenEncUserKey', () => [mk9(), id9(), hid9()])
  sm9Method('sm9Sign', () => [msgArg(), ds9(), mpkS9()])
  sm9Method('sm9Verify', () => [msgArg(), sig9(), id9(), mpkS9(), hid9()], true)
  sm9Method('sm9Encrypt', () => [msgArg(), id9(), mpkE9(), hid9(), mode9()])
  sm9Method('sm9Decrypt', () => [ct9(), id9(), de9(), mode9()])
  sm9Method('sm9DecryptString', () => [ct9(), id9(), de9(), mode9()])
  sm9Method('sm9Encapsulate', () => [id9(), mpkE9(), len9(), hid9()])
  sm9Method('sm9Decapsulate', () => [kem9(), id9(), de9(), len9()])
  sm9Method('sm9ExchangeInit', () => [id9(), mpkE9(), hid9()])
  // The exchange steps report failure in the result and must never throw.
  fn(
    T9 + 'sm9ExchangeRespond',
    (...a) => sm9.sm9ExchangeRespond(...a).success,
    () => [len9(), id9(), id9(), mpkE9(), de9(), r9(), g1x9(), g1x9()],
    true,
  )
  fn(
    T9 + 'sm9ExchangeConfirm',
    (...a) => sm9.sm9ExchangeConfirm(...a).success,
    () => [len9(), id9(), id9(), mpkE9(), de9(), r9(), g1x9(), g1x9(), sb9()],
    true,
  )
  sm9Method('sm9ExchangeCheck', () => [sb9(), sb9()], true)

  // ---- sm2/utils ----
  fn('utils.getGlobalCurve', util.getGlobalCurve, () => [])
  fn('utils.generateEcparam', util.generateEcparam, () => [])
  fn('utils.generateKeyPairHex', util.generateKeyPairHex, () => [])
  fn('utils.compressPublicKeyHex', util.compressPublicKeyHex, () => [pubArg()])
  fn('utils.verifyPublicKey', util.verifyPublicKey, () => [pubArg()], true)
  fn(
    'utils.comparePublicKeyHex',
    util.comparePublicKeyHex,
    () => [pubArg(), pubArg()],
    true,
  )
  fn('utils.hexToArray', util.hexToArray, () => [junk()])
  fn('utils.arrayToHex', util.arrayToHex, () => [junk()])
  fn('utils.bytes2hex', util.bytes2hex, () => [junk()])
  fn('utils.hexToBytes', util.hexToBytes, () => [junk()])
  fn('utils.stringToBytes', util.stringToBytes, () => [junk()])
  fn('utils.bytesToUTF8String', util.bytesToUTF8String, () => [junk()])
  fn('utils.leftPad', util.leftPad, () => [
    junk(),
    chance(90) ? below(100) : junk(),
  ])

  // ---- common/utils ----
  fn('common.stringToBytes', common.stringToBytes, () => [junk()])
  fn('common.bytesToString', common.bytesToString, () => [junk()])
  fn('common.bytesToHex', common.bytesToHex, () => [junk()])
  fn('common.hexToBytes', common.hexToBytes, () => [junk()])
  fn('common.intToBytesBE', common.intToBytesBE, () => [
    junk(),
    new Uint8Array(4),
    chance(80) ? 0 : junk(),
  ])
  fn('common.bytesToIntBE', common.bytesToIntBE, () => [
    junk(),
    chance(80) ? 0 : junk(),
  ])
  fn('common.leftPad', common.leftPad, () => [
    junk(),
    chance(90) ? below(100) : junk(),
  ])

  // ---- SM3 ----
  const dataArg = () => (chance(40) ? new Uint8Array(below(200)) : junk())
  method('SM3.update', makeSm3, 'update', () => [dataArg()])
  method('SM3.updateString', makeSm3, 'updateString', () => [msgArg()])
  method('SM3.updateBytes', makeSm3, 'updateBytes', () => [
    dataArg(),
    intArg(),
    intArg(),
  ])
  method('SM3.digest', makeSm3, 'digest', () => [])
  method('SM3.hexDigest', makeSm3, 'hexDigest', () => [])
  method('SM3.finish', makeSm3, 'finish', () => [])
  method('SM3.getHashCode', makeSm3, 'getHashCode', () => [])
  method('SM3.getHashBytes', makeSm3, 'getHashBytes', () => [])
  fn(
    'SM3.hash',
    (a) => SM3.hash(a),
    () => [msgArg()],
  )
  fn(
    'SM3.hashHex',
    (a) => SM3.hashHex(a),
    () => [msgArg()],
  )
  fn(
    'new SM3',
    () => new SM3(),
    () => [],
  )
  fn('getSM3', getSM3, () => [])

  // ---- SM4 ----
  const sm4Key = () =>
    chance(40)
      ? SM4_KEY
      : chance(40)
        ? mutateHex(SM4_KEY)
        : chance(30)
          ? 'k'.repeat(16)
          : junk()
  method(
    'SM4.setKey',
    () => new SM4(),
    'setKey',
    () => [sm4Key(), sm4Key(), chance(50) ? true : junk()],
  )
  method('SM4.encrypt', makeSm4, 'encrypt', () => [msgArg()])
  method('SM4.decrypt', makeSm4, 'decrypt', () => [
    chance(30) ? SM4_CIPHER : chance(60) ? mutateHex(SM4_CIPHER) : junk(),
  ])
  method('SM4.decryptBytes', makeSm4, 'decryptBytes', () => [
    chance(30) ? SM4_CIPHER : chance(60) ? mutateHex(SM4_CIPHER) : junk(),
  ])
  method('SM4._expandKey', makeSm4, '_expandKey', () => [junk()])
  method('SM4._encryptBlock', makeSm4, '_encryptBlock', () => [
    junk(),
    new Uint8Array(16),
    chance(80) ? 0 : junk(),
  ])
  method('SM4._decryptBlock', makeSm4, '_decryptBlock', () => [
    junk(),
    chance(80) ? 0 : junk(),
    new Uint8Array(16),
    chance(80) ? 0 : junk(),
  ])
  fn('getSM4', getSM4, () => [])

  // ---- curve and points ----
  const curves = [
    () => curve,
    () =>
      new ECCurveFp(
        new BigInteger('61', 16),
        new BigInteger('2', 16),
        new BigInteger('3', 16),
      ),
    () => new ECCurveFp(newBig(), newBig(), newBig()),
  ]
  const anyCurve = () => pick(curves)()
  fn(
    'new ECCurveFp',
    (a, b, c) => new ECCurveFp(a, b, c),
    () => [bigArg(), bigArg(), bigArg()],
  )
  method('curve.decodePointHex', anyCurve, 'decodePointHex', () => [pubArg()])
  method('curve.fromBigInteger', anyCurve, 'fromBigInteger', () => [junk()])
  method('curve.equals', anyCurve, 'equals', () => [anyCurve()])
  method('curve.getInfinity', anyCurve, 'getInfinity', () => [])
  method('curve.validatePoint', anyCurve, 'validatePoint', () => [
    feArg(),
    feArg(),
  ])
  method('curve.checkPoints', anyCurve, 'checkPoints', () => [
    junk(),
    junk(),
    junk(),
  ])
  fn(
    'new ECPointFp',
    (a, b, c, d) => new ECPointFp(a, b, c, d),
    () => [curve, feArg(), feArg(), junk()],
  )
  const pointMethods = {
    isValid: () => [],
    getX: () => [],
    getY: () => [],
    equals: () => [newPoint()],
    isInfinity: () => [],
    negate: () => [],
    add: () => [chance(90) ? newPoint() : junk()],
    twice: () => [],
    subtract: () => [chance(90) ? newPoint() : junk()],
    timesPow2: () => [chance(90) ? below(20) : junk()],
    multiply: () => [bigArg()],
    _multiplyPublic: () => [bigArg()],
  }
  for (const [m, args] of Object.entries(pointMethods)) {
    method(`point.${m}`, newPoint, m, args)
  }
  const fieldMethods = {
    equals: () => [feArg()],
    toBigInteger: () => [],
    isZero: () => [],
    negate: () => [],
    add: () => [feArg()],
    subtract: () => [feArg()],
    multiply: () => [feArg()],
    divide: () => [feArg()],
    square: () => [],
  }
  for (const [m, args] of Object.entries(fieldMethods)) {
    method(`field.${m}`, () => fe(newBig()), m, args)
  }

  // ---- BigInteger, including its low-level mutators ----
  fn('new BigInteger', (a, b, c) => new BigInteger(a, b, c), anyArgs(3))
  fn(
    'new BigInteger(bits, rng)',
    (a, b) => new BigInteger(a, b),
    () => [chance(80) ? below(512) : junk(), rngArg()],
  )
  fn(
    'new BigInteger(bits, certainty, rng)',
    (a, b, c) => new BigInteger(a, b, c),
    () => [
      chance(90) ? below(48) : junk(),
      chance(90) ? below(8) : junk(),
      rngArg(),
    ],
  )
  fn(
    'new BigInteger(string, radix)',
    (a, b) => new BigInteger(a, b),
    () => [
      chance(70) ? randomHex(below(80)) : junk(),
      chance(80) ? pick([2, 4, 8, 10, 16, 32, 36]) : junk(),
    ],
  )
  fn(
    'BigInteger.nbi',
    () => BigInteger.nbi(),
    () => [],
  )
  fn(
    'BigInteger.nbv',
    (a) => BigInteger.nbv(a),
    () => [junk()],
  )
  const noArg = () => []
  const oneBig = () => [bigArg()]
  const toR = () => [newBig()]
  const bigMethods = {
    copyTo: toR,
    fromInt: () => [junk()],
    fromString: () => [junk(), junk()],
    clamp: noArg,
    toString: () => [chance(80) ? pick([2, 4, 8, 10, 16, 32, 36]) : junk()],
    toRadix: () => [chance(80) ? pick([2, 10, 16, 36]) : junk()],
    fromRadix: () => [junk(), junk()],
    fromNumber: () => [junk(), rngArg(), junk()],
    toByteArray: noArg,
    negate: noArg,
    abs: noArg,
    clone: noArg,
    compareTo: oneBig,
    equals: oneBig,
    min: oneBig,
    max: oneBig,
    signum: noArg,
    intValue: noArg,
    byteValue: noArg,
    shortValue: noArg,
    chunkSize: () => [junk()],
    isEven: noArg,
    bitLength: noArg,
    dlShiftTo: () => [intArg(), newBig()],
    drShiftTo: () => [intArg(), newBig()],
    lShiftTo: () => [intArg(), newBig()],
    rShiftTo: () => [intArg(), newBig()],
    shiftLeft: () => [intArg()],
    shiftRight: () => [intArg()],
    addTo: () => [bigArg(), newBig()],
    subTo: () => [bigArg(), newBig()],
    multiplyTo: () => [bigArg(), newBig()],
    squareTo: toR,
    divRemTo: () => [bigArg(), newBig(), newBig()],
    add: oneBig,
    subtract: oneBig,
    multiply: oneBig,
    square: noArg,
    divide: oneBig,
    remainder: oneBig,
    divideAndRemainder: oneBig,
    mod: oneBig,
    dMultiply: () => [junk()],
    dAddOffset: () => [junk(), junk()],
    bitwiseTo: () => [bigArg(), (x, y) => x ^ y, newBig()],
    and: oneBig,
    or: oneBig,
    xor: oneBig,
    andNot: oneBig,
    not: noArg,
    getLowestSetBit: noArg,
    bitCount: noArg,
    testBit: () => [junk()],
    changeBit: () => [intArg(), (x, y) => x | y],
    setBit: () => [intArg()],
    clearBit: () => [intArg()],
    flipBit: () => [intArg()],
    invDigit: noArg,
    modPowInt: () => [junk(), bigArg()],
    exp: () => [junk(), junk()],
    modPow: () => [bigArg(), bigArg()],
    modInverse: oneBig,
    pow: () => [chance(80) ? below(40) : junk()],
    gcd: oneBig,
    modInt: () => [junk()],
    isProbablePrime: () => [chance(80) ? below(8) : junk()],
    millerRabin: () => [chance(80) ? below(8) : junk()],
    multiplyLowerTo: () => [bigArg(), intArg(), newBig()],
    multiplyUpperTo: () => [bigArg(), intArg(), newBig()],
    am: () => [
      intArg(),
      junk(),
      [],
      intArg(),
      junk(),
      chance(90) ? below(30) : junk(),
    ],
  }
  for (const [m, args] of Object.entries(bigMethods)) {
    method(`BigInteger.${m}`, newBig, m, args)
  }
  method(
    'SecureRandom.nextBytes',
    () => new SecureRandom(),
    'nextBytes',
    () => [junk()],
  )

  // ---- sanity: shared buffers and constants must survive anything above ----
  function sanity() {
    const k = util.generateKeyPairHex()
    const sig = sm2.sm2Sign('id', k.privateKey, 'm')
    if (!sm2.sm2VerifySign('id', sig, 'm', k.publicKey)) return 'sign/verify'
    if (
      sm2.sm2Decrypt(sm2.sm2Encrypt('m', k.publicKey), k.privateKey) !== 'm'
    ) {
      return 'encrypt/decrypt'
    }
    if (sm2.getPublicKeyFromPrivateKey(D) !== PUB) return 'public key'
    if (
      SM3.hashHex('abc') !==
      '66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0'
    ) {
      return 'sm3'
    }
    if (
      new SM4().setKey(SM4_KEY, SM4_KEY, true).encrypt('hello') !== SM4_CIPHER
    ) {
      return 'sm4'
    }
    if (!BigInteger.ZERO.equals(new BigInteger('0', 16))) return 'ZERO'
    if (!BigInteger.ONE.equals(new BigInteger('1', 16))) return 'ONE'
    if (w !== 127 || !n.isProbablePrime(4)) return 'params'
    if (!sm9.sm9Verify('message', SIG9, 'id', MPK9S)) return 'sm9 verify'
    if (sm9.sm9DecryptString(CT9, 'id', DE9) !== 'plaintext')
      return 'sm9 decrypt'
    if (sm9.sm9SignMasterPublicKey(K9S) !== MPK9S) return 'sm9 master key'
    return null
  }

  const ENGINE_ERROR =
    /Cannot read|is not a function|is not iterable|Cannot convert|Maximum call stack/
  const STRICT =
    /^(SM9\.|SM2\.(sm2|get|check|userSM3Z)|utils\.|SM3\.(update|digest|hexDigest|finish|hash)|SM4\.(setKey|encrypt|decrypt|decryptBytes)|curve\.decodePointHex)/
  const failures = []
  let calls = 0
  const onlyRe = only ? new RegExp(only) : null
  for (let index = 0; index < F.length; index++) {
    const { name, call, boolean } = F[index]
    if (index % shards !== shard) continue
    if (onlyRe && !onlyRe.test(name)) continue
    Atomics.store(shared, 1, index)
    parentPort.postMessage({ current: name })
    let functionFailures = 0
    for (let i = 0; i < cases; i++) {
      reseed(name, i)
      Atomics.store(shared, 2, i)
      Atomics.add(shared, 0, 1)
      calls++
      try {
        const result = call()
        if (boolean && typeof result !== 'boolean') {
          throw Object.assign(new Error(`returned ${typeof result}`), {
            fatal: true,
          })
        }
      } catch (e) {
        const hostileError =
          e instanceof Error && e.message.startsWith('hostile')
        const bad =
          e?.fatal ||
          !(e instanceof Error) ||
          (boolean && !hostileError) ||
          (!hostileError &&
            STRICT.test(name) &&
            ENGINE_ERROR.test(e.message)) ||
          /Maximum call stack/.test(e.message)
        if (bad && functionFailures++ < 3) {
          failures.push(
            `${name} case ${i}: ${e?.name}: ${String(e?.message).slice(0, 120)}`,
          )
        }
      }
      if (i % SANITY_EVERY === SANITY_EVERY - 1) {
        const broken = sanity()
        if (broken)
          failures.push(`${name} case ${i}: library state broken: ${broken}`)
      }
    }
    const broken = sanity()
    if (broken) failures.push(`${name}: library state broken: ${broken}`)
    if (functionFailures)
      failures.push(`${name}: ${functionFailures} failing cases`)
    parentPort.postMessage({
      log: `${name}: ${cases} cases, ${functionFailures} failing`,
    })
  }
  for (const f of failures) parentPort.postMessage({ log: `[FAIL] ${f}` })
  parentPort.postMessage({ done: true, calls, failures: failures.length })
}
