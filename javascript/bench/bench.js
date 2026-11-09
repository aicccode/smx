/**
 * Benchmark for SM2/SM3/SM4/SM9 using only the public API and no dependencies.
 *
 *   node bench/bench.js [libraryRoot] [--rounds=N] [--ms=N] [--json] [--only=regex]
 *
 * libraryRoot defaults to this package, so the same script can measure another
 * copy of the library. Each case reports the best of N timed rounds.
 */
import { resolve, dirname } from 'node:path'
import { performance } from 'node:perf_hooks'
import { fileURLToPath, pathToFileURL } from 'node:url'

const args = process.argv.slice(2)
const flag = (name, dflt) => {
  const hit = args.find((a) => a.startsWith(`--${name}=`))
  return hit ? Number(hit.split('=')[1]) : dflt
}
const root = resolve(
  args.find((a) => !a.startsWith('--')) ??
    resolve(dirname(fileURLToPath(import.meta.url)), '..'),
)
const ROUNDS = flag('rounds', 5)
const ROUND_MS = flag('ms', 300)
const JSON_OUT = args.includes('--json')
const ONLY = args.find((a) => a.startsWith('--only='))?.slice(7)
const onlyRe = ONLY ? new RegExp(ONLY) : null

const load = (p) => import(pathToFileURL(resolve(root, p)).href)
const { SM3 } = await load('sm3/sm3.js')
const { SM4 } = await load('sm4/sm4.js')
const { getSM2 } = await load('sm2/sm2.js')
const util = await load('sm2/utils.js')
const sm9Module = await load('sm9/sm9.js').catch(() => null)

let sink = 0
const results = []

function bench(name, fn, bytes = 0) {
  if (onlyRe && !onlyRe.test(name)) return
  let best = 0
  for (let r = 0; r < ROUNDS; r++) {
    let n = 0
    const start = performance.now()
    let now = start
    do {
      sink ^= fn() ? 1 : 0
      n++
      now = performance.now()
    } while (now - start < ROUND_MS)
    best = Math.max(best, n / ((now - start) / 1000))
  }
  results.push({ name, opsPerSec: best, bytes })
  if (!JSON_OUT) {
    const mb = bytes ? `  ${((best * bytes) / 1e6).toFixed(1)} MB/s` : ''
    const us = 1e6 / best
    console.log(
      `${name.padEnd(24)} ${best.toFixed(1).padStart(12)} ops/s ${us.toFixed(2).padStart(12)} us/op${mb}`,
    )
  }
}

// ---- SM3 ----
for (const [label, size] of [
  ['64B', 64],
  ['1KB', 1024],
  ['1MB', 1048576],
]) {
  const data = new Uint8Array(size).map((_, i) => i & 0xff)
  bench(`sm3 ${label}`, () => new SM3().update(data).digest()[0], size)
}

// ---- SM4 ----
const KEY = '0123456789abcdeffedcba9876543210'
const IV = '00112233445566778899aabbccddeeff'
const sm4 = new SM4().setKey(KEY, IV, true)
bench('sm4 key schedule', () => new SM4().setKey(KEY, IV, true))
for (const [label, size] of [
  ['16B', 15],
  ['1KB', 1023],
  ['1MB', 1048575],
]) {
  const text = 'a'.repeat(size)
  const cipher = sm4.encrypt(text)
  bench(`sm4 encrypt ${label}`, () => sm4.encrypt(text).length, size + 1)
  bench(`sm4 decrypt ${label}`, () => sm4.decrypt(cipher).length, size + 1)
}

// ---- SM2 ----
const D = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8'
const sm2 = getSM2()
const PUB = sm2.getPublicKeyFromPrivateKey(D)
const MSG = 'message digest'
const ID = '1234567812345678'
const SIG = sm2.sm2Sign(ID, D, MSG)
const CIPHER = sm2.sm2Encrypt(MSG, PUB)

const DB = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8'
const RA = '81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029'
const RB = '7fb1f3a6c7a4d3d94cfa6c2a0d6c0e5a48e6e5a1b5f3c9d27a6e0f1b3c4d5e6f'
const DA = '6fcba2ef9ae0ab902bc3bde3ff915d44ba4cc78f88e2f8e7f8996d3b8cceedee'
const PA = sm2.getPublicKeyFromPrivateKey(DA)
const PB = sm2.getPublicKeyFromPrivateKey(DB)
const RAH = sm2.getPublicKeyFromPrivateKey(RA)
const RBH = sm2.getPublicKeyFromPrivateKey(RB)
const IDA = 'alice@example.com'
const IDB = 'bob@example.com'

bench('sm2 keygen', () => util.generateKeyPairHex().publicKey)
bench('sm2 pubkey from priv', () => sm2.getPublicKeyFromPrivateKey(D))
bench('sm2 sign', () => sm2.sm2Sign(ID, D, MSG))
bench('sm2 verify', () => sm2.sm2VerifySign(ID, SIG, MSG, PUB))
bench('sm2 encrypt', () => sm2.sm2Encrypt(MSG, PUB))
bench('sm2 decrypt', () => sm2.sm2Decrypt(CIPHER, D))
bench(
  'sm2 key exchange',
  () => sm2.getSb(16, PA, RAH, IDA, IDB, DB, PB, RB, RBH).Kb.length,
)

// ---- SM9 (skipped when libraryRoot has no SM9) ----
if (sm9Module !== null) {
  const sm9 = sm9Module.getSM9()
  const KS = '1f2e3d4c5b6a79880102030405060708090a0b0c0d0e0f101112131415161718'
  const KE = '2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819'
  const MPK_S = sm9.sm9SignMasterPublicKey(KS)
  const MPK_E = sm9.sm9EncMasterPublicKey(KE)
  const DS = sm9.sm9GenSignUserKey(KS, 'alice@example.com')
  const DE = sm9.sm9GenEncUserKey(KE, 'bob@example.com')
  const SIG9 = sm9.sm9Sign(MSG, DS, MPK_S)
  const CT9 = sm9.sm9Encrypt(MSG, 'bob@example.com', MPK_E)
  const CT9_SM4 = sm9.sm9Encrypt(MSG, 'bob@example.com', MPK_E, 3, 'sm4')
  const KEM9 = sm9.sm9Encapsulate('bob@example.com', MPK_E, 32)
  const DA9 = sm9.sm9GenEncUserKey(KE, IDA, 2)
  const DB9 = sm9.sm9GenEncUserKey(KE, IDB, 2)
  const XA = sm9.sm9ExchangeInit(IDB, MPK_E)
  const XB = sm9.sm9ExchangeInit(IDA, MPK_E)
  const XR = sm9.sm9ExchangeRespond(16, IDA, IDB, MPK_E, DB9, XB.r, XB.R, XA.R)

  bench('sm9 sign master keygen', () => sm9.sm9GenSignMasterKey().publicKey)
  bench('sm9 sign user key', () =>
    sm9.sm9GenSignUserKey(KS, 'alice@example.com'),
  )
  bench('sm9 enc user key', () => sm9.sm9GenEncUserKey(KE, 'bob@example.com'))
  bench('sm9 sign', () => sm9.sm9Sign(MSG, DS, MPK_S))
  bench('sm9 verify', () =>
    sm9.sm9Verify(MSG, SIG9, 'alice@example.com', MPK_S),
  )
  bench('sm9 encrypt', () => sm9.sm9Encrypt(MSG, 'bob@example.com', MPK_E))
  bench('sm9 decrypt', () => sm9.sm9Decrypt(CT9, 'bob@example.com', DE).length)
  bench('sm9 encrypt sm4', () =>
    sm9.sm9Encrypt(MSG, 'bob@example.com', MPK_E, 3, 'sm4'),
  )
  bench(
    'sm9 decrypt sm4',
    () => sm9.sm9Decrypt(CT9_SM4, 'bob@example.com', DE, 'sm4').length,
  )
  bench(
    'sm9 encapsulate',
    () => sm9.sm9Encapsulate('bob@example.com', MPK_E, 32).key,
  )
  bench('sm9 decapsulate', () =>
    sm9.sm9Decapsulate(KEM9.ciphertext, 'bob@example.com', DE, 32),
  )
  bench('sm9 exchange init', () => sm9.sm9ExchangeInit(IDB, MPK_E).R)
  bench(
    'sm9 exchange respond',
    () =>
      sm9.sm9ExchangeRespond(16, IDA, IDB, MPK_E, DB9, XB.r, XB.R, XA.R)
        .success,
  )
  bench(
    'sm9 exchange confirm',
    () =>
      sm9.sm9ExchangeConfirm(16, IDA, IDB, MPK_E, DA9, XA.r, XA.R, XB.R, XR.sB)
        .success,
  )
}

if (JSON_OUT) console.log(JSON.stringify(results))
if (sink === 0.5) console.log(sink)
