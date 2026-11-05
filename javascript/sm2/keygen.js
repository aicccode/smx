/**
 * Key pair generation shared by the public API and the signing nonce.
 *
 * Internal module, not part of the public API.
 */
import { BigInteger, SecureRandom } from './biginteger.js'
import { bigToBytes } from './bytes.js'
import { mulG } from './point.js'

const rng = new SecureRandom()
const TWO = BigInteger.nbv(2)
const N = new BigInteger(
  'fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123',
  16,
)
const N_BITS = 256
const MIN_NAF_WEIGHT = N_BITS >>> 2

function nafWeight(k) {
  return k.signum() === 0 ? 0 : k.shiftLeft(1).add(k).xor(k).bitCount()
}

/**
 * Draws d in [2, n - 1] with NAF weight at least n.bitLength() / 4, and computes
 * d * G. Returns the scalar and the public point as bytes.
 */
export function generateKeyMaterial() {
  let d
  do {
    d = new BigInteger(N_BITS, rng)
  } while (
    d.compareTo(TWO) < 0 ||
    d.compareTo(N) >= 0 ||
    nafWeight(d) < MIN_NAF_WEIGHT
  )
  const dBytes = bigToBytes(d, new Uint8Array(32))
  const x = new Uint8Array(32)
  const y = new Uint8Array(32)
  mulG(dBytes, x, y)
  return { d, dBytes, x, y }
}
