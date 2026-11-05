/**
 * Secret scalar generation shared by the public API and the signing nonce.
 *
 * Internal module, not part of the public API.
 */
import { randomFill } from '../common/rng.js'
import { mulG } from './point.js'
import { isValidPrivateScalar } from './scalar.js'

/**
 * A rejection is a 2^-32 event for a working generator, so running out of attempts
 * means that the source is broken, for example returning all zeros.
 */
const MAX_DRAWS = 64

/**
 * Draws d uniformly from [1, n - 2] by rejection sampling on the OS CSPRNG, and
 * computes d * G. The same range is used for nonces: leaving out n - 1 changes
 * their distribution by 2^-256.
 * @returns {{dBytes: Uint8Array, x: Uint8Array, y: Uint8Array}}
 */
export function generateKeyMaterial() {
  const dBytes = new Uint8Array(32)
  for (let draw = 0; draw < MAX_DRAWS; draw++) {
    randomFill(dBytes)
    if (isValidPrivateScalar(dBytes)) {
      const x = new Uint8Array(32)
      const y = new Uint8Array(32)
      mulG(dBytes, x, y)
      return { dBytes, x, y }
    }
  }
  dBytes.fill(0)
  throw new Error('Random source failed to produce a valid scalar')
}
