/**
 * Operating system CSPRNG access. Internal module, not part of the public API.
 *
 * Web Crypto is used where it exists. Node.js versions without a global `crypto`
 * use node:crypto, loaded here because it can only be imported asynchronously. If
 * neither exists, randomFill throws: there is deliberately no weaker fallback.
 */
const WEB_CRYPTO_MAX_BYTES = 65536

let nodeCrypto = null
if (typeof globalThis.crypto?.getRandomValues !== 'function') {
  try {
    const specifier = 'node:crypto'
    nodeCrypto = await import(
      /* webpackIgnore: true */ /* @vite-ignore */ specifier
    )
  } catch {
    nodeCrypto = null
  }
}

/**
 * Fills a Uint8Array with random bytes from the OS.
 * @param {Uint8Array} out
 * @returns {Uint8Array} out
 */
export function randomFill(out) {
  const webCrypto = globalThis.crypto
  if (typeof webCrypto?.getRandomValues === 'function') {
    for (let i = 0; i < out.length; i += WEB_CRYPTO_MAX_BYTES) {
      const end = Math.min(i + WEB_CRYPTO_MAX_BYTES, out.length)
      webCrypto.getRandomValues(out.subarray(i, end))
    }
    return out
  }
  if (typeof nodeCrypto?.randomFillSync === 'function') {
    nodeCrypto.randomFillSync(out)
    return out
  }
  throw new Error('No secure random source is available')
}
