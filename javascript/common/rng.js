/**
 * Operating system CSPRNG access. Internal module, not part of the public API.
 *
 * The source is chosen once, at load. Web Crypto is used where the platform provides
 * it. Lookups stop before Object.prototype, so a polluted prototype cannot supply a
 * fake generator, and later changes to globals have no effect. Node.js versions with
 * no global `crypto` use node:crypto, which can only be imported asynchronously. If
 * neither exists, filling throws: there is deliberately no weaker fallback.
 */
const WEB_CRYPTO_MAX_BYTES = 65536

/** Property value found on the object or its prototypes, excluding Object.prototype. */
function ownChainValue(object, key) {
  let holder = object
  while (holder !== null && holder !== Object.prototype) {
    const descriptor = Object.getOwnPropertyDescriptor(holder, key)
    if (descriptor !== undefined) {
      return 'value' in descriptor
        ? descriptor.value
        : descriptor.get?.call(object)
    }
    holder = Object.getPrototypeOf(holder)
  }
  return undefined
}

function findWebCrypto(globalObject) {
  const webCrypto = ownChainValue(globalObject, 'crypto')
  if (webCrypto === null || typeof webCrypto !== 'object') return null
  const generate = ownChainValue(webCrypto, 'getRandomValues')
  if (typeof generate !== 'function') return null
  return { webCrypto, generate }
}

/**
 * Builds the fill function for given platform objects. Exported for tests.
 * @returns {(out: Uint8Array) => Uint8Array}
 */
export function createRandomFill(globalObject, nodeCrypto) {
  const found = findWebCrypto(globalObject)
  if (found !== null) {
    const { webCrypto, generate } = found
    return (out) => {
      for (let i = 0; i < out.length; i += WEB_CRYPTO_MAX_BYTES) {
        const end = Math.min(i + WEB_CRYPTO_MAX_BYTES, out.length)
        generate.call(webCrypto, out.subarray(i, end))
      }
      return out
    }
  }
  const fill = nodeCrypto === null ? undefined : nodeCrypto.randomFillSync
  if (typeof fill === 'function') {
    return (out) => {
      fill(out)
      return out
    }
  }
  return () => {
    throw new Error('No secure random source is available')
  }
}

let nodeCrypto = null
if (findWebCrypto(globalThis) === null) {
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
export const randomFill = createRandomFill(globalThis, nodeCrypto)
