/**
 * Hex and byte validation helpers. Internal module, not part of the public API.
 *
 * Hex values may be secret (keys, nonces), so encoding and decoding use arithmetic
 * masks, with no branch or table lookup that depends on a digit. Only the final
 * valid or invalid result is branched on.
 */

/** Value of a hex digit, or a negative number for anything else. */
function digitValue(c) {
  const digit = c - 48
  const letter = (c | 32) - 97
  const notDigit = (digit | (9 - digit)) >> 31
  const notLetter = (letter | (5 - letter)) >> 31
  return (
    (digit & ~notDigit) | ((letter + 10) & ~notLetter) | (notDigit & notLetter)
  )
}

/**
 * Decodes a string of an even number of hex digits, in either case.
 * @param {string} hex
 * @returns {Uint8Array|null} null unless the whole string is valid
 */
export function decodeHex(hex) {
  if (typeof hex !== 'string' || (hex.length & 1) !== 0) return null
  const n = hex.length >>> 1
  const out = new Uint8Array(n)
  let bad = 0
  for (let i = 0; i < n; i++) {
    const high = digitValue(hex.charCodeAt(2 * i))
    const low = digitValue(hex.charCodeAt(2 * i + 1))
    bad |= high | low
    out[i] = (high << 4) | low
  }
  if (bad < 0) {
    out.fill(0)
    return null
  }
  return out
}

/**
 * Decodes the canonical form of data this library emits: lowercase only, so that one
 * signature or ciphertext has exactly one accepted string. A dedup or replay cache
 * keyed on the string cannot be bypassed by changing case.
 * @param {string} hex
 * @returns {Uint8Array|null} null unless the whole string is valid
 */
export function decodeLowerHex(hex) {
  if (typeof hex !== 'string' || (hex.length & 1) !== 0) return null
  const n = hex.length >>> 1
  const out = new Uint8Array(n)
  let bad = 0
  for (let i = 0; i < n; i++) {
    const high = lowerDigitValue(hex.charCodeAt(2 * i))
    const low = lowerDigitValue(hex.charCodeAt(2 * i + 1))
    bad |= high | low
    out[i] = (high << 4) | low
  }
  return bad < 0 ? null : out
}

function lowerDigitValue(c) {
  const digit = c - 48
  const letter = c - 97
  const notDigit = (digit | (9 - digit)) >> 31
  const notLetter = (letter | (5 - letter)) >> 31
  return (
    (digit & ~notDigit) | ((letter + 10) & ~notLetter) | (notDigit & notLetter)
  )
}

const decoder = new TextDecoder('utf-8')
const FROM_CHAR_CODE_LIMIT = 4096

/** Lowercase hex of a Uint8Array. */
export function encodeHex(bytes) {
  const n = bytes.length
  const codes = new Uint8Array(2 * n)
  for (let i = 0; i < n; i++) {
    const b = bytes[i]
    const high = b >>> 4
    const low = b & 15
    codes[2 * i] = high + 48 + (((9 - high) >> 31) & 39)
    codes[2 * i + 1] = low + 48 + (((9 - low) >> 31) & 39)
  }
  return codes.length <= FROM_CHAR_CODE_LIMIT
    ? String.fromCharCode.apply(null, codes)
    : decoder.decode(codes)
}

const typedArrayTag = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  Symbol.toStringTag,
).get

const SIGNED_BYTE_MIN = -128
const UNSIGNED_BYTE_MAX = 255

/**
 * Accepts a Uint8Array (returned as is), an Int8Array, or an array of integers in
 * [-128, 255], the historical signed-byte form. Anything else would have to be
 * silently truncated to be used as bytes, so it throws.
 * @returns {Uint8Array}
 */
export function toByteArray(data) {
  if (data instanceof Uint8Array) return data
  const tag = typedArrayTag.call(data)
  // The tag also recognises typed arrays from other realms, such as an iframe.
  if (tag === 'Uint8Array') return data
  if (tag === 'Int8Array') {
    return new Uint8Array(data.buffer, data.byteOffset, data.length)
  }
  if (!Array.isArray(data)) throw new TypeError('Expected a byte array')
  for (let i = 0; i < data.length; i++) {
    const v = data[i]
    if (!Number.isInteger(v) || v < SIGNED_BYTE_MIN || v > UNSIGNED_BYTE_MAX) {
      throw new TypeError('Expected a byte array')
    }
  }
  return Uint8Array.from(data)
}

const LONE_SURROGATE = /\p{Surrogate}/u

/**
 * Throws on a non-string or a string with unpaired surrogates. UTF-8 encoding would
 * replace those with U+FFFD, so distinct strings would hash and sign identically.
 */
export function requireWellFormedString(s) {
  if (typeof s !== 'string') throw new TypeError('Expected a string')
  if (LONE_SURROGATE.test(s)) {
    throw new TypeError('String contains an unpaired surrogate')
  }
}
