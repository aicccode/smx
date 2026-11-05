/**
 * Hex tables and strict decoding shared inside this package.
 *
 * Internal module, not part of the public API: common/utils.js is re-exported
 * from index.js, so these helpers must not live there.
 */

/** "00" to "ff" */
export const HEX_PAIRS = Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, '0'),
)

export const HEX_CODES = new Uint8Array(512)
for (let i = 0; i < 256; i++) {
  HEX_CODES[2 * i] = HEX_PAIRS[i].charCodeAt(0)
  HEX_CODES[2 * i + 1] = HEX_PAIRS[i].charCodeAt(1)
}

/** Char code to hex value, or 255 for anything that is not a hex digit. */
const HEX_VALUES = new Uint8Array(256).fill(255)
for (let i = 0; i < 16; i++) {
  HEX_VALUES['0123456789abcdef'.charCodeAt(i)] = i
  HEX_VALUES['0123456789ABCDEF'.charCodeAt(i)] = i
}

/**
 * Decodes an even-length string of hex digits, or returns null if any other
 * character appears. Callers fall back to parseHexPair.
 */
export function decodeStrictHex(hex) {
  const n = hex.length >>> 1
  const out = new Uint8Array(n)
  let bad = 0
  for (let i = 0; i < n; i++) {
    const a = hex.charCodeAt(2 * i)
    const b = hex.charCodeAt(2 * i + 1)
    if ((a | b) > 255) return null
    const high = HEX_VALUES[a]
    const low = HEX_VALUES[b]
    bad |= high | low
    out[i] = (high << 4) | low
  }
  return bad > 15 ? null : out
}

/** The historical parse of a malformed pair, kept for its exact results. */
export function parseHexPair(hex, index) {
  return parseInt(hex.substring(2 * index, 2 * index + 2), 16)
}
