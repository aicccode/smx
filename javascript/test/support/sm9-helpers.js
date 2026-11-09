/**
 * Shared helpers of the SM9 tests: vectors, counters and small utilities.
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { encodeHex } from '../../common/hex.js'
import * as api from '../../index.js'
import { getSM9 } from '../../sm9/sm9.js'

const here = dirname(fileURLToPath(import.meta.url))
export const V = JSON.parse(
  readFileSync(resolve(here, '../../../testvectors/sm9-vectors.json'), 'utf8'),
)

const counts = { passed: 0, failed: 0 }
export function ok(name, condition, detail = '') {
  if (condition) counts.passed++
  else {
    counts.failed++
    console.error(`[FAIL] ${name} ${detail}`)
  }
}
export function eq(name, got, want) {
  ok(name, got === want, `\n  got:  ${got}\n  want: ${want}`)
}
export function throws(name, fn, message) {
  try {
    const v = fn()
    ok(name, false, `returned ${String(v).slice(0, 60)}`)
  } catch (e) {
    const right =
      e instanceof Error && (message == null || e.message === message)
    ok(name, right, `threw ${e && e.message}`)
  }
}
/** Prints the counts and exits with the status. */
export function finish(label) {
  console.log(`${label}: ${counts.passed} passed, ${counts.failed} failed`)
  process.exit(counts.failed ? 1 : 0)
}

export const sm9 = getSM9()
export const hexToBytes = (h) =>
  Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16))
export const hex = encodeHex
export const STREAM = api.SM9_MODE_STREAM
export const SM4 = api.SM9_MODE_SM4
export const DECRYPT_ERROR = 'SM9 decryption failed'
export const N = BigInt('0x' + V.params.n)
export const scalarHex = (v) => v.toString(16).padStart(64, '0')
export const flipHex = (s, at) =>
  s.slice(0, at) + (parseInt(s[at], 16) ^ 1).toString(16) + s.slice(at + 1)
