/**
 * Test support: installs a switchable global `crypto`. The library captures its
 * source when it loads, so this module must be imported before any library module.
 */
import { randomFillSync } from 'node:crypto'

const realSource = (a) => randomFillSync(a)
let source = realSource

Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues: (a) => source(a) },
})

/** Runs fn with the given replacement for getRandomValues. */
export function withRandom(replacement, fn) {
  source = replacement
  try {
    return fn()
  } finally {
    source = realSource
  }
}
