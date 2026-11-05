/**
 * Test support, run in a child process: pollution of Object.prototype must not
 * supply the random source, either before or after the library loads. Prints the
 * number of generated keys that came from the polluted generator.
 */
const poison = {
  getRandomValues(a) {
    return a.fill(0x42)
  },
}
const mode = process.argv[2]
if (mode === 'before') Object.prototype.crypto = poison
if (mode === 'method') Object.prototype.getRandomValues = poison.getRandomValues
const { generateKeyPairHex } = await import('../../sm2/utils.js')
if (mode === 'after') Object.prototype.crypto = poison
const key = generateKeyPairHex().privateKey
console.log(key === '42'.repeat(32) ? 'POISONED' : 'clean')
