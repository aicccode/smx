/**
 * Generates sm4/sbox-circuit.js: the SM4 S-box as straight-line Boolean logic.
 *
 *   node tools/gen-sm4-sbox.js > sm4/sbox-circuit.js && prettier --write sm4/sbox-circuit.js
 *
 * S(x) = A * inv(A * x + c) + c over GF(2^8) mod x^8+x^7+x^6+x^5+x^4+x^2+1. The
 * inversion is done in the tower GF(((2^2)^2)^2). The generator checks the circuit
 * on all 256 inputs against the published table before printing anything.
 */
const SBOX_HEX =
  'd690e9fecce13db716b614c228fb2c052b679a762abe04c3aa441326498606999c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa64707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d351e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89eeabf8ad240c738b5a3f7f2cef96115a1e0ae5da49b341a55ad933230f58cb1e31df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b518d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b08969974a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3ed7cb3948'

const FIELD_POLY = 0x1f5

function fieldMul(a, b) {
  let r = 0
  for (let i = 0; i < 8; i++) {
    if ((b >> i) & 1) r ^= a << i
  }
  for (let i = 15; i >= 8; i--) {
    if ((r >> i) & 1) r ^= FIELD_POLY << (i - 8)
  }
  return r
}

function fieldInv(a) {
  if (a === 0) return 0
  for (let b = 1; b < 256; b++) if (fieldMul(a, b) === 1) return b
  throw new Error('no inverse')
}

// ---- tower arithmetic on integers, used to derive the linear maps ----
const mul4 = (a, b) => {
  const ah = a >> 1
  const al = a & 1
  const bh = b >> 1
  const bl = b & 1
  const p = ah & bh
  const q = al & bl
  const r = (ah ^ al) & (bh ^ bl)
  return ((r ^ q) << 1) | (q ^ p)
}
const MU = 2 // w
const mul16 = (a, b) => {
  const [ah, al, bh, bl] = [a >> 2, a & 3, b >> 2, b & 3]
  const p = mul4(ah, bh)
  const q = mul4(al, bl)
  const r = mul4(ah ^ al, bh ^ bl)
  return ((r ^ q) << 2) | (q ^ mul4(MU, p))
}

function findLambda() {
  for (let l = 1; l < 16; l++) {
    let reducible = false
    for (let y = 0; y < 16; y++) {
      if ((mul16(y, y) ^ y ^ l) === 0) reducible = true
    }
    if (!reducible) return l
  }
  throw new Error('no lambda')
}
const LAMBDA = findLambda()

const mul256 = (a, b) => {
  const [ah, al, bh, bl] = [a >> 4, a & 15, b >> 4, b & 15]
  const p = mul16(ah, bh)
  const q = mul16(al, bl)
  const r = mul16(ah ^ al, bh ^ bl)
  return ((r ^ q) << 4) | (q ^ mul16(LAMBDA, p))
}

/** Field-to-tower isomorphism: x^i maps to beta^i for a root beta of the field poly. */
function findIsomorphism() {
  for (let beta = 2; beta < 256; beta++) {
    const powers = [1]
    for (let i = 1; i <= 8; i++) powers.push(mul256(powers[i - 1], beta))
    let value = 0
    for (let i = 0; i <= 8; i++) {
      if ((FIELD_POLY >> i) & 1) value ^= powers[i]
    }
    if (value !== 0) continue
    const cols = powers.slice(0, 8)
    if (rank(cols) === 8) return cols
  }
  throw new Error('no isomorphism')
}

function rank(cols) {
  const v = cols.slice()
  let r = 0
  for (let bit = 0; bit < 8; bit++) {
    const pivot = v.findIndex((x, i) => i >= r && (x >> bit) & 1)
    if (pivot < 0) continue
    ;[v[r], v[pivot]] = [v[pivot], v[r]]
    for (let i = 0; i < v.length; i++) {
      if (i !== r && (v[i] >> bit) & 1) v[i] ^= v[r]
    }
    r++
  }
  return r
}

/** Apply a linear map given by the image of each basis bit. */
const applyLinear = (cols, x) => {
  let r = 0
  for (let i = 0; i < 8; i++) if ((x >> i) & 1) r ^= cols[i]
  return r
}

function invertLinear(cols) {
  const table = new Array(256)
  for (let x = 0; x < 256; x++) table[applyLinear(cols, x)] = x
  return Array.from({ length: 8 }, (_, i) => table[1 << i])
}

const compose = (outer, inner) => inner.map((c) => applyLinear(outer, c))

/** Finds the affine map A, c: a circulant matrix, as in the literature on SM4. */
function findAffine(sbox) {
  const rotl8 = (x, n) => ((x << n) | (x >> (8 - n))) & 0xff
  for (let row = 1; row < 256; row++) {
    const a = Array.from({ length: 8 }, (_, i) => rotl8(row, i))
    if (rank(a) !== 8) continue
    for (let c = 0; c < 256; c++) {
      let ok = true
      for (let x = 0; x < 256 && ok; x++) {
        const y = applyLinear(a, fieldInv(applyLinear(a, x) ^ c)) ^ c
        ok = y === sbox[x]
      }
      if (ok) return { a, c }
    }
  }
  throw new Error('S-box is not of the expected form')
}

// ---- circuit emission ----
const lines = []
let nextGate = 0
const xorMemo = new Map()
const andMemo = new Map()
const gate = (expr) => {
  const name = `g${nextGate++}`
  lines.push(`const ${name} = ${expr}`)
  return name
}
function xor(a, b) {
  if (a === null) return b
  if (b === null) return a
  if (a === b) return null
  const key = a < b ? `${a},${b}` : `${b},${a}`
  if (!xorMemo.has(key)) xorMemo.set(key, gate(`${a} ^ ${b}`))
  return xorMemo.get(key)
}
function and(a, b) {
  if (a === null || b === null) return null
  const key = a < b ? `${a},${b}` : `${b},${a}`
  if (!andMemo.has(key)) andMemo.set(key, gate(`${a} & ${b}`))
  return andMemo.get(key)
}

/**
 * XOR network for a linear map, using Paar's greedy common-pair extraction.
 * inputs: names of the input bits. Returns output names, bit 0 first.
 */
function linearNetwork(cols, width, inputs) {
  const sets = []
  for (let bit = 0; bit < width; bit++) {
    const s = new Set()
    for (let i = 0; i < inputs.length; i++) {
      if ((cols[i] >> bit) & 1) s.add(inputs[i])
    }
    sets.push(s)
  }
  for (;;) {
    const counts = new Map()
    for (const s of sets) {
      const items = [...s]
      for (let i = 0; i < items.length; i++) {
        for (let j = i + 1; j < items.length; j++) {
          const key = [items[i], items[j]].sort().join(',')
          counts.set(key, (counts.get(key) ?? 0) + 1)
        }
      }
    }
    let best = null
    let bestCount = 0
    for (const [key, count] of counts) {
      if (count > bestCount) {
        best = key
        bestCount = count
      }
    }
    if (best === null) break
    const [a, b] = best.split(',')
    const g = xor(a, b)
    for (const s of sets) {
      if (s.has(a) && s.has(b)) {
        s.delete(a)
        s.delete(b)
        s.add(g)
      }
    }
  }
  return sets.map((s) => {
    if (s.size > 1) throw new Error('unreduced network')
    return s.size === 1 ? [...s][0] : null
  })
}

const xorBits = (a, b) => a.map((x, i) => xor(x, b[i]))

function mul4Bits([al, ah], [bl, bh]) {
  const p = and(ah, bh)
  const q = and(al, bl)
  const r = and(xor(ah, al), xor(bh, bl))
  return [xor(q, p), xor(r, q)]
}
const scaleMu4 = ([l, h]) => [h, xor(h, l)] // multiply by w: (hw+l)w = (h+l)w + h
const square4 = ([l, h]) => [xor(l, h), h]

function mul16Bits(a, b) {
  const [al, ah] = [a.slice(0, 2), a.slice(2)]
  const [bl, bh] = [b.slice(0, 2), b.slice(2)]
  const p = mul4Bits(ah, bh)
  const q = mul4Bits(al, bl)
  const r = mul4Bits(xorBits(ah, al), xorBits(bh, bl))
  return [...xorBits(q, scaleMu4(p)), ...xorBits(r, q)]
}

function inv16Bits(x) {
  const [d, c] = [x.slice(0, 2), x.slice(2)] // x = c*Z + d
  const s = xorBits(c, d)
  const delta = xorBits(
    xorBits(scaleMu4(square4(c)), mul4Bits(c, d)),
    square4(d),
  )
  const inv = square4(delta) // in GF(4), the inverse is the square
  return [...mul4Bits(s, inv), ...mul4Bits(c, inv)]
}

/** The linear map y -> lambda * y^2 on GF(16), as images of the basis bits. */
const LAMBDA_SQUARE = [1, 2, 4, 8].map((b) => mul16(LAMBDA, mul16(b, b)))

function emitBody() {
  const sbox = Uint8Array.from(SBOX_HEX.match(/../g), (h) => parseInt(h, 16))
  const { a, c } = findAffine(sbox)
  const toTower = findIsomorphism()
  const fromTower = invertLinear(toTower)
  const inputs = Array.from({ length: 8 }, (_, i) => `x${i}`)

  // Input layer: u = T * A * x, then XOR the constant T * c as NOTs on the bits.
  const top = compose(toTower, a)
  const constant = applyLinear(toTower, c)
  let u = linearNetwork(top, 8, inputs)
  u = u.map((name, bit) =>
    (constant >> bit) & 1 ? gate(`${name} ^ ones`) : name,
  )

  // Tower inversion of (a, b) = a*Y + b.
  const lo = u.slice(0, 4)
  const hi = u.slice(4)
  const sum = xorBits(hi, lo)
  const scaled = linearNetwork(LAMBDA_SQUARE, 4, hi)
  const product = mul16Bits(hi, lo)
  const loSquare = linearNetwork(
    [1, 2, 4, 8].map((b) => mul16(b, b)),
    4,
    lo,
  )
  const delta = xorBits(xorBits(scaled, product), loSquare)
  const inverse = inv16Bits(delta)
  const outLo = mul16Bits(sum, inverse)
  const outHi = mul16Bits(hi, inverse)

  // Output layer: y = A * T^-1 * v + c.
  const bottom = compose(a, fromTower)
  const v = linearNetwork(bottom, 8, [...outLo, ...outHi])
  return v.map((name, bit) => ((c >> bit) & 1 ? gate(`${name} ^ ones`) : name))
}

const outputs = emitBody()
const body = lines.join('\n')

/** Runs the emitted body on one byte per word, for the check below. */
const check = new Function(
  'x0,x1,x2,x3,x4,x5,x6,x7,ones',
  `${body}\nreturn [${outputs.join(',')}]`,
)
const expected = Uint8Array.from(SBOX_HEX.match(/../g), (h) => parseInt(h, 16))
for (let x = 0; x < 256; x++) {
  const bits = Array.from({ length: 8 }, (_, i) => (x >> i) & 1)
  const out = check(...bits, 1)
  let y = 0
  for (let i = 0; i < 8; i++) y |= (out[i] & 1) << i
  if (y !== expected[x]) throw new Error(`S-box mismatch at ${x}`)
}

const planesOut = outputs.map((name, i) => `p[${i}] = ${name}`).join('\n')
const wordOut = outputs.map((name, i) => `(${name} << ${i})`).join(' | ')
const planeIn = Array.from(
  { length: 8 },
  (_, i) => `const x${i} = p[${i}]`,
).join('\n')
const wordIn = Array.from(
  { length: 8 },
  (_, i) => `const x${i} = (t >>> ${i}) & ones`,
).join('\n')

process.stdout
  .write(`// Generated by tools/gen-sm4-sbox.js. Do not edit by hand.
//
// The SM4 S-box as ${lines.length} Boolean gates. It has no table lookups and no branches,
// so there is no secret-dependent memory access or control flow. The generator and
// the tests both check it against the published table on all 256 inputs.

/** Applies the S-box to each of the four bytes of a 32-bit word. */
export function sboxWord(t) {
const ones = 0x01010101
${wordIn}
${body}
return ${wordOut}
}

/**
 * Applies the S-box in parallel to 32 bytes held as eight bit planes: p[i] holds
 * bit i of every byte. Updates p in place.
 */
export function sboxPlanes(p) {
const ones = -1
${planeIn}
${body}
${planesOut}
}
`)
