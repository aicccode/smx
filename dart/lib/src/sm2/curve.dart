/// SM2 curve internals: Jacobian formulas on 29-bit limbs, the fixed-base comb,
/// fixed-window variable-base multiplication and the variable-time paths.
///
/// Timing: **Dart integers give no constant-time guarantee.** For secret
/// scalars this code removes what Dart source can control: the schedule of
/// doublings and additions is fixed, every table lookup reads the whole table
/// through masks, and field arithmetic has no value-dependent branch. The only
/// branch on secret-derived data is the exceptional-case check of the mixed
/// addition, which a random scalar reaches with negligible probability (the
/// fallback still returns the correct result). [mulPublic] and [mulShamir]
/// are variable time and only for public scalars.
///
/// Layout: a Jacobian point is X, Y, Z (27 limbs); an affine point is x, y
/// (18 limbs); both in Montgomery form at an offset in a Uint32List.
library;

import 'dart:typed_data';

import '../field/field.dart';
import '../field/sm2_fp.g.dart';

final BigInt curveP = sm2Fp.modulus;
final BigInt curveA = BigInt.parse(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    radix: 16);
final BigInt curveB = BigInt.parse(
    '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
    radix: 16);
final BigInt curveN = BigInt.parse(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    radix: 16);
final BigInt curveGx = BigInt.parse(
    '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7',
    radix: 16);
final BigInt curveGy = BigInt.parse(
    'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0',
    radix: 16);

const int _l = limbs;
const int _y = limbs;
const int _z = 2 * limbs;
const int jacSize = 3 * limbs;
const int affSize = 2 * limbs;

const int _window = 5;
const int _windowCount = 52; // 52 * 5 = 260 bits, enough for k + n < 2^257
const int tableSize = 16; // odd multiples 1P, 3P, ..., 31P

final MontField _f = sm2Fp;

/// The Montgomery form of an integer in [0, p).
Uint32List montOf(BigInt v) {
  final r = Uint32List(_l);
  _f.setBigInt(r, 0, v);
  return r;
}

final Uint32List _bMont = montOf(curveB);

// Scratch registers. Dart code in one isolate runs without preemption, so
// synchronous functions can share them.
final Uint32List _t0 = Uint32List(_l);
final Uint32List _t1 = Uint32List(_l);
final Uint32List _t2 = Uint32List(_l);
final Uint32List _t3 = Uint32List(_l);
final Uint32List _t4 = Uint32List(_l);
final Uint32List _t5 = Uint32List(_l);
final Uint32List _t6 = Uint32List(_l);

/// p = 2p in place (a = -3 formulas). Infinity (Z = 0) stays infinity.
void jacDouble(Uint32List p, int o) {
  final x = o, y = o + _y, z = o + _z;
  fpSqr(_t0, 0, p, z); // delta
  fpSqr(_t1, 0, p, y); // gamma
  fpMul(_t2, 0, p, x, _t1, 0); // beta
  fpSub(_t3, 0, p, x, _t0, 0);
  fpAdd(_t4, 0, p, x, _t0, 0);
  fpMul(_t3, 0, _t3, 0, _t4, 0);
  fpAdd(_t4, 0, _t3, 0, _t3, 0);
  fpAdd(_t3, 0, _t4, 0, _t3, 0); // alpha
  fpMul(p, z, p, y, p, z);
  fpAdd(p, z, p, z, p, z); // Z3 = 2YZ
  fpSqr(_t4, 0, _t3, 0);
  fpAdd(_t5, 0, _t2, 0, _t2, 0);
  fpAdd(_t5, 0, _t5, 0, _t5, 0); // 4 beta
  fpAdd(_t6, 0, _t5, 0, _t5, 0); // 8 beta
  fpSub(p, x, _t4, 0, _t6, 0); // X3
  fpSub(_t5, 0, _t5, 0, p, x);
  fpMul(_t5, 0, _t3, 0, _t5, 0);
  fpSqr(_t1, 0, _t1, 0);
  fpAdd(_t1, 0, _t1, 0, _t1, 0);
  fpAdd(_t1, 0, _t1, 0, _t1, 0);
  fpAdd(_t1, 0, _t1, 0, _t1, 0); // 8 gamma^2
  fpSub(p, y, _t5, 0, _t1, 0);
}

/// p = p + q for Jacobian p and affine q, without special cases.
///
/// Returns true when the x coordinates matched (p = q, p = -q, or p is
/// infinity), in which case p is left unchanged and the caller must handle it.
bool jacAddAffineUnchecked(Uint32List p, int o, Uint32List q, int qo) {
  final x = o, y = o + _y, z = o + _z;
  fpSqr(_t0, 0, p, z);
  fpMul(_t1, 0, q, qo, _t0, 0); // u2
  fpMul(_t2, 0, p, z, _t0, 0);
  fpMul(_t2, 0, q, qo + _y, _t2, 0); // s2
  fpSub(_t1, 0, _t1, 0, p, x); // h
  fpSub(_t2, 0, _t2, 0, p, y); // r
  if (_f.zeroMask(_t1, 0) != 0) return true;
  fpSqr(_t3, 0, _t1, 0); // hh
  fpMul(_t4, 0, _t1, 0, _t3, 0); // hhh
  fpMul(_t5, 0, p, x, _t3, 0); // v
  fpSqr(_t6, 0, _t2, 0);
  fpSub(_t6, 0, _t6, 0, _t4, 0);
  fpSub(_t6, 0, _t6, 0, _t5, 0);
  fpSub(p, x, _t6, 0, _t5, 0); // X3
  fpSub(_t5, 0, _t5, 0, p, x);
  fpMul(_t5, 0, _t2, 0, _t5, 0);
  fpMul(_t4, 0, p, y, _t4, 0);
  fpSub(p, y, _t5, 0, _t4, 0); // Y3
  fpMul(p, z, p, z, _t1, 0); // Z3
  return false;
}

/// Sets p to infinity (1, 1, 0).
void setInfinity(Uint32List p, int o) {
  MontField.copy(p, o, _f.one, 0);
  MontField.copy(p, o + _y, _f.one, 0);
  p.fillRange(o + _z, o + _z + _l, 0);
}

bool isInfinity(Uint32List p, int o) => _f.isZero(p, o + _z);

/// p = affine q.
void setFromAffine(Uint32List p, int o, Uint32List q, int qo) {
  MontField.copy(p, o, q, qo);
  MontField.copy(p, o + _y, q, qo + _y);
  MontField.copy(p, o + _z, _f.one, 0);
}

/// p = p + q for affine q, handling every case. Variable time.
void jacAddAffine(Uint32List p, int o, Uint32List q, int qo) {
  if (isInfinity(p, o)) {
    setFromAffine(p, o, q, qo);
    return;
  }
  if (!jacAddAffineUnchecked(p, o, q, qo)) return;
  // Same x: _t2 still holds r = s2 - y1.
  if (_f.isZero(_t2, 0)) {
    jacDouble(p, o);
  } else {
    setInfinity(p, o);
  }
}

/// Writes the affine form of a finite Jacobian point; returns false for
/// infinity. The inversion has a fixed schedule.
bool toAffine(Uint32List out, int oo, Uint32List p, int o) {
  if (isInfinity(p, o)) return false;
  final zi = Uint32List(_l), zi2 = Uint32List(_l);
  _f.invert(zi, 0, p, o + _z);
  fpSqr(zi2, 0, zi, 0);
  fpMul(out, oo, p, o, zi2, 0);
  fpMul(zi2, 0, zi2, 0, zi, 0);
  fpMul(out, oo + _y, p, o + _y, zi2, 0);
  return true;
}

/// Converts [count] finite Jacobian points (consecutive in [points]) to affine
/// with one inversion (Montgomery's trick). Only for public values.
void batchToAffine(
    Uint32List out, int oo, Uint32List points, int po, int count) {
  final prefix = Uint32List(count * _l);
  MontField.copy(prefix, 0, points, po + _z);
  for (var i = 1; i < count; i++) {
    fpMul(prefix, i * _l, prefix, (i - 1) * _l, points, po + i * jacSize + _z);
  }
  final inv = Uint32List(_l), zi = Uint32List(_l), zi2 = Uint32List(_l);
  _f.invert(inv, 0, prefix, (count - 1) * _l);
  for (var i = count - 1; i >= 0; i--) {
    final p = po + i * jacSize;
    if (i > 0) {
      fpMul(zi, 0, inv, 0, prefix, (i - 1) * _l);
      fpMul(inv, 0, inv, 0, points, p + _z);
    } else {
      MontField.copy(zi, 0, inv, 0);
    }
    fpSqr(zi2, 0, zi, 0);
    fpMul(out, oo + i * affSize, points, p, zi2, 0);
    fpMul(zi2, 0, zi2, 0, zi, 0);
    fpMul(out, oo + i * affSize + _y, points, p + _y, zi2, 0);
  }
}

/// Returns the affine odd multiples 1Q, 3Q, ..., 31Q of an affine point of
/// order n (public).
Uint32List oddMultiples(Uint32List q, int qo) {
  final jac = Uint32List(tableSize * jacSize);
  final two = Uint32List(jacSize);
  setFromAffine(two, 0, q, qo);
  jacDouble(two, 0);
  final twoAff = Uint32List(affSize);
  toAffine(twoAff, 0, two, 0);
  setFromAffine(jac, 0, q, qo);
  for (var i = 1; i < tableSize; i++) {
    jac.setRange(i * jacSize, (i + 1) * jacSize, jac, (i - 1) * jacSize);
    jacAddAffine(jac, i * jacSize, twoAff, 0);
  }
  final out = Uint32List(tableSize * affSize);
  batchToAffine(out, 0, jac, 0, tableSize);
  return out;
}

/// Digits for the fixed-window paths: k' = sum(d_i 32^i) with odd non-zero
/// d_i = 2 a_i - 31, where k' is k or k + n, whichever is odd. Returns the
/// 52 values a_i in [0, 31].
Int32List recodeWith(BigInt k, BigInt n) {
  final odd = k.isOdd ? k : k + n;
  final a =
      (odd + ((BigInt.one << (_window * _windowCount)) - BigInt.one)) >> 1;
  final digits = Int32List(_windowCount);
  final bytes = a.toUnsigned(_window * _windowCount);
  var v = bytes;
  final mask = BigInt.from(0xFFFFFFF);
  // Take 28 bits (and so 5 digits plus 3 bits) at a time.
  var acc = 0, accBits = 0, i = 0;
  while (i < _windowCount) {
    if (accBits < _window) {
      acc |= (v & mask).toInt() << accBits;
      v >>= 28;
      accBits += 28;
    }
    digits[i++] = acc & 31;
    acc >>= _window;
    accBits -= _window;
  }
  return digits;
}

/// [recodeWith] for the SM2 group order.
Int32List recode(BigInt k) => recodeWith(k, curveN);

final Uint32List _sel = Uint32List(affSize);
final Uint32List _negY = Uint32List(_l);

/// Reads every entry of a 16-entry affine table through masks and leaves
/// d * entry in [_sel], for the recoded digit a (d = 2a - 31).
void _selectSigned(Uint32List table, int to, int a) {
  final positive = a >> 4; // 1 when d > 0
  final index = (a ^ (positive - 1)) & 15;
  _sel.fillRange(0, affSize, 0);
  for (var i = 0; i < tableSize; i++) {
    final mask = eqMask(i, index);
    final base = to + i * affSize;
    for (var k = 0; k < affSize; k++) {
      _sel[k] |= table[base + k] & mask;
    }
  }
  fpNeg(_negY, 0, _sel, _y);
  MontField.cmov(_sel, _y, _negY, 0, positive - 1);
}

/// Direct lookup of d * entry for public digits.
void _selectSignedPublic(Uint32List table, int to, int a) {
  final positive = a >> 4;
  final index = (a ^ (positive - 1)) & 15;
  final base = to + index * affSize;
  _sel.setRange(0, affSize, table, base);
  if (positive == 0) fpNeg(_sel, _y, _sel, _y);
}

// ---------------------------------------------------------------- fixed base

Uint32List? _combTable;

/// Row i holds the odd multiples of 32^i G.
Uint32List _comb() {
  final cached = _combTable;
  if (cached != null) return cached;
  final table = Uint32List(_windowCount * tableSize * affSize);
  final base = Uint32List.fromList(_generatorAffine());
  final next = Uint32List(jacSize);
  for (var row = 0; row < _windowCount; row++) {
    final multiples = oddMultiples(base, 0);
    table.setRange(
        row * tableSize * affSize, (row + 1) * tableSize * affSize, multiples);
    // 32 B = 31 B + B.
    setFromAffine(next, 0, multiples, (tableSize - 1) * affSize);
    jacAddAffine(next, 0, base, 0);
    toAffine(base, 0, next, 0);
  }
  return _combTable = table;
}

/// [k]G for a secret k in [1, n-1], with the 52 x 16 comb and masked lookups.
void mulGenerator(Uint32List out, BigInt k) {
  final table = _comb();
  final digits = recode(k);
  for (var row = 0; row < _windowCount; row++) {
    _selectSigned(table, row * tableSize * affSize, digits[row]);
    if (row == 0) {
      setFromAffine(out, 0, _sel, 0);
    } else if (jacAddAffineUnchecked(out, 0, _sel, 0)) {
      // Partial sums only meet a table point for k = 2^256 - n (negligible).
      _mulDoubleAndAdd(out, _generatorAffine(), 0, k);
      return;
    }
  }
}

Uint32List? _gAffine;
Uint32List _generatorAffine() {
  final cached = _gAffine;
  if (cached != null) return cached;
  final g = Uint32List(affSize);
  _f.setBigInt(g, 0, curveGx);
  _f.setBigInt(g, _y, curveGy);
  return _gAffine = g;
}

/// Variable-time double-and-add for any k > 0; only the fallback of the
/// fixed-window paths.
void _mulDoubleAndAdd(Uint32List out, Uint32List q, int qo, BigInt k) {
  setInfinity(out, 0);
  for (var i = k.bitLength - 1; i >= 0; i--) {
    jacDouble(out, 0);
    if ((k >> i).isOdd) jacAddAffine(out, 0, q, qo);
  }
}

// ---------------------------------------------------------------- variable base

/// [k]Q for a secret k in [1, n-1], with a fixed 5-bit window over the table
/// of odd multiples of Q (from [oddMultiples]). Every window costs five
/// doublings and one mixed addition with a masked lookup.
void mulPointWithTable(
    Uint32List out, Uint32List q, int qo, BigInt k, Uint32List table) {
  final digits = recode(k);
  _selectSigned(table, 0, digits[_windowCount - 1]);
  setFromAffine(out, 0, _sel, 0);
  for (var i = _windowCount - 2; i >= 0; i--) {
    jacDouble(out, 0);
    jacDouble(out, 0);
    jacDouble(out, 0);
    jacDouble(out, 0);
    jacDouble(out, 0);
    _selectSigned(table, 0, digits[i]);
    if (jacAddAffineUnchecked(out, 0, _sel, 0)) {
      // Only reachable for k = n - 6 in the last window (negligible).
      _mulDoubleAndAdd(out, q, qo, k);
      return;
    }
  }
}

// ---------------------------------------------------------------- public scalars

/// Width-w NAF digits of a non-negative k, least significant first.
Int32List wnaf(BigInt k, int w) {
  // Work on 32-bit words so the loop needs no BigInt operations.
  final words = Uint32List(10);
  var v = k;
  final m32 = BigInt.from(0xFFFFFFFF);
  for (var i = 0; i < 9; i++) {
    words[i] = (v & m32).toInt();
    v >>= 32;
  }
  final digits = Int32List(k.bitLength + 1);
  final size = 1 << w, half = size >> 1, mask = size - 1;
  bool nonZero() {
    for (final x in words) {
      if (x != 0) return true;
    }
    return false;
  }

  var pos = 0;
  while (nonZero()) {
    if (words[0] & 1 == 1) {
      var d = words[0] & mask;
      if (d >= half) d -= size;
      digits[pos] = d;
      // words -= d
      var carry = -d;
      for (var i = 0; i < words.length && carry != 0; i++) {
        final t = words[i] + carry;
        words[i] = t & 0xFFFFFFFF;
        carry = t >> 32;
      }
    }
    // words >>= 1
    for (var i = 0; i < words.length; i++) {
      final hi = i + 1 < words.length ? words[i + 1] & 1 : 0;
      words[i] = (words[i] >> 1) | (hi << 31);
    }
    pos++;
  }
  return digits;
}

void _addDigit(Uint32List out, Uint32List table, int d) {
  final index = (d.abs() - 1) >> 1;
  _sel.setRange(0, affSize, table, index * affSize);
  if (d < 0) fpNeg(_sel, _y, _sel, _y);
  jacAddAffine(out, 0, _sel, 0);
}

/// [k]Q for a public k >= 0, with wNAF over the odd multiples table (window 5,
/// so the same 16-entry table serves). Variable time.
void mulPublic(Uint32List out, Uint32List table, BigInt k) {
  setInfinity(out, 0);
  final digits = wnaf(k, _window);
  for (var i = digits.length - 1; i >= 0; i--) {
    jacDouble(out, 0);
    final d = digits[i];
    if (d != 0) _addDigit(out, table, d);
  }
}

/// [s]G + [t]Q for public s, t in [1, n-1]. Variable time.
void mulShamir(Uint32List out, BigInt s, BigInt t, Uint32List qTable) {
  mulPublic(out, qTable, t);
  final comb = _comb();
  final digits = recode(s);
  for (var row = 0; row < _windowCount; row++) {
    _selectSignedPublic(comb, row * tableSize * affSize, digits[row]);
    jacAddAffine(out, 0, _sel, 0);
  }
}

/// [k]G for a public k (comb with direct lookups). Variable time.
void mulGeneratorPublic(Uint32List out, BigInt k) {
  setInfinity(out, 0);
  final comb = _comb();
  final digits = recode(k);
  for (var row = 0; row < _windowCount; row++) {
    _selectSignedPublic(comb, row * tableSize * affSize, digits[row]);
    jacAddAffine(out, 0, _sel, 0);
  }
}

/// True when affine limbs (x, y) satisfy y^2 = x^3 + ax + b.
bool isOnCurveLimbs(Uint32List q, int qo) {
  final x2 = Uint32List(_l), rhs = Uint32List(_l), lhs = Uint32List(_l);
  fpSqr(x2, 0, q, qo);
  fpMul(rhs, 0, x2, 0, q, qo); // x^3
  fpSub(rhs, 0, rhs, 0, q, qo);
  fpSub(rhs, 0, rhs, 0, q, qo);
  fpSub(rhs, 0, rhs, 0, q, qo); // x^3 - 3x
  fpAdd(rhs, 0, rhs, 0, _bMont, 0);
  fpSqr(lhs, 0, q, qo + _y);
  return _f.equals(lhs, 0, rhs, 0);
}
