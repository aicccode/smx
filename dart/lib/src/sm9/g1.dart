/// SM9 G1: E(Fq): y^2 = x^3 + 5, prime order N, cofactor 1.
///
/// Same layout and timing rules as the SM2 curve code: Jacobian X, Y, Z
/// (27 limbs), affine x, y (18 limbs), Montgomery form. Secret scalars use a
/// fixed 5-bit window with masked lookups; the `Public` functions are
/// variable time.
library;

import 'dart:typed_data';

import '../field/field.dart';
import '../field/sm9_fq.g.dart';
import '../sm2/curve.dart' show recodeWith, wnaf;
import 'params.dart';

const int _l = limbs;
const int _y = limbs;
const int _z = 2 * limbs;
const int g1Jac = 3 * limbs;
const int g1Aff = 2 * limbs;
const int _tableSize = 16;
const int _windows = 52;

final MontField _f = sm9Fq;

Uint32List _mont(BigInt v) {
  final r = Uint32List(_l);
  _f.setBigInt(r, 0, v);
  return r;
}

final Uint32List _five = _mont(BigInt.from(5));

/// P1 in affine Montgomery form.
final Uint32List p1Affine = Uint32List(g1Aff)
  ..setRange(0, _l, _mont(sm9P1x))
  ..setRange(_l, 2 * _l, _mont(sm9P1y));

final _t0 = Uint32List(_l), _t1 = Uint32List(_l), _t2 = Uint32List(_l);
final _t3 = Uint32List(_l), _t4 = Uint32List(_l), _t5 = Uint32List(_l);
final _t6 = Uint32List(_l);

/// p = 2p (a = 0). Infinity stays infinity.
void g1Double(Uint32List p, int o) {
  final x = o, y = o + _y, z = o + _z;
  fqSqr(_t0, 0, p, x); // A
  fqSqr(_t1, 0, p, y); // B
  fqSqr(_t2, 0, _t1, 0); // C
  fqAdd(_t3, 0, p, x, _t1, 0);
  fqSqr(_t3, 0, _t3, 0);
  fqSub(_t3, 0, _t3, 0, _t0, 0);
  fqSub(_t3, 0, _t3, 0, _t2, 0);
  fqAdd(_t3, 0, _t3, 0, _t3, 0); // D
  fqAdd(_t4, 0, _t0, 0, _t0, 0);
  fqAdd(_t4, 0, _t4, 0, _t0, 0); // E
  fqSqr(_t5, 0, _t4, 0); // F
  fqMul(p, z, p, y, p, z);
  fqAdd(p, z, p, z, p, z); // Z3
  fqAdd(_t6, 0, _t3, 0, _t3, 0);
  fqSub(p, x, _t5, 0, _t6, 0); // X3
  fqSub(_t3, 0, _t3, 0, p, x);
  fqMul(_t3, 0, _t4, 0, _t3, 0);
  fqAdd(_t2, 0, _t2, 0, _t2, 0);
  fqAdd(_t2, 0, _t2, 0, _t2, 0);
  fqAdd(_t2, 0, _t2, 0, _t2, 0);
  fqSub(p, y, _t3, 0, _t2, 0); // Y3
}

/// p = p + q (q affine) without special cases; returns true, leaving p
/// unchanged, when the x coordinates match.
bool g1AddUnchecked(Uint32List p, int o, Uint32List q, int qo) {
  final x = o, y = o + _y, z = o + _z;
  fqSqr(_t0, 0, p, z);
  fqMul(_t1, 0, q, qo, _t0, 0);
  fqMul(_t2, 0, p, z, _t0, 0);
  fqMul(_t2, 0, q, qo + _y, _t2, 0);
  fqSub(_t1, 0, _t1, 0, p, x); // h
  fqSub(_t2, 0, _t2, 0, p, y); // r
  if (_f.zeroMask(_t1, 0) != 0) return true;
  fqSqr(_t3, 0, _t1, 0);
  fqMul(_t4, 0, _t1, 0, _t3, 0);
  fqMul(_t5, 0, p, x, _t3, 0);
  fqSqr(_t6, 0, _t2, 0);
  fqSub(_t6, 0, _t6, 0, _t4, 0);
  fqSub(_t6, 0, _t6, 0, _t5, 0);
  fqSub(p, x, _t6, 0, _t5, 0);
  fqSub(_t5, 0, _t5, 0, p, x);
  fqMul(_t5, 0, _t2, 0, _t5, 0);
  fqMul(_t4, 0, p, y, _t4, 0);
  fqSub(p, y, _t5, 0, _t4, 0);
  fqMul(p, z, p, z, _t1, 0);
  return false;
}

void g1SetInfinity(Uint32List p, int o) {
  MontField.copy(p, o, _f.one, 0);
  MontField.copy(p, o + _y, _f.one, 0);
  p.fillRange(o + _z, o + _z + _l, 0);
}

bool g1IsInfinity(Uint32List p, int o) => _f.isZero(p, o + _z);

void g1FromAffine(Uint32List p, int o, Uint32List q, int qo) {
  MontField.copy(p, o, q, qo);
  MontField.copy(p, o + _y, q, qo + _y);
  MontField.copy(p, o + _z, _f.one, 0);
}

/// p = p + q (q affine), every case handled. Variable time.
void g1Add(Uint32List p, int o, Uint32List q, int qo) {
  if (g1IsInfinity(p, o)) {
    g1FromAffine(p, o, q, qo);
    return;
  }
  if (!g1AddUnchecked(p, o, q, qo)) return;
  if (_f.isZero(_t2, 0)) {
    g1Double(p, o);
  } else {
    g1SetInfinity(p, o);
  }
}

/// Affine form of a Jacobian point; false for infinity.
bool g1ToAffine(Uint32List out, int oo, Uint32List p, int o) {
  if (g1IsInfinity(p, o)) return false;
  final zi = Uint32List(_l), zi2 = Uint32List(_l);
  _f.invert(zi, 0, p, o + _z);
  fqSqr(zi2, 0, zi, 0);
  fqMul(out, oo, p, o, zi2, 0);
  fqMul(zi2, 0, zi2, 0, zi, 0);
  fqMul(out, oo + _y, p, o + _y, zi2, 0);
  return true;
}

/// 1Q, 3Q, ..., 31Q in affine form, for an affine point of order N.
Uint32List g1OddMultiples(Uint32List q, int qo) {
  final jac = Uint32List(_tableSize * g1Jac);
  final two = Uint32List(g1Jac);
  g1FromAffine(two, 0, q, qo);
  g1Double(two, 0);
  final twoAff = Uint32List(g1Aff);
  g1ToAffine(twoAff, 0, two, 0);
  g1FromAffine(jac, 0, q, qo);
  for (var i = 1; i < _tableSize; i++) {
    jac.setRange(i * g1Jac, (i + 1) * g1Jac, jac, (i - 1) * g1Jac);
    g1Add(jac, i * g1Jac, twoAff, 0);
  }
  // One inversion for all (Montgomery's trick); the points are public
  // multiples of a public or secret-key point, all finite.
  final prefix = Uint32List(_tableSize * _l);
  MontField.copy(prefix, 0, jac, _z);
  for (var i = 1; i < _tableSize; i++) {
    fqMul(prefix, i * _l, prefix, (i - 1) * _l, jac, i * g1Jac + _z);
  }
  final inv = Uint32List(_l), zi = Uint32List(_l), zi2 = Uint32List(_l);
  _f.invert(inv, 0, prefix, (_tableSize - 1) * _l);
  final out = Uint32List(_tableSize * g1Aff);
  for (var i = _tableSize - 1; i >= 0; i--) {
    if (i > 0) {
      fqMul(zi, 0, inv, 0, prefix, (i - 1) * _l);
      fqMul(inv, 0, inv, 0, jac, i * g1Jac + _z);
    } else {
      MontField.copy(zi, 0, inv, 0);
    }
    fqSqr(zi2, 0, zi, 0);
    fqMul(out, i * g1Aff, jac, i * g1Jac, zi2, 0);
    fqMul(zi2, 0, zi2, 0, zi, 0);
    fqMul(out, i * g1Aff + _y, jac, i * g1Jac + _y, zi2, 0);
  }
  return out;
}

final _sel = Uint32List(g1Aff), _negY = Uint32List(_l);

void _select(Uint32List table, int a) {
  final positive = a >> 4;
  final index = (a ^ (positive - 1)) & 15;
  _sel.fillRange(0, g1Aff, 0);
  for (var i = 0; i < _tableSize; i++) {
    final mask = eqMask(i, index);
    final base = i * g1Aff;
    for (var k = 0; k < g1Aff; k++) {
      _sel[k] |= table[base + k] & mask;
    }
  }
  fqNeg(_negY, 0, _sel, _y);
  MontField.cmov(_sel, _y, _negY, 0, positive - 1);
}

/// out = [k]Q for a secret k in [1, N-1] (fixed window, masked lookups),
/// given the table of [g1OddMultiples] and Q itself (affine).
void g1MulSecret(
    Uint32List out, Uint32List q, int qo, BigInt k, Uint32List table) {
  final digits = recodeWith(k, sm9N);
  _select(table, digits[_windows - 1]);
  g1FromAffine(out, 0, _sel, 0);
  for (var i = _windows - 2; i >= 0; i--) {
    g1Double(out, 0);
    g1Double(out, 0);
    g1Double(out, 0);
    g1Double(out, 0);
    g1Double(out, 0);
    _select(table, digits[i]);
    if (g1AddUnchecked(out, 0, _sel, 0)) {
      // Negligible probability for a random k; still correct.
      g1MulPublic(out, q, qo, k);
      return;
    }
  }
}

/// out = [k]Q for a public k >= 0 (wNAF). Variable time.
void g1MulPublic(Uint32List out, Uint32List q, int qo, BigInt k,
    [Uint32List? table]) {
  final t = table ?? g1OddMultiples(q, qo);
  g1SetInfinity(out, 0);
  final digits = wnaf(k, 5);
  final sel = Uint32List(g1Aff);
  for (var i = digits.length - 1; i >= 0; i--) {
    g1Double(out, 0);
    final d = digits[i];
    if (d == 0) continue;
    sel.setRange(0, g1Aff, t, ((d.abs() - 1) >> 1) * g1Aff);
    if (d < 0) fqNeg(sel, _y, sel, _y);
    g1Add(out, 0, sel, 0);
  }
}

/// True when affine limbs satisfy y^2 = x^3 + 5.
bool g1IsOnCurve(Uint32List q, int qo) {
  final rhs = Uint32List(_l), lhs = Uint32List(_l);
  fqSqr(rhs, 0, q, qo);
  fqMul(rhs, 0, rhs, 0, q, qo);
  fqAdd(rhs, 0, rhs, 0, _five, 0);
  fqSqr(lhs, 0, q, qo + _y);
  return _f.equals(lhs, 0, rhs, 0);
}

/// Decodes `04 || x || y` (65 bytes) into affine limbs, or returns null for
/// anything that is not a finite point of G1.
Uint32List? g1Decode(List<int> data) {
  if (data.length != 65 || data[0] != 4) return null;
  final q = Uint32List(g1Aff);
  if (!_f.setBytes(q, 0, data, 1) || !_f.setBytes(q, _y, data, 33)) {
    return null;
  }
  // (0, 0) is not on the curve, so on-curve points are all finite.
  return g1IsOnCurve(q, 0) ? q : null;
}

/// `x || y`, 64 bytes.
Uint8List g1Xy(Uint32List q, int qo) {
  final out = Uint8List(64);
  _f.getBytes(out, 0, q, qo);
  _f.getBytes(out, 32, q, qo + _y);
  return out;
}

/// `04 || x || y`, 65 bytes.
Uint8List g1Encode(Uint32List q, int qo) {
  final out = Uint8List(65);
  out[0] = 4;
  out.setRange(1, 65, g1Xy(q, qo));
  return out;
}

Uint32List? _p1Table;

/// The odd-multiples table of P1 (built once).
Uint32List p1Table() => _p1Table ??= g1OddMultiples(p1Affine, 0);

/// Affine [k]Q for a secret k; null only if the result is infinity.
Uint32List? g1MulSecretAffine(Uint32List q, BigInt k, Uint32List table) {
  final jac = Uint32List(g1Jac);
  g1MulSecret(jac, q, 0, k, table);
  final out = Uint32List(g1Aff);
  return g1ToAffine(out, 0, jac, 0) ? out : null;
}

// ---------------------------------------------------------------- fixed base P1

Uint32List? _comb;

/// Row i holds the odd multiples of 32^i P1 (52 x 16 affine points).
Uint32List _p1Comb() {
  final cached = _comb;
  if (cached != null) return cached;
  final table = Uint32List(_windows * _tableSize * g1Aff);
  final base = Uint32List.fromList(p1Affine);
  final next = Uint32List(g1Jac);
  for (var row = 0; row < _windows; row++) {
    final m = g1OddMultiples(base, 0);
    table.setRange(row * _tableSize * g1Aff, (row + 1) * _tableSize * g1Aff, m);
    g1FromAffine(next, 0, m, (_tableSize - 1) * g1Aff);
    g1Add(next, 0, base, 0);
    g1ToAffine(base, 0, next, 0);
  }
  return _comb = table;
}

/// out = [k]P1 with the comb. For a secret k the lookups are masked and the
/// schedule is fixed; for a public k they are direct.
void g1MulP1(Uint32List out, BigInt k, {required bool secret}) {
  final table = _p1Comb();
  final digits = recodeWith(k, sm9N);
  final sel = Uint32List(g1Aff);
  g1SetInfinity(out, 0);
  for (var row = 0; row < _windows; row++) {
    final a = digits[row];
    final positive = a >> 4;
    final index = (a ^ (positive - 1)) & 15;
    final o = row * _tableSize * g1Aff;
    if (secret) {
      _selectAt(sel, table, o, index);
    } else {
      sel.setRange(0, g1Aff, table, o + index * g1Aff);
    }
    fqNeg(_negY, 0, sel, _y);
    MontField.cmov(sel, _y, _negY, 0, positive - 1);
    if (row == 0) {
      g1FromAffine(out, 0, sel, 0);
    } else if (!secret) {
      g1Add(out, 0, sel, 0);
    } else if (g1AddUnchecked(out, 0, sel, 0)) {
      g1MulPublic(out, p1Affine, 0, k, p1Table());
      return;
    }
  }
}

void _selectAt(Uint32List out, Uint32List table, int o, int index) {
  out.fillRange(0, g1Aff, 0);
  for (var i = 0; i < _tableSize; i++) {
    final mask = eqMask(i, index);
    final base = o + i * g1Aff;
    for (var k = 0; k < g1Aff; k++) {
      out[k] |= table[base + k] & mask;
    }
  }
}

/// Affine [k]P1 for a secret k in [1, N-1].
Uint32List g1MulP1Secret(BigInt k) {
  final jac = Uint32List(g1Jac);
  g1MulP1(jac, k, secret: true);
  final out = Uint32List(g1Aff);
  g1ToAffine(out, 0, jac, 0);
  return out;
}
