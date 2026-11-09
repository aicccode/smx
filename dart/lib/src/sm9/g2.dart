/// SM9 G2 on the twist E'(Fq2): y^2 = x^3 + 5u.
///
/// Jacobian X, Y, Z (54 limbs), affine x, y (36 limbs), each coordinate an
/// Fq2 element (a0, a1). The twist has a cofactor, so decoded points get an
/// explicit subgroup check. Secret scalars use a fixed 5-bit window with
/// masked lookups; the `Public` functions are variable time.
library;

import 'dart:typed_data';

import '../field/field.dart';
import '../sm2/curve.dart' show recodeWith, wnaf;
import 'params.dart';
import 'tower.dart';

const int _y = f2;
const int _z = 2 * f2;
const int g2Jac = 3 * f2;
const int g2Aff = 2 * f2;
const int _tableSize = 16;
const int _windows = 52;

Uint32List _f2(BigInt a0, BigInt a1) {
  final r = Uint32List(f2);
  fq.setBigInt(r, 0, a0);
  fq.setBigInt(r, f1, a1);
  return r;
}

final Uint32List _bTwist = _f2(BigInt.zero, BigInt.from(5));

/// P2 in affine Montgomery form.
final Uint32List p2Affine = Uint32List(g2Aff)
  ..setRange(0, f2, _f2(sm9P2x0, sm9P2x1))
  ..setRange(f2, 2 * f2, _f2(sm9P2y0, sm9P2y1));

final _t0 = Uint32List(f2), _t1 = Uint32List(f2), _t2 = Uint32List(f2);
final _t3 = Uint32List(f2), _t4 = Uint32List(f2), _t5 = Uint32List(f2);
final _t6 = Uint32List(f2);

/// p = 2p (a = 0).
void g2Double(Uint32List p, int o) {
  final x = o, y = o + _y, z = o + _z;
  f2Sqr(_t0, 0, p, x); // A
  f2Sqr(_t1, 0, p, y); // B
  f2Sqr(_t2, 0, _t1, 0); // C
  f2Add(_t3, 0, p, x, _t1, 0);
  f2Sqr(_t3, 0, _t3, 0);
  f2Sub(_t3, 0, _t3, 0, _t0, 0);
  f2Sub(_t3, 0, _t3, 0, _t2, 0);
  f2Dbl(_t3, 0, _t3, 0); // D
  f2Dbl(_t4, 0, _t0, 0);
  f2Add(_t4, 0, _t4, 0, _t0, 0); // E
  f2Sqr(_t5, 0, _t4, 0); // F
  f2Mul(p, z, p, y, p, z);
  f2Dbl(p, z, p, z);
  f2Dbl(_t6, 0, _t3, 0);
  f2Sub(p, x, _t5, 0, _t6, 0);
  f2Sub(_t3, 0, _t3, 0, p, x);
  f2Mul(_t3, 0, _t4, 0, _t3, 0);
  f2Dbl(_t2, 0, _t2, 0);
  f2Dbl(_t2, 0, _t2, 0);
  f2Dbl(_t2, 0, _t2, 0);
  f2Sub(p, y, _t3, 0, _t2, 0);
}

/// p = p + q (q affine) without special cases; true (p unchanged) when the
/// x coordinates match.
bool g2AddUnchecked(Uint32List p, int o, Uint32List q, int qo) {
  final x = o, y = o + _y, z = o + _z;
  f2Sqr(_t0, 0, p, z);
  f2Mul(_t1, 0, q, qo, _t0, 0);
  f2Mul(_t2, 0, p, z, _t0, 0);
  f2Mul(_t2, 0, q, qo + _y, _t2, 0);
  f2Sub(_t1, 0, _t1, 0, p, x);
  f2Sub(_t2, 0, _t2, 0, p, y);
  if ((fq.zeroMask(_t1, 0) & fq.zeroMask(_t1, f1)) != 0) return true;
  f2Sqr(_t3, 0, _t1, 0);
  f2Mul(_t4, 0, _t1, 0, _t3, 0);
  f2Mul(_t5, 0, p, x, _t3, 0);
  f2Sqr(_t6, 0, _t2, 0);
  f2Sub(_t6, 0, _t6, 0, _t4, 0);
  f2Sub(_t6, 0, _t6, 0, _t5, 0);
  f2Sub(p, x, _t6, 0, _t5, 0);
  f2Sub(_t5, 0, _t5, 0, p, x);
  f2Mul(_t5, 0, _t2, 0, _t5, 0);
  f2Mul(_t4, 0, p, y, _t4, 0);
  f2Sub(p, y, _t5, 0, _t4, 0);
  f2Mul(p, z, p, z, _t1, 0);
  return false;
}

void g2SetInfinity(Uint32List p, int o) {
  f2One(p, o);
  f2One(p, o + _y);
  p.fillRange(o + _z, o + _z + f2, 0);
}

bool g2IsInfinity(Uint32List p, int o) => f2IsZero(p, o + _z);

void g2FromAffine(Uint32List p, int o, Uint32List q, int qo) {
  f2Copy(p, o, q, qo);
  f2Copy(p, o + _y, q, qo + _y);
  f2One(p, o + _z);
}

/// p = p + q (q affine), every case handled. Variable time.
void g2Add(Uint32List p, int o, Uint32List q, int qo) {
  if (g2IsInfinity(p, o)) {
    g2FromAffine(p, o, q, qo);
    return;
  }
  if (!g2AddUnchecked(p, o, q, qo)) return;
  if (f2IsZero(_t2, 0)) {
    g2Double(p, o);
  } else {
    g2SetInfinity(p, o);
  }
}

/// Affine form; false for infinity.
bool g2ToAffine(Uint32List out, int oo, Uint32List p, int o) {
  if (g2IsInfinity(p, o)) return false;
  final zi = Uint32List(f2), zi2 = Uint32List(f2);
  f2Inv(zi, 0, p, o + _z);
  f2Sqr(zi2, 0, zi, 0);
  f2Mul(out, oo, p, o, zi2, 0);
  f2Mul(zi2, 0, zi2, 0, zi, 0);
  f2Mul(out, oo + _y, p, o + _y, zi2, 0);
  return true;
}

/// 1Q, 3Q, ..., 31Q in affine form, for an affine Q of order N.
Uint32List g2OddMultiples(Uint32List q, int qo) {
  final two = Uint32List(g2Jac);
  g2FromAffine(two, 0, q, qo);
  g2Double(two, 0);
  final twoAff = Uint32List(g2Aff);
  g2ToAffine(twoAff, 0, two, 0);
  final jac = Uint32List(_tableSize * g2Jac);
  g2FromAffine(jac, 0, q, qo);
  for (var i = 1; i < _tableSize; i++) {
    jac.setRange(i * g2Jac, (i + 1) * g2Jac, jac, (i - 1) * g2Jac);
    g2Add(jac, i * g2Jac, twoAff, 0);
  }
  // One inversion for all of them (Montgomery's trick).
  final prefix = Uint32List(_tableSize * f2);
  f2Copy(prefix, 0, jac, _z);
  for (var i = 1; i < _tableSize; i++) {
    f2Mul(prefix, i * f2, prefix, (i - 1) * f2, jac, i * g2Jac + _z);
  }
  final inv = Uint32List(f2), zi = Uint32List(f2), zi2 = Uint32List(f2);
  f2Inv(inv, 0, prefix, (_tableSize - 1) * f2);
  final out = Uint32List(_tableSize * g2Aff);
  for (var i = _tableSize - 1; i >= 0; i--) {
    if (i > 0) {
      f2Mul(zi, 0, inv, 0, prefix, (i - 1) * f2);
      f2Mul(inv, 0, inv, 0, jac, i * g2Jac + _z);
    } else {
      f2Copy(zi, 0, inv, 0);
    }
    f2Sqr(zi2, 0, zi, 0);
    f2Mul(out, i * g2Aff, jac, i * g2Jac, zi2, 0);
    f2Mul(zi2, 0, zi2, 0, zi, 0);
    f2Mul(out, i * g2Aff + _y, jac, i * g2Jac + _y, zi2, 0);
  }
  return out;
}

final _sel = Uint32List(g2Aff), _negY = Uint32List(f2);

void _select(Uint32List table, int a) {
  final positive = a >> 4;
  final index = (a ^ (positive - 1)) & 15;
  _sel.fillRange(0, g2Aff, 0);
  for (var i = 0; i < _tableSize; i++) {
    final mask = eqMask(i, index);
    final base = i * g2Aff;
    for (var k = 0; k < g2Aff; k++) {
      _sel[k] |= table[base + k] & mask;
    }
  }
  f2Neg(_negY, 0, _sel, _y);
  final m = positive - 1;
  MontField.cmov(_sel, _y, _negY, 0, m);
  MontField.cmov(_sel, _y + f1, _negY, f1, m);
}

/// out = [k]Q for a secret k in [1, N-1] (fixed window, masked lookups).
void g2MulSecret(
    Uint32List out, Uint32List q, int qo, BigInt k, Uint32List table) {
  final digits = recodeWith(k, sm9N);
  _select(table, digits[_windows - 1]);
  g2FromAffine(out, 0, _sel, 0);
  for (var i = _windows - 2; i >= 0; i--) {
    g2Double(out, 0);
    g2Double(out, 0);
    g2Double(out, 0);
    g2Double(out, 0);
    g2Double(out, 0);
    _select(table, digits[i]);
    if (g2AddUnchecked(out, 0, _sel, 0)) {
      g2MulPublic(out, q, qo, k);
      return;
    }
  }
}

/// out = [k]Q for a public k >= 0 (wNAF). Variable time.
void g2MulPublic(Uint32List out, Uint32List q, int qo, BigInt k) {
  final t = g2OddMultiples(q, qo);
  g2SetInfinity(out, 0);
  final digits = wnaf(k, 5);
  final sel = Uint32List(g2Aff);
  for (var i = digits.length - 1; i >= 0; i--) {
    g2Double(out, 0);
    final d = digits[i];
    if (d == 0) continue;
    sel.setRange(0, g2Aff, t, ((d.abs() - 1) >> 1) * g2Aff);
    if (d < 0) f2Neg(sel, _y, sel, _y);
    g2Add(out, 0, sel, 0);
  }
}

/// True when affine limbs satisfy y^2 = x^3 + 5u.
bool g2IsOnCurve(Uint32List q, int qo) {
  final rhs = Uint32List(f2), lhs = Uint32List(f2);
  f2Sqr(rhs, 0, q, qo);
  f2Mul(rhs, 0, rhs, 0, q, qo);
  f2Add(rhs, 0, rhs, 0, _bTwist, 0);
  f2Sqr(lhs, 0, q, qo + _y);
  return f2Equals(lhs, 0, rhs, 0);
}

/// True when [N]Q is infinity, for an on-curve affine Q. Variable time.
bool g2InSubgroup(Uint32List q, int qo) {
  // [N]Q = [N - 1]Q + Q; computing [N-1]Q and comparing with -Q avoids
  // relying on the addition formula reaching infinity.
  final jac = Uint32List(g2Jac);
  g2MulPublic(jac, q, qo, sm9N - BigInt.one);
  final aff = Uint32List(g2Aff);
  if (!g2ToAffine(aff, 0, jac, 0)) return false;
  final negY = Uint32List(f2);
  f2Neg(negY, 0, q, qo + _y);
  return f2Equals(aff, 0, q, qo) && f2Equals(aff, _y, negY, 0);
}

/// Decodes `04 || x1 || x0 || y1 || y0` (129 bytes) into an on-curve affine
/// point, or returns null. No subgroup check; see [g2Decode].
Uint32List? g2DecodeOnCurve(List<int> data) {
  if (data.length != 129 || data[0] != 4) return null;
  final q = Uint32List(g2Aff);
  if (!fq.setBytes(q, f1, data, 1) ||
      !fq.setBytes(q, 0, data, 33) ||
      !fq.setBytes(q, f2 + f1, data, 65) ||
      !fq.setBytes(q, f2, data, 97)) {
    return null;
  }
  // (0, 0) is not on the twist, so on-curve points are all finite.
  return g2IsOnCurve(q, 0) ? q : null;
}

/// Decodes a G2 point, or returns null for anything that is not a point of
/// G2 other than infinity (the subgroup is checked).
Uint32List? g2Decode(List<int> data) {
  final q = g2DecodeOnCurve(data);
  return q != null && g2InSubgroup(q, 0) ? q : null;
}

/// `x1 || x0 || y1 || y0`, 128 bytes.
Uint8List g2Xy(Uint32List q, int qo) {
  final out = Uint8List(128);
  fq.getBytes(out, 0, q, qo + f1);
  fq.getBytes(out, 32, q, qo);
  fq.getBytes(out, 64, q, qo + f2 + f1);
  fq.getBytes(out, 96, q, qo + f2);
  return out;
}

/// `04 || x1 || x0 || y1 || y0`, 129 bytes.
Uint8List g2Encode(Uint32List q, int qo) {
  final out = Uint8List(129);
  out[0] = 4;
  out.setRange(1, 129, g2Xy(q, qo));
  return out;
}

Uint32List? _p2Table;

/// The odd-multiples table of P2 (built once).
Uint32List p2Table() => _p2Table ??= g2OddMultiples(p2Affine, 0);

/// Affine [k]Q for a secret k; null only if the result is infinity.
Uint32List? g2MulSecretAffine(Uint32List q, BigInt k, Uint32List table) {
  final jac = Uint32List(g2Jac);
  g2MulSecret(jac, q, 0, k, table);
  final out = Uint32List(g2Aff);
  return g2ToAffine(out, 0, jac, 0) ? out : null;
}

// Frobenius on the twist: pi(x, y) = (conj(x) * piX, conj(y) * piY) with
// piX = u^(-(q-1)/3), piY = u^(-(q-1)/2).
final List<Uint32List> _pi = () {
  final u = Uint32List(f2);
  MontField.copy(u, f1, fq.one, 0);
  final x = Uint32List(f2), y = Uint32List(f2);
  final q1 = fq.modulus - BigInt.one;
  f2PowPublic(x, 0, u, 0, q1 ~/ BigInt.from(3));
  f2Inv(x, 0, x, 0);
  f2PowPublic(y, 0, u, 0, q1 ~/ BigInt.two);
  f2Inv(y, 0, y, 0);
  return [x, y];
}();

/// r = pi(q) for affine q.
void g2Frobenius(Uint32List r, int ro, Uint32List q, int qo) {
  f2Conj(r, ro, q, qo);
  f2Mul(r, ro, r, ro, _pi[0], 0);
  f2Conj(r, ro + _y, q, qo + _y);
  f2Mul(r, ro + _y, r, ro + _y, _pi[1], 0);
}

// ---------------------------------------------------------------- fixed base P2

Uint32List? _comb;

/// Row i holds the odd multiples of 32^i P2 (52 x 16 affine points).
Uint32List _p2Comb() {
  final cached = _comb;
  if (cached != null) return cached;
  final table = Uint32List(_windows * _tableSize * g2Aff);
  final base = Uint32List.fromList(p2Affine);
  final next = Uint32List(g2Jac);
  for (var row = 0; row < _windows; row++) {
    final m = g2OddMultiples(base, 0);
    table.setRange(row * _tableSize * g2Aff, (row + 1) * _tableSize * g2Aff, m);
    g2FromAffine(next, 0, m, (_tableSize - 1) * g2Aff);
    g2Add(next, 0, base, 0);
    g2ToAffine(base, 0, next, 0);
  }
  return _comb = table;
}

/// out = [k]P2 with the comb. For a secret k the lookups are masked and the
/// schedule is fixed; for a public k they are direct.
void g2MulP2(Uint32List out, BigInt k, {required bool secret}) {
  final table = _p2Comb();
  final digits = recodeWith(k, sm9N);
  final sel = Uint32List(g2Aff);
  g2SetInfinity(out, 0);
  for (var row = 0; row < _windows; row++) {
    final a = digits[row];
    final positive = a >> 4;
    final index = (a ^ (positive - 1)) & 15;
    final o = row * _tableSize * g2Aff;
    if (secret) {
      sel.fillRange(0, g2Aff, 0);
      for (var i = 0; i < _tableSize; i++) {
        final mask = eqMask(i, index);
        final b = o + i * g2Aff;
        for (var j = 0; j < g2Aff; j++) {
          sel[j] |= table[b + j] & mask;
        }
      }
    } else {
      sel.setRange(0, g2Aff, table, o + index * g2Aff);
    }
    f2Neg(_negY, 0, sel, _y);
    final m = positive - 1;
    MontField.cmov(sel, _y, _negY, 0, m);
    MontField.cmov(sel, _y + f1, _negY, f1, m);
    if (row == 0) {
      g2FromAffine(out, 0, sel, 0);
    } else if (!secret) {
      g2Add(out, 0, sel, 0);
    } else if (g2AddUnchecked(out, 0, sel, 0)) {
      g2MulPublic(out, p2Affine, 0, k);
      return;
    }
  }
}

/// Affine [k]P2 for a secret k in [1, N-1].
Uint32List g2MulP2Secret(BigInt k) {
  final jac = Uint32List(g2Jac);
  g2MulP2(jac, k, secret: true);
  final out = Uint32List(g2Aff);
  g2ToAffine(out, 0, jac, 0);
  return out;
}
