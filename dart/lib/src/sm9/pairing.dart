/// The SM9 R-ate pairing and exponentiation in GT.
///
/// Miller loop over a = 6t + 2 with the twist point in Jacobian coordinates
/// and lines evaluated at P, then T += pi(Q), T -= pi^2(Q), as in
/// GB/T 38635.1 B.6.2 and testvectors/sm9_ref.py. Every line is scaled by an
/// Fq2 factor, which the final exponentiation removes. The final
/// exponentiation computes exactly f^((q^12 - 1)/N): the easy part
/// (q^6 - 1)(q^2 + 1), then the hard part (q^4 - q^2 + 1)/N with the BN
/// addition chain in t of Scott et al., using cyclotomic squarings.
library;

import 'dart:typed_data';

import '../field/field.dart';
import 'g2.dart';
import 'params.dart';
import 'tower.dart';

const int _y = f2;
const int _z = 2 * f2;

final List<int> _loopBits = () {
  final a = sm9T * BigInt.from(6) + BigInt.two;
  return [for (var i = a.bitLength - 2; i >= 0; i--) (a >> i).isOdd ? 1 : 0];
}();

final _l0 = Uint32List(f2), _l1 = Uint32List(f2), _l2 = Uint32List(f2);
final _l3 = Uint32List(f2), _l4 = Uint32List(f2), _l5 = Uint32List(f2);

/// T = 2T; writes the tangent line at P (xP, -yP in Fq) into line.
void _doubleStep(
    Uint32List t, Uint32List line, Uint32List xP, Uint32List negYP) {
  const x = 0, y = _y, z = _z;
  f2Sqr(_l0, 0, t, x); // A = X^2
  f2Sqr(_l1, 0, t, y); // B = Y^2
  f2Sqr(_l2, 0, _l1, 0); // C = B^2
  f2Sqr(_l3, 0, t, z); // ZZ
  f2Dbl(_l4, 0, _l0, 0);
  f2Add(_l4, 0, _l4, 0, _l0, 0); // M = 3A
  // line c0 = 2B - M X, c2 = M ZZ xP
  f2Mul(_l5, 0, _l4, 0, t, x);
  f2Dbl(line, 0, _l1, 0);
  f2Sub(line, 0, line, 0, _l5, 0);
  f2Mul(line, f2, _l4, 0, _l3, 0);
  f2MulFq(line, f2, line, f2, xP, 0);
  // S = 4 X B
  f2Mul(_l5, 0, t, x, _l1, 0);
  f2Dbl(_l5, 0, _l5, 0);
  f2Dbl(_l5, 0, _l5, 0);
  // Z3 = 2 Y Z, line c3 = -Z3 ZZ yP
  f2Mul(t, z, t, y, t, z);
  f2Dbl(t, z, t, z);
  f2Mul(line, 2 * f2, t, z, _l3, 0);
  f2MulFq(line, 2 * f2, line, 2 * f2, negYP, 0);
  // X3 = M^2 - 2S, Y3 = M (S - X3) - 8C
  f2Sqr(_l0, 0, _l4, 0);
  f2Sub(_l0, 0, _l0, 0, _l5, 0);
  f2Sub(t, x, _l0, 0, _l5, 0);
  f2Sub(_l5, 0, _l5, 0, t, x);
  f2Mul(_l5, 0, _l4, 0, _l5, 0);
  f2Dbl(_l2, 0, _l2, 0);
  f2Dbl(_l2, 0, _l2, 0);
  f2Dbl(_l2, 0, _l2, 0);
  f2Sub(t, y, _l5, 0, _l2, 0);
}

/// T = T + Q for affine Q; writes the line through T and Q at P into line.
void _addStep(Uint32List t, Uint32List q, int qo, Uint32List line,
    Uint32List xP, Uint32List negYP) {
  const x = 0, y = _y, z = _z;
  f2Sqr(_l0, 0, t, z); // ZZ
  f2Mul(_l1, 0, q, qo, _l0, 0); // U2
  f2Mul(_l2, 0, t, z, _l0, 0);
  f2Mul(_l2, 0, q, qo + _y, _l2, 0); // S2
  f2Sub(_l1, 0, _l1, 0, t, x); // H
  f2Sub(_l2, 0, _l2, 0, t, y); // R
  // Z3 = Z H
  f2Mul(t, z, t, z, _l1, 0);
  // line c0 = y2 Z3 - R x2, c2 = R xP, c3 = -Z3 yP
  f2Mul(line, 0, q, qo + _y, t, z);
  f2Mul(_l3, 0, _l2, 0, q, qo);
  f2Sub(line, 0, line, 0, _l3, 0);
  f2MulFq(line, f2, _l2, 0, xP, 0);
  f2MulFq(line, 2 * f2, t, z, negYP, 0);
  // HH, HHH, V = X HH
  f2Sqr(_l3, 0, _l1, 0);
  f2Mul(_l4, 0, _l1, 0, _l3, 0);
  f2Mul(_l5, 0, t, x, _l3, 0);
  // X3 = R^2 - HHH - 2V
  f2Sqr(_l0, 0, _l2, 0);
  f2Sub(_l0, 0, _l0, 0, _l4, 0);
  f2Sub(_l0, 0, _l0, 0, _l5, 0);
  f2Sub(t, x, _l0, 0, _l5, 0);
  // Y3 = R (V - X3) - Y HHH
  f2Sub(_l5, 0, _l5, 0, t, x);
  f2Mul(_l5, 0, _l2, 0, _l5, 0);
  f2Mul(_l4, 0, t, y, _l4, 0);
  f2Sub(t, y, _l5, 0, _l4, 0);
}

/// The Miller loop value f for P in G1 and Q in G2, both affine and finite.
Uint32List millerLoop(Uint32List p, int po, Uint32List q, int qo) {
  final xP = Uint32List(f1)..setRange(0, f1, p, po);
  final negYP = Uint32List(f1);
  fq.sub(negYP, 0, Uint32List(f1), 0, p, po + f1);
  final t = Uint32List(3 * f2);
  g2FromAffine(t, 0, q, qo);
  final f = Uint32List(f12);
  f12One(f, 0);
  final line = Uint32List(3 * f2);
  var first = true;
  for (final bit in _loopBits) {
    _doubleStep(t, line, xP, negYP);
    if (!first) f12Sqr(f, 0, f, 0);
    first = false;
    f12MulLine(f, 0, line, 0);
    if (bit == 1) {
      _addStep(t, q, qo, line, xP, negYP);
      f12MulLine(f, 0, line, 0);
    }
  }
  final q1 = Uint32List(2 * f2), q2 = Uint32List(2 * f2);
  g2Frobenius(q1, 0, q, qo);
  g2Frobenius(q2, 0, q1, 0);
  f2Neg(q2, _y, q2, _y);
  _addStep(t, q1, 0, line, xP, negYP);
  f12MulLine(f, 0, line, 0);
  _addStep(t, q2, 0, line, xP, negYP);
  f12MulLine(f, 0, line, 0);
  return f;
}

/// r = a^t (t public, a in the cyclotomic subgroup).
void _powT(Uint32List r, Uint32List a) {
  final base = Uint32List.fromList(a);
  final acc = Uint32List.fromList(a);
  final t = sm9T;
  for (var i = t.bitLength - 2; i >= 0; i--) {
    f12CycSqr(acc, 0, acc, 0);
    if ((t >> i).isOdd) f12Mul(acc, 0, acc, 0, base, 0);
  }
  r.setRange(0, f12, acc);
}

/// f^((q^12 - 1)/N).
Uint32List finalExponentiation(Uint32List input) {
  final f = Uint32List(f12), t = Uint32List(f12);
  // Easy part: f^(q^6 - 1), then ^(q^2 + 1).
  f12Inv(t, 0, input, 0);
  f12Conj(f, 0, input, 0);
  f12Mul(f, 0, f, 0, t, 0);
  f12Frob(t, 0, f, 0, 2);
  f12Mul(f, 0, f, 0, t, 0);
  // Hard part.
  final fx = Uint32List(f12), fx2 = Uint32List(f12), fx3 = Uint32List(f12);
  _powT(fx, f);
  _powT(fx2, fx);
  _powT(fx3, fx2);
  final y0 = Uint32List(f12), y1 = Uint32List(f12), y2 = Uint32List(f12);
  final y3 = Uint32List(f12), y4 = Uint32List(f12), y5 = Uint32List(f12);
  final y6 = Uint32List(f12);
  f12Frob(y0, 0, f, 0, 1);
  f12Frob(t, 0, f, 0, 2);
  f12Mul(y0, 0, y0, 0, t, 0);
  f12Frob(t, 0, f, 0, 3);
  f12Mul(y0, 0, y0, 0, t, 0);
  f12Conj(y1, 0, f, 0);
  f12Frob(y2, 0, fx2, 0, 2);
  f12Frob(y3, 0, fx, 0, 1);
  f12Conj(y3, 0, y3, 0);
  f12Frob(y4, 0, fx2, 0, 1);
  f12Mul(y4, 0, y4, 0, fx, 0);
  f12Conj(y4, 0, y4, 0);
  f12Conj(y5, 0, fx2, 0);
  f12Frob(y6, 0, fx3, 0, 1);
  f12Mul(y6, 0, y6, 0, fx3, 0);
  f12Conj(y6, 0, y6, 0);
  final t0 = Uint32List(f12), t1 = Uint32List(f12);
  f12CycSqr(t0, 0, y6, 0);
  f12Mul(t0, 0, t0, 0, y4, 0);
  f12Mul(t0, 0, t0, 0, y5, 0);
  f12Mul(t1, 0, y3, 0, y5, 0);
  f12Mul(t1, 0, t1, 0, t0, 0);
  f12Mul(t0, 0, t0, 0, y2, 0);
  f12CycSqr(t1, 0, t1, 0);
  f12Mul(t1, 0, t1, 0, t0, 0);
  f12CycSqr(t1, 0, t1, 0);
  f12Mul(t0, 0, t1, 0, y1, 0);
  f12Mul(t1, 0, t1, 0, y0, 0);
  f12CycSqr(t0, 0, t0, 0);
  f12Mul(t0, 0, t0, 0, t1, 0);
  return t0;
}

/// e(P, Q) for affine finite P in G1 and Q in G2.
Uint32List pairing(Uint32List p, int po, Uint32List q, int qo) =>
    finalExponentiation(millerLoop(p, po, q, qo));

/// a^e for a secret e in [0, 2^256) and a in the cyclotomic subgroup:
/// a fixed 4-bit window, every window reads the whole 16-entry table through
/// masks.
Uint32List gtPowSecret(Uint32List a, BigInt e) {
  final table = Uint32List(16 * f12);
  f12One(table, 0);
  table.setRange(f12, 2 * f12, a);
  for (var i = 2; i < 16; i++) {
    f12Mul(table, i * f12, table, (i - 1) * f12, a, 0);
  }
  final digits = Int32List(64);
  var v = e;
  final m = BigInt.from(15);
  for (var i = 0; i < 64; i++) {
    digits[i] = (v & m).toInt();
    v >>= 4;
  }
  final acc = Uint32List(f12), sel = Uint32List(f12);
  void select(int digit) {
    sel.fillRange(0, f12, 0);
    for (var i = 0; i < 16; i++) {
      final mask = eqMask(i, digit);
      final base = i * f12;
      for (var k = 0; k < f12; k++) {
        sel[k] |= table[base + k] & mask;
      }
    }
  }

  select(digits[63]);
  acc.setRange(0, f12, sel);
  for (var i = 62; i >= 0; i--) {
    f12CycSqr(acc, 0, acc, 0);
    f12CycSqr(acc, 0, acc, 0);
    f12CycSqr(acc, 0, acc, 0);
    f12CycSqr(acc, 0, acc, 0);
    select(digits[i]);
    f12Mul(acc, 0, acc, 0, sel, 0);
  }
  return acc;
}

/// a^e for a public e >= 0 (a in the cyclotomic subgroup). Variable time.
Uint32List gtPowPublic(Uint32List a, BigInt e) {
  final table = Uint32List(16 * f12);
  f12One(table, 0);
  table.setRange(f12, 2 * f12, a);
  for (var i = 2; i < 16; i++) {
    f12Mul(table, i * f12, table, (i - 1) * f12, a, 0);
  }
  final acc = Uint32List(f12);
  f12One(acc, 0);
  final windows = (e.bitLength + 3) >> 2;
  final m = BigInt.from(15);
  for (var i = windows - 1; i >= 0; i--) {
    if (i != windows - 1) {
      f12CycSqr(acc, 0, acc, 0);
      f12CycSqr(acc, 0, acc, 0);
      f12CycSqr(acc, 0, acc, 0);
      f12CycSqr(acc, 0, acc, 0);
    }
    final d = ((e >> (4 * i)) & m).toInt();
    if (d != 0) f12Mul(acc, 0, acc, 0, table, d * f12);
  }
  return acc;
}
