/// The SM9 extension tower on 29-bit Montgomery limbs:
///
///   Fq2  = Fq[u]/(u^2 + 2)            2 x 9 limbs:  a0, a1
///   Fq6  = Fq2[s]/(s^3 - u)           3 x 18 limbs: b0, b1, b2
///   Fq12 = Fq6[w]/(w^2 - s)           2 x 54 limbs: A, B
///
/// so s = w^2 and w^6 = u. An Fq12 element is sum x_j w^j with x0 = A.b0,
/// x1 = B.b0, x2 = A.b1, x3 = B.b1, x4 = A.b2, x5 = B.b2, the same
/// coefficients the reference (testvectors/sm9_ref.py) uses.
///
/// Every function reads its inputs before writing the output (it computes into
/// private scratch first), so outputs may alias inputs. The functions are not
/// reentrant, which is fine as Dart runs synchronous code without preemption.
/// No branch or index depends on element values.
library;

import 'dart:typed_data';

import '../field/field.dart';
import '../field/sm9_fq.g.dart';
import '../field/sm9_fq2_mul.g.dart';
import '../field/sm9_fq2_sqr.g.dart';

const int f1 = limbs; // limbs of Fq
const int f2 = 2 * limbs; // limbs of Fq2
const int f6 = 6 * limbs;
const int f12 = 12 * limbs;

final MontField fq = sm9Fq;

Uint32List _buf(int n) => Uint32List(n);

// ---------------------------------------------------------------- Fq2

final _m0 = _buf(f1), _m1 = _buf(f1);

void f2Copy(Uint32List r, int ro, Uint32List a, int ao) {
  for (var i = 0; i < f2; i++) {
    r[ro + i] = a[ao + i];
  }
}

void f2Add(Uint32List r, int ro, Uint32List a, int ao, Uint32List b, int bo) {
  fqAdd(r, ro, a, ao, b, bo);
  fqAdd(r, ro + f1, a, ao + f1, b, bo + f1);
}

void f2Sub(Uint32List r, int ro, Uint32List a, int ao, Uint32List b, int bo) {
  fqSub(r, ro, a, ao, b, bo);
  fqSub(r, ro + f1, a, ao + f1, b, bo + f1);
}

void f2Neg(Uint32List r, int ro, Uint32List a, int ao) {
  fqNeg(r, ro, a, ao);
  fqNeg(r, ro + f1, a, ao + f1);
}

void f2Dbl(Uint32List r, int ro, Uint32List a, int ao) =>
    f2Add(r, ro, a, ao, a, ao);

void f2Conj(Uint32List r, int ro, Uint32List a, int ao) {
  MontField.copy(r, ro, a, ao);
  fqNeg(r, ro + f1, a, ao + f1);
}

/// r = a * b (fused: three unreduced products, two reductions).
void f2Mul(Uint32List r, int ro, Uint32List a, int ao, Uint32List b, int bo) =>
    fq2Mul(r, ro, a, ao, b, bo);

/// r = a^2 (fused: (a0 + a1)(a0 - 2 a1) + a0 a1, and 2 a0 a1).
void f2Sqr(Uint32List r, int ro, Uint32List a, int ao) => fq2Sqr(r, ro, a, ao);

/// r = a * u = -2 a1 + a0 u.
void f2MulU(Uint32List r, int ro, Uint32List a, int ao) {
  MontField.copy(_m0, 0, a, ao);
  fqAdd(_m1, 0, a, ao + f1, a, ao + f1);
  fqNeg(r, ro, _m1, 0);
  MontField.copy(r, ro + f1, _m0, 0);
}

/// r = a * e for e in Fq.
void f2MulFq(Uint32List r, int ro, Uint32List a, int ao, Uint32List e, int eo) {
  fqMul(r, ro, a, ao, e, eo);
  fqMul(r, ro + f1, a, ao + f1, e, eo);
}

/// r = 1/a, via the norm a0^2 + 2 a1^2; the inverse of 0 is 0.
void f2Inv(Uint32List r, int ro, Uint32List a, int ao) {
  fqSqr(_m0, 0, a, ao);
  fqSqr(_m1, 0, a, ao + f1);
  fqAdd(_m1, 0, _m1, 0, _m1, 0);
  fqAdd(_m0, 0, _m0, 0, _m1, 0);
  fq.invert(_m0, 0, _m0, 0);
  fqNeg(_m1, 0, a, ao + f1);
  fqMul(r, ro, a, ao, _m0, 0);
  fqMul(r, ro + f1, _m1, 0, _m0, 0);
}

bool f2IsZero(Uint32List a, int ao) =>
    fq.isZero(a, ao) && fq.isZero(a, ao + f1);

bool f2Equals(Uint32List a, int ao, Uint32List b, int bo) =>
    fq.equals(a, ao, b, bo) && fq.equals(a, ao + f1, b, bo + f1);

/// Sets r to 1.
void f2One(Uint32List r, int ro) {
  MontField.copy(r, ro, fq.one, 0);
  r.fillRange(ro + f1, ro + f2, 0);
}

/// r = a^e for a public exponent (square and multiply).
void f2PowPublic(Uint32List r, int ro, Uint32List a, int ao, BigInt e) {
  final base = Uint32List(f2)..setRange(0, f2, a, ao);
  final acc = Uint32List(f2);
  f2One(acc, 0);
  for (var i = e.bitLength - 1; i >= 0; i--) {
    f2Sqr(acc, 0, acc, 0);
    if ((e >> i).isOdd) f2Mul(acc, 0, acc, 0, base, 0);
  }
  f2Copy(r, ro, acc, 0);
}

// ---------------------------------------------------------------- Fq6

final _s6 = _buf(8 * f2);

void f6Add(Uint32List r, int ro, Uint32List a, int ao, Uint32List b, int bo) {
  for (var i = 0; i < 6; i++) {
    fqAdd(r, ro + i * f1, a, ao + i * f1, b, bo + i * f1);
  }
}

void f6Sub(Uint32List r, int ro, Uint32List a, int ao, Uint32List b, int bo) {
  for (var i = 0; i < 6; i++) {
    fqSub(r, ro + i * f1, a, ao + i * f1, b, bo + i * f1);
  }
}

void f6Neg(Uint32List r, int ro, Uint32List a, int ao) {
  for (var i = 0; i < 6; i++) {
    fqNeg(r, ro + i * f1, a, ao + i * f1);
  }
}

/// r = a * b (Karatsuba, 6 Fq2 multiplications).
void f6Mul(Uint32List r, int ro, Uint32List a, int ao, Uint32List b, int bo) {
  final s = _s6;
  const v0 = 0, v1 = f2, v2 = 2 * f2, t0 = 3 * f2, t1 = 4 * f2;
  const c0 = 5 * f2, c1 = 6 * f2, c2 = 7 * f2;
  f2Mul(s, v0, a, ao, b, bo);
  f2Mul(s, v1, a, ao + f2, b, bo + f2);
  f2Mul(s, v2, a, ao + 2 * f2, b, bo + 2 * f2);
  // c0 = v0 + u((a1 + a2)(b1 + b2) - v1 - v2)
  f2Add(s, t0, a, ao + f2, a, ao + 2 * f2);
  f2Add(s, t1, b, bo + f2, b, bo + 2 * f2);
  f2Mul(s, t0, s, t0, s, t1);
  f2Sub(s, t0, s, t0, s, v1);
  f2Sub(s, t0, s, t0, s, v2);
  f2MulU(s, t0, s, t0);
  f2Add(s, c0, s, t0, s, v0);
  // c1 = (a0 + a1)(b0 + b1) - v0 - v1 + u v2
  f2Add(s, t0, a, ao, a, ao + f2);
  f2Add(s, t1, b, bo, b, bo + f2);
  f2Mul(s, t0, s, t0, s, t1);
  f2Sub(s, t0, s, t0, s, v0);
  f2Sub(s, t0, s, t0, s, v1);
  f2MulU(s, t1, s, v2);
  f2Add(s, c1, s, t0, s, t1);
  // c2 = (a0 + a2)(b0 + b2) - v0 - v2 + v1
  f2Add(s, t0, a, ao, a, ao + 2 * f2);
  f2Add(s, t1, b, bo, b, bo + 2 * f2);
  f2Mul(s, t0, s, t0, s, t1);
  f2Sub(s, t0, s, t0, s, v0);
  f2Sub(s, t0, s, t0, s, v2);
  f2Add(s, c2, s, t0, s, v1);
  r.setRange(ro, ro + f6, s, c0);
}

/// r = a^2 (Chung-Hasan SQR2).
void f6Sqr(Uint32List r, int ro, Uint32List a, int ao) {
  final s = _s6;
  const s0 = 0, s1 = f2, s2 = 2 * f2, s3 = 3 * f2, s4 = 4 * f2;
  const c0 = 5 * f2, c1 = 6 * f2, c2 = 7 * f2;
  f2Sqr(s, s0, a, ao);
  f2Mul(s, s1, a, ao, a, ao + f2);
  f2Dbl(s, s1, s, s1);
  f2Sub(s, s2, a, ao, a, ao + f2);
  f2Add(s, s2, s, s2, a, ao + 2 * f2);
  f2Sqr(s, s2, s, s2);
  f2Mul(s, s3, a, ao + f2, a, ao + 2 * f2);
  f2Dbl(s, s3, s, s3);
  f2Sqr(s, s4, a, ao + 2 * f2);
  f2MulU(s, c0, s, s3);
  f2Add(s, c0, s, c0, s, s0);
  f2MulU(s, c1, s, s4);
  f2Add(s, c1, s, c1, s, s1);
  f2Add(s, c2, s, s1, s, s2);
  f2Add(s, c2, s, c2, s, s3);
  f2Sub(s, c2, s, c2, s, s0);
  f2Sub(s, c2, s, c2, s, s4);
  r.setRange(ro, ro + f6, s, c0);
}

final _sMulS = _buf(f2);

/// r = a * s = (u a2, a0, a1).
void f6MulS(Uint32List r, int ro, Uint32List a, int ao) {
  f2MulU(_sMulS, 0, a, ao + 2 * f2);
  f2Copy(r, ro + 2 * f2, a, ao + f2);
  f2Copy(r, ro + f2, a, ao);
  f2Copy(r, ro, _sMulS, 0);
}

final _sInv6 = _buf(5 * f2);

/// r = 1/a.
void f6Inv(Uint32List r, int ro, Uint32List a, int ao) {
  final s = _sInv6;
  const c0 = 0, c1 = f2, c2 = 2 * f2, t = 3 * f2, t2 = 4 * f2;
  // c0 = a0^2 - u a1 a2
  f2Sqr(s, c0, a, ao);
  f2Mul(s, t, a, ao + f2, a, ao + 2 * f2);
  f2MulU(s, t, s, t);
  f2Sub(s, c0, s, c0, s, t);
  // c1 = u a2^2 - a0 a1
  f2Sqr(s, c1, a, ao + 2 * f2);
  f2MulU(s, c1, s, c1);
  f2Mul(s, t, a, ao, a, ao + f2);
  f2Sub(s, c1, s, c1, s, t);
  // c2 = a1^2 - a0 a2
  f2Sqr(s, c2, a, ao + f2);
  f2Mul(s, t, a, ao, a, ao + 2 * f2);
  f2Sub(s, c2, s, c2, s, t);
  // t = a0 c0 + u (a2 c1 + a1 c2)
  f2Mul(s, t, a, ao + 2 * f2, s, c1);
  f2Mul(s, t2, a, ao + f2, s, c2);
  f2Add(s, t, s, t, s, t2);
  f2MulU(s, t, s, t);
  f2Mul(s, t2, a, ao, s, c0);
  f2Add(s, t, s, t, s, t2);
  f2Inv(s, t, s, t);
  f2Mul(r, ro, s, c0, s, t);
  f2Mul(r, ro + f2, s, c1, s, t);
  f2Mul(r, ro + 2 * f2, s, c2, s, t);
}

// ---------------------------------------------------------------- Fq12

final _s12 = _buf(4 * f6);

void f12One(Uint32List r, int ro) {
  r.fillRange(ro, ro + f12, 0);
  MontField.copy(r, ro, fq.one, 0);
}

void f12Copy(Uint32List r, int ro, Uint32List a, int ao) =>
    r.setRange(ro, ro + f12, a, ao);

/// r = a * b (Karatsuba over Fq6, 3 Fq6 multiplications).
void f12Mul(Uint32List r, int ro, Uint32List a, int ao, Uint32List b, int bo) {
  final s = _s12;
  const v0 = 0, v1 = f6, t0 = 2 * f6, t1 = 3 * f6;
  f6Mul(s, v0, a, ao, b, bo);
  f6Mul(s, v1, a, ao + f6, b, bo + f6);
  f6Add(s, t0, a, ao, a, ao + f6);
  f6Add(s, t1, b, bo, b, bo + f6);
  f6Mul(s, t0, s, t0, s, t1);
  f6Sub(s, t0, s, t0, s, v0);
  f6Sub(s, t0, s, t0, s, v1); // c1
  f6MulS(s, v1, s, v1);
  f6Add(r, ro, s, v0, s, v1);
  r.setRange(ro + f6, ro + f12, s, t0);
}

/// r = a^2: c0 = (A + B)(A + sB) - AB - sAB, c1 = 2AB.
void f12Sqr(Uint32List r, int ro, Uint32List a, int ao) {
  final s = _s12;
  const ab = 0, t0 = f6, t1 = 2 * f6;
  f6Mul(s, ab, a, ao, a, ao + f6);
  f6Add(s, t0, a, ao, a, ao + f6);
  f6MulS(s, t1, a, ao + f6);
  f6Add(s, t1, s, t1, a, ao);
  f6Mul(s, t0, s, t0, s, t1);
  f6Sub(s, t0, s, t0, s, ab);
  f6MulS(s, t1, s, ab);
  f6Sub(r, ro, s, t0, s, t1);
  f6Add(r, ro + f6, s, ab, s, ab);
}

/// r = a^(q^6) = A - Bw, which is 1/a in the cyclotomic subgroup.
void f12Conj(Uint32List r, int ro, Uint32List a, int ao) {
  if (!identical(r, a) || ro != ao) r.setRange(ro, ro + f6, a, ao);
  f6Neg(r, ro + f6, a, ao + f6);
}

final _sInv12 = _buf(3 * f6);

/// r = 1/a = (A - Bw) / (A^2 - s B^2).
void f12Inv(Uint32List r, int ro, Uint32List a, int ao) {
  final s = _sInv12;
  f6Sqr(s, 0, a, ao);
  f6Sqr(s, f6, a, ao + f6);
  f6MulS(s, f6, s, f6);
  f6Sub(s, 0, s, 0, s, f6);
  f6Inv(s, 0, s, 0);
  f6Mul(s, f6, a, ao, s, 0);
  f6Mul(s, 2 * f6, a, ao + f6, s, 0);
  r.setRange(ro, ro + f6, s, f6);
  f6Neg(r, ro + f6, s, 2 * f6);
}

final _sLine = _buf(4 * f6);

/// f = f * l for a line l = c0 + c2 w^2 + c3 w^3, given as three Fq2 values
/// at lo (c0), lo + 18 (c2) and lo + 36 (c3). In the tower, l = (c0, c2, 0)
/// + (0, c3, 0) w.
void f12MulLine(Uint32List f, int fo, Uint32List l, int lo) {
  final s = _sLine;
  const v0 = 0, v1 = f6, t0 = 2 * f6, t1 = 3 * f6;
  _f6MulSparse01(s, v0, f, fo, l, lo, l, lo + f2);
  _f6MulSparse1(s, v1, f, fo + f6, l, lo + 2 * f2);
  f6Add(s, t0, f, fo, f, fo + f6);
  f2Add(s, t1, l, lo + f2, l, lo + 2 * f2); // c2 + c3 as scratch
  _f6MulSparse01(s, t0, s, t0, l, lo, s, t1);
  f6Sub(s, t0, s, t0, s, v0);
  f6Sub(s, t0, s, t0, s, v1);
  f6MulS(s, v1, s, v1);
  f6Add(f, fo, s, v0, s, v1);
  f.setRange(fo + f6, fo + f12, s, t0);
}

final _sSp = _buf(5 * f2);

/// r = a * (x + y s) for Fq2 x, y.
void _f6MulSparse01(Uint32List r, int ro, Uint32List a, int ao, Uint32List x,
    int xo, Uint32List y, int yo) {
  final s = _sSp;
  // (a0 + a1 s + a2 s^2)(x + y s) = a0x + u a2 y + (a0 y + a1 x) s + (a1 y + a2 x) s^2
  f2Mul(s, 0, a, ao, x, xo);
  f2Mul(s, f2, a, ao + 2 * f2, y, yo);
  f2MulU(s, f2, s, f2);
  f2Add(s, 0, s, 0, s, f2);
  f2Mul(s, f2, a, ao, y, yo);
  f2Mul(s, 2 * f2, a, ao + f2, x, xo);
  f2Add(s, f2, s, f2, s, 2 * f2);
  f2Mul(s, 2 * f2, a, ao + f2, y, yo);
  f2Mul(s, 3 * f2, a, ao + 2 * f2, x, xo);
  f2Add(s, 2 * f2, s, 2 * f2, s, 3 * f2);
  r.setRange(ro, ro + f6, s, 0);
}

/// r = a * (y s) for Fq2 y: (u a2 y, a0 y, a1 y).
void _f6MulSparse1(
    Uint32List r, int ro, Uint32List a, int ao, Uint32List y, int yo) {
  final s = _sSp;
  f2Mul(s, 0, a, ao + 2 * f2, y, yo);
  f2MulU(s, 0, s, 0);
  f2Mul(s, f2, a, ao, y, yo);
  f2Mul(s, 2 * f2, a, ao + f2, y, yo);
  r.setRange(ro, ro + f6, s, 0);
}

/// Offset of the coefficient x_j of w^j inside an Fq12 element.
int coeff(int j) => j.isEven ? (j >> 1) * f2 : f6 + (j >> 1) * f2;

// Frobenius constants gamma_k^j, gamma_k = u^((q^k - 1)/6), k = 1, 2, 3.
final List<Uint32List> _gamma = _frobeniusConstants();

List<Uint32List> _frobeniusConstants() {
  final u = Uint32List(f2);
  MontField.copy(u, f1, fq.one, 0);
  return [
    for (var k = 1; k <= 3; k++)
      _powers(u, (fq.modulus.pow(k) - BigInt.one) ~/ BigInt.from(6)),
  ];
}

Uint32List _powers(Uint32List u, BigInt e) {
  final g = Uint32List(f2);
  f2PowPublic(g, 0, u, 0, e);
  final out = Uint32List(6 * f2);
  f2One(out, 0);
  for (var j = 1; j < 6; j++) {
    f2Mul(out, j * f2, out, (j - 1) * f2, g, 0);
  }
  return out;
}

/// r = a^(q^k) for k in 1..3: x_j -> conj^k(x_j) gamma_k^j.
void f12Frob(Uint32List r, int ro, Uint32List a, int ao, int k) {
  final g = _gamma[k - 1];
  for (var j = 0; j < 6; j++) {
    final o = coeff(j);
    if (k.isOdd) {
      f2Conj(r, ro + o, a, ao + o);
    } else if (!identical(r, a) || ro != ao) {
      f2Copy(r, ro + o, a, ao + o);
    }
    if (j > 0) f2Mul(r, ro + o, r, ro + o, g, j * f2);
  }
}

final _sCyc = _buf(9 * f2);

/// r = a^2 for a in the cyclotomic subgroup (Granger-Scott).
void f12CycSqr(Uint32List r, int ro, Uint32List a, int ao) {
  final s = _sCyc;
  // z0 = A.b0, z4 = A.b1, z3 = A.b2, z2 = B.b0, z1 = B.b1, z5 = B.b2
  final z0 = ao, z4 = ao + f2, z3 = ao + 2 * f2;
  final z2 = ao + f6, z1 = ao + f6 + f2, z5 = ao + f6 + 2 * f2;
  const t0 = 0, t1 = f2, t2 = 2 * f2, t3 = 3 * f2, t4 = 4 * f2, t5 = 5 * f2;
  const tmp = 6 * f2, tmp2 = 7 * f2;
  void sqr4(int x, int y, int outA, int outB) {
    // (x + y Y)^2 with Y^2 = u: outA = x^2 + u y^2, outB = 2xy
    f2Mul(s, tmp, a, x, a, y);
    f2Add(s, outA, a, x, a, y);
    f2MulU(s, tmp2, a, y);
    f2Add(s, tmp2, s, tmp2, a, x);
    f2Mul(s, outA, s, outA, s, tmp2);
    f2Sub(s, outA, s, outA, s, tmp);
    f2MulU(s, tmp2, s, tmp);
    f2Sub(s, outA, s, outA, s, tmp2);
    f2Dbl(s, outB, s, tmp);
  }

  sqr4(z0, z1, t0, t1);
  sqr4(z2, z3, t2, t3);
  sqr4(z4, z5, t4, t5);
  final o = Uint32List(f12); // assembled here so that r may alias a
  // A.b0 = 3 t0 - 2 z0
  f2Sub(o, 0, s, t0, a, z0);
  f2Dbl(o, 0, o, 0);
  f2Add(o, 0, o, 0, s, t0);
  // B.b1 = 3 t1 + 2 z1
  f2Add(o, f6 + f2, s, t1, a, z1);
  f2Dbl(o, f6 + f2, o, f6 + f2);
  f2Add(o, f6 + f2, o, f6 + f2, s, t1);
  // B.b0 = 3 u t5 + 2 z2
  f2MulU(s, tmp, s, t5);
  f2Add(o, f6, s, tmp, a, z2);
  f2Dbl(o, f6, o, f6);
  f2Add(o, f6, o, f6, s, tmp);
  // A.b2 = 3 t4 - 2 z3
  f2Sub(o, 2 * f2, s, t4, a, z3);
  f2Dbl(o, 2 * f2, o, 2 * f2);
  f2Add(o, 2 * f2, o, 2 * f2, s, t4);
  // A.b1 = 3 t2 - 2 z4
  f2Sub(o, f2, s, t2, a, z4);
  f2Dbl(o, f2, o, f2);
  f2Add(o, f2, o, f2, s, t2);
  // B.b2 = 3 t3 + 2 z5
  f2Add(o, f6 + 2 * f2, s, t3, a, z5);
  f2Dbl(o, f6 + 2 * f2, o, f6 + 2 * f2);
  f2Add(o, f6 + 2 * f2, o, f6 + 2 * f2, s, t3);
  r.setRange(ro, ro + f12, o);
}

/// True when a == b.
bool f12Equals(Uint32List a, int ao, Uint32List b, int bo) {
  for (var i = 0; i < 12; i++) {
    if (!fq.equals(a, ao + i * f1, b, bo + i * f1)) return false;
  }
  return true;
}

/// The 384-byte encoding: c2 || c1 || c0 with c_i = x_i + x_{i+3} v written
/// as x_{i+3} || x_i, each Fq2 as a1 || a0.
Uint8List f12ToBytes(Uint32List a, int ao) {
  final out = Uint8List(384);
  var p = 0;
  for (final j in const [5, 2, 4, 1, 3, 0]) {
    final o = ao + coeff(j);
    fq.getBytes(out, p, a, o + f1);
    fq.getBytes(out, p + 32, a, o);
    p += 64;
  }
  return out;
}
