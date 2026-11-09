/// Helpers shared by the generated Montgomery fields: conversions, inversion,
/// masked selection.
///
/// Elements are 9 limbs of 29 bits at an offset in a [Uint32List], in
/// Montgomery form, kept in [0, 2m). Dart integers give no constant-time
/// guarantee; the code below has no branch or memory index that depends on an
/// element's value, which is as far as Dart source can go.
library;

import 'dart:typed_data';

import 'sm2_fp.g.dart';
import 'sm9_fq.g.dart';

/// Number of limbs in one element.
const int limbs = 9;
const int _bits = 29;
const int _mask = (1 << _bits) - 1;

typedef MulFn = void Function(
    Uint32List r, int ro, Uint32List a, int ao, Uint32List b, int bo);
typedef UnaryFn = void Function(Uint32List r, int ro, Uint32List a, int ao);

/// One prime field with its generated arithmetic.
final class MontField {
  MontField._(this.modulus, this.modulusLimbs, this.mul, this.sqr, this.add,
      this.sub, this.canon) {
    final r = (BigInt.one << (limbs * _bits)) % modulus;
    _setRaw(one, 0, r);
    _setRaw(_r2, 0, (r * r) % modulus);
    final e = modulus - BigInt.two;
    _digits = [
      for (var w = (e.bitLength + 3) >> 2; w > 0; w--)
        ((e >> (4 * (w - 1))) & BigInt.from(15)).toInt(),
    ];
  }

  /// The modulus.
  final BigInt modulus;

  /// The modulus as raw limbs.
  final List<int> modulusLimbs;

  final MulFn mul;
  final UnaryFn sqr;
  final MulFn add;
  final MulFn sub;
  final UnaryFn canon;

  /// 1 in Montgomery form.
  final Uint32List one = Uint32List(limbs);
  final Uint32List _r2 = Uint32List(limbs);
  final Uint32List _rawOne = Uint32List(limbs)..[0] = 1;
  late final List<int> _digits;

  static void _setRaw(Uint32List r, int ro, BigInt v) {
    var x = v;
    final m = BigInt.from(_mask);
    for (var i = 0; i < limbs; i++) {
      r[ro + i] = (x & m).toInt();
      x >>= _bits;
    }
  }

  /// Sets r to the Montgomery form of an integer in [0, m).
  void setBigInt(Uint32List r, int ro, BigInt v) {
    _setRaw(r, ro, v);
    mul(r, ro, r, ro, _r2, 0);
  }

  /// Sets r to the Montgomery form of a small non-negative integer.
  void setInt(Uint32List r, int ro, int v) => setBigInt(r, ro, BigInt.from(v));

  /// Returns the integer value in [0, m).
  BigInt toBigInt(Uint32List a, int ao) {
    final t = Uint32List(limbs);
    mul(t, 0, a, ao, _rawOne, 0);
    canon(t, 0, t, 0);
    var v = BigInt.zero;
    for (var i = limbs - 1; i >= 0; i--) {
      v = (v << _bits) | BigInt.from(t[i]);
    }
    return v;
  }

  /// Reads 32 big-endian bytes; returns false (leaving r undefined) when the
  /// value is not below the modulus.
  bool setBytes(Uint32List r, int ro, List<int> b, int bo) {
    var acc = 0;
    var accBits = 0;
    var li = 0;
    for (var i = 31; i >= 0; i--) {
      acc |= b[bo + i] << accBits;
      accBits += 8;
      if (accBits >= _bits) {
        r[ro + li++] = acc & _mask;
        acc >>= _bits;
        accBits -= _bits;
      }
    }
    r[ro + li] = acc;
    // Below the modulus when r - m borrows.
    var t = 0;
    for (var i = 0; i < limbs; i++) {
      t = r[ro + i] - modulusLimbs[i] + (t >> _bits);
    }
    if (t >= 0) return false;
    mul(r, ro, r, ro, _r2, 0);
    return true;
  }

  /// Writes the canonical value as 32 big-endian bytes.
  void getBytes(Uint8List out, int oo, Uint32List a, int ao) {
    final t = Uint32List(limbs);
    mul(t, 0, a, ao, _rawOne, 0);
    canon(t, 0, t, 0);
    var acc = 0;
    var accBits = 0;
    var li = 0;
    for (var i = 31; i >= 0; i--) {
      if (accBits < 8) {
        acc |= t[li++] << accBits;
        accBits += _bits;
      }
      out[oo + i] = acc & 0xFF;
      acc >>= 8;
      accBits -= 8;
    }
  }

  /// Returns 32 big-endian bytes of the canonical value.
  Uint8List bytes(Uint32List a, int ao) {
    final out = Uint8List(32);
    getBytes(out, 0, a, ao);
    return out;
  }

  /// All ones when a == 0 (mod m), else 0; reads every limb.
  int zeroMask(Uint32List a, int ao) {
    final t = Uint32List(limbs);
    canon(t, 0, a, ao);
    var acc = 0;
    for (var i = 0; i < limbs; i++) {
      acc |= t[i];
    }
    return (acc - 1) >> 63;
  }

  bool isZero(Uint32List a, int ao) => zeroMask(a, ao) != 0;

  /// True when a == b (mod m).
  bool equals(Uint32List a, int ao, Uint32List b, int bo) {
    final t = Uint32List(limbs);
    sub(t, 0, a, ao, b, bo);
    return isZero(t, 0);
  }

  /// r = a^-1 by Fermat's little theorem (a^(m-2)), with a fixed schedule:
  /// the exponent is public. The inverse of 0 is 0.
  void invert(Uint32List r, int ro, Uint32List a, int ao) {
    final table = Uint32List(16 * limbs);
    table.setRange(0, limbs, one);
    table.setRange(limbs, 2 * limbs, a, ao);
    for (var i = 2; i < 16; i++) {
      mul(table, i * limbs, table, (i - 1) * limbs, a, ao);
    }
    final acc = Uint32List(limbs);
    final digits = _digits;
    acc.setRange(0, limbs, table, digits[0] * limbs);
    for (var w = 1; w < digits.length; w++) {
      sqr(acc, 0, acc, 0);
      sqr(acc, 0, acc, 0);
      sqr(acc, 0, acc, 0);
      sqr(acc, 0, acc, 0);
      mul(acc, 0, acc, 0, table, digits[w] * limbs);
    }
    r.setRange(ro, ro + limbs, acc);
  }

  /// Copies one element.
  static void copy(Uint32List r, int ro, Uint32List a, int ao) {
    for (var i = 0; i < limbs; i++) {
      r[ro + i] = a[ao + i];
    }
  }

  /// r = mask ? a : r, for mask all ones or zero.
  static void cmov(Uint32List r, int ro, Uint32List a, int ao, int mask) {
    for (var i = 0; i < limbs; i++) {
      final v = r[ro + i];
      r[ro + i] = v ^ ((v ^ a[ao + i]) & mask);
    }
  }
}

/// All ones when a == b, else 0, for small non-negative ints. Branch-free.
int eqMask(int a, int b) => (((a ^ b) - 1) >> 63);

/// The SM2 field.
final MontField sm2Fp = MontField._(
    BigInt.parse(
        'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
        radix: 16),
    fpModulus,
    fpMul,
    fpSqr,
    fpAdd,
    fpSub,
    fpCanon);

/// The SM9 base field.
final MontField sm9Fq = MontField._(
    BigInt.parse(
        'B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D',
        radix: 16),
    fqModulus,
    fqMul,
    fqSqr,
    fqAdd,
    fqSub,
    fqCanon);
