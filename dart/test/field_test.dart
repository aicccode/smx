import 'dart:math';
import 'dart:typed_data';

import 'package:smx/src/field/field.dart';
import 'package:smx/src/field/sm9_fq.g.dart';
import 'package:smx/src/field/sm9_fq2_mul.g.dart';
import 'package:smx/src/field/sm9_fq2_sqr.g.dart';
import 'package:test/test.dart';

void main() {
  final rng = Random(42);
  BigInt rand(BigInt m) {
    var v = BigInt.zero;
    for (var i = 0; i < 9; i++) {
      v = (v << 32) | BigInt.from(rng.nextInt(1 << 32));
    }
    return v % m;
  }

  for (final (name, f) in [('sm2', sm2Fp), ('sm9', sm9Fq)]) {
    test('$name field matches BigInt arithmetic', () {
      final m = f.modulus;
      final a = Uint32List(9), b = Uint32List(9), r = Uint32List(9);
      final specials = [
        BigInt.zero,
        BigInt.one,
        m - BigInt.one,
        m - BigInt.two
      ];
      for (var i = 0; i < 2000; i++) {
        final x = i < 16 ? specials[i % 4] : rand(m);
        final y = i < 16 ? specials[i ~/ 4] : rand(m);
        f.setBigInt(a, 0, x);
        f.setBigInt(b, 0, y);
        expect(f.toBigInt(a, 0), x);
        f.mul(r, 0, a, 0, b, 0);
        expect(f.toBigInt(r, 0), x * y % m);
        f.sqr(r, 0, a, 0);
        expect(f.toBigInt(r, 0), x * x % m);
        f.add(r, 0, a, 0, b, 0);
        expect(f.toBigInt(r, 0), (x + y) % m);
        f.sub(r, 0, a, 0, b, 0);
        expect(f.toBigInt(r, 0), (x - y) % m);
        // Lazy forms: chains of operations stay correct.
        f.add(r, 0, r, 0, r, 0);
        f.mul(r, 0, r, 0, r, 0);
        expect(f.toBigInt(r, 0), (BigInt.two * (x - y)).pow(2) % m);
        if (x != BigInt.zero) {
          f.invert(r, 0, a, 0);
          expect(f.toBigInt(r, 0), x.modInverse(m));
        }
        final bytes = f.bytes(a, 0);
        expect(f.setBytes(r, 0, bytes, 0), isTrue);
        expect(f.equals(r, 0, a, 0), isTrue);
      }
      final mBytes = Uint8List(32);
      var v = m;
      for (var i = 31; i >= 0; i--) {
        mBytes[i] = (v & BigInt.from(255)).toInt();
        v >>= 8;
      }
      expect(f.setBytes(r, 0, mBytes, 0), isFalse);
      expect(
          f.setBytes(r, 0, Uint8List(32)..fillRange(0, 32, 255), 0), isFalse);
    });
  }

  test('fused Fq2 multiplication and squaring', () {
    final m = sm9Fq.modulus;
    final a = Uint32List(18), b = Uint32List(18), r = Uint32List(18);
    final big = [m - BigInt.one, BigInt.zero, BigInt.one, m - BigInt.two];
    for (var i = 0; i < 3000; i++) {
      final x = [
        for (var j = 0; j < 4; j++) i < 64 ? big[(i >> j) & 3] : rand(m),
      ];
      for (var j = 0; j < 4; j++) {
        sm9Fq.setBigInt(j < 2 ? a : b, (j & 1) * 9, x[j]);
      }
      // Also exercise lazy inputs in [q, 2q).
      if (i.isOdd) {
        fqAdd(a, 0, a, 0, a, 0);
        fqSub(a, 0, a, 0, a, 9);
        fqAdd(a, 0, a, 0, a, 9);
        x[0] = (x[0] * BigInt.two) % m;
      }
      fq2Mul(r, 0, a, 0, b, 0);
      final c0 = (x[0] * x[2] - BigInt.two * x[1] * x[3]) % m;
      final c1 = (x[0] * x[3] + x[1] * x[2]) % m;
      expect(sm9Fq.toBigInt(r, 0), c0);
      expect(sm9Fq.toBigInt(r, 9), c1);
      fq2Sqr(r, 0, a, 0);
      expect(
          sm9Fq.toBigInt(r, 0), (x[0] * x[0] - BigInt.two * x[1] * x[1]) % m);
      expect(sm9Fq.toBigInt(r, 9), (BigInt.two * x[0] * x[1]) % m);
      for (var j = 0; j < 18; j++) {
        expect(r[j] < (1 << 29), isTrue);
      }
    }
  });
}
