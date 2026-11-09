import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:smx/src/hex.dart';
import 'package:smx/src/sm9/g1.dart';
import 'package:smx/src/sm9/g2.dart';
import 'package:smx/src/sm9/pairing.dart';
import 'package:smx/src/sm9/params.dart';
import 'package:smx/src/sm9/tower.dart';
import 'package:test/test.dart';

void main() {
  final vectors =
      jsonDecode(File('../testvectors/sm9-vectors.json').readAsStringSync())
          as Map;
  final sign = (vectors['standard'] as Map)['sign'] as Map;

  test('pairing matches the standard example', () {
    final ppub = g2Decode(hexToBytes(sign['master_public_key'] as String))!;
    final g = pairing(p1Affine, 0, ppub, 0);
    expect(bytesToHex(f12ToBytes(g, 0)), sign['pairing_g']);
  });

  test('pairing is bilinear', () {
    final a = BigInt.from(123456789), b = BigInt.parse('987654321987654321');
    final pa = g1MulSecretAffine(p1Affine, a, p1Table())!;
    final qb = g2MulSecretAffine(p2Affine, b, p2Table())!;
    final e1 = pairing(pa, 0, qb, 0);
    final e = pairing(p1Affine, 0, p2Affine, 0);
    final e2 = gtPowSecret(e, a * b % sm9N);
    expect(f12Equals(e1, 0, e2, 0), isTrue);
    expect(f12Equals(gtPowPublic(e, a * b), 0, e2, 0), isTrue);
    expect(f12Equals(gtPowSecret(e, sm9N), 0, Uint32List(f12)..[0] = 0, 0),
        isFalse);
    final one = Uint32List(f12);
    f12One(one, 0);
    expect(f12Equals(gtPowPublic(e, sm9N), 0, one, 0), isTrue);
  });

  test('cyclotomic squaring matches squaring', () {
    final e = pairing(p1Affine, 0, p2Affine, 0);
    final a = Uint32List(f12), b = Uint32List(f12);
    f12Sqr(a, 0, e, 0);
    f12CycSqr(b, 0, e, 0);
    expect(f12Equals(a, 0, b, 0), isTrue);
  });
}
