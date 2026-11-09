import 'dart:typed_data';

import 'package:smx/src/errors.dart';
import 'package:smx/src/hex.dart';
import 'package:test/test.dart';

final Matcher throwsSmx = throwsA(isA<SmxException>());

void main() {
  final all = Uint8List.fromList([for (var i = 0; i < 256; i++) i]);
  String reference(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  test('encoding matches a reference for every byte', () {
    expect(bytesToHex(all), reference(all));
    expect(bytesToHexUpper(all), reference(all).toUpperCase());
    expect(bytesToHex([]), '');
  });

  test('decoding round trips and accepts either case where allowed', () {
    expect(hexToBytes(reference(all)), all);
    expect(hexToBytes(reference(all).toUpperCase()), all);
    expect(hexToBytes('aBcD'), [0xab, 0xcd]);
    expect(lowercaseHexToBytes(reference(all)), all);
    expect(hexToBytes(''), isEmpty);
  });

  test('lowercase decoding rejects uppercase', () {
    expect(() => lowercaseHexToBytes('AB'), throwsSmx);
    expect(() => lowercaseHexToBytes('aB'), throwsSmx);
    expect(tryLowercaseHexToBytes('Ab'), isNull);
  });

  test('rejects odd length, non-hex and non-ASCII input', () {
    for (final bad in [
      'a', 'abc', 'zz', 'g0', '0x12', ' 12', '12 ', '1-', //
      'é1', '١٢', '\u0000\u0000', '/0', ':0', '@0', 'G0', '`0',
    ]) {
      expect(() => hexToBytes(bad), throwsSmx, reason: bad);
      expect(() => lowercaseHexToBytes(bad), throwsSmx, reason: bad);
      expect(tryHexToBytes(bad), isNull, reason: bad);
    }
    // A code unit whose low byte is a hex digit is still rejected.
    expect(() => hexToBytes('İİ'), throwsSmx);
    expect(() => hexToBytes('šš'), throwsSmx);
  });

  test('hexToBigInt', () {
    expect(hexToBigInt('ff'), BigInt.from(255));
    expect(hexToBigInt('FfF'), BigInt.from(0xfff));
    expect(hexToBigInt('0'), BigInt.zero);
    expect(hexToBigInt('0123456789abcdef0123456789ABCDEF'),
        BigInt.parse('0123456789abcdef0123456789abcdef', radix: 16));
    for (final bad in ['', 'x', '0x1', '-1', '+1', ' 1']) {
      expect(() => hexToBigInt(bad), throwsSmx, reason: bad);
    }
  });

  test('bytesToBigInt and bigIntToBytes', () {
    expect(bytesToBigInt([]), BigInt.zero);
    expect(bytesToBigInt([1, 2, 3, 4, 5]), BigInt.from(0x0102030405));
    final v = BigInt.parse(
        'fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff',
        radix: 16);
    expect(bytesToBigInt(bigIntToBytes(v, 32)), v);
    expect(bigIntToBytes(BigInt.one, 32), [...List<int>.filled(31, 0), 1]);
    expect(bigIntToBytes(BigInt.from(0x010203), 3), [1, 2, 3]);
    expect(bigIntToBytes(BigInt.from(0x0102030405), 5), [1, 2, 3, 4, 5]);
    expect(bigIntToBytes(BigInt.zero, 0), isEmpty);
  });
}
