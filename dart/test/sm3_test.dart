import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:smx/src/errors.dart';
import 'package:smx/src/sm3.dart';
import 'package:test/test.dart';

import 'support/sha256.dart';

const sm3Kat = <int, String>{
  0: '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b',
  1: '3b3d1dc88741456e6098252daa25975988f1d9152f41c8a7616f591591fdf36d',
  3: '5981303b32602f50a364ec83d5e7af9a914fa6033a961dc4b6ffe33b231699f1',
  55: 'f2cfc4e33f2404086e81e6a3792d3ed496a3e4d136c4d25035f72cf2231c9a0d',
  56: '41e3288b5ce3dd21773decdf74ecbab58805b022e68af979d347d94b99df0bee',
  63: '6bbfac2e8fd30e86e5d7189bb3fe08436c24648278d23984b06df043f12321ac',
  64: 'fa3fbcc919f53f6c6dc5d565702e9996d299949c84219813fc1b7de3d635ed77',
  65: 'adfa40587f401fe1fa649dce346196ca41ee18d344846d97008c2f0ea9d350e0',
  127: '8b14f4bfbc5f8b82047db4858a5d9e848e0b45c32a6d3e50523ddb64288e7d60',
  128: '00ab524c0bec4349e9497c9420ff8dbba165a01aa864deec69bef6c3b2d3bf04',
  1000: '703459d1cb730b8d9f732363cfeb32370a4f8c17956040fde2394c9aa606d25d',
  4096: '737f42dd13b773d71674968c03bcc571130f6cb3be804aa344fbd0afdfc478d1',
  65536: '4317c0383c1a7d6c3ede8bb2bc2745eb7c3579731868b4bb4543cf0763dcb40f',
};

String sm3Hex(List<int> data) => SM3().update(data).finish().hashHex();

Uint8List range(int n) => Uint8List.fromList([for (var i = 0; i < n; i++) i]);

/// Straightforward KDF reference: SM3(seed || ct) concatenated.
Uint8List referenceKdf(List<int> seed, int length) {
  final out = BytesBuilder();
  for (var ct = 1; out.length < length; ct++) {
    out.add(sm3Digest([
      ...seed,
      (ct >> 24) & 0xFF,
      (ct >> 16) & 0xFF,
      (ct >> 8) & 0xFF,
      ct & 0xFF,
    ]));
  }
  return Uint8List.sublistView(out.toBytes(), 0, length);
}

void main() {
  group('known answers', () {
    test('GB/T 32905 vectors', () {
      expect(sm3Hex(utf8.encode('abc')),
          '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');
      expect(sm3Hex(utf8.encode('abcd' * 16)),
          'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732');
      expect(SM3().update(utf8.encode('abc')).finish().hashHexUpper(),
          '66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0');
    });

    test('padding boundaries match Go', () {
      const vectors = <int, String>{
        54: '1BB1B592239447B5DE0395D94159996EA7CC4FCC7B9F66CCC5F0CFDC89586782',
        55: 'A79CF9DCEE3404ABF7F769698201647FD9D3FF61D629D0F58BB4B5579A427DB8',
        56: '62F7363B15F4DE76DD925C493B9D6D00D4BA0EF2A1F334C1D0F13B293AEB40D1',
        57: '441F67CC31781DD2986FC612B92DFADE871D81357F2487F5C86D94A8C6778D82',
        63: '6165E4CBB15CDE01C6226E0015A47F710F8F8E1F2C296700033BB34D9212109C',
        65: 'C886E6814BE748285A10B28AE62DDACD85DB830CD2CF3A2BFA2F729C15F63618',
        119: '8F3EA392A89A7119982D6634660DB1A95F35D68267A2235E3255998A857F4FBF',
        120: '6BABEE35E6A1515AF9D6255109C24F3C08897829422C6225D235FD4C8527E9EC',
      };
      vectors.forEach((length, expected) {
        expect(SM3().update(range(length)).finish().hashHexUpper(), expected,
            reason: '$length');
      });
    });

    test('pinned digests', () {
      sm3Kat.forEach((length, expected) {
        expect(sm3Hex(det(length)), expected, reason: '$length');
        expect(hexOf(sm3Digest(det(length))), expected, reason: '$length');
      });
    });

    test('any chunking gives the same digest', () {
      final data = det(1000);
      for (final chunk in [1, 3, 7, 13, 63, 64, 65, 127, 128, 129, 500]) {
        final hasher = SM3();
        for (var o = 0; o < data.length; o += chunk) {
          final end = o + chunk < data.length ? o + chunk : data.length;
          hasher.update(Uint8List.sublistView(data, o, end));
        }
        expect(hasher.finish().hashHex(), sm3Kat[1000], reason: '$chunk');
      }
    });

    test('plain List<int> input hashes like Uint8List', () {
      final data = det(200);
      expect(sm3Hex(List<int>.of(data)), sm3Hex(data));
    });

    test('updateByte matches update', () {
      for (final length in [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 130]) {
        final data = det(length);
        final hasher = SM3();
        for (final b in data.sublist(0, length ~/ 2)) {
          hasher.updateByte(b);
        }
        hasher.update(data.sublist(length ~/ 2));
        expect(hasher.finish().hashHex(), sm3Hex(data), reason: '$length');
      }
    });
  });

  group('input and state rules', () {
    test('rejected byte does not change the state', () {
      final hasher = SM3().update(utf8.encode('ab'));
      expect(() => hasher.updateByte(256), throwsA(isA<SmxException>()));
      expect(() => hasher.updateByte(-1), throwsA(isA<SmxException>()));
      expect(() => hasher.update([0x63, 256]), throwsA(isA<SmxException>()));
      expect(() => hasher.update([-1]), throwsA(isA<SmxException>()));
      expect(
          hasher.update([0x63]).finish().hashHex(), sm3Hex(utf8.encode('abc')));
    });

    test('instance resets after finish', () {
      final hasher = SM3().update(utf8.encode('first')).finish();
      expect(hasher.update(utf8.encode('abc')).finish().hashHex(),
          sm3Hex(utf8.encode('abc')));
    });

    test('digest rules mirror the other languages', () {
      final hasher = SM3();
      expect(hasher.hashBytes, throwsA(isA<SmxException>()));
      hasher.finish(); // a fresh instance hashes the empty message
      expect(hasher.hashHex(), sm3Kat[0]);
      expect(hasher.finish, throwsA(isA<SmxException>()));
      hasher.update(utf8.encode('x'));
      expect(hasher.hashBytes, throwsA(isA<SmxException>()));
      hasher.finish();
      hasher.update([]);
      expect(hasher.hashBytes, throwsA(isA<SmxException>()));
      expect(hasher.finish().hashHex(), sm3Kat[0]);
    });

    test('hashBytes returns a copy', () {
      final hasher = SM3().update(utf8.encode('abc')).finish();
      hasher.hashBytes()[0] ^= 1;
      expect(hasher.hashHex(), sm3Hex(utf8.encode('abc')));
      expect(hasher.hashBytes().length, 32);
    });
  });

  group('KDF', () {
    test('matches a straightforward reference', () {
      for (final seedLength in [0, 1, 55, 56, 59, 60, 61, 63, 64, 100, 128]) {
        final seed = det(seedLength, 'seed');
        for (final length in [0, 1, 31, 32, 33, 64, 100]) {
          expect(hexOf(sm3Kdf(seed, length)), hexOf(referenceKdf(seed, length)),
              reason: '$seedLength/$length');
        }
      }
    });

    test('rejects out-of-range lengths', () {
      expect(() => sm3Kdf([1], -1), throwsA(isA<SmxException>()));
      expect(
          () => sm3Kdf([1], 0xFFFFFFFF * 32 + 1), throwsA(isA<SmxException>()));
    });
  });

  group('shared security vectors', () {
    final vectors = jsonDecode(
            File('../testvectors/security-vectors.json').readAsStringSync())
        as Map<String, dynamic>;
    final v = vectors['sm3'] as Map<String, dynamic>;
    final chunk = Uint8List(1 << 20);

    test('512 MiB of zeros', () {
      final hasher = SM3();
      for (var i = 0; i < 512; i++) {
        hasher.update(chunk);
      }
      expect(hasher.finish().hashHex(), v['zeros_512_mib']);
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('1024 MiB of zeros', () {
      final hasher = SM3();
      for (var i = 0; i < 1024; i++) {
        hasher.update(chunk);
      }
      expect(hasher.finish().hashHex(), v['zeros_1024_mib']);
    },
        skip: Platform.environment['SMX_SLOW_TESTS'] == null
            ? 'slow; set SMX_SLOW_TESTS=1 to run'
            : null,
        timeout: const Timeout(Duration(minutes: 5)));
  });
}
