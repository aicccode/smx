import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:smx/smx.dart';
import 'package:smx/src/sm2/sm2.dart' show sm2EncryptWithK, sm2SignWithK;
import 'package:test/test.dart';

import 'support/sha256.dart';
import 'support/sm2_kat_vectors.dart';

BigInt h(String s) => BigInt.parse(s, radix: 16);

const stdPrivate =
    '3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8';
const stdPublic =
    '0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020'
    'ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13';
const idA = 'ALICE123@YAHOO.COM';
const idB = 'BILL456@YAHOO.COM';
final dA =
    h('6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE');
final ra =
    h('83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563');
final dB =
    h('5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53');
final rb =
    h('33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80');

const goCiphertexts = {
  'encryption standard':
      '0444858f1f9e6a1fcc7c0256486d672ad2b8b0df45aba1ce422363df0daaa5fb07'
          'ff62ecd1ab9a3c722034588f16af133b080ef33f1c950a547eaba1ce54079b511f'
          'f91c1c0f710c859da92f5b26ae46f1df098531e4e8716c7ab69ba291f35f7920'
          'b0fbeddf0a85f0ddbf53d09096c47b11cb2a',
  '国密SM2': '0403df678f154bd3e90d43750b61432bd30ecf0978e37fea7bbe4ecc058b157074'
      '8cc4fb73c4479af28ed86bfa4033e827c2cc64fa841988b644a65e058dcdb993'
      'efc5f5c74dbbec64278d2da6f43c13289e3d5aa70771090bc0664bd75346f130'
      '3561403bcd479879d7',
};
const goSignatures = {
  'encryption standard':
      '4572a19e2ca29c80ad6797817e94cf36930a7189222866e6d73424ab1f969caf'
          'h81ff065c408c2ff4f49e35937b60e7206b50ed20569394a1aec9764514e725d7',
  '国密SM2': 'c55230ad6c1cae418ee4f78a6c9c0557d19202950fbb2a6ed4b45170e40d4e19'
      'h2b215b38ee1d5bfd99e9f7dffb60d73e252cc4261f2ab846bd7971b90dd03dd4',
};

Matcher throwsSmx([String? message]) => throwsA(isA<SmxException>().having(
    (e) => e.message, 'message', message == null ? anything : equals(message)));

String flipHex(String hex, int index) {
  final c = int.parse(hex[index], radix: 16) ^ 1;
  return hex.substring(0, index) +
      c.toRadixString(16) +
      hex.substring(index + 1);
}

void main() {
  final vectors = jsonDecode(
          File('../testvectors/security-vectors.json').readAsStringSync())
      as Map<String, dynamic>;
  final v = vectors['sm2'] as Map<String, dynamic>;

  group('known answers', () {
    test('generator multiples', () {
      for (final MapEntry(:key, :value) in multKat.entries) {
        expect(ECPoint.generator().multiply(h(key)).toHexEncoded(), value,
            reason: key);
      }
    });

    test('variable-base multiples', () {
      final point = sm2GetPublicKey(h(stdPrivate));
      expect(point.toHexEncoded(), stdPublic);
      for (final MapEntry(:key, :value) in multPKat.entries) {
        expect(point.multiply(h(key)).toHexEncoded(), value, reason: key);
      }
    });

    test('encrypt with fixed k', () {
      final point = sm2DecodePoint(stdPublic);
      for (final (k, text, repeat, expected) in encryptKat) {
        final message = text * repeat;
        final ciphertext = sm2EncryptWithK(utf8.encode(message), point, h(k))!;
        if (expected.startsWith('sha256:')) {
          expect('sha256:${sha256Hex(ascii.encode(ciphertext))}', expected);
        } else {
          expect(ciphertext, expected);
        }
        expect(sm2Decrypt(ciphertext, stdPrivate), message);
      }
    });

    test('sign with fixed k', () {
      for (final (k, id, idRepeat, text, textRepeat, expected) in signKat) {
        final userId = id * idRepeat, message = text * textRepeat;
        expect(sm2SignWithK(userId, message, stdPrivate, h(k)), expected);
        expect(sm2Verify(userId, expected, message, stdPublic), isTrue);
      }
    });

    test('key exchange', () {
      final g = ECPoint.generator();
      for (final (len, da, ra, db, rb, ka, sa, sb, vHex) in exchangeKat) {
        final pA = g.multiply(h(da)), bigRa = g.multiply(h(ra));
        final pB = g.multiply(h(db)), bigRb = g.multiply(h(rb));
        final sideB =
            sm2GetSb(len, pA, bigRa, pB, h(db), bigRb, h(rb), 'A', 'B');
        final sideA = sm2GetSa(
            len, pB, bigRb, pA, h(da), bigRa, h(ra), 'A', 'B', hexToBytes(sb));
        expect(sideB.success, isTrue);
        expect(sideA.success, isTrue);
        expect(sideA.ka, ka);
        expect(sideB.kb, ka);
        expect(sideA.sa, sa);
        expect(sideB.sb, sb);
        expect(sideB.v!.toHexEncoded(), vHex);
        expect(
            sm2CheckSa(sideB.v!, sideB.za, sideB.zb, bigRa, bigRb,
                hexToBytes(sideA.sa)),
            isTrue);
      }
    });

    test('decrypts Go ciphertexts and verifies Go signatures', () {
      for (final MapEntry(:key, :value) in goCiphertexts.entries) {
        expect(sm2Decrypt(value, stdPrivate), key);
      }
      for (final MapEntry(:key, :value) in goSignatures.entries) {
        expect(sm2Verify(idA, value, key, stdPublic), isTrue);
      }
    });
  });

  group('shared security vectors', () {
    final private = v['private_key'] as String;
    final public = v['public_key'] as String;
    final signature = '${v['r']}h${v['s']}';

    test('valid values', () {
      expect(sm2GetPublicKey(h(private)).toHexEncoded(), public);
      expect(
          sm2Verify(v['user_id'] as String, signature, v['message'] as String,
              public),
          isTrue);
      final k = h(v['nonce_k'] as String);
      expect(
          sm2SignWithK(
              v['user_id'] as String, v['message'] as String, private, k),
          signature);
      expect(
          sm2EncryptWithK(
              utf8.encode(v['plaintext'] as String), sm2DecodePoint(public), k),
          v['ciphertext']);
      expect(sm2Decrypt(v['ciphertext'] as String, private), v['plaintext']);
    });

    test('invalid public keys', () {
      for (final c
          in (v['invalid_public_keys'] as List).cast<Map<String, dynamic>>()) {
        final value = c['value'] as String;
        expect(() => sm2DecodePoint(value), throwsSmx(),
            reason: '${c['name']}');
        expect(() => sm2Encrypt('x', value), throwsSmx(),
            reason: '${c['name']}');
        expect(sm2Verify('id', signature, 'm', value), isFalse,
            reason: '${c['name']}');
      }
    });

    test('invalid private keys', () {
      for (final c
          in (v['invalid_private_keys'] as List).cast<Map<String, dynamic>>()) {
        final value = c['value'] as String;
        expect(() => sm2Sign('id', 'm', value), throwsSmx(),
            reason: '${c['name']}');
        expect(() => sm2Decrypt(v['ciphertext'] as String, value), throwsSmx(),
            reason: '${c['name']}');
      }
    });

    test('largest valid private key', () {
      final d = v['n_minus_2_is_max_valid_private_key'] as String;
      final pub = sm2GetPublicKey(h(d)).toHexEncoded();
      expect(sm2Verify('id', sm2Sign('id', 'm', d), 'm', pub), isTrue);
      expect(sm2Decrypt(sm2Encrypt('hello', pub), d), 'hello');
    });

    test('invalid signatures', () {
      for (final c
          in (v['invalid_signatures'] as List).cast<Map<String, dynamic>>()) {
        expect(
            sm2Verify(v['user_id'] as String, '${c['r']}h${c['s']}',
                v['message'] as String, public),
            isFalse,
            reason: '${c['name']}');
      }
    });

    test('invalid ciphertexts all fail the same way', () {
      for (final c
          in (v['invalid_ciphertexts'] as List).cast<Map<String, dynamic>>()) {
        expect(() => sm2Decrypt(c['value'] as String, private),
            throwsSmx('decryption failed'),
            reason: '${c['name']}');
      }
    });

    test('user id limit counts bytes', () {
      final point = sm2DecodePoint(public);
      final longest = 'a' * (v['user_id_max_bytes'] as int);
      final tooLong = 'a' * (v['user_id_first_invalid_bytes'] as int);
      final sig = sm2Sign(longest, 'm', private);
      expect(sm2Verify(longest, sig, 'm', public), isTrue);
      expect(userSm3Z(utf8.encode(longest), point).length, 32);
      expect(() => sm2Sign(tooLong, 'm', private), throwsSmx());
      expect(sm2Verify(tooLong, sig, 'm', public), isFalse);
      expect(() => userSm3Z(utf8.encode(tooLong), point), throwsSmx());
      expect(sm2Verify('密' * 2731, sig, 'm', public), isFalse);
    });
  });

  group('encryption', () {
    test('round trip, text and bytes', () {
      final pair = sm2GenKeyPair();
      expect(pair.privateKey, matches(RegExp(r'^[0-9A-F]{64}$')));
      expect(pair.publicKey, matches(RegExp(r'^04[0-9a-f]{128}$')));
      expect(pair.toString(), isNot(contains(pair.privateKey)));
      for (final m in ['a', '国密SM2', 'x' * 1000]) {
        expect(sm2Decrypt(sm2Encrypt(m, pair.publicKey), pair.privateKey), m);
      }
      final bytes = Uint8List.fromList(List.generate(300, (i) => i & 255));
      expect(
          sm2DecryptBytes(
              sm2EncryptBytes(bytes, pair.publicKey), pair.privateKey),
          bytes);
    });

    test('rejects empty plaintext and lone surrogates', () {
      expect(() => sm2Encrypt('', stdPublic), throwsSmx());
      expect(() => sm2Encrypt('\uD800', stdPublic), throwsSmx());
      expect(() => sm2EncryptBytes([256], stdPublic), throwsSmx());
    });

    test('tampering, wrong key and uppercase hex fail the same way', () {
      final ciphertext = sm2Encrypt('secret', stdPublic);
      for (final index in [140, 200, ciphertext.length - 1]) {
        expect(() => sm2Decrypt(flipHex(ciphertext, index), stdPrivate),
            throwsSmx('decryption failed'));
      }
      final other = sm2GenKeyPair();
      expect(() => sm2Decrypt(ciphertext, other.privateKey),
          throwsSmx('decryption failed'));
      expect(() => sm2Decrypt(ciphertext.toUpperCase(), stdPrivate),
          throwsSmx('decryption failed'));
      expect(() => sm2Decrypt('${ciphertext}00', stdPrivate),
          throwsSmx('decryption failed'));
    });

    test('invalid UTF-8 plaintext fails only the string interface', () {
      final ciphertext = sm2EncryptBytes([0xFF, 0xFE], stdPublic);
      expect(() => sm2Decrypt(ciphertext, stdPrivate),
          throwsSmx('decryption failed'));
      expect(sm2DecryptBytes(ciphertext, stdPrivate), [0xFF, 0xFE]);
    });

    test('works with the key caches off', () {
      setKeyCacheEnabled(false);
      try {
        expect(keyCacheEnabled, isFalse);
        final pair = sm2GenKeyPair();
        expect(
            sm2Decrypt(sm2Encrypt('x', pair.publicKey), pair.privateKey), 'x');
        expect(
            sm2Verify(
                'id', sm2Sign('id', 'm', pair.privateKey), 'm', pair.publicKey),
            isTrue);
      } finally {
        setKeyCacheEnabled(true);
      }
      clearKeyCaches();
    });
  });

  group('signatures', () {
    test('round trip and rejection of changes', () {
      final pair = sm2GenKeyPair();
      final sig = sm2Sign(idA, 'message', pair.privateKey);
      expect(sig, matches(RegExp(r'^[0-9a-f]{64}h[0-9a-f]{64}$')));
      expect(sm2Verify(idA, sig, 'message', pair.publicKey), isTrue);
      expect(sm2Verify(idB, sig, 'message', pair.publicKey), isFalse);
      expect(sm2Verify(idA, sig, 'Message', pair.publicKey), isFalse);
      expect(sm2Verify(idA, sig, 'message', stdPublic), isFalse);
      expect(sm2Verify(idA, sig.toUpperCase(), 'message', pair.publicKey),
          isFalse);
      for (final index in [0, 63, 65, 128]) {
        expect(sm2Verify(idA, flipHex(sig, index), 'message', pair.publicKey),
            isFalse);
      }
      expect(
          sm2Verify(idA, sig.replaceFirst('h', 'H'), 'message', pair.publicKey),
          isFalse);
      expect(sm2Verify('\uDC00', sig, 'message', pair.publicKey), isFalse);
    });

    test('verification uses the cached tables consistently', () {
      final sig = sm2Sign('id', 'm', stdPrivate);
      for (var i = 0; i < 3; i++) {
        expect(sm2Verify('id', sig, 'm', stdPublic), isTrue);
      }
    });
  });

  group('points', () {
    test('arithmetic', () {
      final g = ECPoint.generator();
      expect(g.isOnCurve(), isTrue);
      expect(g.twice(), g.add(g));
      expect(g.add(g).add(g), g.multiply(BigInt.from(3)));
      expect(g.subtract(g).infinity, isTrue);
      expect(g.add(ECPoint.atInfinity()), g);
      expect(g.multiply(BigInt.zero).infinity, isTrue);
      expect(g.multiply(sm2N).infinity, isTrue);
      expect(g.multiply(sm2N + BigInt.one), g);
      expect(g.negate().add(g.twice()), g);
      expect(ECPoint.fromEncoded(g.toEncoded()), g);
      expect(ECPoint.atInfinity().toEncoded(), [0]);
    });

    test('validation', () {
      expect(() => ECPoint(sm2P, BigInt.one), throwsSmx());
      expect(() => ECPoint(BigInt.from(-1), BigInt.one), throwsSmx());
      final off = ECPoint(BigInt.one, BigInt.one);
      expect(off.isOnCurve(), isFalse);
      expect(() => off.multiply(BigInt.two), throwsSmx());
      expect(() => off.add(ECPoint.generator()), throwsSmx());
      expect(() => sm2DecodePoint('0x${stdPublic.substring(2)}'), throwsSmx());
      expect(sm2DecodePoint(stdPublic.toUpperCase()).toHexEncoded(), stdPublic);
    });
  });

  group('key exchange', () {
    final pA = sm2GetPublicKey(dA), bigRa = sm2GetPublicKey(ra);
    final pB = sm2GetPublicKey(dB), bigRb = sm2GetPublicKey(rb);

    (SM2KeySwapParams, SM2KeySwapParams) run(int len) {
      final b = sm2GetSb(len, pA, bigRa, pB, dB, bigRb, rb, idA, idB);
      expect(b.success, isTrue, reason: b.message);
      final a = sm2GetSa(
          len, pB, bigRb, pA, dA, bigRa, ra, idA, idB, hexToBytes(b.sb));
      expect(a.success, isTrue, reason: a.message);
      return (a, b);
    }

    test('matches the Go vector', () {
      final (a, b) = run(16);
      expect(a.ka, 'f02f9068ad13e14f2b2602e0dfb2504f');
      expect(b.kb, a.ka);
      expect(b.sb,
          'b93374ade30a74e12ddb40e4c03d0c6fcf61badbf2c2c5cc39a91201d9228e2e');
      expect(a.sa,
          'daefca6c32f53c48444d4ef35f98471e5d1cd1e3b5b8e3322dede310306689f6');
      expect(bytesToHex(b.za),
          '5d0b1182e1cee9093e96b6bdbf2e32f854d5c753e2ce9865d4984b8b70a8ae2b');
      expect(bytesToHex(b.zb),
          '441bf12aca4164c866bf282787dfc63e0cc8268fa34d435491b0cbc7f6ddbd5e');
      expect(b.toString(), isNot(contains(b.kb)));
      final (a48, _) = run(48);
      expect(
          a48.ka,
          'f02f9068ad13e14f2b2602e0dfb2504ff5fabef8555364b7'
          '374436e8566d02aa5704021bc20a93dbefc42d1978da9b68');
    });

    test('confirmation and mismatches', () {
      final (a, b) = run(16);
      final sa = hexToBytes(a.sa);
      expect(sm2CheckSa(b.v!, b.za, b.zb, bigRa, bigRb, sa), isTrue);
      sa[0] ^= 1;
      expect(sm2CheckSa(b.v!, b.za, b.zb, bigRa, bigRb, sa), isFalse);
      expect(sm2CheckSa(b.v!, b.za, b.zb, bigRa, bigRb, [1, 2]), isFalse);
      final wrongSb = hexToBytes(b.sb)..[5] ^= 1;
      final failed =
          sm2GetSa(16, pB, bigRb, pA, dA, bigRa, ra, idA, idB, wrongSb);
      expect(failed.success, isFalse);
      expect(failed.ka, isEmpty);
      final wrongId = sm2GetSa(
          16, pB, bigRb, pA, dA, bigRa, ra, idA, 'other', hexToBytes(b.sb));
      expect(wrongId.success, isFalse);
    });

    test('invalid inputs', () {
      final off = ECPoint(BigInt.one, BigInt.one);
      expect(sm2GetSb(16, off, bigRa, pB, dB, bigRb, rb, idA, idB).message,
          'PA point is not on curve');
      expect(
          sm2GetSb(16, pA, ECPoint.atInfinity(), pB, dB, bigRb, rb, idA, idB)
              .success,
          isFalse);
      expect(sm2GetSb(16, pA, bigRa, pB, sm2N, bigRb, rb, idA, idB).message,
          'private key out of range');
      expect(sm2GetSb(16, pA, bigRa, pB, dB, bigRb, rb, '\uD800', idB).message,
          'invalid user id');
      expect(() => sm2GetSb(0, pA, bigRa, pB, dB, bigRb, rb, idA, idB),
          throwsSmx());
      expect(
          () => sm2GetSb((1 << 20) + 1, pA, bigRa, pB, dB, bigRb, rb, idA, idB),
          throwsSmx());
    });
  });
}
