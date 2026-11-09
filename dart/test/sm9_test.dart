import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:smx/smx.dart';
import 'package:smx/src/sm9/encrypt.dart'
    show sm9EncapsulateWithR, sm9EncryptWithR;
import 'package:smx/src/sm9/exchange.dart' show sm9ExchangeInitWithR;
import 'package:smx/src/sm9/sign.dart' show sm9SignWithR;
import 'package:test/test.dart';

typedef Json = Map<String, dynamic>;

BigInt h(String s) => BigInt.parse(s, radix: 16);
List<int> utf(String s) => utf8.encode(s);

Matcher throwsSmx([String? message]) => throwsA(isA<SmxException>().having(
    (e) => e.message, 'message', message == null ? anything : equals(message)));

String flipHex(String hex, int index) {
  final c = int.parse(hex[index], radix: 16) ^ 1;
  return hex.substring(0, index) +
      c.toRadixString(16) +
      hex.substring(index + 1);
}

void main() {
  final vectors =
      jsonDecode(File('../testvectors/sm9-vectors.json').readAsStringSync())
          as Json;
  final std = vectors['standard'] as Json;
  final extra = vectors['extra'] as Json;
  final params = vectors['params'] as Json;

  test('parameters', () {
    expect(sm9HidSign, params['hid_sign']);
    expect(sm9HidExchange, params['hid_exchange']);
    expect(sm9HidEncrypt, params['hid_encrypt']);
  });

  group('standard (GB/T 38635.5)', () {
    test('signature, appendix A', () {
      final v = std['sign'] as Json;
      final master = v['master_private_key'] as String;
      final public = v['master_public_key'] as String;
      expect(sm9SignMasterPublicKey(master), public);
      final userKey = sm9GenSignUserKey(master, v['user_id'] as String,
          hid: v['hid'] as int);
      expect(userKey, v['user_private_key']);
      final msg = utf(v['message'] as String);
      expect(sm9SignWithR(msg, userKey, public, h(v['r'] as String)),
          v['signature']);
      expect(
          sm9Verify(
              msg, v['signature'] as String, v['user_id'] as String, public),
          isTrue);
    });

    test('key exchange, appendix B', () {
      checkExchange(std['exchange'] as Json, std['exchange'] as Json);
    });

    test('key encapsulation, appendix C', () {
      final v = std['encapsulate'] as Json;
      checkKem(v, v);
    });

    test('encryption, appendix D', () {
      final v = std['encrypt'] as Json;
      final master = v['master_private_key'] as String;
      final public = v['master_public_key'] as String;
      expect(sm9EncMasterPublicKey(master), public);
      final userKey = sm9GenEncUserKey(master, v['user_id'] as String,
          hid: v['hid'] as int);
      expect(userKey, v['user_private_key']);
      checkEncrypt(public, v['user_id'] as String, userKey,
          utf(v['plaintext'] as String), v);
    });
  });

  group('extra vectors', () {
    final signMaster = extra['sign_master_private_key'] as String;
    final signPublic = extra['sign_master_public_key'] as String;
    final encMaster = extra['enc_master_private_key'] as String;
    final encPublic = extra['enc_master_public_key'] as String;

    test('master public keys', () {
      expect(sm9SignMasterPublicKey(signMaster), signPublic);
      expect(sm9EncMasterPublicKey(encMaster), encPublic);
    });

    test('signatures', () {
      for (final c in (extra['sign'] as List).cast<Json>()) {
        final id = c['user_id'] as String;
        final userKey = sm9GenSignUserKey(signMaster, id);
        expect(userKey, c['user_private_key'], reason: id);
        final msg = hexToBytes(c['message_hex'] as String);
        expect(sm9SignWithR(msg, userKey, signPublic, h(c['r'] as String)),
            c['signature'],
            reason: id);
        expect(
            sm9Verify(msg, c['signature'] as String, id, signPublic), isTrue);
      }
    });

    test('encryption, both modes', () {
      for (final c in (extra['encrypt'] as List).cast<Json>()) {
        final id = c['user_id'] as String;
        final userKey = sm9GenEncUserKey(encMaster, id);
        expect(userKey, c['user_private_key'], reason: id);
        checkEncrypt(encPublic, id, userKey,
            hexToBytes(c['plaintext_hex'] as String), c);
      }
    });

    test('key encapsulation', () {
      for (final c in (extra['encapsulate'] as List).cast<Json>()) {
        checkKem({
          ...c,
          'master_private_key': encMaster,
          'master_public_key': encPublic,
          'hid': sm9HidEncrypt,
        }, c);
      }
    });

    test('key exchange', () {
      for (final c in (extra['exchange'] as List).cast<Json>()) {
        checkExchange({
          'master_private_key': encMaster,
          'master_public_key': encPublic,
          'hid': sm9HidExchange,
        }, c);
      }
    });
  });

  group('invalid inputs', () {
    final invalid = vectors['invalid_points'] as Json;
    final g1 = (invalid['g1'] as List).cast<Json>();
    final g2 = (invalid['g2'] as List).cast<Json>();
    final scalars = (vectors['invalid_scalars'] as List).cast<Json>();
    final sign = std['sign'] as Json;
    final enc = std['encrypt'] as Json;
    final kx = std['exchange'] as Json;
    final kem = std['encapsulate'] as Json;

    test('every invalid G1 encoding is rejected', () {
      for (final c in g1) {
        final value = c['value'] as String;
        final name = c['name'];
        expect(() => sm9Encrypt([1], 'Bob', value), throwsSmx(),
            reason: '$name as master public key');
        expect(() => sm9Encapsulate('Bob', value, 16), throwsSmx(),
            reason: '$name as master public key');
        expect(() => sm9ExchangeInit('Bob', value), throwsSmx(),
            reason: '$name as master public key');
        expect(() => sm9Sign([1], value, sign['master_public_key'] as String),
            throwsSmx(),
            reason: '$name as user private key');
        expect(
            () => sm9Decapsulate(
                value, 'Bob', kem['user_private_key'] as String, 32),
            throwsSmx('decapsulation failed'),
            reason: '$name as KEM ciphertext');
        expect(
            sm9ExchangeRespond(
                    16,
                    'Alice',
                    'Bob',
                    kx['master_public_key'] as String,
                    kx['user_private_key_b'] as String,
                    kx['r_b'] as String,
                    kx['R_b'] as String,
                    value)
                .success,
            isFalse,
            reason: '$name as R_A');
        expect(
            sm9ExchangeConfirm(
                    16,
                    'Alice',
                    'Bob',
                    kx['master_public_key'] as String,
                    kx['user_private_key_a'] as String,
                    kx['r_a'] as String,
                    kx['R_a'] as String,
                    value,
                    kx['s_b'] as String)
                .success,
            isFalse,
            reason: '$name as R_B');
        if (value.length == 130) {
          // As C1, with a valid-looking C3 || C2 behind it.
          final ct =
              value + (enc['ciphertext_stream'] as String).substring(130);
          expect(
              () => sm9Decrypt(
                  ct.toLowerCase(), 'Bob', enc['user_private_key'] as String),
              throwsSmx('decryption failed'),
              reason: '$name as C1');
        }
        // As the S part of a signature.
        if (value.length == 130) {
          final sig = (sign['signature'] as String).substring(0, 64) + value;
          expect(
              sm9Verify(utf(sign['message'] as String), sig, 'Alice',
                  sign['master_public_key'] as String),
              isFalse,
              reason: '$name as S');
        }
      }
    });

    test('every invalid G2 encoding is rejected', () {
      for (final c in g2) {
        final value = c['value'] as String;
        final name = c['name'];
        expect(
            () => sm9Sign(utf('m'), sign['user_private_key'] as String, value),
            throwsSmx(),
            reason: '$name as master public key');
        expect(
            sm9Verify(utf(sign['message'] as String),
                sign['signature'] as String, 'Alice', value),
            isFalse,
            reason: '$name as master public key');
        expect(
            () => sm9Decrypt(enc['ciphertext_stream'] as String, 'Bob', value),
            throwsSmx('invalid user private key'),
            reason: '$name as user private key');
        expect(
            () => sm9Decapsulate(kem['ciphertext'] as String, 'Bob', value, 32),
            throwsSmx('invalid user private key'),
            reason: '$name as user private key');
        expect(
            sm9ExchangeRespond(
                    16,
                    'Alice',
                    'Bob',
                    kx['master_public_key'] as String,
                    value,
                    kx['r_b'] as String,
                    kx['R_b'] as String,
                    kx['R_a'] as String)
                .message,
            'invalid user private key',
            reason: '$name as user private key');
      }
    });

    test('every invalid scalar is rejected', () {
      for (final c in scalars) {
        final value = c['value'] as String;
        final name = c['name'];
        expect(() => sm9SignMasterPublicKey(value), throwsSmx(),
            reason: '$name');
        expect(() => sm9EncMasterPublicKey(value), throwsSmx(),
            reason: '$name');
        expect(() => sm9GenSignUserKey(value, 'Alice'), throwsSmx(),
            reason: '$name');
        expect(() => sm9GenEncUserKey(value, 'Bob'), throwsSmx(),
            reason: '$name');
        expect(
            sm9ExchangeRespond(
                    16,
                    'Alice',
                    'Bob',
                    kx['master_public_key'] as String,
                    kx['user_private_key_b'] as String,
                    value,
                    kx['R_b'] as String,
                    kx['R_a'] as String)
                .message,
            'invalid ephemeral private key',
            reason: '$name');
      }
    });

    test('the largest master private key works', () {
      final ks = vectors['max_valid_master_private_key'] as String;
      final public = sm9SignMasterPublicKey(ks);
      final userKey = sm9GenSignUserKey(ks, 'max');
      expect(
          sm9Verify([7], sm9Sign([7], userKey, public), 'max', public), isTrue);
    });

    test('hid and key length limits', () {
      final ks = sign['master_private_key'] as String;
      expect(() => sm9GenSignUserKey(ks, 'a', hid: 256), throwsSmx());
      expect(() => sm9GenSignUserKey(ks, 'a', hid: -1), throwsSmx());
      expect(sm9GenSignUserKey(ks, 'a', hid: 0),
          isNot(sm9GenSignUserKey(ks, 'a')));
      expect(sm9GenSignUserKey(ks, 'a', hid: 255), hasLength(130));
      final pub = kem['master_public_key'] as String;
      expect(() => sm9Encapsulate('Bob', pub, 0), throwsSmx());
      expect(() => sm9Encapsulate('Bob', pub, (1 << 20) + 1), throwsSmx());
      expect(() => sm9Encrypt([], 'Bob', pub), throwsSmx());
      expect(() => sm9Encrypt([256], 'Bob', pub), throwsSmx());
      expect(() => sm9Encrypt([1], '\uD800', pub), throwsSmx());
      expect(() => sm9ExchangeRespond(0, 'a', 'b', pub, '', '', '', ''),
          throwsSmx());
    });
  });

  group('round trips with random keys', () {
    final signKeys = sm9GenSignMasterKey();
    final encKeys = sm9GenEncMasterKey();

    test('key pair format and secrecy', () {
      expect(signKeys.privateKey, matches(RegExp(r'^[0-9a-f]{64}$')));
      expect(signKeys.publicKey, matches(RegExp(r'^04[0-9a-f]{256}$')));
      expect(encKeys.publicKey, matches(RegExp(r'^04[0-9a-f]{128}$')));
      expect(signKeys.toString(), isNot(contains(signKeys.privateKey)));
      expect(sm9SignMasterPublicKey(signKeys.privateKey.toUpperCase()),
          signKeys.publicKey);
      expect(sm9EncMasterPublicKey(encKeys.privateKey), encKeys.publicKey);
    });

    test('sign and verify, with tampering', () {
      final userKey = sm9GenSignUserKey(signKeys.privateKey, 'alice@example');
      final msg = utf('hello SM9');
      final sig = sm9Sign(msg, userKey, signKeys.publicKey);
      expect(sig, matches(RegExp(r'^[0-9a-f]{64}04[0-9a-f]{128}$')));
      expect(sm9Verify(msg, sig, 'alice@example', signKeys.publicKey), isTrue);
      expect(
          sm9Verify(utf('hello SM8'), sig, 'alice@example', signKeys.publicKey),
          isFalse);
      expect(sm9Verify(msg, sig, 'bob@example', signKeys.publicKey), isFalse);
      expect(sm9Verify(msg, sig, 'alice@example', signKeys.publicKey, hid: 2),
          isFalse);
      final other = sm9GenSignMasterKey();
      expect(sm9Verify(msg, sig, 'alice@example', other.publicKey), isFalse);
      for (final i in [0, 63, 66, 130, 193]) {
        expect(
            sm9Verify(
                msg, flipHex(sig, i), 'alice@example', signKeys.publicKey),
            isFalse,
            reason: 'bit flipped at $i');
      }
      expect(
          sm9Verify(
              msg, sig.toUpperCase(), 'alice@example', signKeys.publicKey),
          isFalse);
      expect(
          sm9Verify(msg, sig.substring(2), 'alice@example', signKeys.publicKey),
          isFalse);
      // A key for another identity signs validly only for that identity.
      final bobKey = sm9GenSignUserKey(signKeys.privateKey, 'bob@example');
      final bobSig = sm9Sign(msg, bobKey, signKeys.publicKey);
      expect(
          sm9Verify(msg, bobSig, 'alice@example', signKeys.publicKey), isFalse);
      expect(sm9Verify(msg, bobSig, 'bob@example', signKeys.publicKey), isTrue);
    });

    test('encrypt and decrypt, with tampering', () {
      final userKey = sm9GenEncUserKey(encKeys.privateKey, '张三');
      for (final mode in SM9EncryptMode.values) {
        for (final size in [1, 15, 16, 17, 100]) {
          final msg = Uint8List.fromList(List.generate(size, (i) => i * 31));
          final ct = sm9Encrypt(msg, '张三', encKeys.publicKey, mode: mode);
          expect(sm9Decrypt(ct, '张三', userKey, mode: mode), msg);
        }
        final ct =
            sm9Encrypt(utf('国密 SM9'), '张三', encKeys.publicKey, mode: mode);
        expect(sm9DecryptString(ct, '张三', userKey, mode: mode), '国密 SM9');
        for (final i in [3, 140, 200, ct.length - 1]) {
          expect(() => sm9Decrypt(flipHex(ct, i), '张三', userKey, mode: mode),
              throwsSmx('decryption failed'),
              reason: 'bit flipped at $i');
        }
        expect(() => sm9Decrypt(ct, '李四', userKey, mode: mode),
            throwsSmx('decryption failed'));
        final otherKey = sm9GenEncUserKey(encKeys.privateKey, '李四');
        expect(() => sm9Decrypt(ct, '张三', otherKey, mode: mode),
            throwsSmx('decryption failed'));
        expect(() => sm9Decrypt(ct.toUpperCase(), '张三', userKey, mode: mode),
            throwsSmx('decryption failed'));
        expect(
            () => sm9Decrypt(ct.substring(0, 194), '张三', userKey, mode: mode),
            throwsSmx('decryption failed'));
      }
      // The ciphertext does not record the mode.
      final ct = sm9Encrypt(utf('x' * 16), '张三', encKeys.publicKey,
          mode: SM9EncryptMode.sm4);
      expect(
          () => sm9Decrypt(ct, '张三', userKey), throwsSmx('decryption failed'));
      final invalidUtf8 = sm9Encrypt([0xFF], '张三', encKeys.publicKey);
      expect(() => sm9DecryptString(invalidUtf8, '张三', userKey),
          throwsSmx('decryption failed'));
    });

    test('key encapsulation, with tampering', () {
      final userKey = sm9GenEncUserKey(encKeys.privateKey, 'carol');
      final kem = sm9Encapsulate('carol', encKeys.publicKey, 48);
      expect(kem.key, hasLength(96));
      expect(kem.toString(), isNot(contains(kem.key)));
      expect(sm9Decapsulate(kem.ciphertext, 'carol', userKey, 48), kem.key);
      expect(
          sm9Decapsulate(kem.ciphertext, 'dave', userKey, 48), isNot(kem.key));
      expect(
          () => sm9Decapsulate(
              flipHex(kem.ciphertext, 129), 'carol', userKey, 48),
          throwsSmx('decapsulation failed'));
      expect(
          () => sm9Decapsulate(
              kem.ciphertext.toUpperCase(), 'carol', userKey, 48),
          throwsSmx('decapsulation failed'));
    });

    test('key exchange, with mismatches', () {
      final master = encKeys.publicKey;
      final keyA = sm9GenEncUserKey(encKeys.privateKey, 'A', hid: 2);
      final keyB = sm9GenEncUserKey(encKeys.privateKey, 'B', hid: 2);
      final initA = sm9ExchangeInit('B', master);
      final initB = sm9ExchangeInit('A', master);
      expect(initA.toString(), isNot(contains(initA.r)));
      final b = sm9ExchangeRespond(
          32, 'A', 'B', master, keyB, initB.r, initB.bigR, initA.bigR);
      expect(b.success, isTrue, reason: b.message);
      final a = sm9ExchangeConfirm(
          32, 'A', 'B', master, keyA, initA.r, initA.bigR, initB.bigR, b.sB);
      expect(a.success, isTrue, reason: a.message);
      expect(a.sharedKey, b.sharedKey);
      expect(a.sharedKey, hasLength(64));
      expect(sm9ExchangeCheck(b.s2, a.sA), isTrue);
      expect(sm9ExchangeCheck(b.s2, flipHex(a.sA, 0)), isFalse);
      expect(sm9ExchangeCheck(b.s2, a.sA.toUpperCase()), isFalse);
      expect(sm9ExchangeCheck(b.s2, ''), isFalse);
      expect(b.toString(), isNot(contains(b.sharedKey)));

      // A wrong S_B is caught by A before any key is released.
      final badSb = sm9ExchangeConfirm(32, 'A', 'B', master, keyA, initA.r,
          initA.bigR, initB.bigR, flipHex(b.sB, 5));
      expect(badSb.success, isFalse);
      expect(badSb.sharedKey, isEmpty);
      // A tampered R_A makes B's S_B fail at A.
      final otherInit = sm9ExchangeInit('B', master);
      final b2 = sm9ExchangeRespond(
          32, 'A', 'B', master, keyB, initB.r, initB.bigR, otherInit.bigR);
      expect(b2.success, isTrue);
      expect(
          sm9ExchangeConfirm(32, 'A', 'B', master, keyA, initA.r, initA.bigR,
                  initB.bigR, b2.sB)
              .success,
          isFalse);
      // Swapped identities do not agree.
      final b3 = sm9ExchangeRespond(
          32, 'B', 'A', master, keyB, initB.r, initB.bigR, initA.bigR);
      expect(
          sm9ExchangeConfirm(32, 'A', 'B', master, keyA, initA.r, initA.bigR,
                  initB.bigR, b3.sB)
              .success,
          isFalse);
      // A key for the wrong hid does not agree either.
      final wrongHid = sm9GenEncUserKey(encKeys.privateKey, 'A');
      expect(
          sm9ExchangeConfirm(32, 'A', 'B', master, wrongHid, initA.r,
                  initA.bigR, initB.bigR, b.sB)
              .success,
          isFalse);
    });

    test('everything works with the key caches off', () {
      setKeyCacheEnabled(false);
      try {
        final userKey = sm9GenSignUserKey(signKeys.privateKey, 'x');
        final sig = sm9Sign([1, 2, 3], userKey, signKeys.publicKey);
        expect(sm9Verify([1, 2, 3], sig, 'x', signKeys.publicKey), isTrue);
        final encKey = sm9GenEncUserKey(encKeys.privateKey, 'x');
        final ct = sm9Encrypt([9], 'x', encKeys.publicKey);
        expect(sm9Decrypt(ct, 'x', encKey), [9]);
      } finally {
        setKeyCacheEnabled(true);
      }
    });
  });
}

void checkExchange(Json master, Json c) {
  final ks = master['master_private_key'] as String;
  final public = master['master_public_key'] as String;
  final hid = master['hid'] as int;
  final idA = c['id_a'] as String, idB = c['id_b'] as String;
  expect(sm9EncMasterPublicKey(ks), public);
  final keyA = sm9GenEncUserKey(ks, idA, hid: hid);
  final keyB = sm9GenEncUserKey(ks, idB, hid: hid);
  expect(keyA, c['user_private_key_a']);
  expect(keyB, c['user_private_key_b']);
  final initA = sm9ExchangeInitWithR(idB, public, h(c['r_a'] as String));
  final initB = sm9ExchangeInitWithR(idA, public, h(c['r_b'] as String));
  expect(initA.bigR, c['R_a']);
  expect(initB.bigR, c['R_b']);
  final len = c['key_len'] as int;
  final b = sm9ExchangeRespond(
      len, idA, idB, public, keyB, initB.r, initB.bigR, initA.bigR);
  expect(b.success, isTrue, reason: b.message);
  expect(b.sharedKey, c['shared_key']);
  expect(b.sB, c['s_b']);
  final a = sm9ExchangeConfirm(
      len, idA, idB, public, keyA, initA.r, initA.bigR, initB.bigR, b.sB);
  expect(a.success, isTrue, reason: a.message);
  expect(a.sharedKey, c['shared_key']);
  expect(a.sA, c['s_a']);
  expect(sm9ExchangeCheck(b.s2, a.sA), isTrue);
}

void checkKem(Json master, Json c) {
  final ke = master['master_private_key'] as String;
  final public = master['master_public_key'] as String;
  final id = c['user_id'] as String;
  final userKey = sm9GenEncUserKey(ke, id, hid: master['hid'] as int);
  expect(userKey, c['user_private_key']);
  final len = c['key_len'] as int;
  final kem = sm9EncapsulateWithR(id, public, len, h(c['r'] as String))!;
  expect(kem.ciphertext, c['ciphertext']);
  expect(kem.key, c['key']);
  expect(sm9Decapsulate(kem.ciphertext, id, userKey, len), c['key']);
}

void checkEncrypt(
    String public, String id, String userKey, List<int> msg, Json c) {
  final r = h(c['r'] as String);
  final stream = sm9EncryptWithR(msg, id, public, r);
  final block = sm9EncryptWithR(msg, id, public, r, mode: SM9EncryptMode.sm4);
  expect(stream, c['ciphertext_stream']);
  expect(block, c['ciphertext_sm4']);
  expect(sm9Decrypt(stream!, id, userKey), msg);
  expect(sm9Decrypt(block!, id, userKey, mode: SM9EncryptMode.sm4), msg);
}
