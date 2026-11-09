// Malformed input to every public function must end in SmxException (or a
// false/unsuccessful result), never in another exception type.
import 'dart:math';

import 'package:smx/smx.dart';
import 'package:test/test.dart';

const _alphabet = '0123456789abcdefABCDEFhxz é密\uD800';

String _mutate(Random rng, String valid) {
  final chars = valid.split('');
  switch (rng.nextInt(5)) {
    case 0: // change one character
      if (chars.isNotEmpty) {
        chars[rng.nextInt(chars.length)] =
            _alphabet[rng.nextInt(_alphabet.length)];
      }
    case 1: // truncate
      if (chars.isNotEmpty) {
        chars.removeRange(rng.nextInt(chars.length), chars.length);
      }
    case 2: // extend
      for (var i = rng.nextInt(4); i >= 0; i--) {
        chars.add(_alphabet[rng.nextInt(_alphabet.length)]);
      }
    case 3: // random string of the same length
      for (var i = 0; i < chars.length; i++) {
        chars[i] = _alphabet[rng.nextInt(_alphabet.length)];
      }
    default: // random short string
      return String.fromCharCodes(
          List.generate(rng.nextInt(8), (_) => rng.nextInt(0x10000)));
  }
  return chars.join();
}

void _expectClean(Object? Function() f) {
  try {
    f();
  } on SmxException {
    // expected
  }
}

void main() {
  final rng = Random(2026);
  final sm2 = sm2GenKeyPair();
  final sm2Sig = sm2Sign('id', 'm', sm2.privateKey);
  final sm2Ct = sm2Encrypt('m', sm2.publicKey);
  final sm4 = SM4()..setKey(List.filled(16, 1), List.filled(16, 2));
  final sm4Ct = sm4.encrypt('hello');
  final signMaster = sm9GenSignMasterKey();
  final signUser = sm9GenSignUserKey(signMaster.privateKey, 'a');
  final sm9Sig = sm9Sign([1], signUser, signMaster.publicKey);
  final encMaster = sm9GenEncMasterKey();
  final encUser = sm9GenEncUserKey(encMaster.privateKey, 'a');
  final sm9Ct = sm9Encrypt([1, 2], 'a', encMaster.publicKey);
  final kem = sm9Encapsulate('a', encMaster.publicKey, 16);

  test('SM2 and SM4 reject malformed input cleanly', () {
    for (var i = 0; i < 300; i++) {
      final pub = _mutate(rng, sm2.publicKey);
      final priv = _mutate(rng, sm2.privateKey);
      final sig = _mutate(rng, sm2Sig);
      final ct = _mutate(rng, sm2Ct);
      expect(sm2Verify('id', sig, 'm', sm2.publicKey), isA<bool>());
      expect(sm2Verify('id', sm2Sig, 'm', pub), isA<bool>());
      _expectClean(() => sm2DecodePoint(pub));
      _expectClean(() => sm2Encrypt('m', pub));
      _expectClean(() => sm2Sign('id', 'm', priv));
      _expectClean(() => sm2Decrypt(ct, sm2.privateKey));
      _expectClean(() => sm2Decrypt(sm2Ct, priv));
      _expectClean(() => sm4.decrypt(_mutate(rng, sm4Ct)));
      _expectClean(() => hexToBytes(pub));
      _expectClean(() => hexToBigInt(priv));
    }
  });

  test('SM9 rejects malformed input cleanly', () {
    for (var i = 0; i < 150; i++) {
      final sig = _mutate(rng, sm9Sig);
      expect(sm9Verify([1], sig, 'a', signMaster.publicKey), isA<bool>());
      expect(sm9Verify([1], sm9Sig, 'a', _mutate(rng, signMaster.publicKey)),
          isA<bool>());
      _expectClean(
          () => sm9Sign([1], _mutate(rng, signUser), signMaster.publicKey));
      _expectClean(
          () => sm9Encrypt([1], 'a', _mutate(rng, encMaster.publicKey)));
      _expectClean(() => sm9Decrypt(_mutate(rng, sm9Ct), 'a', encUser));
      _expectClean(() => sm9Decrypt(sm9Ct, 'a', _mutate(rng, encUser)));
      _expectClean(
          () => sm9Decapsulate(_mutate(rng, kem.ciphertext), 'a', encUser, 16));
      _expectClean(
          () => sm9GenSignUserKey(_mutate(rng, signMaster.privateKey), 'a'));
      final r = sm9ExchangeRespond(
          16,
          'a',
          'b',
          encMaster.publicKey,
          encUser,
          _mutate(rng, signMaster.privateKey),
          _mutate(rng, kem.ciphertext),
          _mutate(rng, kem.ciphertext));
      expect(r.success, isFalse);
      expect(sm9ExchangeCheck(_mutate(rng, sm9Sig), _mutate(rng, sm9Sig)),
          isA<bool>());
    }
  });
}
