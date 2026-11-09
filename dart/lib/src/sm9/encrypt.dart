/// SM9 key encapsulation and public key encryption (GB/T 38635.2, parts 4
/// and 5 of the original GM/T 0044).
library;

import 'dart:typed_data';

import '../bytes.dart';
import '../errors.dart';
import '../hex.dart';
import '../sm3.dart';
import '../sm4.dart';
import 'common.dart';
import 'g1.dart';
import 'pairing.dart';
import 'tower.dart';

const int _maxRetries = 128;
const int _macKeyLen = 32;
const int _sm4KeyLen = 16;
const String _decryptError = 'decryption failed';
const String _decapsulateError = 'decapsulation failed';

/// How [sm9Encrypt] turns the KDF output into C2. The ciphertext does not
/// record the mode, so decryption must be told the same mode.
enum SM9EncryptMode {
  /// C2 = M xor K1 (the default).
  stream,

  /// C2 = SM4-ECB(K1, PKCS#7(M)), as in the standard's example.
  sm4,
}

/// A KEM result. [toString] does not show the key.
final class SM9Encapsulation {
  const SM9Encapsulation(this.key, this.ciphertext);

  /// The shared key as lowercase hex. Secret.
  final String key;

  /// The encapsulation C, a G1 point, as lowercase hex.
  final String ciphertext;

  @override
  String toString() => 'SM9Encapsulation(ciphertext: $ciphertext)';
}

void _requireKeyLen(int keyLen) {
  if (keyLen < 1 || keyLen > maxKeyBytes) {
    throw const SmxException('key length must be between 1 and 1048576');
  }
}

/// C = [r]QB and w = e(Ppub-e, P2)^r.
(Uint32List, Uint32List)? _keyMaterial(
    Uint32List qb, EncMaster master, BigInt r, Uint32List qbTable) {
  final c = g1MulSecretAffine(qb, r, qbTable);
  if (c == null) return null;
  return (c, master.pow(r));
}

Uint8List _z(Uint32List c, Uint32List w, Uint8List id) =>
    concatBytes([g1Xy(c, 0), f12ToBytes(w, 0), id]);

Uint32List _receiverPoint(Uint8List id, int hid, EncMaster master) =>
    userEncPoint(id, hid, master.point) ??
    (throw const SmxException('invalid master public key'));

// ---------------------------------------------------------------- KEM

/// Encapsulates a fresh key of [keyLen] bytes (1 to 1 MiB) for [userId].
SM9Encapsulation sm9Encapsulate(
    String userId, String masterPublicKey, int keyLen,
    {int hid = sm9HidEncrypt}) {
  requireHid(hid);
  _requireKeyLen(keyLen);
  final id = encodeId(userId);
  final master = encMaster(masterPublicKey);
  final qb = _receiverPoint(id, hid, master);
  final table = g1OddMultiples(qb, 0);
  for (var i = 0; i < _maxRetries; i++) {
    final result =
        _encapsulateWith(id, qb, table, master, keyLen, sm9RandomScalar());
    if (result != null) return result;
  }
  throw const SmxException('encapsulation failed');
}

SM9Encapsulation? _encapsulateWith(Uint8List id, Uint32List qb,
    Uint32List table, EncMaster master, int keyLen, BigInt r) {
  final material = _keyMaterial(qb, master, r, table);
  if (material == null) return null;
  final (c, w) = material;
  final key = sm3Kdf(_z(c, w, id), keyLen);
  if (isAllZero(key)) return null;
  return SM9Encapsulation(bytesToHex(key), bytesToHex(g1Encode(c, 0)));
}

/// Encapsulation with a given r; null when r must be replaced. Internal,
/// for known-answer tests.
SM9Encapsulation? sm9EncapsulateWithR(
    String userId, String masterPublicKey, int keyLen, BigInt r,
    {int hid = sm9HidEncrypt}) {
  final id = encodeId(userId);
  final master = encMaster(masterPublicKey);
  final qb = _receiverPoint(id, hid, master);
  return _encapsulateWith(id, qb, g1OddMultiples(qb, 0), master, keyLen, r);
}

Uint32List _parseUserKey(String userPrivateKey) =>
    tryParseUserKey(userPrivateKey) ??
    (throw const SmxException('invalid user private key'));

/// Recovers the key of [keyLen] bytes from an encapsulation (lowercase hex).
///
/// A malformed user private key throws its own [SmxException]; every other
/// failure throws SmxException('decapsulation failed').
String sm9Decapsulate(
    String ciphertext, String userId, String userPrivateKey, int keyLen) {
  _requireKeyLen(keyLen);
  final de = _parseUserKey(userPrivateKey);
  final id = encodeId(userId);
  final c = tryParseG1(ciphertext, lowercase: true);
  if (c == null) throw const SmxException(_decapsulateError);
  final w = pairing(c, 0, de, 0);
  final key = sm3Kdf(_z(c, w, id), keyLen);
  if (isAllZero(key)) throw const SmxException(_decapsulateError);
  return bytesToHex(key);
}

// ---------------------------------------------------------------- encryption

int _kdfLength(SM9EncryptMode mode, int messageLength) =>
    (mode == SM9EncryptMode.stream ? messageLength : _sm4KeyLen) + _macKeyLen;

/// Encrypts [plaintext] (not empty) for [userId]; returns `C1 || C3 || C2`
/// as lowercase hex, with C1 a G1 point (65 bytes, 04 prefix included).
String sm9Encrypt(List<int> plaintext, String userId, String masterPublicKey,
    {int hid = sm9HidEncrypt, SM9EncryptMode mode = SM9EncryptMode.stream}) {
  requireHid(hid);
  final msg = requireBytes(plaintext, 'plaintext');
  if (msg.isEmpty) throw const SmxException('plaintext cannot be empty');
  if (msg.length > maxKdfBytes - _macKeyLen) {
    throw const SmxException('plaintext too long');
  }
  final id = encodeId(userId);
  final master = encMaster(masterPublicKey);
  final qb = _receiverPoint(id, hid, master);
  final table = g1OddMultiples(qb, 0);
  for (var i = 0; i < _maxRetries; i++) {
    final result =
        _encryptWith(msg, id, qb, table, master, mode, sm9RandomScalar());
    if (result != null) return result;
  }
  throw const SmxException('encryption failed');
}

String? _encryptWith(Uint8List msg, Uint8List id, Uint32List qb,
    Uint32List table, EncMaster master, SM9EncryptMode mode, BigInt r) {
  final material = _keyMaterial(qb, master, r, table);
  if (material == null) return null;
  final (c1, w) = material;
  final k = sm3Kdf(_z(c1, w, id), _kdfLength(mode, msg.length));
  final k1Len = k.length - _macKeyLen;
  final k1 = Uint8List.sublistView(k, 0, k1Len);
  if (isAllZero(k1)) return null;
  final Uint8List c2;
  if (mode == SM9EncryptMode.stream) {
    c2 = Uint8List(msg.length);
    for (var i = 0; i < msg.length; i++) {
      c2[i] = msg[i] ^ k1[i];
    }
  } else {
    c2 = sm4EcbEncryptPadded(k1, msg);
  }
  final c3 = sm3Digest(concatBytes([c2, Uint8List.sublistView(k, k1Len)]));
  return '${bytesToHex(g1Encode(c1, 0))}${bytesToHex(c3)}${bytesToHex(c2)}';
}

/// Encryption with a given r; null when r must be replaced. Internal, for
/// known-answer tests.
String? sm9EncryptWithR(
    List<int> plaintext, String userId, String masterPublicKey, BigInt r,
    {int hid = sm9HidEncrypt, SM9EncryptMode mode = SM9EncryptMode.stream}) {
  final id = encodeId(userId);
  final master = encMaster(masterPublicKey);
  final qb = _receiverPoint(id, hid, master);
  return _encryptWith(requireBytes(plaintext, 'plaintext'), id, qb,
      g1OddMultiples(qb, 0), master, mode, r);
}

/// Decrypts lowercase `C1 || C3 || C2` hex and returns the plaintext bytes.
///
/// A malformed user private key or user id throws its own [SmxException].
/// Every failure concerning the ciphertext throws the same
/// SmxException('decryption failed'). C3 is checked, in constant time,
/// before anything is decrypted or unpadded.
Uint8List sm9Decrypt(String ciphertext, String userId, String userPrivateKey,
    {SM9EncryptMode mode = SM9EncryptMode.stream}) {
  final de = _parseUserKey(userPrivateKey);
  final id = encodeId(userId);
  const fail = SmxException(_decryptError);
  if (ciphertext.length < 2 * (65 + 32 + 1)) throw fail;
  final data = tryLowercaseHexToBytes(ciphertext);
  if (data == null) throw fail;
  final c1 = g1Decode(Uint8List.sublistView(data, 0, 65));
  if (c1 == null) throw fail;
  final c3 = Uint8List.sublistView(data, 65, 97);
  final c2 = Uint8List.sublistView(data, 97);
  if (mode == SM9EncryptMode.sm4 && c2.length % 16 != 0) throw fail;
  if (c2.length > maxKdfBytes - _macKeyLen) throw fail;
  final w = pairing(c1, 0, de, 0);
  final k = sm3Kdf(_z(c1, w, id), _kdfLength(mode, c2.length));
  final k1Len = k.length - _macKeyLen;
  final k1 = Uint8List.sublistView(k, 0, k1Len);
  final zeroKey = isAllZero(k1);
  final mac = sm3Digest(concatBytes([c2, Uint8List.sublistView(k, k1Len)]));
  final valid = constantTimeEquals(mac, c3);
  if (zeroKey || !valid) throw fail;
  if (mode == SM9EncryptMode.sm4) {
    return sm4EcbDecryptPadded(k1, c2) ?? (throw fail);
  }
  final out = Uint8List(c2.length);
  for (var i = 0; i < c2.length; i++) {
    out[i] = c2[i] ^ k1[i];
  }
  return out;
}

/// Like [sm9Decrypt], returning UTF-8 text; invalid UTF-8 fails the same way.
String sm9DecryptString(String ciphertext, String userId, String userPrivateKey,
    {SM9EncryptMode mode = SM9EncryptMode.stream}) {
  final data = sm9Decrypt(ciphertext, userId, userPrivateKey, mode: mode);
  return decodeUtf8OrNull(data) ?? (throw const SmxException(_decryptError));
}
