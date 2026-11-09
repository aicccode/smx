/// SM2 public key cryptography (GB/T 32918): encryption and signatures.
///
/// Ciphertexts use the `C1 || C3 || C2` layout and signatures `r + "h" + s`,
/// both as lowercase hex, the same wire formats as the other languages of this
/// repository. Key exchange is in `exchange.dart`.
library;

import 'dart:typed_data';

import '../bytes.dart';
import '../errors.dart';
import '../field/field.dart';
import '../hex.dart';
import '../key_cache.dart';
import '../random.dart';
import '../sm3.dart';
import 'curve.dart';
import 'point.dart';

final BigInt sm2P = curveP;
final BigInt sm2A = curveA;
final BigInt sm2B = curveB;
final BigInt sm2N = curveN;
final BigInt sm2Gx = curveGx;
final BigInt sm2Gy = curveGy;

const int _c1Size = 65;
const int _c1HexLen = 130;
const int _c3HexLen = 64;
const int _hashSize = 32;
const int _privateKeyHexLen = 64;
const int _signatureLen = 129;
const int _maxRetries = 128;
const int maxKdfBytes = 0xFFFFFFFF * _hashSize;
const int maxUserIdBytes = 8191; // ENTL is the bit length in 16 bits
const String decryptError = 'decryption failed';

final Uint8List _zCurveParameters = concatBytes([
  for (final v in [curveA, curveB, curveGx, curveGy]) bigIntToBytes(v, 32),
]);

/// A generated key pair. [toString] does not show the private key.
final class SM2KeyPair {
  const SM2KeyPair(this.privateKey, this.publicKey);

  /// 64 uppercase hex digits, as the other implementations emit.
  final String privateKey;

  /// `04 || x || y` as 130 lowercase hex digits.
  final String publicKey;

  @override
  String toString() => 'SM2KeyPair(publicKey: $publicKey)';
}

// ---------------------------------------------------------------- key caches

final KeyCache<(BigInt, BigInt), Uint32List> _tableCache = KeyCache(32);
// SM3 digest of the private key -> public key. Only public keys and one-way
// digests are kept, so the cache does not extend the lifetime of any secret.
final KeyCache<String, ECPoint> _publicKeyCache = KeyCache(64);

/// The odd-multiples table of a public point, cached when enabled.
Uint32List publicTable(ECPoint point) =>
    _tableCache.lookup((point.x, point.y), () => oddMultiples(point.limbs, 0));

ECPoint _multiplyGenerator(BigInt k) {
  final jac = Uint32List(jacSize);
  mulGenerator(jac, k);
  return ECPoint.fromJacobian(jac);
}

ECPoint _publicKeyOf(BigInt d) {
  if (!keyCacheEnabled) return _multiplyGenerator(d);
  return _publicKeyCache.lookup(
      bytesToHex(sm3Digest(bigIntToBytes(d, 32))), () => _multiplyGenerator(d));
}

// ---------------------------------------------------------------- inputs

Uint8List encodeUserId(String userId) {
  final encoded = encodeUtf8Strict(userId, 'user id');
  if (encoded.length > maxUserIdBytes) {
    throw const SmxException('user id too long');
  }
  return encoded;
}

/// Parses exactly 64 hex digits (either case) into d in [1, n-2].
BigInt parsePrivateKey(String text) {
  if (text.length != _privateKeyHexLen) {
    throw const SmxException('private key must be 64 hex digits');
  }
  final d = bytesToBigInt(hexToBytes(text));
  if (!isPrivateScalar(d)) {
    throw const SmxException('private key out of range');
  }
  return d;
}

bool isPrivateScalar(BigInt v) => v >= BigInt.one && v <= curveN - BigInt.two;

/// Inverts a secret value modulo n without showing it to modInverse:
/// modInverse only ever sees value * r for a fresh random r.
BigInt invertBlinded(BigInt value, BigInt modulus) {
  final blind = randomScalar(modulus);
  return blind * ((value * blind) % modulus).modInverse(modulus) % modulus;
}

/// Z = SM3(ENTL || ID || a || b || Gx || Gy || x || y).
Uint8List userSm3Z(List<int> userId, ECPoint publicKey) {
  if (userId.length > maxUserIdBytes) {
    throw const SmxException('user id too long');
  }
  if (!publicKey.isValidPublic) {
    throw const SmxException('invalid public key');
  }
  final entl = userId.length * 8;
  return sm3Digest(concatBytes([
    [entl >> 8, entl & 0xFF],
    userId,
    _zCurveParameters,
    publicKey.xBytes(),
    publicKey.yBytes(),
  ]));
}

Uint8List _xor(List<int> a, List<int> b) {
  final out = Uint8List(a.length);
  for (var i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

// ---------------------------------------------------------------- keys

/// Returns a new key pair with d uniform in [1, n-2].
SM2KeyPair sm2GenKeyPair() {
  for (var i = 0; i < _maxRetries; i++) {
    final d = randomScalar(curveN);
    if (d <= curveN - BigInt.two) {
      return SM2KeyPair(bytesToHexUpper(bigIntToBytes(d, 32)),
          _multiplyGenerator(d).toHexEncoded());
    }
  }
  throw const SmxException('could not generate a key');
}

/// Decodes a `04 || x || y` hex public key (either case).
ECPoint sm2DecodePoint(String text) => ECPoint.fromHexEncoded(text);

/// The public key [d]G for a private key in [1, n-2].
ECPoint sm2GetPublicKey(BigInt privateKey) {
  if (!isPrivateScalar(privateKey)) {
    throw const SmxException('private key out of range');
  }
  return _multiplyGenerator(privateKey);
}

// ---------------------------------------------------------------- encryption

/// Encrypts a UTF-8 string; returns `C1 || C3 || C2` as lowercase hex.
String sm2Encrypt(String plaintext, String publicKey) =>
    sm2EncryptBytes(encodeUtf8Strict(plaintext, 'plaintext'), publicKey);

/// Encrypts bytes; returns `C1 || C3 || C2` as lowercase hex.
String sm2EncryptBytes(List<int> plaintext, String publicKey) {
  final message = requireBytes(plaintext, 'plaintext');
  if (message.isEmpty) throw const SmxException('plaintext cannot be empty');
  if (message.length > maxKdfBytes) {
    throw const SmxException('plaintext too long');
  }
  final point = ECPoint.fromHexEncoded(publicKey);
  for (var i = 0; i < _maxRetries; i++) {
    final result = sm2EncryptWithK(message, point, randomScalar(curveN));
    if (result != null) return result;
  }
  throw const SmxException('encryption failed');
}

/// Encryption with a given k; null when k must be replaced. Internal, for
/// known-answer tests.
String? sm2EncryptWithK(Uint8List message, ECPoint point, BigInt k) {
  final c1 = Uint32List(jacSize);
  mulGenerator(c1, k);
  final c1Aff = Uint32List(affSize);
  toAffine(c1Aff, 0, c1, 0);
  final p2 = Uint32List(jacSize);
  mulPointWithTable(p2, point.limbs, 0, k, publicTable(point));
  final p2Aff = Uint32List(affSize);
  if (!toAffine(p2Aff, 0, p2, 0)) return null;
  final x2 = sm2Fp.bytes(p2Aff, 0), y2 = sm2Fp.bytes(p2Aff, limbs);
  final key = sm3Kdf(concatBytes([x2, y2]), message.length);
  if (isAllZero(key)) return null;
  final c2 = _xor(message, key);
  final c3 = sm3Digest(concatBytes([x2, message, y2]));
  return '04${bytesToHex(sm2Fp.bytes(c1Aff, 0))}'
      '${bytesToHex(sm2Fp.bytes(c1Aff, limbs))}'
      '${bytesToHex(c3)}${bytesToHex(c2)}';
}

/// Decrypts lowercase `C1 || C3 || C2` hex and returns the UTF-8 plaintext.
///
/// A malformed private key throws its own [SmxException]. Every failure
/// concerning the ciphertext (format, C1, C3, invalid UTF-8) throws the same
/// SmxException('decryption failed').
String sm2Decrypt(String ciphertext, String privateKey) {
  final data = sm2DecryptBytes(ciphertext, privateKey);
  return decodeUtf8OrNull(data) ?? (throw const SmxException(decryptError));
}

/// Like [sm2Decrypt], returning the plaintext bytes with no UTF-8 step.
Uint8List sm2DecryptBytes(String ciphertext, String privateKey) {
  final d = parsePrivateKey(privateKey);
  if (ciphertext.length < _c1HexLen + _c3HexLen + 2 ||
      ciphertext.length.isOdd) {
    throw const SmxException(decryptError);
  }
  final data = tryLowercaseHexToBytes(ciphertext);
  if (data == null || data.length - _c1Size - _hashSize > maxKdfBytes) {
    throw const SmxException(decryptError);
  }
  final ECPoint c1;
  try {
    c1 = ECPoint.fromEncoded(Uint8List.sublistView(data, 0, _c1Size));
  } on SmxException {
    throw const SmxException(decryptError);
  }
  final c3 = Uint8List.sublistView(data, _c1Size, _c1Size + _hashSize);
  final c2 = Uint8List.sublistView(data, _c1Size + _hashSize);
  final p2 = Uint32List(jacSize);
  mulPointWithTable(p2, c1.limbs, 0, d, oddMultiples(c1.limbs, 0));
  final p2Aff = Uint32List(affSize);
  if (!toAffine(p2Aff, 0, p2, 0)) throw const SmxException(decryptError);
  final x2 = sm2Fp.bytes(p2Aff, 0), y2 = sm2Fp.bytes(p2Aff, limbs);
  final key = sm3Kdf(concatBytes([x2, y2]), c2.length);
  final zeroKey = isAllZero(key);
  final message = _xor(c2, key);
  final check = sm3Digest(concatBytes([x2, message, y2]));
  final valid = constantTimeEquals(check, c3);
  if (zeroKey || !valid) {
    message.fillRange(0, message.length, 0);
    throw const SmxException(decryptError);
  }
  return message;
}

// ---------------------------------------------------------------- signatures

/// Signs a message; returns `r + "h" + s` as lowercase hex (64 digits each).
String sm2Sign(String userId, String message, String privateKey) {
  final d = parsePrivateKey(privateKey);
  final publicKey = _publicKeyOf(d);
  final Uint8List id, msg;
  try {
    id = encodeUserId(userId);
    msg = encodeUtf8Strict(message, 'message');
  } on SmxException {
    throw const SmxException('invalid user id or message');
  }
  final e =
      bytesToBigInt(sm3Digest(concatBytes([userSm3Z(id, publicKey), msg])));
  final inv = invertBlinded(d + BigInt.one, curveN);
  for (var i = 0; i < _maxRetries; i++) {
    final signature = sm2SignDigestWithK(e, d, inv, randomScalar(curveN));
    if (signature != null) return signature;
  }
  throw const SmxException('signing failed');
}

/// Signs the digest e with nonce k, given inv = (1 + d)^-1 mod n; null when k
/// must be replaced. Internal, for known-answer tests.
String? sm2SignDigestWithK(BigInt e, BigInt d, BigInt inv, BigInt k) {
  final jac = Uint32List(jacSize);
  mulGenerator(jac, k);
  final aff = Uint32List(affSize);
  toAffine(aff, 0, jac, 0);
  final x1 = sm2Fp.toBigInt(aff, 0);
  final r = (e + x1) % curveN;
  if (r == BigInt.zero || r + k == curveN) return null;
  final s = (inv * ((k - r * d) % curveN)) % curveN;
  if (s == BigInt.zero) return null;
  return '${bytesToHex(bigIntToBytes(r, 32))}h${bytesToHex(bigIntToBytes(s, 32))}';
}

/// Signs with a given nonce. Internal, for known-answer tests.
String? sm2SignWithK(
    String userId, String message, String privateKey, BigInt k) {
  final d = parsePrivateKey(privateKey);
  final e = bytesToBigInt(sm3Digest(concatBytes([
    userSm3Z(encodeUserId(userId), _publicKeyOf(d)),
    encodeUtf8Strict(message, 'message'),
  ])));
  return sm2SignDigestWithK(e, d, (d + BigInt.one).modInverse(curveN), k);
}

/// Verifies a signature. Any invalid input of any kind returns false.
bool sm2Verify(
    String userId, String signature, String message, String publicKey) {
  if (signature.length != _signatureLen || signature[64] != 'h') return false;
  final rBytes = tryLowercaseHexToBytes(signature.substring(0, 64));
  final sBytes = tryLowercaseHexToBytes(signature.substring(65));
  if (rBytes == null || sBytes == null) return false;
  final r = bytesToBigInt(rBytes), s = bytesToBigInt(sBytes);
  if (r < BigInt.one || r >= curveN || s < BigInt.one || s >= curveN) {
    return false;
  }
  final t = (r + s) % curveN;
  if (t == BigInt.zero) return false;
  final Uint8List id, msg;
  final ECPoint point;
  try {
    id = encodeUserId(userId);
    msg = encodeUtf8Strict(message, 'message');
    point = ECPoint.fromHexEncoded(publicKey);
  } on SmxException {
    return false;
  }
  final e = bytesToBigInt(sm3Digest(concatBytes([userSm3Z(id, point), msg])));
  final jac = Uint32List(jacSize);
  mulShamir(jac, s, t, publicTable(point));
  final aff = Uint32List(affSize);
  if (!toAffine(aff, 0, jac, 0)) return false;
  return (e + sm2Fp.toBigInt(aff, 0)) % curveN == r;
}
