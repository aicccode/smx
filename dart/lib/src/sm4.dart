/// SM4 block cipher (GB/T 32907-2016) with CBC mode and PKCS#7 padding.
///
/// Security notes for callers:
///
/// - **CBC gives confidentiality only, with no integrity.** An attacker can
///   change a ciphertext undetected, and any error a receiver reveals about a
///   forged message can become a decryption oracle. Authenticate the
///   ciphertext separately (encrypt then MAC, or a signature) and check that
///   before calling [SM4.decrypt].
/// - **The IV is fixed by [SM4.setKey] and every [SM4.encrypt] call reuses
///   it**, so equal plaintexts give equal ciphertexts and a shared prefix
///   shows. Call `setKey` with a fresh random IV for each message, and send the
///   IV along.
/// - [SM4.encryptBlock] and [SM4.decryptBlock] are raw ECB building blocks.
///
/// **This SM4 uses table lookups and is not cache-timing resistant.** The key
/// schedule and every block index T-tables (the S-box merged with the linear
/// transform) by key- and data-dependent bytes, as OpenSSL and BouncyCastle
/// do. An attacker who can observe cache timing on the same machine may learn
/// the key. The `security` branch of this repository has the variant without
/// secret-indexed tables.
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'errors.dart';
import 'hex.dart';

const int _mask = 0xFFFFFFFF;
const int _blockSize = 16;
const String _decryptError = 'decryption failed';

const List<int> _sbox = [
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, //
  0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
  0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4,
  0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
  0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
  0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
  0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2,
  0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
  0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b,
  0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
  0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2,
  0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
  0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
  0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
  0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
  0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
  0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41,
  0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
  0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a,
  0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
  0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e,
  0xd7, 0xcb, 0x39, 0x48,
];

const List<int> _fk = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];

const List<int> _ck = [
  0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, //
  0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
  0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
  0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
  0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
  0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
  0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
  0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
];

int _rotl(int x, int n) => ((x << n) | (x >> (32 - n))) & _mask;

/// T_i[x] = linear(S(x)) for x in byte i of the word (byte 0 is the highest).
List<Uint32List> _byteTables(int Function(int) linear) {
  final low = Uint32List(256);
  for (var i = 0; i < 256; i++) {
    low[i] = linear(_sbox[i]);
  }
  Uint32List rotated(int n) {
    final t = Uint32List(256);
    for (var i = 0; i < 256; i++) {
      t[i] = _rotl(low[i], n);
    }
    return t;
  }

  return [rotated(24), rotated(16), rotated(8), low];
}

// Round function tables, L(B) = B ^ B<<<2 ^ B<<<10 ^ B<<<18 ^ B<<<24.
final List<Uint32List> _roundTables = _byteTables(
    (b) => b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24));
final Uint32List _t0 = _roundTables[0];
final Uint32List _t1 = _roundTables[1];
final Uint32List _t2 = _roundTables[2];
final Uint32List _t3 = _roundTables[3];

// Key schedule tables, L'(B) = B ^ B<<<13 ^ B<<<23.
final List<Uint32List> _keyTables =
    _byteTables((b) => b ^ _rotl(b, 13) ^ _rotl(b, 23));

int _word(List<int> b, int o) =>
    (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3];

/// Expands a 16-byte key into 32 round keys.
Uint32List _expandKey(List<int> key) {
  final k0 = _keyTables[0], k1 = _keyTables[1];
  final k2 = _keyTables[2], k3 = _keyTables[3];
  var a = _word(key, 0) ^ _fk[0];
  var b = _word(key, 4) ^ _fk[1];
  var c = _word(key, 8) ^ _fk[2];
  var d = _word(key, 12) ^ _fk[3];
  final rk = Uint32List(32);
  for (var i = 0; i < 32; i += 4) {
    var x = b ^ c ^ d ^ _ck[i];
    a ^= k0[x >> 24] ^ k1[(x >> 16) & 255] ^ k2[(x >> 8) & 255] ^ k3[x & 255];
    x = c ^ d ^ a ^ _ck[i + 1];
    b ^= k0[x >> 24] ^ k1[(x >> 16) & 255] ^ k2[(x >> 8) & 255] ^ k3[x & 255];
    x = d ^ a ^ b ^ _ck[i + 2];
    c ^= k0[x >> 24] ^ k1[(x >> 16) & 255] ^ k2[(x >> 8) & 255] ^ k3[x & 255];
    x = a ^ b ^ c ^ _ck[i + 3];
    d ^= k0[x >> 24] ^ k1[(x >> 16) & 255] ^ k2[(x >> 8) & 255] ^ k3[x & 255];
    rk[i] = a;
    rk[i + 1] = b;
    rk[i + 2] = c;
    rk[i + 3] = d;
  }
  return rk;
}

Uint32List _reversed(Uint32List rk) {
  final out = Uint32List(32);
  for (var i = 0; i < 32; i++) {
    out[i] = rk[31 - i];
  }
  return out;
}

const int _ecb = 0;
const int _cbcEncrypt = 1;
const int _cbcDecrypt = 2;

/// Runs whole blocks of [input] through the cipher into [out].
///
/// [mode] is ECB, CBC encryption or CBC decryption; [iv] is used by CBC.
void _process(
    Uint32List rk, Uint8List input, Uint8List out, int mode, List<int>? iv) {
  final t0 = _t0, t1 = _t1, t2 = _t2, t3 = _t3;
  var p0 = 0, p1 = 0, p2 = 0, p3 = 0;
  if (iv != null) {
    p0 = _word(iv, 0);
    p1 = _word(iv, 4);
    p2 = _word(iv, 8);
    p3 = _word(iv, 12);
  }
  for (var o = 0; o < input.length; o += _blockSize) {
    final c0 = (input[o] << 24) |
        (input[o + 1] << 16) |
        (input[o + 2] << 8) |
        input[o + 3];
    final c1 = (input[o + 4] << 24) |
        (input[o + 5] << 16) |
        (input[o + 6] << 8) |
        input[o + 7];
    final c2 = (input[o + 8] << 24) |
        (input[o + 9] << 16) |
        (input[o + 10] << 8) |
        input[o + 11];
    final c3 = (input[o + 12] << 24) |
        (input[o + 13] << 16) |
        (input[o + 14] << 8) |
        input[o + 15];
    var a = c0, b = c1, c = c2, d = c3;
    if (mode == _cbcEncrypt) {
      a ^= p0;
      b ^= p1;
      c ^= p2;
      d ^= p3;
    }
    for (var i = 0; i < 32; i += 4) {
      var x = b ^ c ^ d ^ rk[i];
      a ^= t0[x >> 24] ^ t1[(x >> 16) & 255] ^ t2[(x >> 8) & 255] ^ t3[x & 255];
      x = c ^ d ^ a ^ rk[i + 1];
      b ^= t0[x >> 24] ^ t1[(x >> 16) & 255] ^ t2[(x >> 8) & 255] ^ t3[x & 255];
      x = d ^ a ^ b ^ rk[i + 2];
      c ^= t0[x >> 24] ^ t1[(x >> 16) & 255] ^ t2[(x >> 8) & 255] ^ t3[x & 255];
      x = a ^ b ^ c ^ rk[i + 3];
      d ^= t0[x >> 24] ^ t1[(x >> 16) & 255] ^ t2[(x >> 8) & 255] ^ t3[x & 255];
    }
    // Output words are d, c, b, a.
    var r0 = d, r1 = c, r2 = b, r3 = a;
    if (mode == _cbcEncrypt) {
      p0 = r0;
      p1 = r1;
      p2 = r2;
      p3 = r3;
    } else if (mode == _cbcDecrypt) {
      r0 ^= p0;
      r1 ^= p1;
      r2 ^= p2;
      r3 ^= p3;
      p0 = c0;
      p1 = c1;
      p2 = c2;
      p3 = c3;
    }
    out[o] = r0 >> 24;
    out[o + 1] = r0 >> 16;
    out[o + 2] = r0 >> 8;
    out[o + 3] = r0;
    out[o + 4] = r1 >> 24;
    out[o + 5] = r1 >> 16;
    out[o + 6] = r1 >> 8;
    out[o + 7] = r1;
    out[o + 8] = r2 >> 24;
    out[o + 9] = r2 >> 16;
    out[o + 10] = r2 >> 8;
    out[o + 11] = r2;
    out[o + 12] = r3 >> 24;
    out[o + 13] = r3 >> 16;
    out[o + 14] = r3 >> 8;
    out[o + 15] = r3;
  }
}

/// Pads data to a multiple of the block size (PKCS#7).
Uint8List pkcs7Pad(List<int> data) {
  final padLength = _blockSize - data.length % _blockSize;
  final out = Uint8List(data.length + padLength);
  out.setRange(0, data.length, data);
  out.fillRange(data.length, out.length, padLength);
  return out;
}

/// Returns 1 if the non-empty data does not end in valid padding, else 0.
///
/// This always reads the whole last block and has no branch on its content.
int _paddingIsBad(List<int> data) {
  final n = data.length;
  final padLength = data[n - 1];
  // Each term is 1 when its condition fails: padLength is 0 or above 16.
  var bad = ((padLength - 1) >> 8) & 1;
  bad |= ((_blockSize - padLength) >> 8) & 1;
  for (var offset = 1; offset <= _blockSize; offset++) {
    final insidePadding = ((offset - padLength - 1) >> 8) & 1;
    final differs = (((data[n - offset] ^ padLength) + 255) >> 8) & 1;
    bad |= insidePadding & differs;
  }
  return bad;
}

/// Removes and validates PKCS#7 padding; every failure throws the same
/// [SmxException].
Uint8List pkcs7Unpad(List<int> data) {
  final size = data.length;
  if (size == 0 || size % _blockSize != 0 || _paddingIsBad(data) != 0) {
    throw const SmxException(_decryptError);
  }
  return Uint8List.fromList(data.sublist(0, size - data[size - 1]));
}

Uint8List _require16(List<int> value, String name) {
  var bad = value.length ^ _blockSize;
  if (bad == 0) {
    for (var i = 0; i < _blockSize; i++) {
      bad |= value[i] & ~0xFF;
    }
  }
  if (bad != 0) throw SmxException('$name must be exactly 16 bytes');
  return Uint8List.fromList(value);
}

/// SM4-ECB encryption of PKCS#7-padded [data] (the SM9 encryption mode).
Uint8List sm4EcbEncryptPadded(List<int> key16, List<int> data) {
  final rk = _expandKey(_require16(key16, 'key'));
  final padded = pkcs7Pad(data);
  final out = Uint8List(padded.length);
  _process(rk, padded, out, _ecb, null);
  return out;
}

/// SM4-ECB decryption followed by PKCS#7 unpadding; null when the length is
/// not a positive multiple of 16 or the padding is bad.
Uint8List? sm4EcbDecryptPadded(List<int> key16, List<int> data) {
  final size = data.length;
  if (size == 0 || size % _blockSize != 0) return null;
  final rk = _reversed(_expandKey(_require16(key16, 'key')));
  final input = data is Uint8List ? data : Uint8List.fromList(data);
  final out = Uint8List(size);
  _process(rk, input, out, _ecb, null);
  if (_paddingIsBad(out) != 0) return null;
  return Uint8List.sublistView(out, 0, size - out[size - 1]);
}

/// Expanded key material, replaced as one object so that a key and its IV
/// always belong together.
final class _Keys {
  _Keys(this.encrypt, this.decrypt, this.iv);
  final Uint32List encrypt;
  final Uint32List decrypt;
  final Uint8List iv;
}

/// SM4-CBC cipher. Call [setKey] before encrypting or decrypting.
///
/// See the library documentation: CBC has no integrity, the IV stays the same
/// for every [encrypt] until the next [setKey], and this table-based SM4 is
/// not cache-timing resistant.
class SM4 {
  /// Creates a cipher with no key.
  SM4();

  _Keys? _keys;

  /// Sets the key and IV, each exactly 16 bytes; anything else throws
  /// [SmxException] and keeps the previous key.
  void setKey(List<int> key, List<int> iv) {
    final keyBytes = _require16(key, 'key');
    final ivBytes = _require16(iv, 'iv');
    final expanded = _expandKey(keyBytes);
    _keys = _Keys(expanded, _reversed(expanded), ivBytes);
  }

  _Keys _requireKey() => _keys ?? (throw const SmxException('key not set'));

  /// Encrypts one raw 16-byte block without chaining or padding (ECB).
  Uint8List encryptBlock(List<int> block) {
    final keys = _requireKey();
    final out = Uint8List(_blockSize);
    _process(keys.encrypt, _require16(block, 'block'), out, _ecb, null);
    return out;
  }

  /// Decrypts one raw 16-byte block without chaining or padding (ECB).
  Uint8List decryptBlock(List<int> block) {
    final keys = _requireKey();
    final out = Uint8List(_blockSize);
    _process(keys.decrypt, _require16(block, 'block'), out, _ecb, null);
    return out;
  }

  /// Encrypts a string (UTF-8) and returns lowercase hex ciphertext.
  ///
  /// CBC gives no integrity, and this reuses the IV of [setKey]. A string
  /// with an unpaired surrogate throws [SmxException].
  String encrypt(String plaintext) {
    final keys = _requireKey();
    return _encrypt(keys, encodeUtf8Strict(plaintext, 'plaintext'));
  }

  /// Encrypts bytes and returns lowercase hex ciphertext.
  String encryptBytes(List<int> plaintext) {
    final keys = _requireKey();
    return _encrypt(keys, requireBytes(plaintext, 'plaintext'));
  }

  String _encrypt(_Keys keys, Uint8List data) {
    final padded = pkcs7Pad(data);
    final out = Uint8List(padded.length);
    _process(keys.encrypt, padded, out, _cbcEncrypt, keys.iv);
    return bytesToHex(out);
  }

  /// Returns all decrypted bytes, padding included, or null if malformed.
  Uint8List? _decryptAll(String ciphertext) {
    final keys = _requireKey();
    final data = tryLowercaseHexToBytes(ciphertext);
    if (data == null || data.isEmpty || data.length % _blockSize != 0) {
      return null;
    }
    final out = Uint8List(data.length);
    _process(keys.decrypt, data, out, _cbcDecrypt, keys.iv);
    return out;
  }

  /// Decrypts lowercase hex ciphertext and returns the UTF-8 plaintext.
  ///
  /// Malformed hex, uppercase hex, a bad length (including empty input), bad
  /// padding and plaintext that is not valid UTF-8 all throw the same
  /// [SmxException]. CBC gives no integrity, so authenticate the ciphertext
  /// first. The UTF-8 check runs on the same bytes whether or not the padding
  /// is valid, but its duration still depends on the content; for binary
  /// data use [decryptBytes].
  String decrypt(String ciphertext) {
    final plain = _decryptAll(ciphertext);
    if (plain == null) throw const SmxException(_decryptError);
    // Valid padding bytes are themselves single-byte characters, so they do
    // not change the outcome of the UTF-8 check.
    final bad = _paddingIsBad(plain);
    final text = decodeUtf8OrNull(plain);
    if (bad != 0 || text == null) throw const SmxException(_decryptError);
    return text.substring(0, text.length - plain[plain.length - 1]);
  }

  /// Decrypts lowercase hex ciphertext and returns the plaintext bytes.
  ///
  /// Every failure throws the same [SmxException] as [decrypt].
  Uint8List decryptBytes(String ciphertext) {
    final plain = _decryptAll(ciphertext);
    if (plain == null || _paddingIsBad(plain) != 0) {
      throw const SmxException(_decryptError);
    }
    return Uint8List.sublistView(plain, 0, plain.length - plain.last);
  }

  @override
  String toString() => 'SM4()';
}
