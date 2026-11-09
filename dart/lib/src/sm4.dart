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
/// **This SM4 has no secret-indexed table lookups.** The S-box is evaluated as a
/// Boolean circuit (see `sm4_sbox_circuit.g.dart`), so neither the key schedule
/// nor the block function reads memory at key- or data-dependent addresses. The
/// Dart VM gives no formal constant-time guarantee.
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'errors.dart';
import 'hex.dart';
import 'sm4_sbox_circuit.g.dart';

const int _mask = 0xFFFFFFFF;
const int _blockSize = 16;
const String _decryptError = 'decryption failed';

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

/// Round function T: S-box circuit, then L(B) = B ^ B<<<2 ^ B<<<10 ^ B<<<18 ^ B<<<24.
@pragma('vm:prefer-inline')
int _roundT(int x) {
  final b = sm4SboxWord(x);
  return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24);
}

/// Key schedule T': S-box circuit, then L'(B) = B ^ B<<<13 ^ B<<<23.
@pragma('vm:prefer-inline')
int _keyT(int x) {
  final b = sm4SboxWord(x);
  return b ^ _rotl(b, 13) ^ _rotl(b, 23);
}

int _word(List<int> b, int o) =>
    (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3];

/// Expands a 16-byte key into 32 round keys.
Uint32List _expandKey(List<int> key) {
  var a = _word(key, 0) ^ _fk[0];
  var b = _word(key, 4) ^ _fk[1];
  var c = _word(key, 8) ^ _fk[2];
  var d = _word(key, 12) ^ _fk[3];
  final rk = Uint32List(32);
  for (var i = 0; i < 32; i += 4) {
    var x = b ^ c ^ d ^ _ck[i];
    a ^= _keyT(x);
    x = c ^ d ^ a ^ _ck[i + 1];
    b ^= _keyT(x);
    x = d ^ a ^ b ^ _ck[i + 2];
    c ^= _keyT(x);
    x = a ^ b ^ c ^ _ck[i + 3];
    d ^= _keyT(x);
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
      a ^= _roundT(x);
      x = c ^ d ^ a ^ rk[i + 1];
      b ^= _roundT(x);
      x = d ^ a ^ b ^ rk[i + 2];
      c ^= _roundT(x);
      x = a ^ b ^ c ^ rk[i + 3];
      d ^= _roundT(x);
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
