/// Strict hexadecimal helpers shared by every algorithm.
///
/// Encoding and decoding work on code units with arithmetic only: no table is
/// indexed by a (possibly secret) digit and there is no per-character branch
/// on its value. Dart gives no constant-time guarantee, so this only removes
/// the obvious leaks.
library;

import 'dart:typed_data';

import 'errors.dart';

const _invalidHex = 'invalid hex string';

String _encode(List<int> data, int letterOffset) {
  final out = Uint8List(data.length * 2);
  for (var i = 0; i < data.length; i++) {
    final b = data[i];
    final hi = (b >> 4) & 0xF;
    final lo = b & 0xF;
    // (n + 6) >> 4 is 1 for n in 10..15 and 0 for 0..9.
    out[2 * i] = 0x30 + hi + ((hi + 6) >> 4) * letterOffset;
    out[2 * i + 1] = 0x30 + lo + ((lo + 6) >> 4) * letterOffset;
  }
  return String.fromCharCodes(out);
}

/// Encodes bytes as lowercase hex.
String bytesToHex(List<int> data) => _encode(data, 0x27);

/// Encodes bytes as uppercase hex.
String bytesToHexUpper(List<int> data) => _encode(data, 0x07);

/// Returns the value of one hex digit, or -1. Branch-free on the character;
/// [upper] is -1 to accept A-F as well, 0 otherwise.
int _digit(int c, int upper) {
  // ~((c - lo) | (hi - c)) >> 63 is all ones exactly when lo <= c <= hi.
  final isDigit = ~(((c - 0x30) | (0x39 - c)) >> 63);
  final isLower = ~(((c - 0x61) | (0x66 - c)) >> 63);
  final isUpper = ~(((c - 0x41) | (0x46 - c)) >> 63) & upper;
  final value =
      (isDigit & (c - 0x30)) | (isLower & (c - 0x57)) | (isUpper & (c - 0x37));
  final valid = isDigit | isLower | isUpper;
  return (valid & value) | ~valid;
}

Uint8List? _decode(String text, bool allowUpper) {
  final size = text.length;
  if (size.isOdd) return null;
  final upper = allowUpper ? -1 : 0;
  final out = Uint8List(size >> 1);
  var bad = 0;
  for (var i = 0, j = 0; i < out.length; i++, j += 2) {
    final hi = _digit(text.codeUnitAt(j), upper);
    final lo = _digit(text.codeUnitAt(j + 1), upper);
    bad |= hi | lo;
    out[i] = (hi << 4) | (lo & 0xF);
  }
  return bad < 0 ? null : out;
}

/// Decodes an even-length hex string of either case; no prefix or separators.
///
/// Throws [SmxException] for anything else.
Uint8List hexToBytes(String text) =>
    _decode(text, true) ?? (throw const SmxException(_invalidHex));

/// Decodes the canonical lowercase hex this library emits for signatures and
/// ciphertexts, so that each value has exactly one accepted spelling.
Uint8List lowercaseHexToBytes(String text) =>
    _decode(text, false) ?? (throw const SmxException(_invalidHex));

/// Like [hexToBytes], returning null instead of throwing.
Uint8List? tryHexToBytes(String text) => _decode(text, true);

/// Like [lowercaseHexToBytes], returning null instead of throwing.
Uint8List? tryLowercaseHexToBytes(String text) => _decode(text, false);

/// Parses a non-empty big-endian hex string of either case (no prefix).
BigInt hexToBigInt(String text) {
  if (text.isEmpty) throw const SmxException(_invalidHex);
  return bytesToBigInt(hexToBytes(text.length.isOdd ? '0$text' : text));
}

/// Big-endian unsigned bytes to an integer.
BigInt bytesToBigInt(List<int> bytes) {
  var v = BigInt.zero;
  for (var i = 0; i < bytes.length; i += 4) {
    var chunk = 0;
    var width = 0;
    for (var j = i; j < i + 4 && j < bytes.length; j++) {
      chunk = (chunk << 8) | bytes[j];
      width += 8;
    }
    v = (v << width) | BigInt.from(chunk);
  }
  return v;
}

/// An integer in [0, 2^(8 * length)) to big-endian bytes of exactly [length].
Uint8List bigIntToBytes(BigInt value, int length) {
  final out = Uint8List(length);
  var v = value;
  final mask = BigInt.from(0xFFFFFFFF);
  for (var i = length; i > 0; i -= 4) {
    var word = (v & mask).toInt();
    v >>= 32;
    for (var j = i - 1; j >= i - 4 && j >= 0; j--) {
      out[j] = word & 0xFF;
      word >>= 8;
    }
  }
  return out;
}
