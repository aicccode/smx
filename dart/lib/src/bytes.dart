import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';

/// Compares two byte lists in time that depends only on their lengths.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Returns true when every byte is zero, reading every byte.
bool isAllZero(List<int> data) {
  var acc = 0;
  for (var i = 0; i < data.length; i++) {
    acc |= data[i];
  }
  return acc == 0;
}

/// Concatenates byte lists.
Uint8List concatBytes(List<List<int>> parts) {
  var size = 0;
  for (final p in parts) {
    size += p.length;
  }
  final out = Uint8List(size);
  var offset = 0;
  for (final p in parts) {
    out.setRange(offset, offset + p.length, p);
    offset += p.length;
  }
  return out;
}

/// Copies [data] into a new Uint8List, rejecting values outside 0..255.
///
/// Throws [SmxException] naming [what] for an element that is not a byte.
Uint8List requireBytes(List<int> data, String what) {
  if (data is Uint8List) return Uint8List.fromList(data);
  var bad = 0;
  for (var i = 0; i < data.length; i++) {
    bad |= data[i] & ~0xFF;
  }
  if (bad != 0) throw SmxException('$what must contain only bytes (0-255)');
  return Uint8List.fromList(data);
}

/// Encodes a string as UTF-8, rejecting unpaired surrogates.
///
/// Dart's own encoder silently replaces them with U+FFFD, which would change
/// the data that is signed or encrypted.
Uint8List encodeUtf8Strict(String text, String what) {
  for (var i = 0; i < text.length; i++) {
    final c = text.codeUnitAt(i);
    if (c & 0xF800 != 0xD800) continue;
    final isHigh = c < 0xDC00;
    final nextIsLow =
        i + 1 < text.length && (text.codeUnitAt(i + 1) & 0xFC00) == 0xDC00;
    if (!isHigh || !nextIsLow) {
      throw SmxException('$what is not valid text');
    }
    i++;
  }
  return utf8.encode(text);
}

/// Decodes strict UTF-8, or returns null. The exception, which quotes the
/// data, never leaves this function.
String? decodeUtf8OrNull(List<int> data) {
  try {
    return utf8.decode(data);
  } on FormatException {
    return null;
  }
}
