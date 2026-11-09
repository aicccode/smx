/// SM3 cryptographic hash (GB/T 32905-2016) and the GB/T 32918.4 KDF.
library;

import 'dart:typed_data';

import 'errors.dart';
import 'hex.dart';

const int _blockSize = 64;
const int _mask = 0xFFFFFFFF;

/// The padded length field holds 64 bits of bit length.
const int _maxMessageBytes = (1 << 61) - 1;

/// Largest KDF output: (2^32 - 1) blocks of 32 bytes.
const int _maxKdfBytes = 0xFFFFFFFF * 32;

const List<int> _iv = [
  0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, //
  0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
];

/// Tj rotated left by j mod 32, for j = 0..63.
final Uint32List _tj = () {
  final t = Uint32List(64);
  for (var j = 0; j < 64; j++) {
    final c = j < 16 ? 0x79CC4519 : 0x7A879D8A;
    final n = j % 32;
    t[j] = n == 0 ? c : ((c << n) | (c >> (32 - n))) & _mask;
  }
  return t;
}();

/// Message expansion scratch, reused by every compression (single isolate).
final Uint32List _w = Uint32List(68);

/// Compresses [blocks] 64-byte blocks of [data] starting at [offset] into
/// the eight-word state [v].
void _compress(Uint32List v, Uint8List data, int offset, int blocks) {
  final w = _w;
  final tj = _tj;
  var off = offset;
  for (var blk = 0; blk < blocks; blk++, off += _blockSize) {
    for (var i = 0; i < 16; i++) {
      final p = off + 4 * i;
      w[i] = (data[p] << 24) |
          (data[p + 1] << 16) |
          (data[p + 2] << 8) |
          data[p + 3];
    }
    for (var j = 16; j < 68; j++) {
      final r3 = w[j - 3];
      var x = w[j - 16] ^ w[j - 9] ^ (((r3 << 15) | (r3 >> 17)) & _mask);
      x = x ^
          (((x << 15) | (x >> 17)) & _mask) ^
          (((x << 23) | (x >> 9)) & _mask);
      final r13 = w[j - 13];
      w[j] = x ^ (((r13 << 7) | (r13 >> 25)) & _mask) ^ w[j - 6];
    }
    var a = v[0], b = v[1], c = v[2], d = v[3];
    var e = v[4], f = v[5], g = v[6], h = v[7];
    for (var j = 0; j < 16; j++) {
      final a12 = ((a << 12) | (a >> 20)) & _mask;
      final s = (a12 + e + tj[j]) & _mask;
      final ss1 = ((s << 7) | (s >> 25)) & _mask;
      final ss2 = ss1 ^ a12;
      final wj = w[j];
      final tt1 = ((a ^ b ^ c) + d + ss2 + (wj ^ w[j + 4])) & _mask;
      final tt2 = ((e ^ f ^ g) + h + ss1 + wj) & _mask;
      d = c;
      c = ((b << 9) | (b >> 23)) & _mask;
      b = a;
      a = tt1;
      h = g;
      g = ((f << 19) | (f >> 13)) & _mask;
      f = e;
      e = tt2 ^
          (((tt2 << 9) | (tt2 >> 23)) & _mask) ^
          (((tt2 << 17) | (tt2 >> 15)) & _mask);
    }
    for (var j = 16; j < 64; j++) {
      final a12 = ((a << 12) | (a >> 20)) & _mask;
      final s = (a12 + e + tj[j]) & _mask;
      final ss1 = ((s << 7) | (s >> 25)) & _mask;
      final ss2 = ss1 ^ a12;
      final wj = w[j];
      final tt1 =
          (((a & b) | ((a | b) & c)) + d + ss2 + (wj ^ w[j + 4])) & _mask;
      final tt2 = (((e & f) | (~e & g)) + h + ss1 + wj) & _mask;
      d = c;
      c = ((b << 9) | (b >> 23)) & _mask;
      b = a;
      a = tt1;
      h = g;
      g = ((f << 19) | (f >> 13)) & _mask;
      f = e;
      e = tt2 ^
          (((tt2 << 9) | (tt2 >> 23)) & _mask) ^
          (((tt2 << 17) | (tt2 >> 15)) & _mask);
    }
    v[0] ^= a;
    v[1] ^= b;
    v[2] ^= c;
    v[3] ^= d;
    v[4] ^= e;
    v[5] ^= f;
    v[6] ^= g;
    v[7] ^= h;
  }
}

/// Pads the unabsorbed [tail] (fewer than 64 bytes) of a [totalLength]-byte
/// message, compresses it into [state] and writes the digest to [out].
void _finishInto(Uint32List state, Uint8List tail, int tailLength,
    int totalLength, Uint8List out, int outOffset) {
  final blocks = tailLength < 56 ? 1 : 2;
  final pad = Uint8List(blocks * _blockSize);
  pad.setRange(0, tailLength, tail);
  pad[tailLength] = 0x80;
  final end = pad.length;
  // Bit length as 64 bits: high word from the top bits, low word masked.
  final high = (totalLength >> 29) & _mask;
  final low = (totalLength << 3) & _mask;
  pad[end - 8] = high >> 24;
  pad[end - 7] = (high >> 16) & 0xFF;
  pad[end - 6] = (high >> 8) & 0xFF;
  pad[end - 5] = high & 0xFF;
  pad[end - 4] = low >> 24;
  pad[end - 3] = (low >> 16) & 0xFF;
  pad[end - 2] = (low >> 8) & 0xFF;
  pad[end - 1] = low & 0xFF;
  _compress(state, pad, 0, blocks);
  for (var i = 0; i < 8; i++) {
    final x = state[i];
    final o = outOffset + 4 * i;
    out[o] = x >> 24;
    out[o + 1] = (x >> 16) & 0xFF;
    out[o + 2] = (x >> 8) & 0xFF;
    out[o + 3] = x & 0xFF;
  }
}

Uint8List _asUint8List(List<int> data) =>
    data is Uint8List ? data : Uint8List.fromList(data);

/// Returns the SM3 digest of a complete message.
///
/// The fast path for internal use: elements must already be bytes.
Uint8List sm3Digest(List<int> data) {
  final bytes = _asUint8List(data);
  final state = Uint32List.fromList(_iv);
  final full = bytes.length ~/ _blockSize;
  if (full > 0) _compress(state, bytes, 0, full);
  final tailStart = full * _blockSize;
  final tail = Uint8List.sublistView(bytes, tailStart);
  final out = Uint8List(32);
  _finishInto(state, tail, tail.length, bytes.length, out, 0);
  return out;
}

/// GB/T 32918.4 KDF: SM3(seed || ct) for 32-bit big-endian ct = 1, 2, ...,
/// concatenated and truncated to [length] bytes.
///
/// Throws [SmxException] when [length] is negative or above (2^32 - 1) * 32.
Uint8List sm3Kdf(List<int> seed, int length) {
  if (length < 0 || length > _maxKdfBytes) {
    throw const SmxException('KDF output too long');
  }
  final bytes = _asUint8List(seed);
  final out = Uint8List(length);
  if (length == 0) return out;
  // Only the block holding the counter changes: absorb the whole blocks once.
  final base = Uint32List.fromList(_iv);
  final full = bytes.length ~/ _blockSize;
  if (full > 0) _compress(base, bytes, 0, full);
  final tailLength = bytes.length - full * _blockSize + 4;
  final tail = Uint8List(tailLength + _blockSize);
  tail.setRange(0, tailLength - 4, bytes, full * _blockSize);
  final total = bytes.length + 4;
  final state = Uint32List(8);
  final block = Uint8List(32);
  final count = (length + 31) ~/ 32;
  for (var ct = 1; ct <= count; ct++) {
    tail[tailLength - 4] = (ct >> 24) & 0xFF;
    tail[tailLength - 3] = (ct >> 16) & 0xFF;
    tail[tailLength - 2] = (ct >> 8) & 0xFF;
    tail[tailLength - 1] = ct & 0xFF;
    state.setAll(0, base);
    if (tailLength >= _blockSize) {
      // The counter pushed the tail over a block boundary.
      _compress(state, tail, 0, 1);
      final rest = Uint8List.sublistView(tail, _blockSize, tailLength);
      _finishInto(state, rest, rest.length, total, block, 0);
    } else {
      _finishInto(state, tail, tailLength, total, block, 0);
    }
    final start = (ct - 1) * 32;
    final n = length - start < 32 ? length - start : 32;
    out.setRange(start, start + n, block);
  }
  return out;
}

/// Incremental SM3 hash; the instance resets itself after [finish].
///
/// Call [finish] once per message and read the digest before the next
/// update. Reading a digest that does not belong to the data fed so far
/// throws [SmxException], and so does a second [finish] with no update in
/// between. To hash an empty message on a used instance, call `update([])`
/// first.
class SM3 {
  /// Creates a hash with no data.
  SM3();

  final Uint32List _state = Uint32List.fromList(_iv);
  final Uint8List _buffer = Uint8List(_blockSize);
  int _buffered = 0;
  int _length = 0;
  Uint8List? _digest;

  /// Feeds bytes into the hash.
  ///
  /// Throws [SmxException], leaving the state unchanged, when an element is
  /// not a byte (0-255) or the total would exceed 2^61 - 1 bytes.
  SM3 update(List<int> data) {
    final Uint8List bytes;
    if (data is Uint8List) {
      bytes = data;
    } else {
      var bad = 0;
      for (var i = 0; i < data.length; i++) {
        bad |= data[i] & ~0xFF;
      }
      if (bad != 0) {
        throw const SmxException('data must contain only bytes (0-255)');
      }
      bytes = Uint8List.fromList(data);
    }
    final size = bytes.length;
    if (size > _maxMessageBytes - _length) {
      throw const SmxException('message too long for SM3');
    }
    _length += size;
    _digest = null;
    var start = 0;
    if (_buffered > 0) {
      final need = _blockSize - _buffered;
      if (size < need) {
        _buffer.setRange(_buffered, _buffered + size, bytes);
        _buffered += size;
        return this;
      }
      _buffer.setRange(_buffered, _blockSize, bytes);
      _compress(_state, _buffer, 0, 1);
      _buffered = 0;
      start = need;
    }
    final blocks = (size - start) ~/ _blockSize;
    if (blocks > 0) _compress(_state, bytes, start, blocks);
    final end = start + blocks * _blockSize;
    if (end < size) {
      _buffer.setRange(0, size - end, bytes, end);
      _buffered = size - end;
    }
    return this;
  }

  /// Feeds a single byte (0-255) into the hash.
  SM3 updateByte(int value) {
    if (value < 0 || value > 0xFF) {
      throw const SmxException('value must be a byte (0-255)');
    }
    if (_length + 1 > _maxMessageBytes) {
      throw const SmxException('message too long for SM3');
    }
    _buffer[_buffered++] = value;
    _length++;
    _digest = null;
    if (_buffered == _blockSize) {
      _compress(_state, _buffer, 0, 1);
      _buffered = 0;
    }
    return this;
  }

  /// Applies the padding, stores the digest and resets for reuse.
  SM3 finish() {
    if (_digest != null) {
      throw const SmxException(
          'already finished; update before finishing again');
    }
    final out = Uint8List(32);
    _finishInto(_state, _buffer, _buffered, _length, out, 0);
    _digest = out;
    _state.setAll(0, _iv);
    _buffer.fillRange(0, _blockSize, 0);
    _buffered = 0;
    _length = 0;
    return this;
  }

  /// Returns a copy of the 32-byte digest computed by the last [finish].
  Uint8List hashBytes() {
    final digest = _digest;
    if (digest == null) {
      throw const SmxException(
          'no digest: finish has not been called since the last update');
    }
    return Uint8List.fromList(digest);
  }

  /// Returns the last digest as an uppercase hex string.
  String hashHexUpper() => bytesToHexUpper(hashBytes());

  /// Returns the last digest as a lowercase hex string.
  String hashHex() => bytesToHex(hashBytes());
}
