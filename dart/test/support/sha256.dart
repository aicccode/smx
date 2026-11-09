/// A small SHA-256 (FIPS 180-4) for tests only: it rebuilds the deterministic
/// inputs and digests used by the shared known-answer vectors.
library;

import 'dart:convert';
import 'dart:typed_data';

const _k = <int>[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, //
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF;

/// SHA-256 of [data].
Uint8List sha256(List<int> data) {
  final h = Uint32List.fromList([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  final padLen = ((data.length + 9 + 63) ~/ 64) * 64;
  final msg = Uint8List(padLen)..setRange(0, data.length, data);
  msg[data.length] = 0x80;
  final bits = data.length * 8;
  for (var i = 0; i < 8; i++) {
    msg[padLen - 1 - i] = (bits >> (8 * i)) & 0xFF;
  }
  final w = Uint32List(64);
  for (var o = 0; o < padLen; o += 64) {
    for (var i = 0; i < 16; i++) {
      w[i] = (msg[o + 4 * i] << 24) |
          (msg[o + 4 * i + 1] << 16) |
          (msg[o + 4 * i + 2] << 8) |
          msg[o + 4 * i + 3];
    }
    for (var i = 16; i < 64; i++) {
      final s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      final s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    var a = h[0], b = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];
    for (var i = 0; i < 64; i++) {
      final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      final ch = (e & f) ^ (~e & g & 0xFFFFFFFF);
      final t1 = (hh + s1 + ch + _k[i] + w[i]) & 0xFFFFFFFF;
      final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = (s0 + maj) & 0xFFFFFFFF;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) & 0xFFFFFFFF;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & 0xFFFFFFFF;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }
  final out = Uint8List(32);
  for (var i = 0; i < 8; i++) {
    out[4 * i] = h[i] >> 24;
    out[4 * i + 1] = h[i] >> 16;
    out[4 * i + 2] = h[i] >> 8;
    out[4 * i + 3] = h[i];
  }
  return out;
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// Lowercase hex SHA-256 of [data].
String sha256Hex(List<int> data) => _hex(sha256(data));

/// Deterministic test bytes, the same function that produced the vectors:
/// SHA-256(label || 4-byte big-endian counter) for counters 0, 1, ...
Uint8List det(int length, [String label = 'kat']) {
  final out = BytesBuilder();
  var counter = 0;
  final l = utf8.encode(label);
  while (out.length < length) {
    out.add(sha256([
      ...l,
      (counter >> 24) & 0xFF,
      (counter >> 16) & 0xFF,
      (counter >> 8) & 0xFF,
      counter & 0xFF,
    ]));
    counter++;
  }
  return Uint8List.sublistView(out.toBytes(), 0, length);
}

/// Lowercase hex of bytes (independent of the library's encoder).
String hexOf(List<int> b) => _hex(b);
