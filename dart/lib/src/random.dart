import 'dart:math';
import 'dart:typed_data';

import 'errors.dart';
import 'hex.dart';

Random? _secure;

Random _source() {
  // Random.secure() throws UnsupportedError when the platform has no secure
  // source. That error propagates; no weaker source is ever tried.
  return _secure ??= Random.secure();
}

/// Returns [length] bytes from the platform CSPRNG.
Uint8List secureRandomBytes(int length) {
  final rng = _source();
  final out = Uint8List(length);
  var i = 0;
  while (i + 4 <= length) {
    final v = rng.nextInt(0x100000000);
    out[i] = v >> 24;
    out[i + 1] = (v >> 16) & 0xFF;
    out[i + 2] = (v >> 8) & 0xFF;
    out[i + 3] = v & 0xFF;
    i += 4;
  }
  for (; i < length; i++) {
    out[i] = rng.nextInt(256);
  }
  return out;
}

const _maxRetries = 128;

/// Returns a uniform integer in [1, n - 1] by rejection sampling, with no
/// modulo bias. [n] must be below 2^256.
BigInt randomScalar(BigInt n) {
  final limit = n - BigInt.one;
  final topBits = n.bitLength - 248; // bits used in the first byte
  final topMask = (1 << topBits) - 1;
  for (var i = 0; i < _maxRetries; i++) {
    final bytes = secureRandomBytes(32);
    bytes[0] &= topMask;
    final v = bytesToBigInt(bytes);
    if (v < limit) return v + BigInt.one;
  }
  throw const SmxException('random number generation failed');
}
