/// Shared SM9 pieces: hash functions, input parsing and the per-master-key
/// caches of public values.
library;

import 'dart:typed_data';

import '../bytes.dart';
import '../errors.dart';
import '../hex.dart';
import '../key_cache.dart';
import '../random.dart';
import '../sm3.dart';
import 'g1.dart';
import 'g2.dart';
import 'gt_table.dart';
import 'pairing.dart';
import 'params.dart';
import 'tower.dart';

/// Default hid for signing keys.
const int sm9HidSign = 0x01;

/// Default hid for key exchange keys.
const int sm9HidExchange = 0x02;

/// Default hid for encryption and KEM keys.
const int sm9HidEncrypt = 0x03;

const int maxKeyBytes = 1 << 20;
const int maxKdfBytes = 0xFFFFFFFF * 32;
final BigInt _nMinusOne = sm9N - BigInt.one;

/// A random scalar in [1, N-1] from the platform CSPRNG.
BigInt sm9RandomScalar() => randomScalar(sm9N);

/// H(tag, Z) of GB/T 38635.2: 40 bytes of SM3 output reduced to [1, N-1].
BigInt hashToRange(int tag, List<int> z) {
  final first = sm3Digest(concatBytes([
    [tag],
    z,
    [0, 0, 0, 1],
  ]));
  final second = sm3Digest(concatBytes([
    [tag],
    z,
    [0, 0, 0, 2],
  ]));
  final ha = bytesToBigInt(concatBytes([first, second.sublist(0, 8)]));
  return ha % _nMinusOne + BigInt.one;
}

BigInt h1(List<int> z) => hashToRange(1, z);
BigInt h2(List<int> z) => hashToRange(2, z);

/// Rejects a hid outside 0..255.
void requireHid(int hid) {
  if (hid < 0 || hid > 255) {
    throw const SmxException('hid must be a byte (0-255)');
  }
}

Uint8List encodeId(String id) => encodeUtf8Strict(id, 'user id');

/// Parses a scalar: exactly 64 hex digits (either case) in [1, N-1].
BigInt? tryParseScalar(String text) {
  if (text.length != 64) return null;
  final bytes = tryHexToBytes(text);
  if (bytes == null) return null;
  final v = bytesToBigInt(bytes);
  return v >= BigInt.one && v < sm9N ? v : null;
}

BigInt parseScalar(String text, String what) =>
    tryParseScalar(text) ?? (throw SmxException('invalid $what'));

/// Parses a G1 point (130 hex digits, either case) or returns null.
Uint32List? tryParseG1(String text, {bool lowercase = false}) {
  if (text.length != 130) return null;
  final bytes = lowercase ? tryLowercaseHexToBytes(text) : tryHexToBytes(text);
  return bytes == null ? null : g1Decode(bytes);
}

/// Parses a G2 point (258 hex digits, either case) or returns null.
Uint32List? tryParseG2(String text) {
  if (text.length != 258) return null;
  final bytes = tryHexToBytes(text);
  return bytes == null ? null : g2Decode(bytes);
}

// SM3 digest of a user private key -> whether it passed the subgroup check.
// Only a one-way digest and a boolean are kept, never the key.
final KeyCache<String, bool> _checkedUserKeys = KeyCache(64);

/// Parses a G2 user private key (258 hex digits, either case) or returns
/// null. The subgroup check, the costly part, is remembered per key when the
/// key caches are on.
Uint32List? tryParseUserKey(String text) {
  if (text.length != 258) return null;
  final bytes = tryHexToBytes(text);
  if (bytes == null) return null;
  final q = g2DecodeOnCurve(bytes);
  if (q == null) return null;
  final ok = _checkedUserKeys.lookup(
      bytesToHex(sm3Digest(bytes)), () => g2InSubgroup(q, 0));
  return ok ? q : null;
}

String scalarHex(BigInt v) => bytesToHex(bigIntToBytes(v, 32));

/// Inverts a secret value modulo N without showing it to modInverse.
BigInt invertModN(BigInt value) {
  final blind = sm9RandomScalar();
  return blind * ((value * blind) % sm9N).modInverse(sm9N) % sm9N;
}

/// A decoded signing master public key and its pairing value g = e(P1, Ppub-s).
final class SignMaster {
  SignMaster(this.point);
  final Uint32List point;
  Uint32List? _g;
  GtTable? _table;

  Uint32List get g => _g ??= pairing(p1Affine, 0, point, 0);

  /// g^e for a secret e.
  Uint32List pow(BigInt e) => _powFixed(this, e);
}

/// A decoded encryption master public key and g = e(Ppub-e, P2).
final class EncMaster {
  EncMaster(this.point);
  final Uint32List point;
  Uint32List? _g;
  GtTable? _table;

  Uint32List get g => _g ??= pairing(point, 0, p2Affine, 0);

  /// g^e for a secret e.
  Uint32List pow(BigInt e) => _powFixedEnc(this, e);
}

Uint32List _powFixed(SignMaster m, BigInt e) {
  if (!keyCacheEnabled) return gtPowSecret(m.g, e);
  return (m._table ??= GtTable(m.g)).pow(e);
}

Uint32List _powFixedEnc(EncMaster m, BigInt e) {
  if (!keyCacheEnabled) return gtPowSecret(m.g, e);
  return (m._table ??= GtTable(m.g)).pow(e);
}

final KeyCache<String, SignMaster?> _signMasters = KeyCache(16);
final KeyCache<String, EncMaster?> _encMasters = KeyCache(16);

/// Decodes a signing master public key (G2), or returns null. Decoding and
/// the pairing value are cached per key when the key caches are on.
SignMaster? trySignMaster(String text) {
  final key = text.toLowerCase();
  final cached = _signMasters.lookup(key, () {
    final point = tryParseG2(text);
    return point == null ? null : SignMaster(point);
  });
  return cached;
}

/// Decodes an encryption master public key (G1), or returns null.
EncMaster? tryEncMaster(String text) {
  final key = text.toLowerCase();
  return _encMasters.lookup(key, () {
    final point = tryParseG1(text);
    return point == null ? null : EncMaster(point);
  });
}

SignMaster signMaster(String text) =>
    trySignMaster(text) ??
    (throw const SmxException('invalid master public key'));

EncMaster encMaster(String text) =>
    tryEncMaster(text) ??
    (throw const SmxException('invalid master public key'));

/// Q = [H1(ID || hid)]P1 + Ppub-e (public values; variable time).
Uint32List? userEncPoint(List<int> id, int hid, Uint32List ppubE) {
  final h = h1(concatBytes([
    id,
    [hid],
  ]));
  final jac = Uint32List(g1Jac);
  g1MulP1(jac, h, secret: false);
  g1Add(jac, 0, ppubE, 0);
  final out = Uint32List(g1Aff);
  return g1ToAffine(out, 0, jac, 0) ? out : null;
}

/// e(P, Q), or 1 when either point is the identity (null).
Uint32List pairingOrOne(Uint32List? p, Uint32List? q) {
  if (p == null || q == null) {
    final one = Uint32List(f12);
    f12One(one, 0);
    return one;
  }
  return pairing(p, 0, q, 0);
}
