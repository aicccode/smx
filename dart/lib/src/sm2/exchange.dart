/// SM2 key exchange (GB/T 32918.3) with the optional confirmation values.
library;

import 'dart:typed_data';

import '../bytes.dart';
import '../errors.dart';
import '../hex.dart';
import '../sm3.dart';
import 'curve.dart';
import 'point.dart';
import 'sm2.dart';

const int _tagSb = 0x02;
const int _tagSa = 0x03;
const int _maxExchangeKeyBytes = 1 << 20;
final BigInt _twoPowW = BigInt.one << 127;
final BigInt _wMask = _twoPowW - BigInt.one;

/// Result of one side of the key exchange.
///
/// [toString] does not show the shared keys or the shared point.
final class SM2KeySwapParams {
  const SM2KeySwapParams({
    this.sa = '',
    this.sb = '',
    this.ka = '',
    this.kb = '',
    this.v,
    Uint8List? za,
    Uint8List? zb,
    this.success = false,
    this.message = '',
  })  : _za = za,
        _zb = zb;

  /// A's confirmation value (64 lowercase hex digits), from [sm2GetSa].
  final String sa;

  /// B's confirmation value (64 lowercase hex digits), from [sm2GetSb].
  final String sb;

  /// A's shared key as lowercase hex. Secret.
  final String ka;

  /// B's shared key as lowercase hex. Secret.
  final String kb;

  /// B's shared point V, kept for [sm2CheckSa]. Secret.
  final ECPoint? v;

  final Uint8List? _za;
  final Uint8List? _zb;

  /// Z of A and B (32 bytes each), kept for [sm2CheckSa].
  Uint8List get za => Uint8List.fromList(_za ?? const <int>[]);
  Uint8List get zb => Uint8List.fromList(_zb ?? const <int>[]);

  final bool success;

  /// Why the step failed; empty on success.
  final String message;

  @override
  String toString() =>
      'SM2KeySwapParams(success: $success, message: $message, sa: $sa, sb: $sb)';
}

BigInt _calcX(BigInt x) => _twoPowW + (x & _wMask);

/// [t](P + [xBar]R); xBar and both points are public, only t is secret.
ECPoint _calcPoint(BigInt t, BigInt xBar, ECPoint p, ECPoint r) {
  final jac = Uint32List(jacSize);
  mulPublic(jac, oddMultiples(r.limbs, 0), xBar);
  jacAddAffine(jac, 0, p.limbs, 0);
  final base = ECPoint.fromJacobian(jac);
  return base.multiply(t);
}

Uint8List _createS(
    int tag, ECPoint vu, List<int> za, List<int> zb, ECPoint rA, ECPoint rB) {
  final inner = sm3Digest(concatBytes([
    vu.xBytes(),
    za,
    zb,
    rA.xBytes(),
    rA.yBytes(),
    rB.xBytes(),
    rB.yBytes(),
  ]));
  return sm3Digest(concatBytes([
    [tag],
    vu.yBytes(),
    inner,
  ]));
}

void _requireKeyLength(int byteLen) {
  if (byteLen < 1 || byteLen > _maxExchangeKeyBytes) {
    throw const SmxException('key length must be between 1 and 1048576');
  }
}

(Uint8List, Uint8List)? _encodeIds(String idA, String idB) {
  try {
    return (encodeUserId(idA), encodeUserId(idB));
  } on SmxException {
    return null;
  }
}

Uint8List? _hashValue(List<int> value) {
  if (value.length != 32) return null;
  try {
    return requireBytes(value, 'value');
  } on SmxException {
    return null;
  }
}

String? _checkPoints(List<(String, ECPoint)> points) {
  for (final (name, point) in points) {
    if (!point.isValidPublic) return '$name point is not on curve';
  }
  return null;
}

/// Responder B: computes the shared key Kb and the confirmation value Sb.
///
/// A key length outside 1 to 1 MiB throws [SmxException]. Every other invalid
/// input returns a result with `success == false`.
SM2KeySwapParams sm2GetSb(
  int byteLen,
  ECPoint pA,
  ECPoint rA,
  ECPoint pB,
  BigInt dB,
  ECPoint rB,
  BigInt rb,
  String idA,
  String idB,
) {
  _requireKeyLength(byteLen);
  final bad = _checkPoints([('PA', pA), ('RA', rA), ('PB', pB), ('RB', rB)]);
  if (bad != null) return SM2KeySwapParams(message: bad);
  if (!isPrivateScalar(dB) || !isPrivateScalar(rb)) {
    return const SM2KeySwapParams(message: 'private key out of range');
  }
  final ids = _encodeIds(idA, idB);
  if (ids == null) return const SM2KeySwapParams(message: 'invalid user id');

  final tb = (dB + _calcX(rB.x) * rb) % curveN;
  final v = _calcPoint(tb, _calcX(rA.x), pA, rA);
  if (v.infinity) {
    return const SM2KeySwapParams(message: 'V is point at infinity');
  }
  final za = userSm3Z(ids.$1, pA);
  final zb = userSm3Z(ids.$2, pB);
  final kb = sm3Kdf(concatBytes([v.xBytes(), v.yBytes(), za, zb]), byteLen);
  final sb = _createS(_tagSb, v, za, zb, rA, rB);
  return SM2KeySwapParams(
    sb: bytesToHex(sb),
    kb: bytesToHex(kb),
    v: v,
    za: za,
    zb: zb,
    success: true,
  );
}

/// Initiator A: verifies B's Sb, then computes the shared key Ka and Sa.
///
/// A key length outside 1 to 1 MiB throws [SmxException]. Every other invalid
/// input returns a result with `success == false`.
SM2KeySwapParams sm2GetSa(
  int byteLen,
  ECPoint pB,
  ECPoint rB,
  ECPoint pA,
  BigInt dA,
  ECPoint rA,
  BigInt ra,
  String idA,
  String idB,
  List<int> sb,
) {
  _requireKeyLength(byteLen);
  final bad = _checkPoints([('PB', pB), ('RB', rB), ('PA', pA), ('RA', rA)]);
  if (bad != null) return SM2KeySwapParams(message: bad);
  if (!isPrivateScalar(dA) || !isPrivateScalar(ra)) {
    return const SM2KeySwapParams(message: 'private key out of range');
  }
  final ids = _encodeIds(idA, idB);
  if (ids == null) return const SM2KeySwapParams(message: 'invalid user id');
  const mismatch = "B's verification value does not match";
  final sbBytes = _hashValue(sb);
  if (sbBytes == null) return const SM2KeySwapParams(message: mismatch);

  final ta = (dA + _calcX(rA.x) * ra) % curveN;
  final u = _calcPoint(ta, _calcX(rB.x), pB, rB);
  if (u.infinity) {
    return const SM2KeySwapParams(message: 'U is point at infinity');
  }
  final za = userSm3Z(ids.$1, pA);
  final zb = userSm3Z(ids.$2, pB);
  if (!constantTimeEquals(_createS(_tagSb, u, za, zb, rA, rB), sbBytes)) {
    return const SM2KeySwapParams(message: mismatch);
  }
  final ka = sm3Kdf(concatBytes([u.xBytes(), u.yBytes(), za, zb]), byteLen);
  final sa = _createS(_tagSa, u, za, zb, rA, rB);
  return SM2KeySwapParams(
      sa: bytesToHex(sa), ka: bytesToHex(ka), success: true);
}

/// B's final step: checks A's Sa. Invalid input returns false.
bool sm2CheckSa(ECPoint v, List<int> za, List<int> zb, ECPoint rA, ECPoint rB,
    List<int> sa) {
  final zaBytes = _hashValue(za);
  final zbBytes = _hashValue(zb);
  final saBytes = _hashValue(sa);
  if (zaBytes == null ||
      zbBytes == null ||
      saBytes == null ||
      !v.isValidPublic ||
      !rA.isValidPublic ||
      !rB.isValidPublic) {
    return false;
  }
  return constantTimeEquals(
      _createS(_tagSa, v, zaBytes, zbBytes, rA, rB), saBytes);
}
