import 'dart:typed_data';

import '../errors.dart';
import '../field/field.dart';
import '../hex.dart';
import 'curve.dart';

const int _coordSize = 32;
const int _encodedSize = 1 + 2 * _coordSize;

/// An immutable affine point on the SM2 curve, coordinates in [0, p-1].
///
/// Building a point does not check that it is on the curve, so that
/// [isOnCurve] can answer the question, but every arithmetic method does.
final class ECPoint {
  /// A finite point. Throws [SmxException] when a coordinate is not in [0, p).
  ECPoint(this.x, this.y) : infinity = false {
    if (x.isNegative || x >= curveP || y.isNegative || y >= curveP) {
      throw const SmxException('point coordinate is not in Fp');
    }
  }

  ECPoint._infinity()
      : x = BigInt.zero,
        y = BigInt.zero,
        infinity = true;

  final BigInt x;
  final BigInt y;
  final bool infinity;

  Uint32List? _limbs;
  bool? _onCurve;

  static final ECPoint _inf = ECPoint._infinity();
  static final ECPoint _g = ECPoint(curveGx, curveGy);

  /// The point at infinity.
  static ECPoint atInfinity() => _inf;

  /// The base point G.
  static ECPoint generator() => _g;

  /// Affine limbs (x, y) in Montgomery form. Only for finite points.
  Uint32List get limbs {
    final cached = _limbs;
    if (cached != null) return cached;
    final l = Uint32List(affSize);
    sm2Fp.setBigInt(l, 0, x);
    sm2Fp.setBigInt(l, _yOff, y);
    return _limbs = l;
  }

  static const int _yOff = 9;

  /// Builds a point from affine limbs (finite).
  static ECPoint fromLimbs(Uint32List l, int o) {
    final p = ECPoint(sm2Fp.toBigInt(l, o), sm2Fp.toBigInt(l, o + _yOff));
    p._limbs = Uint32List.fromList(l.sublist(o, o + affSize));
    p._onCurve = true;
    return p;
  }

  /// Converts a Jacobian result to a point (infinity included).
  static ECPoint fromJacobian(Uint32List jac) {
    final aff = Uint32List(affSize);
    if (!toAffine(aff, 0, jac, 0)) return _inf;
    return fromLimbs(aff, 0);
  }

  /// Decodes exactly `04 || x || y`; anything else, or an off-curve point,
  /// throws [SmxException].
  static ECPoint fromEncoded(List<int> data) {
    if (data.length != _encodedSize || data[0] != 0x04) {
      throw const SmxException('invalid point encoding');
    }
    final l = Uint32List(affSize);
    if (!sm2Fp.setBytes(l, 0, data, 1) ||
        !sm2Fp.setBytes(l, _yOff, data, 1 + _coordSize)) {
      throw const SmxException('point coordinate is not in Fp');
    }
    if (!isOnCurveLimbs(l, 0)) {
      throw const SmxException('point is not on the curve');
    }
    return fromLimbs(l, 0);
  }

  /// Decodes the 130-digit hex string of `04 || x || y` (either case).
  static ECPoint fromHexEncoded(String text) {
    if (text.length != 2 * _encodedSize) {
      throw const SmxException('invalid point encoding');
    }
    final bytes = tryHexToBytes(text);
    if (bytes == null) throw const SmxException('invalid point encoding');
    return fromEncoded(bytes);
  }

  /// `04 || x || y`, or a single 0x00 byte for infinity.
  Uint8List toEncoded() {
    if (infinity) return Uint8List(1);
    final out = Uint8List(_encodedSize);
    out[0] = 4;
    out.setRange(1, 33, xBytes());
    out.setRange(33, 65, yBytes());
    return out;
  }

  /// [toEncoded] as lowercase hex.
  String toHexEncoded() => bytesToHex(toEncoded());

  Uint8List xBytes() => bigIntToBytes(x, _coordSize);
  Uint8List yBytes() => bigIntToBytes(y, _coordSize);

  /// Checks y^2 = x^3 + ax + b; infinity counts as on the curve.
  bool isOnCurve() {
    if (infinity) return true;
    return _onCurve ??= isOnCurveLimbs(limbs, 0);
  }

  /// True for a finite point on the curve (every such point has order n).
  bool get isValidPublic => !infinity && isOnCurve();

  void _requireGroupElement() {
    if (!isOnCurve()) throw const SmxException('point is not on the curve');
  }

  ECPoint negate() {
    if (infinity) return this;
    return ECPoint(x, y == BigInt.zero ? y : curveP - y);
  }

  ECPoint add(ECPoint other) {
    _requireGroupElement();
    other._requireGroupElement();
    if (infinity) return other;
    if (other.infinity) return this;
    final jac = Uint32List(jacSize);
    setFromAffine(jac, 0, limbs, 0);
    jacAddAffine(jac, 0, other.limbs, 0);
    return fromJacobian(jac);
  }

  ECPoint subtract(ECPoint other) => add(other.negate());

  ECPoint twice() {
    _requireGroupElement();
    if (infinity) return this;
    final jac = Uint32List(jacSize);
    setFromAffine(jac, 0, limbs, 0);
    jacDouble(jac, 0);
    return fromJacobian(jac);
  }

  /// [k]P, treating k as secret (fixed window, masked lookups). k is reduced
  /// modulo n, since every finite on-curve point has the prime order n.
  ECPoint multiply(BigInt k) {
    if (k.isNegative) throw const SmxException('scalar must be non-negative');
    _requireGroupElement();
    if (k == BigInt.zero || infinity) return _inf;
    if (k == BigInt.one) return this;
    final reduced = k % curveN;
    if (reduced == BigInt.zero) return _inf;
    final jac = Uint32List(jacSize);
    if (x == curveGx && y == curveGy) {
      mulGenerator(jac, reduced);
    } else {
      mulPointWithTable(jac, limbs, 0, reduced, oddMultiples(limbs, 0));
    }
    return fromJacobian(jac);
  }

  @override
  bool operator ==(Object other) =>
      other is ECPoint &&
      other.infinity == infinity &&
      other.x == x &&
      other.y == y;

  @override
  int get hashCode => Object.hash(x, y, infinity);

  @override
  String toString() =>
      infinity ? 'ECPoint(infinity)' : 'ECPoint(${toHexEncoded()})';
}
