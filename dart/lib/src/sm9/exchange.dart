/// SM9 key exchange with confirmation (GB/T 38635.2).
///
/// A (initiator, ID_A) and B (responder, ID_B) each call [sm9ExchangeInit]
/// with the other's identity and send R. B calls [sm9ExchangeRespond] and
/// sends S_B; A calls [sm9ExchangeConfirm], which checks S_B before releasing
/// the key, and sends S_A; B finishes with [sm9ExchangeCheck].
library;

import 'dart:typed_data';

import '../bytes.dart';
import '../errors.dart';
import '../hex.dart';
import '../sm3.dart';
import 'common.dart';
import 'g1.dart';
import 'pairing.dart';
import 'tower.dart';

const int _maxRetries = 128;

/// The ephemeral pair from [sm9ExchangeInit]. [toString] does not show r.
final class SM9ExchangeInit {
  const SM9ExchangeInit(this.r, this.bigR);

  /// The ephemeral private value r: 64 lowercase hex digits. Secret.
  final String r;

  /// R = [r]Q_peer, a G1 point as lowercase hex; send it to the peer.
  final String bigR;

  @override
  String toString() => 'SM9ExchangeInit(R: $bigR)';
}

/// The result of [sm9ExchangeRespond] or [sm9ExchangeConfirm].
///
/// [toString] does not show the shared key.
final class SM9ExchangeResult {
  const SM9ExchangeResult({
    this.success = false,
    this.message = '',
    this.sharedKey = '',
    this.sB = '',
    this.s2 = '',
    this.sA = '',
  });

  final bool success;

  /// Why the step failed; empty on success.
  final String message;

  /// The shared key as lowercase hex. Secret.
  final String sharedKey;

  /// B's confirmation value, sent to A (respond only).
  final String sB;

  /// The value B expects from A, kept for [sm9ExchangeCheck] (respond only).
  final String s2;

  /// A's confirmation value, sent to B (confirm only).
  final String sA;

  @override
  String toString() => 'SM9ExchangeResult(success: $success, '
      'message: $message, sB: $sB, sA: $sA)';
}

void _requireKeyLen(int keyLen) {
  if (keyLen < 1 || keyLen > maxKeyBytes) {
    throw const SmxException('key length must be between 1 and 1048576');
  }
}

/// Starts the exchange: R = [r]Q_peer with Q_peer = [H1(ID_peer || hid)]P1
/// + Ppub-e and a fresh random r.
SM9ExchangeInit sm9ExchangeInit(String peerId, String masterPublicKey,
    {int hid = sm9HidExchange}) {
  requireHid(hid);
  final id = encodeId(peerId);
  final master = encMaster(masterPublicKey);
  final q = userEncPoint(id, hid, master.point) ??
      (throw const SmxException('invalid master public key'));
  final table = g1OddMultiples(q, 0);
  for (var i = 0; i < _maxRetries; i++) {
    final r = sm9RandomScalar();
    final big = g1MulSecretAffine(q, r, table);
    if (big != null) {
      return SM9ExchangeInit(scalarHex(r), bytesToHex(g1Encode(big, 0)));
    }
  }
  throw const SmxException('key exchange failed');
}

/// [sm9ExchangeInit] with a given r. Internal, for known-answer tests.
SM9ExchangeInit sm9ExchangeInitWithR(
    String peerId, String masterPublicKey, BigInt r,
    {int hid = sm9HidExchange}) {
  final master = encMaster(masterPublicKey);
  final q = userEncPoint(encodeId(peerId), hid, master.point)!;
  final big = g1MulSecretAffine(q, r, g1OddMultiples(q, 0))!;
  return SM9ExchangeInit(scalarHex(r), bytesToHex(g1Encode(big, 0)));
}

final class _Inputs {
  _Inputs(
      this.idA, this.idB, this.master, this.de, this.r, this.ownR, this.peerR);
  final Uint8List idA, idB;
  final EncMaster master;
  final Uint32List de;
  final BigInt r;
  final Uint32List ownR, peerR;
}

/// Parses the common inputs, or returns the failure message.
Object _parse(String idA, String idB, String masterPublicKey,
    String userPrivateKey, String r, String ownR, String peerR) {
  final Uint8List a, b;
  try {
    a = encodeId(idA);
    b = encodeId(idB);
  } on SmxException {
    return 'invalid user id';
  }
  final master = tryEncMaster(masterPublicKey);
  if (master == null) return 'invalid master public key';
  final de = tryParseUserKey(userPrivateKey);
  if (de == null) return 'invalid user private key';
  final rv = tryParseScalar(r);
  if (rv == null) return 'invalid ephemeral private key';
  final own = tryParseG1(ownR);
  if (own == null) return 'invalid own ephemeral point';
  final peer = tryParseG1(peerR);
  if (peer == null) return "invalid peer's ephemeral point";
  return _Inputs(a, b, master, de, rv, own, peer);
}

/// (g1, g2, g3) as bytes, plus the shared key and the inner hash.
(Uint8List, Uint8List) _derive(_Inputs x, Uint32List ra, Uint32List rb,
    Uint32List g1, Uint32List g2, Uint32List g3, int keyLen) {
  final g1b = f12ToBytes(g1, 0), g2b = f12ToBytes(g2, 0);
  final g3b = f12ToBytes(g3, 0);
  final tail = concatBytes([x.idA, x.idB, g1Xy(ra, 0), g1Xy(rb, 0)]);
  final key = sm3Kdf(concatBytes([tail, g1b, g2b, g3b]), keyLen);
  final inner = sm3Digest(concatBytes([g2b, g3b, tail]));
  return (key, concatBytes([g1b, inner]));
}

Uint8List _confirmation(int tag, Uint8List g1AndInner) =>
    sm3Digest(concatBytes([
      [tag],
      g1AndInner,
    ]));

/// Responder B: computes the shared key, S_B (to send) and S_2 (expected
/// from A). [rB] and [bigRB] come from B's own [sm9ExchangeInit].
///
/// A key length outside 1 to 1 MiB throws [SmxException]; any other invalid
/// input returns `success == false`.
SM9ExchangeResult sm9ExchangeRespond(
  int keyLen,
  String idA,
  String idB,
  String masterPublicKey,
  String userPrivateKeyB,
  String rB,
  String bigRB,
  String bigRA,
) {
  _requireKeyLen(keyLen);
  final parsed =
      _parse(idA, idB, masterPublicKey, userPrivateKeyB, rB, bigRB, bigRA);
  if (parsed is String) return SM9ExchangeResult(message: parsed);
  final x = parsed as _Inputs;
  final g1 = pairing(x.peerR, 0, x.de, 0);
  final g2 = x.master.pow(x.r);
  final g3 = gtPowSecret(g1, x.r);
  final (key, inner) = _derive(x, x.peerR, x.ownR, g1, g2, g3, keyLen);
  return SM9ExchangeResult(
    success: true,
    sharedKey: bytesToHex(key),
    sB: bytesToHex(_confirmation(0x82, inner)),
    s2: bytesToHex(_confirmation(0x83, inner)),
  );
}

/// Initiator A: checks S_B (in constant time), then computes the shared key
/// and S_A. [rA] and [bigRA] come from A's own [sm9ExchangeInit].
///
/// A key length outside 1 to 1 MiB throws [SmxException]; any other invalid
/// input, or an S_B that does not match, returns `success == false`.
SM9ExchangeResult sm9ExchangeConfirm(
  int keyLen,
  String idA,
  String idB,
  String masterPublicKey,
  String userPrivateKeyA,
  String rA,
  String bigRA,
  String bigRB,
  String sB,
) {
  _requireKeyLen(keyLen);
  final parsed =
      _parse(idA, idB, masterPublicKey, userPrivateKeyA, rA, bigRA, bigRB);
  if (parsed is String) return SM9ExchangeResult(message: parsed);
  final x = parsed as _Inputs;
  const mismatch = "B's confirmation value does not match";
  final sbBytes = sB.length == 64 ? tryLowercaseHexToBytes(sB) : null;
  if (sbBytes == null) return const SM9ExchangeResult(message: mismatch);
  final g1 = x.master.pow(x.r);
  final g2 = pairing(x.peerR, 0, x.de, 0);
  final g3 = gtPowSecret(g2, x.r);
  final (key, inner) = _derive(x, x.ownR, x.peerR, g1, g2, g3, keyLen);
  if (!constantTimeEquals(_confirmation(0x82, inner), sbBytes)) {
    return const SM9ExchangeResult(message: mismatch);
  }
  return SM9ExchangeResult(
    success: true,
    sharedKey: bytesToHex(key),
    sA: bytesToHex(_confirmation(0x83, inner)),
  );
}

/// B's final step: compares S_2 from [sm9ExchangeRespond] with A's S_A in
/// constant time. Both must be 64 lowercase hex digits; anything else is
/// false.
bool sm9ExchangeCheck(String s2, String sA) {
  if (s2.length != 64 || sA.length != 64) return false;
  final a = tryLowercaseHexToBytes(s2), b = tryLowercaseHexToBytes(sA);
  if (a == null || b == null) return false;
  return constantTimeEquals(a, b);
}
