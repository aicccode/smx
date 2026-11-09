/// SM9 key generation and digital signatures (GB/T 38635.2).
library;

import 'dart:typed_data';

import '../bytes.dart';
import '../errors.dart';
import '../hex.dart';
import 'common.dart';
import 'g1.dart';
import 'g2.dart';
import 'params.dart';
import 'tower.dart';

const int _maxRetries = 128;

/// A master key pair. [toString] does not show the private key.
final class SM9MasterKeyPair {
  const SM9MasterKeyPair(this.privateKey, this.publicKey);

  /// The master private key: 64 lowercase hex digits.
  final String privateKey;

  /// The master public key: a G2 point (signing) or G1 point (encryption) as
  /// lowercase hex.
  final String publicKey;

  @override
  String toString() => 'SM9MasterKeyPair(publicKey: $publicKey)';
}

String _g2Hex(Uint32List p) => bytesToHex(g2Encode(p, 0));
String _g1Hex(Uint32List p) => bytesToHex(g1Encode(p, 0));

/// Generates a signing master key pair: ks in [1, N-1], Ppub-s = [ks]P2.
SM9MasterKeyPair sm9GenSignMasterKey() {
  final ks = sm9RandomScalar();
  return SM9MasterKeyPair(scalarHex(ks), _g2Hex(g2MulP2Secret(ks)));
}

/// The signing master public key [ks]P2 of a master private key.
String sm9SignMasterPublicKey(String masterPrivateKey) {
  final ks = parseScalar(masterPrivateKey, 'master private key');
  return _g2Hex(g2MulP2Secret(ks));
}

/// t2 = s * (H1(ID || hid) + s)^-1 mod N; throws when t1 = 0.
BigInt _userScalar(BigInt s, String userId, int hid) {
  requireHid(hid);
  final t1 = (h1(concatBytes([
            encodeId(userId),
            [hid],
          ])) +
          s) %
      sm9N;
  if (t1 == BigInt.zero) {
    throw const SmxException(
        'user key generation failed; generate a new master key');
  }
  return s * invertModN(t1) % sm9N;
}

/// The signing user private key ds = [ks * t1^-1]P1 (a G1 point, hex).
String sm9GenSignUserKey(String masterPrivateKey, String userId,
    {int hid = sm9HidSign}) {
  final ks = parseScalar(masterPrivateKey, 'master private key');
  final t2 = _userScalar(ks, userId, hid);
  return _g1Hex(g1MulP1Secret(t2));
}

/// Generates an encryption master key pair: ke in [1, N-1], Ppub-e = [ke]P1.
SM9MasterKeyPair sm9GenEncMasterKey() {
  final ke = sm9RandomScalar();
  return SM9MasterKeyPair(scalarHex(ke), _g1Hex(g1MulP1Secret(ke)));
}

/// The encryption master public key [ke]P1 of a master private key.
String sm9EncMasterPublicKey(String masterPrivateKey) {
  final ke = parseScalar(masterPrivateKey, 'master private key');
  return _g1Hex(g1MulP1Secret(ke));
}

/// The encryption (and key exchange) user private key de = [ke * t1^-1]P2
/// (a G2 point, hex). Use hid 0x02 for key exchange keys.
String sm9GenEncUserKey(String masterPrivateKey, String userId,
    {int hid = sm9HidEncrypt}) {
  final ke = parseScalar(masterPrivateKey, 'master private key');
  final t2 = _userScalar(ke, userId, hid);
  return _g2Hex(g2MulP2Secret(t2));
}

// ---------------------------------------------------------------- signatures

/// Signs a message; returns `h || S` (97 bytes) as lowercase hex.
///
/// The signer's identity is bound into the user private key, so it is not
/// an argument here.
String sm9Sign(
    List<int> message, String userPrivateKey, String masterPublicKey) {
  final msg = requireBytes(message, 'message');
  final ds = tryParseG1(userPrivateKey) ??
      (throw const SmxException('invalid user private key'));
  final master = signMaster(masterPublicKey);
  final table = g1OddMultiples(ds, 0);
  for (var i = 0; i < _maxRetries; i++) {
    final s = _signWith(msg, ds, table, master, sm9RandomScalar());
    if (s != null) return s;
  }
  throw const SmxException('signing failed');
}

String? _signWith(Uint8List msg, Uint32List ds, Uint32List table,
    SignMaster master, BigInt r) {
  final w = master.pow(r);
  final h = h2(concatBytes([msg, f12ToBytes(w, 0)]));
  final l = (r - h) % sm9N;
  if (l == BigInt.zero) return null;
  final s = g1MulSecretAffine(ds, l, table)!;
  return '${scalarHex(h)}${_g1Hex(s)}';
}

/// Signing with a given r; null when r must be replaced. Internal, for
/// known-answer tests.
String? sm9SignWithR(List<int> message, String userPrivateKey,
    String masterPublicKey, BigInt r) {
  final ds = tryParseG1(userPrivateKey)!;
  return _signWith(requireBytes(message, 'message'), ds, g1OddMultiples(ds, 0),
      signMaster(masterPublicKey), r);
}

/// Verifies a signature. Any invalid input returns false.
bool sm9Verify(
    List<int> message, String signature, String userId, String masterPublicKey,
    {int hid = sm9HidSign}) {
  if (hid < 0 || hid > 255 || signature.length != 194) return false;
  final Uint8List msg, id;
  try {
    msg = requireBytes(message, 'message');
    id = encodeId(userId);
  } on SmxException {
    return false;
  }
  final hBytes = tryLowercaseHexToBytes(signature.substring(0, 64));
  if (hBytes == null) return false;
  final h = bytesToBigInt(hBytes);
  if (h < BigInt.one || h >= sm9N) return false;
  final s = tryParseG1(signature.substring(64), lowercase: true);
  if (s == null) return false;
  final master = trySignMaster(masterPublicKey);
  if (master == null) return false;

  final t = master.pow(h);
  final h1v = h1(concatBytes([
    id,
    [hid],
  ]));
  final jac = Uint32List(g2Jac);
  g2MulP2(jac, h1v, secret: false);
  g2Add(jac, 0, master.point, 0);
  final p = Uint32List(g2Aff);
  final u = pairingOrOne(s, g2ToAffine(p, 0, jac, 0) ? p : null);
  f12Mul(u, 0, u, 0, t, 0);
  return h2(concatBytes([msg, f12ToBytes(u, 0)])) == h;
}
