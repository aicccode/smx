// Benchmarks for SM2, SM3, SM4 and SM9, mirroring the other languages.
//
//   dart run benchmark/bench.dart [--rounds=N] [--ms=N] [--only=regex] [--json]
//
// For AOT numbers: dart compile exe benchmark/bench.dart -o bench && ./bench
// Each item reports the best of N rounds; each round runs for --ms milliseconds.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:smx/smx.dart';

late final int rounds;
late final int roundMs;
RegExp? only;
final results = <Map<String, Object>>[];
var jsonOut = false;

void bench(String name, void Function() fn, {int bytes = 0}) {
  if (only != null && !only!.hasMatch(name)) return;
  // Warm up so the JIT has compiled the hot paths.
  final warm = Stopwatch()..start();
  while (warm.elapsedMilliseconds < roundMs ~/ 2) {
    fn();
  }
  var best = 0.0;
  for (var r = 0; r < rounds; r++) {
    final sw = Stopwatch()..start();
    var n = 0;
    while (sw.elapsedMicroseconds < roundMs * 1000) {
      fn();
      n++;
    }
    final ops = n * 1e6 / sw.elapsedMicroseconds;
    if (ops > best) best = ops;
  }
  results.add({'name': name, 'opsPerSec': best, 'bytes': bytes});
  if (!jsonOut) {
    final us = 1e6 / best;
    final mb =
        bytes > 0 ? '  ${(best * bytes / 1e6).toStringAsFixed(1)} MB/s' : '';
    stdout
        .writeln('${name.padRight(26)} ${best.toStringAsFixed(1).padLeft(12)} '
            'ops/s ${us.toStringAsFixed(2).padLeft(12)} us/op$mb');
  }
}

int _flag(List<String> args, String name, int fallback) {
  for (final a in args) {
    if (a.startsWith('--$name='))
      return int.parse(a.substring(name.length + 3));
  }
  return fallback;
}

void main(List<String> args) {
  rounds = _flag(args, 'rounds', 5);
  roundMs = _flag(args, 'ms', 300);
  jsonOut = args.contains('--json');
  for (final a in args) {
    if (a.startsWith('--only=')) only = RegExp(a.substring(7));
  }

  // SM3
  for (final (label, size) in [('64B', 64), ('1KB', 1024), ('1MB', 1 << 20)]) {
    final data = Uint8List(size);
    for (var i = 0; i < size; i++) {
      data[i] = i & 0xFF;
    }
    bench('sm3 $label', () => SM3().update(data).finish(), bytes: size);
  }

  // SM4-CBC: string interface, as the other languages measure it.
  final key = hexToBytes('0123456789abcdeffedcba9876543210');
  final iv = hexToBytes('00112233445566778899aabbccddeeff');
  bench('sm4 key schedule', () => SM4().setKey(key, iv));
  for (final (label, size) in [
    ('16B', 15),
    ('1KB', 1023),
    ('1MB', (1 << 20) - 1)
  ]) {
    final text = 'a' * size;
    final sm4 = SM4()..setKey(key, iv);
    final cipher = sm4.encrypt(text);
    bench('sm4 encrypt $label', () => sm4.encrypt(text), bytes: size + 1);
    bench('sm4 decrypt $label', () => sm4.decrypt(cipher), bytes: size + 1);
  }

  // SM2
  const d = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
  final pub = sm2GetPublicKey(hexToBigInt(d)).toHexEncoded();
  const msg = 'message digest';
  const id = '1234567812345678';
  final sig = sm2Sign(id, msg, d);
  final plain32 = 'x' * 32;
  final cipher = sm2Encrypt(plain32, pub);
  bench('sm2 keygen', sm2GenKeyPair);
  bench('sm2 sign', () => sm2Sign(id, msg, d));
  bench('sm2 verify', () => sm2Verify(id, sig, msg, pub));
  bench('sm2 encrypt 32B', () => sm2Encrypt(plain32, pub));
  bench('sm2 decrypt 32B', () => sm2Decrypt(cipher, d));
  final dA = hexToBigInt(
      '6fcba2ef9ae0ab902bc3bde3ff915d44ba4cc78f88e2f8e7f8996d3b8cceedee');
  final dB = hexToBigInt(
      '5e35d7d3f3c54dbac72e61819e730b019a84208ca3a35e4c2e353dfccb2a3b53');
  final pA = sm2GetPublicKey(dA), pB = sm2GetPublicKey(dB);
  bench('sm2 key exchange', () {
    // Both sides, including the ephemeral keys, as the other languages do.
    final ra = sm2GenKeyPair(), rb = sm2GenKeyPair();
    final raInt = hexToBigInt(ra.privateKey),
        rbInt = hexToBigInt(rb.privateKey);
    final bigRa = sm2DecodePoint(ra.publicKey);
    final bigRb = sm2DecodePoint(rb.publicKey);
    final b = sm2GetSb(16, pA, bigRa, pB, dB, bigRb, rbInt, 'alice', 'bob');
    final a = sm2GetSa(
        16, pB, bigRb, pA, dA, bigRa, raInt, 'alice', 'bob', hexToBytes(b.sb));
    if (!sm2CheckSa(b.v!, b.za, b.zb, bigRa, bigRb, hexToBytes(a.sa))) {
      throw StateError('key exchange failed');
    }
  });

  // SM9
  final signMaster = sm9GenSignMasterKey();
  final signUser = sm9GenSignUserKey(signMaster.privateKey, 'alice');
  final encMaster = sm9GenEncMasterKey();
  final encUser = sm9GenEncUserKey(encMaster.privateKey, 'bob');
  final message = utf8.encode('Chinese IBS standard');
  final sm9Sig = sm9Sign(message, signUser, signMaster.publicKey);
  final plain = Uint8List(32);
  final sm9Cipher = sm9Encrypt(plain, 'bob', encMaster.publicKey);
  bench('sm9 sign', () => sm9Sign(message, signUser, signMaster.publicKey));
  bench('sm9 verify',
      () => sm9Verify(message, sm9Sig, 'alice', signMaster.publicKey));
  bench('sm9 encrypt 32B', () => sm9Encrypt(plain, 'bob', encMaster.publicKey));
  bench('sm9 decrypt 32B', () => sm9Decrypt(sm9Cipher, 'bob', encUser));
  final kxA = sm9GenEncUserKey(encMaster.privateKey, 'alice', hid: 2);
  final kxB = sm9GenEncUserKey(encMaster.privateKey, 'bob', hid: 2);
  bench('sm9 key exchange', () {
    final master = encMaster.publicKey;
    final initA = sm9ExchangeInit('bob', master);
    final initB = sm9ExchangeInit('alice', master);
    final b = sm9ExchangeRespond(
        16, 'alice', 'bob', master, kxB, initB.r, initB.bigR, initA.bigR);
    final a = sm9ExchangeConfirm(
        16, 'alice', 'bob', master, kxA, initA.r, initA.bigR, initB.bigR, b.sB);
    if (!sm9ExchangeCheck(b.s2, a.sA)) throw StateError('key exchange failed');
  });

  if (jsonOut) stdout.writeln(jsonEncode(results));
}
