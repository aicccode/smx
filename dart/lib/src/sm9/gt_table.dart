/// Fixed-base exponentiation in GT for a long-lived public base g.
library;

import 'dart:typed_data';

import '../field/field.dart';
import 'tower.dart';

const int _rows = 64; // 4-bit digits of a 256-bit exponent
const int _entries = 16;

/// Row i holds g^(j * 16^i) for j = 0..15 (about 440 KB), built on creation.
///
/// [pow] multiplies one entry per row, each read through masks over the whole
/// row, so its schedule does not depend on the exponent: 63 multiplications
/// instead of 252 squarings and 63 multiplications.
final class GtTable {
  GtTable(Uint32List g) : _table = Uint32List(_rows * _entries * f12) {
    final base = Uint32List.fromList(g);
    for (var row = 0; row < _rows; row++) {
      final o = row * _entries * f12;
      f12One(_table, o);
      _table.setRange(o + f12, o + 2 * f12, base);
      for (var j = 2; j < _entries; j++) {
        f12Mul(_table, o + j * f12, _table, o + (j - 1) * f12, base, 0);
      }
      // next base = g^(16^(row+1)) = (g^(15 * 16^row)) * g^(16^row)
      f12Mul(base, 0, _table, o + (_entries - 1) * f12, base, 0);
    }
  }

  final Uint32List _table;

  /// g^e for a secret e in [0, 2^256).
  Uint32List pow(BigInt e) {
    final acc = Uint32List(f12), sel = Uint32List(f12);
    var v = e;
    final m = BigInt.from(15);
    for (var row = 0; row < _rows; row++) {
      final digit = (v & m).toInt();
      v >>= 4;
      sel.fillRange(0, f12, 0);
      final o = row * _entries * f12;
      for (var j = 0; j < _entries; j++) {
        final mask = eqMask(j, digit);
        final base = o + j * f12;
        for (var k = 0; k < f12; k++) {
          sel[k] |= _table[base + k] & mask;
        }
      }
      if (row == 0) {
        acc.setRange(0, f12, sel);
      } else {
        f12Mul(acc, 0, acc, 0, sel, 0);
      }
    }
    return acc;
  }
}
