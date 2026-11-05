package site.aicc.sm2.ec;

import java.math.BigInteger;

/**
 * Arithmetic in the SM2 prime field, p = 2^256 - 2^224 - 2^96 + 2^64 - 1.
 *
 * <p>Values are {@code int[8]}, little-endian 32-bit limbs, always fully reduced to [0, p). Every
 * operation runs in time independent of the operand values: carries are handled arithmetically and
 * results are chosen with masks. The JVM gives no formal guarantee about this, but no operation has
 * a value-dependent branch or memory access at the bytecode level.
 *
 * <p>Java 8 has no 64x64-bit wide multiply, so limbs are 32 bits and products are computed in
 * {@code long}. {@code mul} and {@code sqr} are unrolled and keep every limb in a local variable,
 * which removes array bounds checks from the hottest code of the library.
 */
final class Sm2Field {
  static final BigInteger P_BIG =
      new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);

  private static final long M = 0xFFFFFFFFL;

  private Sm2Field() {}

  /** Sets {@code r = a * b mod p}; r may alias a or b. */
  static void mul(int[] r, int[] a, int[] b) {
    long a0 = a[0] & M;
    long a1 = a[1] & M;
    long a2 = a[2] & M;
    long a3 = a[3] & M;
    long a4 = a[4] & M;
    long a5 = a[5] & M;
    long a6 = a[6] & M;
    long a7 = a[7] & M;
    long b0 = b[0] & M;
    long b1 = b[1] & M;
    long b2 = b[2] & M;
    long b3 = b[3] & M;
    long b4 = b[4] & M;
    long b5 = b[5] & M;
    long b6 = b[6] & M;
    long b7 = b[7] & M;
    long m;
    m = a0 * b0;
    long z0 = m & M;
    m = (m >>> 32) + a1 * b0;
    long z1 = m & M;
    m = (m >>> 32) + a2 * b0;
    long z2 = m & M;
    m = (m >>> 32) + a3 * b0;
    long z3 = m & M;
    m = (m >>> 32) + a4 * b0;
    long z4 = m & M;
    m = (m >>> 32) + a5 * b0;
    long z5 = m & M;
    m = (m >>> 32) + a6 * b0;
    long z6 = m & M;
    m = (m >>> 32) + a7 * b0;
    long z7 = m & M;
    long z8 = m >>> 32;
    m = a0 * b1 + z1;
    z1 = m & M;
    m = (m >>> 32) + a1 * b1 + z2;
    z2 = m & M;
    m = (m >>> 32) + a2 * b1 + z3;
    z3 = m & M;
    m = (m >>> 32) + a3 * b1 + z4;
    z4 = m & M;
    m = (m >>> 32) + a4 * b1 + z5;
    z5 = m & M;
    m = (m >>> 32) + a5 * b1 + z6;
    z6 = m & M;
    m = (m >>> 32) + a6 * b1 + z7;
    z7 = m & M;
    m = (m >>> 32) + a7 * b1 + z8;
    z8 = m & M;
    long z9 = m >>> 32;
    m = a0 * b2 + z2;
    z2 = m & M;
    m = (m >>> 32) + a1 * b2 + z3;
    z3 = m & M;
    m = (m >>> 32) + a2 * b2 + z4;
    z4 = m & M;
    m = (m >>> 32) + a3 * b2 + z5;
    z5 = m & M;
    m = (m >>> 32) + a4 * b2 + z6;
    z6 = m & M;
    m = (m >>> 32) + a5 * b2 + z7;
    z7 = m & M;
    m = (m >>> 32) + a6 * b2 + z8;
    z8 = m & M;
    m = (m >>> 32) + a7 * b2 + z9;
    z9 = m & M;
    long z10 = m >>> 32;
    m = a0 * b3 + z3;
    z3 = m & M;
    m = (m >>> 32) + a1 * b3 + z4;
    z4 = m & M;
    m = (m >>> 32) + a2 * b3 + z5;
    z5 = m & M;
    m = (m >>> 32) + a3 * b3 + z6;
    z6 = m & M;
    m = (m >>> 32) + a4 * b3 + z7;
    z7 = m & M;
    m = (m >>> 32) + a5 * b3 + z8;
    z8 = m & M;
    m = (m >>> 32) + a6 * b3 + z9;
    z9 = m & M;
    m = (m >>> 32) + a7 * b3 + z10;
    z10 = m & M;
    long z11 = m >>> 32;
    m = a0 * b4 + z4;
    z4 = m & M;
    m = (m >>> 32) + a1 * b4 + z5;
    z5 = m & M;
    m = (m >>> 32) + a2 * b4 + z6;
    z6 = m & M;
    m = (m >>> 32) + a3 * b4 + z7;
    z7 = m & M;
    m = (m >>> 32) + a4 * b4 + z8;
    z8 = m & M;
    m = (m >>> 32) + a5 * b4 + z9;
    z9 = m & M;
    m = (m >>> 32) + a6 * b4 + z10;
    z10 = m & M;
    m = (m >>> 32) + a7 * b4 + z11;
    z11 = m & M;
    long z12 = m >>> 32;
    m = a0 * b5 + z5;
    z5 = m & M;
    m = (m >>> 32) + a1 * b5 + z6;
    z6 = m & M;
    m = (m >>> 32) + a2 * b5 + z7;
    z7 = m & M;
    m = (m >>> 32) + a3 * b5 + z8;
    z8 = m & M;
    m = (m >>> 32) + a4 * b5 + z9;
    z9 = m & M;
    m = (m >>> 32) + a5 * b5 + z10;
    z10 = m & M;
    m = (m >>> 32) + a6 * b5 + z11;
    z11 = m & M;
    m = (m >>> 32) + a7 * b5 + z12;
    z12 = m & M;
    long z13 = m >>> 32;
    m = a0 * b6 + z6;
    z6 = m & M;
    m = (m >>> 32) + a1 * b6 + z7;
    z7 = m & M;
    m = (m >>> 32) + a2 * b6 + z8;
    z8 = m & M;
    m = (m >>> 32) + a3 * b6 + z9;
    z9 = m & M;
    m = (m >>> 32) + a4 * b6 + z10;
    z10 = m & M;
    m = (m >>> 32) + a5 * b6 + z11;
    z11 = m & M;
    m = (m >>> 32) + a6 * b6 + z12;
    z12 = m & M;
    m = (m >>> 32) + a7 * b6 + z13;
    z13 = m & M;
    long z14 = m >>> 32;
    m = a0 * b7 + z7;
    z7 = m & M;
    m = (m >>> 32) + a1 * b7 + z8;
    z8 = m & M;
    m = (m >>> 32) + a2 * b7 + z9;
    z9 = m & M;
    m = (m >>> 32) + a3 * b7 + z10;
    z10 = m & M;
    m = (m >>> 32) + a4 * b7 + z11;
    z11 = m & M;
    m = (m >>> 32) + a5 * b7 + z12;
    z12 = m & M;
    m = (m >>> 32) + a6 * b7 + z13;
    z13 = m & M;
    m = (m >>> 32) + a7 * b7 + z14;
    z14 = m & M;
    long z15 = m >>> 32;
    // Solinas reduction: 2^256 = 2^224 + 2^96 - 2^64 + 1 (mod p).
    long c = z0 + z8 + z9 + z10 + z11 + z12 + (z13 << 1) + (z14 << 1) + (z15 << 1);
    long v0 = c & M;
    c = (c >> 32) + z1 + z9 + z10 + z11 + z12 + z13 + (z14 << 1) + (z15 << 1);
    long v1 = c & M;
    c = (c >> 32) + z2 - z8 - z9 - z13 - z14;
    long v2 = c & M;
    c = (c >> 32) + z3 + z8 + z11 + z12 + (z13 << 1) + z14 + z15;
    long v3 = c & M;
    c = (c >> 32) + z4 + z9 + z12 + z13 + (z14 << 1) + z15;
    long v4 = c & M;
    c = (c >> 32) + z5 + z10 + z13 + z14 + (z15 << 1);
    long v5 = c & M;
    c = (c >> 32) + z6 + z11 + z14 + z15;
    long v6 = c & M;
    c = (c >> 32) + z7 + z8 + z9 + z10 + z11 + (z12 << 1) + (z13 << 1) + (z14 << 1) + 3 * z15;
    long v7 = c & M;
    // Fold the signed top carry twice, then subtract p once; all without branches.
    long top = c >> 32;
    c = v0 + top;
    v0 = c & M;
    c = (c >> 32) + v1;
    v1 = c & M;
    c = (c >> 32) + v2 - top;
    v2 = c & M;
    c = (c >> 32) + v3 + top;
    v3 = c & M;
    c = (c >> 32) + v4;
    v4 = c & M;
    c = (c >> 32) + v5;
    v5 = c & M;
    c = (c >> 32) + v6;
    v6 = c & M;
    c = (c >> 32) + v7 + top;
    v7 = c & M;
    top = c >> 32;
    c = v0 + top;
    v0 = c & M;
    c = (c >> 32) + v1;
    v1 = c & M;
    c = (c >> 32) + v2 - top;
    v2 = c & M;
    c = (c >> 32) + v3 + top;
    v3 = c & M;
    c = (c >> 32) + v4;
    v4 = c & M;
    c = (c >> 32) + v5;
    v5 = c & M;
    c = (c >> 32) + v6;
    v6 = c & M;
    c = (c >> 32) + v7 + top;
    v7 = c & M;
    top = c >> 32;
    // v + (2^256 - p) carries out exactly when v >= p.
    c = v0 + 1;
    long w0 = c & M;
    c = (c >> 32) + v1;
    long w1 = c & M;
    c = (c >> 32) + v2 - 1;
    long w2 = c & M;
    c = (c >> 32) + v3 + 1;
    long w3 = c & M;
    c = (c >> 32) + v4;
    long w4 = c & M;
    c = (c >> 32) + v5;
    long w5 = c & M;
    c = (c >> 32) + v6;
    long w6 = c & M;
    c = (c >> 32) + v7 + 1;
    long w7 = c & M;
    int keep = (int) (c >> 32) - 1;
    r[0] = ((int) v0 & keep) | ((int) w0 & ~keep);
    r[1] = ((int) v1 & keep) | ((int) w1 & ~keep);
    r[2] = ((int) v2 & keep) | ((int) w2 & ~keep);
    r[3] = ((int) v3 & keep) | ((int) w3 & ~keep);
    r[4] = ((int) v4 & keep) | ((int) w4 & ~keep);
    r[5] = ((int) v5 & keep) | ((int) w5 & ~keep);
    r[6] = ((int) v6 & keep) | ((int) w6 & ~keep);
    r[7] = ((int) v7 & keep) | ((int) w7 & ~keep);
  }

  /** Sets {@code r = a * a mod p}; r may alias a. */
  static void sqr(int[] r, int[] a) {
    long a0 = a[0] & M;
    long a1 = a[1] & M;
    long a2 = a[2] & M;
    long a3 = a[3] & M;
    long a4 = a[4] & M;
    long a5 = a[5] & M;
    long a6 = a[6] & M;
    long a7 = a[7] & M;
    long m;
    m = a1 * a0;
    long z1x = m & M;
    m = (m >>> 32) + a2 * a0;
    long z2x = m & M;
    m = (m >>> 32) + a3 * a0;
    long z3x = m & M;
    m = (m >>> 32) + a4 * a0;
    long z4x = m & M;
    m = (m >>> 32) + a5 * a0;
    long z5x = m & M;
    m = (m >>> 32) + a6 * a0;
    long z6x = m & M;
    m = (m >>> 32) + a7 * a0;
    long z7x = m & M;
    long z8x = m >>> 32;
    m = a2 * a1 + z3x;
    z3x = m & M;
    m = (m >>> 32) + a3 * a1 + z4x;
    z4x = m & M;
    m = (m >>> 32) + a4 * a1 + z5x;
    z5x = m & M;
    m = (m >>> 32) + a5 * a1 + z6x;
    z6x = m & M;
    m = (m >>> 32) + a6 * a1 + z7x;
    z7x = m & M;
    m = (m >>> 32) + a7 * a1 + z8x;
    z8x = m & M;
    long z9x = m >>> 32;
    m = a3 * a2 + z5x;
    z5x = m & M;
    m = (m >>> 32) + a4 * a2 + z6x;
    z6x = m & M;
    m = (m >>> 32) + a5 * a2 + z7x;
    z7x = m & M;
    m = (m >>> 32) + a6 * a2 + z8x;
    z8x = m & M;
    m = (m >>> 32) + a7 * a2 + z9x;
    z9x = m & M;
    long z10x = m >>> 32;
    m = a4 * a3 + z7x;
    z7x = m & M;
    m = (m >>> 32) + a5 * a3 + z8x;
    z8x = m & M;
    m = (m >>> 32) + a6 * a3 + z9x;
    z9x = m & M;
    m = (m >>> 32) + a7 * a3 + z10x;
    z10x = m & M;
    long z11x = m >>> 32;
    m = a5 * a4 + z9x;
    z9x = m & M;
    m = (m >>> 32) + a6 * a4 + z10x;
    z10x = m & M;
    m = (m >>> 32) + a7 * a4 + z11x;
    z11x = m & M;
    long z12x = m >>> 32;
    m = a6 * a5 + z11x;
    z11x = m & M;
    m = (m >>> 32) + a7 * a5 + z12x;
    z12x = m & M;
    long z13x = m >>> 32;
    m = a7 * a6 + z13x;
    z13x = m & M;
    long z14x = m >>> 32;
    m = a0 * a0;
    long z0 = m & M;
    long d = m >>> 32;
    long c1 = d + (z1x << 1);
    long z1 = c1 & M;
    d = c1 >>> 32;
    m = a1 * a1;
    long sq1h = m >>> 32;
    long c2 = d + (z2x << 1) + (m & M);
    long z2 = c2 & M;
    d = c2 >>> 32;
    long c3 = d + (z3x << 1) + sq1h;
    long z3 = c3 & M;
    d = c3 >>> 32;
    m = a2 * a2;
    long sq2h = m >>> 32;
    long c4 = d + (z4x << 1) + (m & M);
    long z4 = c4 & M;
    d = c4 >>> 32;
    long c5 = d + (z5x << 1) + sq2h;
    long z5 = c5 & M;
    d = c5 >>> 32;
    m = a3 * a3;
    long sq3h = m >>> 32;
    long c6 = d + (z6x << 1) + (m & M);
    long z6 = c6 & M;
    d = c6 >>> 32;
    long c7 = d + (z7x << 1) + sq3h;
    long z7 = c7 & M;
    d = c7 >>> 32;
    m = a4 * a4;
    long sq4h = m >>> 32;
    long c8 = d + (z8x << 1) + (m & M);
    long z8 = c8 & M;
    d = c8 >>> 32;
    long c9 = d + (z9x << 1) + sq4h;
    long z9 = c9 & M;
    d = c9 >>> 32;
    m = a5 * a5;
    long sq5h = m >>> 32;
    long c10 = d + (z10x << 1) + (m & M);
    long z10 = c10 & M;
    d = c10 >>> 32;
    long c11 = d + (z11x << 1) + sq5h;
    long z11 = c11 & M;
    d = c11 >>> 32;
    m = a6 * a6;
    long sq6h = m >>> 32;
    long c12 = d + (z12x << 1) + (m & M);
    long z12 = c12 & M;
    d = c12 >>> 32;
    long c13 = d + (z13x << 1) + sq6h;
    long z13 = c13 & M;
    d = c13 >>> 32;
    m = a7 * a7;
    long sq7h = m >>> 32;
    long c14 = d + (z14x << 1) + (m & M);
    long z14 = c14 & M;
    d = c14 >>> 32;
    long c15 = d + 0 + sq7h;
    long z15 = c15 & M;
    d = c15 >>> 32;
    // Solinas reduction: 2^256 = 2^224 + 2^96 - 2^64 + 1 (mod p).
    long c = z0 + z8 + z9 + z10 + z11 + z12 + (z13 << 1) + (z14 << 1) + (z15 << 1);
    long v0 = c & M;
    c = (c >> 32) + z1 + z9 + z10 + z11 + z12 + z13 + (z14 << 1) + (z15 << 1);
    long v1 = c & M;
    c = (c >> 32) + z2 - z8 - z9 - z13 - z14;
    long v2 = c & M;
    c = (c >> 32) + z3 + z8 + z11 + z12 + (z13 << 1) + z14 + z15;
    long v3 = c & M;
    c = (c >> 32) + z4 + z9 + z12 + z13 + (z14 << 1) + z15;
    long v4 = c & M;
    c = (c >> 32) + z5 + z10 + z13 + z14 + (z15 << 1);
    long v5 = c & M;
    c = (c >> 32) + z6 + z11 + z14 + z15;
    long v6 = c & M;
    c = (c >> 32) + z7 + z8 + z9 + z10 + z11 + (z12 << 1) + (z13 << 1) + (z14 << 1) + 3 * z15;
    long v7 = c & M;
    // Fold the signed top carry twice, then subtract p once; all without branches.
    long top = c >> 32;
    c = v0 + top;
    v0 = c & M;
    c = (c >> 32) + v1;
    v1 = c & M;
    c = (c >> 32) + v2 - top;
    v2 = c & M;
    c = (c >> 32) + v3 + top;
    v3 = c & M;
    c = (c >> 32) + v4;
    v4 = c & M;
    c = (c >> 32) + v5;
    v5 = c & M;
    c = (c >> 32) + v6;
    v6 = c & M;
    c = (c >> 32) + v7 + top;
    v7 = c & M;
    top = c >> 32;
    c = v0 + top;
    v0 = c & M;
    c = (c >> 32) + v1;
    v1 = c & M;
    c = (c >> 32) + v2 - top;
    v2 = c & M;
    c = (c >> 32) + v3 + top;
    v3 = c & M;
    c = (c >> 32) + v4;
    v4 = c & M;
    c = (c >> 32) + v5;
    v5 = c & M;
    c = (c >> 32) + v6;
    v6 = c & M;
    c = (c >> 32) + v7 + top;
    v7 = c & M;
    top = c >> 32;
    // v + (2^256 - p) carries out exactly when v >= p.
    c = v0 + 1;
    long w0 = c & M;
    c = (c >> 32) + v1;
    long w1 = c & M;
    c = (c >> 32) + v2 - 1;
    long w2 = c & M;
    c = (c >> 32) + v3 + 1;
    long w3 = c & M;
    c = (c >> 32) + v4;
    long w4 = c & M;
    c = (c >> 32) + v5;
    long w5 = c & M;
    c = (c >> 32) + v6;
    long w6 = c & M;
    c = (c >> 32) + v7 + 1;
    long w7 = c & M;
    int keep = (int) (c >> 32) - 1;
    r[0] = ((int) v0 & keep) | ((int) w0 & ~keep);
    r[1] = ((int) v1 & keep) | ((int) w1 & ~keep);
    r[2] = ((int) v2 & keep) | ((int) w2 & ~keep);
    r[3] = ((int) v3 & keep) | ((int) w3 & ~keep);
    r[4] = ((int) v4 & keep) | ((int) w4 & ~keep);
    r[5] = ((int) v5 & keep) | ((int) w5 & ~keep);
    r[6] = ((int) v6 & keep) | ((int) w6 & ~keep);
    r[7] = ((int) v7 & keep) | ((int) w7 & ~keep);
  }

  /** Sets {@code r = a + b mod p}; r may alias a or b. */
  static void add(int[] r, int[] a, int[] b) {
    long c = (a[0] & M) + (b[0] & M);
    long v0 = c & M;
    c = (c >>> 32) + (a[1] & M) + (b[1] & M);
    long v1 = c & M;
    c = (c >>> 32) + (a[2] & M) + (b[2] & M);
    long v2 = c & M;
    c = (c >>> 32) + (a[3] & M) + (b[3] & M);
    long v3 = c & M;
    c = (c >>> 32) + (a[4] & M) + (b[4] & M);
    long v4 = c & M;
    c = (c >>> 32) + (a[5] & M) + (b[5] & M);
    long v5 = c & M;
    c = (c >>> 32) + (a[6] & M) + (b[6] & M);
    long v6 = c & M;
    c = (c >>> 32) + (a[7] & M) + (b[7] & M);
    long v7 = c & M;
    int carry = (int) (c >>> 32);
    // v + (2^256 - p); a carry out of either sum means the true value is >= p.
    c = v0 + 1;
    long w0 = c & M;
    c = (c >> 32) + v1;
    long w1 = c & M;
    c = (c >> 32) + v2 - 1;
    long w2 = c & M;
    c = (c >> 32) + v3 + 1;
    long w3 = c & M;
    c = (c >> 32) + v4;
    long w4 = c & M;
    c = (c >> 32) + v5;
    long w5 = c & M;
    c = (c >> 32) + v6;
    long w6 = c & M;
    c = (c >> 32) + v7 + 1;
    long w7 = c & M;
    int keep = (carry | (int) (c >> 32)) - 1;
    r[0] = ((int) v0 & keep) | ((int) w0 & ~keep);
    r[1] = ((int) v1 & keep) | ((int) w1 & ~keep);
    r[2] = ((int) v2 & keep) | ((int) w2 & ~keep);
    r[3] = ((int) v3 & keep) | ((int) w3 & ~keep);
    r[4] = ((int) v4 & keep) | ((int) w4 & ~keep);
    r[5] = ((int) v5 & keep) | ((int) w5 & ~keep);
    r[6] = ((int) v6 & keep) | ((int) w6 & ~keep);
    r[7] = ((int) v7 & keep) | ((int) w7 & ~keep);
  }

  /** Sets {@code r = a - b mod p}; r may alias a or b. */
  static void sub(int[] r, int[] a, int[] b) {
    long c = (a[0] & M) - (b[0] & M);
    long v0 = c & M;
    c = (c >> 32) + (a[1] & M) - (b[1] & M);
    long v1 = c & M;
    c = (c >> 32) + (a[2] & M) - (b[2] & M);
    long v2 = c & M;
    c = (c >> 32) + (a[3] & M) - (b[3] & M);
    long v3 = c & M;
    c = (c >> 32) + (a[4] & M) - (b[4] & M);
    long v4 = c & M;
    c = (c >> 32) + (a[5] & M) - (b[5] & M);
    long v5 = c & M;
    c = (c >> 32) + (a[6] & M) - (b[6] & M);
    long v6 = c & M;
    c = (c >> 32) + (a[7] & M) - (b[7] & M);
    long v7 = c & M;
    // On borrow (all ones) add p back, whose limbs are ffffffff ffffffff 0 ffffffff x4 fffffffe.
    long borrow = c >> 32;
    long pLow = borrow & M;
    c = v0 + pLow;
    r[0] = (int) c;
    c = (c >>> 32) + v1 + pLow;
    r[1] = (int) c;
    c = (c >>> 32) + v2;
    r[2] = (int) c;
    c = (c >>> 32) + v3 + pLow;
    r[3] = (int) c;
    c = (c >>> 32) + v4 + pLow;
    r[4] = (int) c;
    c = (c >>> 32) + v5 + pLow;
    r[5] = (int) c;
    c = (c >>> 32) + v6 + pLow;
    r[6] = (int) c;
    c = (c >>> 32) + v7 + (pLow & 0xFFFFFFFEL);
    r[7] = (int) c;
  }

  /** Sets {@code r = -a mod p} (0 stays 0); r may alias a. */
  static void neg(int[] r, int[] a) {
    condNeg(r, a, -1);
  }

  /** Sets {@code r = -a mod p} when mask is all ones and {@code r = a} when mask is 0. */
  static void condNeg(int[] r, int[] a, int mask) {
    // p - 0 would not be canonical, so zero always selects the "keep" branch.
    int negate = mask & ~isZero(a);
    long c = M - (a[0] & M);
    long w0 = c & M;
    c = (c >> 32) + M - (a[1] & M);
    long w1 = c & M;
    c = (c >> 32) - (a[2] & M);
    long w2 = c & M;
    c = (c >> 32) + M - (a[3] & M);
    long w3 = c & M;
    c = (c >> 32) + M - (a[4] & M);
    long w4 = c & M;
    c = (c >> 32) + M - (a[5] & M);
    long w5 = c & M;
    c = (c >> 32) + M - (a[6] & M);
    long w6 = c & M;
    c = (c >> 32) + 0xFFFFFFFEL - (a[7] & M);
    long w7 = c & M;
    r[0] = ((int) w0 & negate) | (a[0] & ~negate);
    r[1] = ((int) w1 & negate) | (a[1] & ~negate);
    r[2] = ((int) w2 & negate) | (a[2] & ~negate);
    r[3] = ((int) w3 & negate) | (a[3] & ~negate);
    r[4] = ((int) w4 & negate) | (a[4] & ~negate);
    r[5] = ((int) w5 & negate) | (a[5] & ~negate);
    r[6] = ((int) w6 & negate) | (a[6] & ~negate);
    r[7] = ((int) w7 & negate) | (a[7] & ~negate);
  }

  /** Returns all ones when {@code a == 0}, else 0. */
  static int isZero(int[] a) {
    int x = a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7];
    return ~((x | -x) >> 31);
  }

  /** Returns all ones when {@code a == b}, else 0. */
  static int isEqual(int[] a, int[] b) {
    int x =
        (a[0] ^ b[0])
            | (a[1] ^ b[1])
            | (a[2] ^ b[2])
            | (a[3] ^ b[3])
            | (a[4] ^ b[4])
            | (a[5] ^ b[5])
            | (a[6] ^ b[6])
            | (a[7] ^ b[7]);
    return ~((x | -x) >> 31);
  }

  /** Copies a into r when mask is all ones; leaves r alone when mask is 0. */
  static void select(int[] r, int[] a, int mask) {
    for (int i = 0; i < 8; i++) {
      r[i] ^= (r[i] ^ a[i]) & mask;
    }
  }

  /** Writes a as 32 big-endian bytes. */
  static void toBytes(int[] a, byte[] out, int off) {
    for (int i = 7, o = off; i >= 0; i--, o += 4) {
      int v = a[i];
      out[o] = (byte) (v >>> 24);
      out[o + 1] = (byte) (v >>> 16);
      out[o + 2] = (byte) (v >>> 8);
      out[o + 3] = (byte) v;
    }
  }

  /** Reads 32 big-endian bytes without range checking the value. */
  static int[] fromBytes(byte[] in, int off) {
    int[] r = new int[8];
    for (int i = 7, o = off; i >= 0; i--, o += 4) {
      r[i] =
          (in[o] & 0xFF) << 24
              | (in[o + 1] & 0xFF) << 16
              | (in[o + 2] & 0xFF) << 8
              | (in[o + 3] & 0xFF);
    }
    return r;
  }

  /** Converts a value in [0, 2^256) to limbs; anything else is rejected, never truncated. */
  static int[] fromBigInteger(BigInteger v) {
    if (v == null || v.signum() < 0 || v.bitLength() > 256) {
      throw new IllegalArgumentException("Value out of range");
    }
    byte[] raw = v.toByteArray();
    byte[] fixed = new byte[32];
    int n = Math.min(raw.length, 32);
    System.arraycopy(raw, raw.length - n, fixed, 32 - n, n);
    int[] limbs = fromBytes(fixed, 0);
    java.util.Arrays.fill(fixed, (byte) 0);
    java.util.Arrays.fill(raw, (byte) 0);
    return limbs;
  }

  static BigInteger toBigInteger(int[] a) {
    byte[] out = new byte[32];
    toBytes(a, out, 0);
    return new BigInteger(1, out);
  }
}
