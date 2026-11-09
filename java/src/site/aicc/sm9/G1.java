package site.aicc.sm9;

import java.math.BigInteger;

/**
 * The group G1: E(Fq): y^2 = x^3 + 5, prime order N, cofactor 1.
 *
 * <p>Points are homogeneous projective (X : Y : Z), 24 ints: X, Y, Z. The identity is (0 : 1 : 0).
 * Addition and doubling use the complete formulas of Renes, Costello and Batina (2016, algorithms 7
 * and 9 for a = 0), correct for every pair of inputs with no case analysis, so scalar
 * multiplication has a single code path whatever the operands.
 */
final class G1 {
  private static final int W = Fp.L;

  /** Ints per point. */
  static final int L = 3 * W;

  /** Bytes of the encoding 04 || x || y. */
  static final int BYTES = 65;

  private static final int[] B3 = Fp.fromBigInteger(BigInteger.valueOf(15));
  private static final int[] B = Fp.fromBigInteger(BigInteger.valueOf(5));

  static final int[] P1 =
      affine(
          new BigInteger("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD", 16),
          new BigInteger("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616", 16));

  private G1() {}

  private static int[] affine(BigInteger x, BigInteger y) {
    int[] p = new int[L];
    Fp.copy(p, 0, Fp.fromBigInteger(x), 0);
    Fp.copy(p, W, Fp.fromBigInteger(y), 0);
    Fp.setOne(p, 2 * W);
    return p;
  }

  static int[] infinity() {
    int[] p = new int[L];
    Fp.setOne(p, W);
    return p;
  }

  static boolean isInfinity(int[] p) {
    return Fp.isZero(p, 2 * W) != 0;
  }

  /** Complete addition r = p + q (12M + 2 by-constant); r may alias p or q. */
  static void add(int[] r, int[] p, int[] q) {
    int[] t = new int[8 * W];
    int t0 = 0;
    int t1 = W;
    int t2 = 2 * W;
    int t3 = 3 * W;
    int t4 = 4 * W;
    int x3 = 5 * W;
    int y3 = 6 * W;
    int z3 = 7 * W;
    Fp.mul(t, t0, p, 0, q, 0);
    Fp.mul(t, t1, p, W, q, W);
    Fp.mul(t, t2, p, 2 * W, q, 2 * W);
    Fp.add(t, t3, p, 0, p, W);
    Fp.add(t, t4, q, 0, q, W);
    Fp.mul(t, t3, t, t3, t, t4);
    Fp.add(t, t4, t, t0, t, t1);
    Fp.sub(t, t3, t, t3, t, t4);
    Fp.add(t, t4, p, W, p, 2 * W);
    Fp.add(t, x3, q, W, q, 2 * W);
    Fp.mul(t, t4, t, t4, t, x3);
    Fp.add(t, x3, t, t1, t, t2);
    Fp.sub(t, t4, t, t4, t, x3);
    Fp.add(t, x3, p, 0, p, 2 * W);
    Fp.add(t, y3, q, 0, q, 2 * W);
    Fp.mul(t, x3, t, x3, t, y3);
    Fp.add(t, y3, t, t0, t, t2);
    Fp.sub(t, y3, t, x3, t, y3);
    Fp.dbl(t, x3, t, t0);
    Fp.add(t, t0, t, x3, t, t0);
    Fp.mul(t, t2, t, t2, B3, 0);
    Fp.add(t, z3, t, t1, t, t2);
    Fp.sub(t, t1, t, t1, t, t2);
    Fp.mul(t, y3, t, y3, B3, 0);
    Fp.mul(t, x3, t, t4, t, y3);
    Fp.mul(t, t2, t, t3, t, t1);
    Fp.sub(t, x3, t, t2, t, x3);
    Fp.mul(t, y3, t, y3, t, t0);
    Fp.mul(t, t1, t, t1, t, z3);
    Fp.add(t, y3, t, t1, t, y3);
    Fp.mul(t, t0, t, t0, t, t3);
    Fp.mul(t, z3, t, z3, t, t4);
    Fp.add(t, z3, t, z3, t, t0);
    System.arraycopy(t, x3, r, 0, L);
  }

  /** Complete doubling r = 2p (6M + 2S + 1 by-constant); r may alias p. */
  static void dbl(int[] r, int[] p) {
    int[] t = new int[6 * W];
    int t0 = 0;
    int t1 = W;
    int t2 = 2 * W;
    int x3 = 3 * W;
    int y3 = 4 * W;
    int z3 = 5 * W;
    Fp.sqr(t, t0, p, W);
    Fp.dbl(t, z3, t, t0);
    Fp.dbl(t, z3, t, z3);
    Fp.dbl(t, z3, t, z3);
    Fp.mul(t, t1, p, W, p, 2 * W);
    Fp.sqr(t, t2, p, 2 * W);
    Fp.mul(t, t2, t, t2, B3, 0);
    Fp.mul(t, x3, t, t2, t, z3);
    Fp.add(t, y3, t, t0, t, t2);
    Fp.mul(t, z3, t, t1, t, z3);
    Fp.dbl(t, t1, t, t2);
    Fp.add(t, t2, t, t1, t, t2);
    Fp.sub(t, t0, t, t0, t, t2);
    Fp.mul(t, y3, t, t0, t, y3);
    Fp.add(t, y3, t, x3, t, y3);
    Fp.mul(t, t1, p, 0, p, W);
    Fp.mul(t, x3, t, t0, t, t1);
    Fp.dbl(t, x3, t, x3);
    System.arraycopy(t, x3, r, 0, L);
  }

  static int[] neg(int[] p) {
    int[] r = p.clone();
    Fp.neg(r, W, p, W);
    return r;
  }

  /**
   * Returns k p for a 256-bit scalar k (little-endian words), in constant time: 4-bit fixed
   * windows, every table entry read for each window, and complete formulas throughout.
   */
  static int[] mul(int[] p, int[] k) {
    int[] table = new int[16 * L];
    System.arraycopy(infinity(), 0, table, 0, L);
    System.arraycopy(p, 0, table, L, L);
    int[] e = new int[L];
    for (int i = 2; i < 16; i++) {
      System.arraycopy(table, (i - 1) * L, e, 0, L);
      add(e, e, p);
      System.arraycopy(e, 0, table, i * L, L);
    }
    int[] acc = infinity();
    for (int win = 63; win >= 0; win--) {
      dbl(acc, acc);
      dbl(acc, acc);
      dbl(acc, acc);
      dbl(acc, acc);
      int digit = (k[win >>> 3] >>> ((win & 7) << 2)) & 15;
      select(e, table, digit);
      add(acc, acc, e);
    }
    java.util.Arrays.fill(table, 0);
    java.util.Arrays.fill(e, 0);
    return acc;
  }

  /** Copies table entry {@code index} into r, touching every entry. */
  private static void select(int[] r, int[] table, int index) {
    select(r, table, 0, index);
  }

  /** Copies entry {@code index} of the 16-entry row at {@code off}, touching every entry. */
  private static void select(int[] r, int[] table, int off, int index) {
    java.util.Arrays.fill(r, 0);
    for (int i = 0; i < 16; i++) {
      int x = i ^ index;
      int mask = ~((x | -x) >> 31);
      int base = off + i * L;
      for (int j = 0; j < L; j++) {
        r[j] |= table[base + j] & mask;
      }
    }
  }

  /** Lazily built: row i holds j 16^i P1 for j = 0..15, projective. */
  private static final class Comb {
    static final int[] TABLE = build();

    private static int[] build() {
      int[] table = new int[64 * 16 * L];
      int[] base = P1.clone();
      int[] e = new int[L];
      for (int row = 0; row < 64; row++) {
        int off = row * 16 * L;
        System.arraycopy(infinity(), 0, table, off, L);
        for (int j = 1; j < 16; j++) {
          System.arraycopy(table, off + (j - 1) * L, e, 0, L);
          add(e, e, base);
          System.arraycopy(e, 0, table, off + j * L, L);
        }
        for (int s = 0; s < 4; s++) {
          dbl(base, base);
        }
      }
      return table;
    }
  }

  /**
   * k P1 for a 256-bit k from the fixed-base table: one complete addition per 4-bit window and no
   * doublings, with every entry of a row read for each window.
   */
  static int[] mulGenerator(int[] k) {
    int[] table = Comb.TABLE;
    int[] acc = infinity();
    int[] e = new int[L];
    for (int win = 0; win < 64; win++) {
      select(e, table, win * 16 * L, (k[win >>> 3] >>> ((win & 7) << 2)) & 15);
      add(acc, acc, e);
    }
    java.util.Arrays.fill(e, 0);
    return acc;
  }

  /** Affine (x, y) as 16 ints; the point must not be the identity. */
  static int[] toAffine(int[] p) {
    int[] zi = new int[W];
    Fp.inv(zi, 0, p, 2 * W);
    int[] a = new int[2 * W];
    Fp.mul(a, 0, p, 0, zi, 0);
    Fp.mul(a, W, p, W, zi, 0);
    return a;
  }

  /** Returns true when p and q are the same point. */
  static boolean equal(int[] p, int[] q) {
    int[] t = new int[4 * W];
    Fp.mul(t, 0, p, 0, q, 2 * W);
    Fp.mul(t, W, q, 0, p, 2 * W);
    Fp.mul(t, 2 * W, p, W, q, 2 * W);
    Fp.mul(t, 3 * W, q, W, p, 2 * W);
    int infP = Fp.isZero(p, 2 * W);
    int infQ = Fp.isZero(q, 2 * W);
    int same = Fp.equal(t, 0, t, W) & Fp.equal(t, 2 * W, t, 3 * W) & ~infP & ~infQ;
    return (same | (infP & infQ)) != 0;
  }

  /** x || y without prefix (64 bytes), as hashed; the point must not be the identity. */
  static byte[] xy(int[] p) {
    int[] a = toAffine(p);
    byte[] out = new byte[64];
    Fp.encode(a, 0, out, 0);
    Fp.encode(a, W, out, 32);
    return out;
  }

  /** 04 || x || y; the point must not be the identity. */
  static byte[] encode(int[] p) {
    byte[] out = new byte[BYTES];
    out[0] = 4;
    System.arraycopy(xy(p), 0, out, 1, 64);
    return out;
  }

  /** Decodes 04 || x || y, or returns null unless it is a point of G1 other than the identity. */
  static int[] decode(byte[] in) {
    if (in == null || in.length != BYTES || in[0] != 4) {
      return null;
    }
    int[] p = new int[L];
    boolean ok = Fp.decode(in, 1, p, 0) & Fp.decode(in, 33, p, W);
    Fp.setOne(p, 2 * W);
    return ok && isOnCurveAffine(p) ? p : null;
  }

  /** y^2 == x^3 + 5 for a point with Z = 1. */
  private static boolean isOnCurveAffine(int[] p) {
    int[] t = new int[2 * W];
    Fp.sqr(t, 0, p, 0);
    Fp.mul(t, 0, t, 0, p, 0);
    Fp.add(t, 0, t, 0, B, 0);
    Fp.sqr(t, W, p, W);
    return Fp.equal(t, 0, t, W) != 0;
  }
}
