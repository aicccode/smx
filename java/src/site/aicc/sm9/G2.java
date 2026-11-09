package site.aicc.sm9;

import java.math.BigInteger;

/**
 * The group G2: points of order N on the twist E'(Fq2): y^2 = x^3 + 5u, whose full group has a
 * cofactor, so decoded points get an explicit subgroup check.
 *
 * <p>Points are homogeneous projective (X : Y : Z) over Fq2, 48 ints. The formulas are those of
 * {@link G1} with b' = 5u: complete, because the twist has odd order and so no point of order 2.
 */
final class G2 {
  private static final int W = Fp2.L;

  /** Ints per point. */
  static final int L = 3 * W;

  /** Bytes of the encoding 04 || x || y. */
  static final int BYTES = 129;

  private static final int[] FIFTEEN = Fp.fromBigInteger(BigInteger.valueOf(15));
  private static final int[] B = Fp2.of(BigInteger.ZERO, BigInteger.valueOf(5));

  static final int[] P2 =
      affine(
          Fp2.of(
              new BigInteger(
                  "3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B", 16),
              new BigInteger(
                  "85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141", 16)),
          Fp2.of(
              new BigInteger(
                  "A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7", 16),
              new BigInteger(
                  "17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96", 16)));

  private static final BigInteger T = new BigInteger("600000000058F98A", 16);
  private static final int[] SIX_T_SQUARED =
      Fp.words(T.multiply(T).multiply(BigInteger.valueOf(6)));

  /** Twisted Frobenius constants: u^(-(q - 1) / 3) and u^(-(q - 1) / 2). */
  private static final int[] PI_X;

  private static final int[] PI_Y;

  static {
    BigInteger q1 = Fp.Q_BIG.subtract(BigInteger.ONE);
    int[] u = Fp2.of(BigInteger.ZERO, BigInteger.ONE);
    PI_X = Fp2.pow(u, q1.divide(BigInteger.valueOf(3)));
    Fp2.inv(PI_X, 0, PI_X, 0);
    PI_Y = Fp2.pow(u, q1.shiftRight(1));
    Fp2.inv(PI_Y, 0, PI_Y, 0);
  }

  private G2() {}

  private static int[] affine(int[] x, int[] y) {
    int[] p = new int[L];
    Fp2.copy(p, 0, x, 0);
    Fp2.copy(p, W, y, 0);
    Fp2.setOne(p, 2 * W);
    return p;
  }

  /** Multiplies by 3b' = 15u. */
  private static void mulB3(int[] t, int o) {
    Fp2.mulFp(t, o, t, o, FIFTEEN, 0);
    Fp2.mulU(t, o, t, o);
  }

  static int[] infinity() {
    int[] p = new int[L];
    Fp2.setOne(p, W);
    return p;
  }

  static boolean isInfinity(int[] p) {
    return Fp2.isZero(p, 2 * W) != 0;
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
    Fp2.mul(t, t0, p, 0, q, 0);
    Fp2.mul(t, t1, p, W, q, W);
    Fp2.mul(t, t2, p, 2 * W, q, 2 * W);
    Fp2.add(t, t3, p, 0, p, W);
    Fp2.add(t, t4, q, 0, q, W);
    Fp2.mul(t, t3, t, t3, t, t4);
    Fp2.add(t, t4, t, t0, t, t1);
    Fp2.sub(t, t3, t, t3, t, t4);
    Fp2.add(t, t4, p, W, p, 2 * W);
    Fp2.add(t, x3, q, W, q, 2 * W);
    Fp2.mul(t, t4, t, t4, t, x3);
    Fp2.add(t, x3, t, t1, t, t2);
    Fp2.sub(t, t4, t, t4, t, x3);
    Fp2.add(t, x3, p, 0, p, 2 * W);
    Fp2.add(t, y3, q, 0, q, 2 * W);
    Fp2.mul(t, x3, t, x3, t, y3);
    Fp2.add(t, y3, t, t0, t, t2);
    Fp2.sub(t, y3, t, x3, t, y3);
    Fp2.dbl(t, x3, t, t0);
    Fp2.add(t, t0, t, x3, t, t0);
    mulB3(t, t2);
    Fp2.add(t, z3, t, t1, t, t2);
    Fp2.sub(t, t1, t, t1, t, t2);
    mulB3(t, y3);
    Fp2.mul(t, x3, t, t4, t, y3);
    Fp2.mul(t, t2, t, t3, t, t1);
    Fp2.sub(t, x3, t, t2, t, x3);
    Fp2.mul(t, y3, t, y3, t, t0);
    Fp2.mul(t, t1, t, t1, t, z3);
    Fp2.add(t, y3, t, t1, t, y3);
    Fp2.mul(t, t0, t, t0, t, t3);
    Fp2.mul(t, z3, t, z3, t, t4);
    Fp2.add(t, z3, t, z3, t, t0);
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
    Fp2.sqr(t, t0, p, W);
    Fp2.dbl(t, z3, t, t0);
    Fp2.dbl(t, z3, t, z3);
    Fp2.dbl(t, z3, t, z3);
    Fp2.mul(t, t1, p, W, p, 2 * W);
    Fp2.sqr(t, t2, p, 2 * W);
    mulB3(t, t2);
    Fp2.mul(t, x3, t, t2, t, z3);
    Fp2.add(t, y3, t, t0, t, t2);
    Fp2.mul(t, z3, t, t1, t, z3);
    Fp2.dbl(t, t1, t, t2);
    Fp2.add(t, t2, t, t1, t, t2);
    Fp2.sub(t, t0, t, t0, t, t2);
    Fp2.mul(t, y3, t, t0, t, y3);
    Fp2.add(t, y3, t, x3, t, y3);
    Fp2.mul(t, t1, p, 0, p, W);
    Fp2.mul(t, x3, t, t0, t, t1);
    Fp2.dbl(t, x3, t, x3);
    System.arraycopy(t, x3, r, 0, L);
  }

  static int[] neg(int[] p) {
    int[] r = p.clone();
    Fp2.neg(r, W, p, W);
    return r;
  }

  /**
   * Returns k p for a 256-bit scalar k (little-endian words), in constant time: 4-bit fixed
   * windows, every table entry read for each window, and complete formulas throughout.
   */
  static int[] mul(int[] p, int[] k) {
    return mul(p, k, 64);
  }

  /** k p for k below 2^(4 windows), with the same constant-time schedule. */
  private static int[] mul(int[] p, int[] k, int windows) {
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
    for (int win = windows - 1; win >= 0; win--) {
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

  /** Lazily built: row i holds j 16^i P2 for j = 0..15, projective. */
  private static final class Comb {
    static final int[] TABLE = build();

    private static int[] build() {
      int[] table = new int[64 * 16 * L];
      int[] base = P2.clone();
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
   * k P2 for a 256-bit k from the fixed-base table: one complete addition per 4-bit window and no
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

  /** Affine (x, y) as 32 ints; the point must not be the identity. */
  static int[] toAffine(int[] p) {
    int[] zi = new int[W];
    Fp2.inv(zi, 0, p, 2 * W);
    int[] a = new int[2 * W];
    Fp2.mul(a, 0, p, 0, zi, 0);
    Fp2.mul(a, W, p, W, zi, 0);
    return a;
  }

  /** The same point with Z = 1; p must not be the identity. */
  static int[] toAffineProjective(int[] p) {
    int[] r = new int[L];
    System.arraycopy(toAffine(p), 0, r, 0, 2 * W);
    Fp2.setOne(r, 2 * W);
    return r;
  }

  /** Returns true when p and q are the same point. */
  static boolean equal(int[] p, int[] q) {
    int[] t = new int[4 * W];
    Fp2.mul(t, 0, p, 0, q, 2 * W);
    Fp2.mul(t, W, q, 0, p, 2 * W);
    Fp2.mul(t, 2 * W, p, W, q, 2 * W);
    Fp2.mul(t, 3 * W, q, W, p, 2 * W);
    int infP = Fp2.isZero(p, 2 * W);
    int infQ = Fp2.isZero(q, 2 * W);
    int same = Fp2.equal(t, 0, t, W) & Fp2.equal(t, 2 * W, t, 3 * W) & ~infP & ~infQ;
    return (same | (infP & infQ)) != 0;
  }

  /** 04 || x1 || x0 || y1 || y0; the point must not be the identity. */
  static byte[] encode(int[] p) {
    int[] a = toAffine(p);
    byte[] out = new byte[BYTES];
    out[0] = 4;
    Fp2.encode(a, 0, out, 1);
    Fp2.encode(a, W, out, 65);
    return out;
  }

  /**
   * Decodes 04 || x1 || x0 || y1 || y0, or returns null unless it is a point of G2 other than the
   * identity: on the twist, coordinates below q, and of order N.
   */
  static int[] decode(byte[] in) {
    if (in == null || in.length != BYTES || in[0] != 4) {
      return null;
    }
    int[] p = new int[L];
    boolean ok = Fp2.decode(in, 1, p, 0) & Fp2.decode(in, 65, p, W);
    Fp2.setOne(p, 2 * W);
    return ok && isOnCurveAffine(p) && inSubgroup(p) ? p : null;
  }

  /**
   * Membership in G2 for an affine twist point: psi(Q) == [6t^2] Q, where psi is the twisted
   * Frobenius. On G2, psi acts as multiplication by q = 6t^2 mod N. The test has no false positives
   * on this curve: psi satisfies psi^2 - tr psi + q = 0 (tr = 6t^2 + 1), so a component of order
   * dividing the cofactor h' = 2q - N that passed would be killed by lambda^2 - tr lambda + q,
   * which is coprime to h'. A 127-bit scalar instead of [N] Q halves the cost.
   */
  static boolean inSubgroup(int[] p) {
    int[] psi = psiAffine(p);
    int[] q = new int[L];
    Fp2.copy(q, 0, psi, 0);
    Fp2.copy(q, W, psi, W);
    Fp2.setOne(q, 2 * W);
    return equal(q, mul(p, SIX_T_SQUARED, 32));
  }

  /** psi(x', y') = (conj(x') PI_X, conj(y') PI_Y) of an affine point (Z = 1); 32 ints. */
  static int[] psiAffine(int[] qa) {
    int[] r = new int[2 * W];
    Fp2.conj(r, 0, qa, 0);
    Fp2.mul(r, 0, r, 0, PI_X, 0);
    Fp2.conj(r, W, qa, W);
    Fp2.mul(r, W, r, W, PI_Y, 0);
    return r;
  }

  /** y^2 == x^3 + 5u for a point with Z = 1. */
  private static boolean isOnCurveAffine(int[] p) {
    int[] t = new int[2 * W];
    Fp2.sqr(t, 0, p, 0);
    Fp2.mul(t, 0, t, 0, p, 0);
    Fp2.add(t, 0, t, 0, B, 0);
    Fp2.sqr(t, W, p, W);
    return Fp2.equal(t, 0, t, W) != 0;
  }
}
