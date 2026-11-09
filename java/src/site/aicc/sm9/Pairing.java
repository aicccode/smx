package site.aicc.sm9;

import java.math.BigInteger;

/**
 * The R-ate pairing e: G1 x G2 -> GT of GB/T 38635.1, with a = 6t + 2.
 *
 * <p>The Miller loop keeps T in homogeneous projective coordinates on the twist, so it needs no
 * inversion. Each line through the untwisted T, evaluated at P, is (y' - lambda x') + lambda xP w^2
 * - yP w^3 scaled by an Fq2 factor (removed by the final exponentiation, as the specification
 * allows), which leaves a sparse value multiplied in with {@link Fp12#mulLine}. The final
 * exponentiation is f^((q^6 - 1)(q^2 + 1)) followed by the BN hard part (q^4 - q^2 + 1) / N = q^3 +
 * (6t^2 + 1) q^2 + (-36t^3 - 18t^2 - 12t + 1) q + (-36t^3 - 30t^2 - 18t - 2), evaluated with three
 * exponentiations by t and the addition chain of Scott et al., so it gives exactly the value of the
 * plain definition.
 *
 * <p>Points and the loop count are public in every use of the pairing here, so the loop may branch
 * on the bits of a; all arithmetic is still constant time.
 */
final class Pairing {
  private static final BigInteger T = new BigInteger("600000000058F98A", 16);
  private static final BigInteger LOOP =
      T.multiply(BigInteger.valueOf(6)).add(BigInteger.valueOf(2));

  private static final int E = Fp2.L;
  private static final int[] FIFTEEN = Fp.fromBigInteger(BigInteger.valueOf(15));

  private Pairing() {}

  /**
   * e(P, Q) for P in G1 and Q in G2 as projective points; 1 when either is the identity. Both must
   * be valid group elements.
   */
  static int[] pair(int[] p, int[] q) {
    if (G1.isInfinity(p) || G2.isInfinity(q)) {
      return Fp12.one();
    }
    return finalExp(miller(G1.toAffine(p), G2.toAffine(q)));
  }

  /** The Miller loop for affine P = (xP, yP) and affine Q = (x', y'). */
  static int[] miller(int[] pa, int[] qa) {
    int w = Fp.L;
    int[] px = new int[w];
    int[] negPy = new int[w];
    Fp.copy(px, 0, pa, 0);
    Fp.neg(negPy, 0, pa, w);
    int[] t = new int[3 * E];
    Fp2.copy(t, 0, qa, 0);
    Fp2.copy(t, E, qa, E);
    Fp2.setOne(t, 2 * E);
    int[] f = Fp12.one();
    int[] line = new int[3 * E];
    boolean first = true;
    for (int i = LOOP.bitLength() - 2; i >= 0; i--) {
      if (!first) {
        Fp12.sqr(f, f);
      }
      first = false;
      doubleStep(t, line, px, negPy);
      Fp12.mulLine(f, line);
      if (LOOP.testBit(i)) {
        addStep(t, qa, 0, line, px, negPy);
        Fp12.mulLine(f, line);
      }
    }
    int[] q1 = G2.psiAffine(qa);
    int[] q2 = G2.psiAffine(q1);
    Fp2.neg(q2, E, q2, E);
    addStep(t, q1, 0, line, px, negPy);
    Fp12.mulLine(f, line);
    addStep(t, q2, 0, line, px, negPy);
    Fp12.mulLine(f, line);
    return f;
  }

  /**
   * T = 2T with the line through T (Aranha et al., homogeneous coordinates): A = XY/2, B = Y^2, C =
   * Z^2, E = 3b'C, F = 3E, G = (B + F)/2, H = (Y + Z)^2 - B - C; X3 = A(B - F), Y3 = G^2 - 3E^2, Z3
   * = BH; line (E - B) + 3X^2 xP w^2 - H yP w^3.
   */
  private static void doubleStep(int[] t, int[] line, int[] px, int[] negPy) {
    int[] s = new int[8 * E];
    int a = 0;
    int b = E;
    int c = 2 * E;
    int e = 3 * E;
    int f = 4 * E;
    int g = 5 * E;
    int h = 6 * E;
    int x = 7 * E;
    Fp2.mul(s, a, t, 0, t, E);
    Fp2.half(s, a, s, a);
    Fp2.sqr(s, b, t, E);
    Fp2.sqr(s, c, t, 2 * E);
    Fp2.mulFp(s, e, s, c, FIFTEEN, 0);
    Fp2.mulU(s, e, s, e);
    Fp2.dbl(s, f, s, e);
    Fp2.add(s, f, s, f, s, e);
    Fp2.add(s, g, s, b, s, f);
    Fp2.half(s, g, s, g);
    Fp2.add(s, h, t, E, t, 2 * E);
    Fp2.sqr(s, h, s, h);
    Fp2.sub(s, h, s, h, s, b);
    Fp2.sub(s, h, s, h, s, c);
    // Line: A = E - B, B = H (-yP), C = 3 X^2 xP.
    Fp2.sub(line, 0, s, e, s, b);
    Fp2.mulFp(line, E, s, h, negPy, 0);
    Fp2.sqr(s, x, t, 0);
    Fp2.dbl(line, 2 * E, s, x);
    Fp2.add(line, 2 * E, line, 2 * E, s, x);
    Fp2.mulFp(line, 2 * E, line, 2 * E, px, 0);
    // Point.
    Fp2.sub(s, x, s, b, s, f);
    Fp2.mul(t, 0, s, a, s, x);
    Fp2.sqr(s, x, s, e);
    Fp2.dbl(s, c, s, x);
    Fp2.add(s, x, s, x, s, c);
    Fp2.sqr(s, g, s, g);
    Fp2.sub(t, E, s, g, s, x);
    Fp2.mul(t, 2 * E, s, b, s, h);
  }

  /**
   * T = T + Q for affine Q = (x2, y2) with the line through them: theta = Y - y2 Z, lambda = X - x2
   * Z, C = theta^2, D = lambda^2, E = lambda^3, F = Z C, G = X D, H = E + F - 2G; X3 = lambda H, Y3
   * = theta (G - H) - E Y, Z3 = Z E; line (y2 lambda - x2 theta) + theta xP w^2 - lambda yP w^3.
   */
  private static void addStep(int[] t, int[] q, int qo, int[] line, int[] px, int[] negPy) {
    int[] s = new int[8 * E];
    int th = 0;
    int la = E;
    int c = 2 * E;
    int d = 3 * E;
    int e = 4 * E;
    int f = 5 * E;
    int g = 6 * E;
    int h = 7 * E;
    Fp2.mul(s, th, q, qo + E, t, 2 * E);
    Fp2.sub(s, th, t, E, s, th);
    Fp2.mul(s, la, q, qo, t, 2 * E);
    Fp2.sub(s, la, t, 0, s, la);
    // Line.
    Fp2.mul(s, c, q, qo + E, s, la);
    Fp2.mul(s, d, q, qo, s, th);
    Fp2.sub(line, 0, s, c, s, d);
    Fp2.mulFp(line, E, s, la, negPy, 0);
    Fp2.mulFp(line, 2 * E, s, th, px, 0);
    // Point.
    Fp2.sqr(s, c, s, th);
    Fp2.sqr(s, d, s, la);
    Fp2.mul(s, e, s, d, s, la);
    Fp2.mul(s, f, t, 2 * E, s, c);
    Fp2.mul(s, g, t, 0, s, d);
    Fp2.add(s, h, s, e, s, f);
    Fp2.sub(s, h, s, h, s, g);
    Fp2.sub(s, h, s, h, s, g);
    Fp2.mul(t, 0, s, la, s, h);
    Fp2.sub(s, g, s, g, s, h);
    Fp2.mul(s, g, s, th, s, g);
    Fp2.mul(s, f, s, e, t, E);
    Fp2.sub(t, E, s, g, s, f);
    Fp2.mul(t, 2 * E, t, 2 * E, s, e);
  }

  /** f^((q^12 - 1) / N). */
  static int[] finalExp(int[] f) {
    // Easy part: f^((q^6 - 1)(q^2 + 1)).
    int[] a = new int[Fp12.L];
    int[] b = new int[Fp12.L];
    Fp12.inv(a, f);
    Fp12.conj6(b, f);
    Fp12.mul(a, b, a);
    Fp12.frobenius(b, a, 2);
    Fp12.mul(a, b, a);
    return hardPart(a);
  }

  /** The BN hard part for f in the cyclotomic subgroup. */
  private static int[] hardPart(int[] f) {
    int[] ft = expByT(f);
    int[] ft2 = expByT(ft);
    int[] ft3 = expByT(ft2);
    int[] tmp = new int[Fp12.L];
    // y0 = f^q f^(q^2) f^(q^3)
    int[] y0 = new int[Fp12.L];
    Fp12.frobenius(y0, f, 1);
    Fp12.frobenius(tmp, f, 2);
    Fp12.mul(y0, y0, tmp);
    Fp12.frobenius(tmp, f, 3);
    Fp12.mul(y0, y0, tmp);
    // y1 = 1/f
    int[] y1 = new int[Fp12.L];
    Fp12.conj6(y1, f);
    // y2 = (f^(t^2))^(q^2)
    int[] y2 = new int[Fp12.L];
    Fp12.frobenius(y2, ft2, 2);
    // y3 = 1/(f^t)^q
    int[] y3 = new int[Fp12.L];
    Fp12.frobenius(y3, ft, 1);
    Fp12.conj6(y3, y3);
    // y4 = 1/(f^t (f^(t^2))^q)
    int[] y4 = new int[Fp12.L];
    Fp12.frobenius(y4, ft2, 1);
    Fp12.mul(y4, y4, ft);
    Fp12.conj6(y4, y4);
    // y5 = 1/f^(t^2)
    int[] y5 = new int[Fp12.L];
    Fp12.conj6(y5, ft2);
    // y6 = 1/(f^(t^3) (f^(t^3))^q)
    int[] y6 = new int[Fp12.L];
    Fp12.frobenius(y6, ft3, 1);
    Fp12.mul(y6, y6, ft3);
    Fp12.conj6(y6, y6);
    // y0 y1^2 y2^6 y3^12 y4^18 y5^30 y6^36
    int[] t0 = new int[Fp12.L];
    int[] t1 = new int[Fp12.L];
    Fp12.cyclotomicSqr(t0, y6);
    Fp12.mul(t0, t0, y4);
    Fp12.mul(t0, t0, y5);
    Fp12.mul(t1, y3, y5);
    Fp12.mul(t1, t1, t0);
    Fp12.mul(t0, t0, y2);
    Fp12.cyclotomicSqr(t1, t1);
    Fp12.mul(t1, t1, t0);
    Fp12.cyclotomicSqr(t1, t1);
    Fp12.mul(t0, t1, y1);
    Fp12.mul(t1, t1, y0);
    Fp12.cyclotomicSqr(t0, t0);
    Fp12.mul(t0, t0, t1);
    return t0;
  }

  /** f^t for f in the cyclotomic subgroup; t is public. */
  private static int[] expByT(int[] f) {
    int[] acc = f.clone();
    for (int i = T.bitLength() - 2; i >= 0; i--) {
      Fp12.cyclotomicSqr(acc, acc);
      if (T.testBit(i)) {
        Fp12.mul(acc, acc, f);
      }
    }
    return acc;
  }

  /**
   * g^k in GT for a secret 256-bit k (little-endian words): 4-bit fixed windows with every table
   * entry read for each window, so the sequence of operations and memory accesses does not depend
   * on k. g must lie in the cyclotomic subgroup (every pairing value does).
   */
  static int[] pow(int[] g, int[] k) {
    int[] table = new int[16 * Fp12.L];
    fillRow(table, 0, g);
    int[] acc = Fp12.one();
    int[] e = new int[Fp12.L];
    for (int win = 63; win >= 0; win--) {
      Fp12.cyclotomicSqr(acc, acc);
      Fp12.cyclotomicSqr(acc, acc);
      Fp12.cyclotomicSqr(acc, acc);
      Fp12.cyclotomicSqr(acc, acc);
      select(e, table, 0, (k[win >>> 3] >>> ((win & 7) << 2)) & 15);
      Fp12.mul(acc, acc, e);
    }
    java.util.Arrays.fill(table, 0);
    java.util.Arrays.fill(e, 0);
    return acc;
  }

  /** Writes g^0, g^1, ..., g^15 at {@code table[off]}. */
  private static void fillRow(int[] table, int off, int[] g) {
    int[] e = Fp12.one();
    System.arraycopy(e, 0, table, off, Fp12.L);
    System.arraycopy(g, 0, table, off + Fp12.L, Fp12.L);
    for (int i = 2; i < 16; i++) {
      System.arraycopy(table, off + (i - 1) * Fp12.L, e, 0, Fp12.L);
      Fp12.mul(e, e, g);
      System.arraycopy(e, 0, table, off + i * Fp12.L, Fp12.L);
    }
  }

  /** Copies entry {@code index} of the 16-entry row at {@code off} into e, reading every entry. */
  private static void select(int[] e, int[] table, int off, int index) {
    java.util.Arrays.fill(e, 0);
    for (int i = 0; i < 16; i++) {
      int x = i ^ index;
      int mask = ~((x | -x) >> 31);
      int base = off + i * Fp12.L;
      for (int j = 0; j < Fp12.L; j++) {
        e[j] |= table[base + j] & mask;
      }
    }
  }

  /**
   * A fixed-base table for a public g: row i holds g^(j 16^i) for j = 0..15 (384 KB). With it,
   * {@link #pow(int[], int[])} becomes 64 products and no squarings.
   */
  static int[] combTable(int[] g) {
    int[] table = new int[64 * 16 * Fp12.L];
    int[] base = g.clone();
    for (int row = 0; row < 64; row++) {
      fillRow(table, row * 16 * Fp12.L, base);
      for (int s = 0; s < 4; s++) {
        Fp12.cyclotomicSqr(base, base);
      }
    }
    return table;
  }

  /** g^k from {@link #combTable}, constant time in k like {@link #pow(int[], int[])}. */
  static int[] powComb(int[] table, int[] k) {
    int[] acc = Fp12.one();
    int[] e = new int[Fp12.L];
    for (int win = 0; win < 64; win++) {
      select(e, table, win * 16 * Fp12.L, (k[win >>> 3] >>> ((win & 7) << 2)) & 15);
      Fp12.mul(acc, acc, e);
    }
    java.util.Arrays.fill(e, 0);
    return acc;
  }
}
