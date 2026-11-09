package site.aicc.sm9;

import java.math.BigInteger;

/**
 * Arithmetic in Fq12 = Fq4[w] / (w^3 - v), the pairing target. An element c0 + c1 w + c2 w^2 is 96
 * ints at offset 0 of its own array: c0, c1, c2, each an {@link Fp4} element.
 *
 * <p>The same field is also Fq2[w] / (w^6 - u) with coefficients x0..x5 of 1, w, ..., w^5, where
 * c_i = x_i + x_{i+3} v; the Frobenius maps and the byte encoding use that view.
 */
final class Fp12 {
  /** Ints per element. */
  static final int L = 3 * Fp4.L;

  /** Bytes of the encoding used inside hashes. */
  static final int BYTES = 384;

  private static final int F = Fp4.L;
  private static final int E = Fp2.L;

  /** Frobenius constants gamma_k^j = u^(j (q^k - 1) / 6), [k - 1][j] for k = 1, 2, 3. */
  private static final int[][][] GAMMA = new int[3][6][];

  static {
    BigInteger q = Fp.Q_BIG;
    int[] u = Fp2.of(BigInteger.ZERO, BigInteger.ONE);
    for (int k = 1; k <= 3; k++) {
      int[] g = Fp2.pow(u, q.pow(k).subtract(BigInteger.ONE).divide(BigInteger.valueOf(6)));
      int[] acc = Fp2.of(BigInteger.ONE, BigInteger.ZERO);
      for (int j = 0; j < 6; j++) {
        GAMMA[k - 1][j] = acc.clone();
        Fp2.mul(acc, 0, acc, 0, g, 0);
      }
    }
  }

  private Fp12() {}

  /** Offset of coefficient x_j of w^j. */
  private static int coefficient(int j) {
    return j < 3 ? F * j : F * (j - 3) + E;
  }

  static int[] one() {
    int[] r = new int[L];
    Fp.setOne(r, 0);
    return r;
  }

  static int[] copyOf(int[] a) {
    return a.clone();
  }

  /** Karatsuba over the cubic extension: six Fq4 products. */
  static void mul(int[] r, int[] a, int[] b) {
    int[] t = new int[6 * F];
    int t0 = 0;
    int t1 = F;
    int t2 = 2 * F;
    int s = 3 * F;
    int u = 4 * F;
    int v = 5 * F;
    Fp4.mul(t, t0, a, 0, b, 0);
    Fp4.mul(t, t1, a, F, b, F);
    Fp4.mul(t, t2, a, 2 * F, b, 2 * F);
    // r0 = t0 + v ((a1 + a2)(b1 + b2) - t1 - t2)
    Fp4.add(t, s, a, F, a, 2 * F);
    Fp4.add(t, u, b, F, b, 2 * F);
    Fp4.mul(t, s, t, s, t, u);
    Fp4.sub(t, s, t, s, t, t1);
    Fp4.sub(t, s, t, s, t, t2);
    Fp4.mulV(t, s, t, s);
    // r1 = (a0 + a1)(b0 + b1) - t0 - t1 + v t2
    Fp4.add(t, u, a, 0, a, F);
    Fp4.add(t, v, b, 0, b, F);
    Fp4.mul(t, u, t, u, t, v);
    Fp4.sub(t, u, t, u, t, t0);
    Fp4.sub(t, u, t, u, t, t1);
    Fp4.mulV(t, v, t, t2);
    Fp4.add(t, u, t, u, t, v);
    // r2 = (a0 + a2)(b0 + b2) - t0 - t2 + t1
    int[] w = new int[2 * F];
    Fp4.add(w, 0, a, 0, a, 2 * F);
    Fp4.add(w, F, b, 0, b, 2 * F);
    Fp4.mul(w, 0, w, 0, w, F);
    Fp4.sub(w, 0, w, 0, t, t0);
    Fp4.sub(w, 0, w, 0, t, t2);
    Fp4.add(r, 2 * F, w, 0, t, t1);
    Fp4.add(r, 0, t, t0, t, s);
    Fp4.copy(r, F, t, u);
  }

  /** Squaring by Chung-Hasan SQR2: three squarings and two products in Fq4. */
  static void sqr(int[] r, int[] a) {
    int[] t = new int[5 * F];
    int s0 = 0;
    int s1 = F;
    int s2 = 2 * F;
    int s3 = 3 * F;
    int s4 = 4 * F;
    Fp4.sqr(t, s0, a, 0);
    Fp4.mul(t, s1, a, 0, a, F);
    Fp4.dbl(t, s1, t, s1);
    Fp4.sub(t, s2, a, 0, a, F);
    Fp4.add(t, s2, t, s2, a, 2 * F);
    Fp4.sqr(t, s2, t, s2);
    Fp4.mul(t, s3, a, F, a, 2 * F);
    Fp4.dbl(t, s3, t, s3);
    Fp4.sqr(t, s4, a, 2 * F);
    // r2 = s1 + s2 + s3 - s0 - s4
    Fp4.add(r, 2 * F, t, s1, t, s2);
    Fp4.add(r, 2 * F, r, 2 * F, t, s3);
    Fp4.sub(r, 2 * F, r, 2 * F, t, s0);
    Fp4.sub(r, 2 * F, r, 2 * F, t, s4);
    // r0 = s0 + v s3, r1 = s1 + v s4
    Fp4.mulV(t, s3, t, s3);
    Fp4.add(r, 0, t, s0, t, s3);
    Fp4.mulV(t, s4, t, s4);
    Fp4.add(r, F, t, s1, t, s4);
  }

  /**
   * Squaring in the cyclotomic subgroup (Granger-Scott): with a = c0 + c1 w + c2 w^2 of norm 1, a^2
   * = (3 c0^2 - 2 conj(c0)) + (3 v c2^2 + 2 conj(c1)) w + (3 c1^2 - 2 conj(c2)) w^2.
   */
  static void cyclotomicSqr(int[] r, int[] a) {
    int[] t = new int[3 * F];
    Fp4.sqr(t, 0, a, 0);
    Fp4.sqr(t, F, a, 2 * F);
    Fp4.mulV(t, F, t, F);
    Fp4.sqr(t, 2 * F, a, F);
    int[] c = new int[F];
    // r0 = 3 t0 - 2 conj(a0) = 2 (t0 - conj(a0)) + t0
    Fp4.conj(c, 0, a, 0);
    Fp4.sub(c, 0, t, 0, c, 0);
    Fp4.dbl(c, 0, c, 0);
    Fp4.add(r, 0, c, 0, t, 0);
    // r1 = 3 t1 + 2 conj(a1) = 2 (t1 + conj(a1)) + t1
    Fp4.conj(c, 0, a, F);
    Fp4.add(c, 0, t, F, c, 0);
    Fp4.dbl(c, 0, c, 0);
    Fp4.add(r, F, c, 0, t, F);
    // r2 = 3 t2 - 2 conj(a2)
    Fp4.conj(c, 0, a, 2 * F);
    Fp4.sub(c, 0, t, 2 * F, c, 0);
    Fp4.dbl(c, 0, c, 0);
    Fp4.add(r, 2 * F, c, 0, t, 2 * F);
  }

  /** a^(q^6): w maps to -w, so the odd coefficients x1, x3, x5 change sign. */
  static void conj6(int[] r, int[] a) {
    for (int j = 0; j < 6; j++) {
      int o = coefficient(j);
      if ((j & 1) == 0) {
        Fp2.copy(r, o, a, o);
      } else {
        Fp2.neg(r, o, a, o);
      }
    }
  }

  /** a^(q^k) for k = 1, 2, 3: x_j maps to x_j^(q^k) gamma_k^j. */
  static void frobenius(int[] r, int[] a, int k) {
    int[][] g = GAMMA[k - 1];
    for (int j = 0; j < 6; j++) {
      int o = coefficient(j);
      if ((k & 1) == 1) {
        Fp2.conj(r, o, a, o);
        Fp2.mul(r, o, r, o, g[j], 0);
      } else {
        Fp2.mul(r, o, a, o, g[j], 0);
      }
    }
  }

  /** Inverse through the norm to Fq4; 0 maps to 0. */
  static void inv(int[] r, int[] a) {
    int[] t = new int[5 * F];
    int t0 = 0;
    int t1 = F;
    int t2 = 2 * F;
    int x = 3 * F;
    int y = 4 * F;
    // t0 = a0^2 - v a1 a2
    Fp4.mul(t, x, a, F, a, 2 * F);
    Fp4.mulV(t, x, t, x);
    Fp4.sqr(t, t0, a, 0);
    Fp4.sub(t, t0, t, t0, t, x);
    // t1 = v a2^2 - a0 a1
    Fp4.sqr(t, x, a, 2 * F);
    Fp4.mulV(t, x, t, x);
    Fp4.mul(t, y, a, 0, a, F);
    Fp4.sub(t, t1, t, x, t, y);
    // t2 = a1^2 - a0 a2
    Fp4.sqr(t, x, a, F);
    Fp4.mul(t, y, a, 0, a, 2 * F);
    Fp4.sub(t, t2, t, x, t, y);
    // norm = a0 t0 + v (a2 t1 + a1 t2)
    Fp4.mul(t, x, a, 2 * F, t, t1);
    Fp4.mul(t, y, a, F, t, t2);
    Fp4.add(t, x, t, x, t, y);
    Fp4.mulV(t, x, t, x);
    Fp4.mul(t, y, a, 0, t, t0);
    Fp4.add(t, x, t, x, t, y);
    Fp4.inv(t, x, t, x);
    Fp4.mul(r, 0, t, t0, t, x);
    Fp4.mul(r, F, t, t1, t, x);
    Fp4.mul(r, 2 * F, t, t2, t, x);
  }

  /**
   * Multiplies f by a line value l0 + l2 w^2 with l0 = (A + B v) and l2 = C in Fq2, given as A, B,
   * C (16 ints each) in {@code line}: 13 Fq2 products instead of 18.
   */
  static void mulLine(int[] f, int[] line) {
    int[] t = new int[5 * F];
    int t0 = 0;
    int t1 = F;
    int t2 = 2 * F;
    int s = 3 * F;
    int l = 4 * F;
    Fp4.mul(t, t0, f, 0, line, 0);
    Fp4.mulFp2(t, t1, f, F, line, 2 * E);
    Fp4.mulFp2(t, t2, f, 2 * F, line, 2 * E);
    // s = (f0 + f2)(l0 + l2)
    Fp2.add(t, l, line, 0, line, 2 * E);
    Fp2.copy(t, l + E, line, E);
    Fp4.add(t, s, f, 0, f, 2 * F);
    Fp4.mul(t, s, t, s, t, l);
    // f1 l0 + v t2 into f1
    Fp4.mul(f, F, f, F, line, 0);
    Fp4.mulV(t, l, t, t2);
    Fp4.add(f, F, f, F, t, l);
    // f2 = s - t0 - t2
    Fp4.sub(t, s, t, s, t, t0);
    Fp4.sub(f, 2 * F, t, s, t, t2);
    // f0 = t0 + v t1
    Fp4.mulV(t, t1, t, t1);
    Fp4.add(f, 0, t, t0, t, t1);
  }

  /** Returns all ones when a equals b, else 0. */
  static int equal(int[] a, int[] b) {
    int x = 0;
    for (int i = 0; i < L; i++) {
      x |= a[i] ^ b[i];
    }
    return ~((x | -x) >> 31);
  }

  /** Sets r to a where mask is all ones. */
  static void cmov(int[] r, int[] a, int ao, int mask) {
    for (int i = 0; i < L; i++) {
      r[i] ^= (r[i] ^ a[ao + i]) & mask;
    }
  }

  /** The 384-byte form: c2 || c1 || c0, each Fq4 as b || a, each Fq2 as a1 || a0. */
  static byte[] encode(int[] a) {
    byte[] out = new byte[BYTES];
    int p = 0;
    for (int i = 2; i >= 0; i--) {
      Fp2.encode(a, F * i + E, out, p);
      Fp2.encode(a, F * i, out, p + 64);
      p += 128;
    }
    return out;
  }

  /** Wipes a secret value. */
  static void wipe(int[] a) {
    if (a != null) {
      java.util.Arrays.fill(a, 0);
    }
  }
}
