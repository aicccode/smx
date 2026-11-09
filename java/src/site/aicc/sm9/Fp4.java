package site.aicc.sm9;

/**
 * Arithmetic in Fq4 = Fq2[v] / (v^2 - u). An element a + b v is 32 ints at an offset: a then b,
 * each an {@link Fp2} element. Results may alias inputs.
 */
final class Fp4 {
  /** Ints per element. */
  static final int L = 2 * Fp2.L;

  private static final int H = Fp2.L;

  private Fp4() {}

  static void add(int[] r, int ro, int[] a, int ao, int[] b, int bo) {
    Fp2.add(r, ro, a, ao, b, bo);
    Fp2.add(r, ro + H, a, ao + H, b, bo + H);
  }

  static void sub(int[] r, int ro, int[] a, int ao, int[] b, int bo) {
    Fp2.sub(r, ro, a, ao, b, bo);
    Fp2.sub(r, ro + H, a, ao + H, b, bo + H);
  }

  static void neg(int[] r, int ro, int[] a, int ao) {
    Fp2.neg(r, ro, a, ao);
    Fp2.neg(r, ro + H, a, ao + H);
  }

  static void dbl(int[] r, int ro, int[] a, int ao) {
    Fp2.dbl(r, ro, a, ao);
    Fp2.dbl(r, ro + H, a, ao + H);
  }

  /** Sets r = a - b v, the q^2-power Frobenius of Fq4. */
  static void conj(int[] r, int ro, int[] a, int ao) {
    Fp2.copy(r, ro, a, ao);
    Fp2.neg(r, ro + H, a, ao + H);
  }

  static void copy(int[] r, int ro, int[] a, int ao) {
    System.arraycopy(a, ao, r, ro, L);
  }

  static void setZero(int[] r, int ro) {
    for (int i = 0; i < L; i++) {
      r[ro + i] = 0;
    }
  }

  static void setOne(int[] r, int ro) {
    setZero(r, ro);
    Fp.setOne(r, ro);
  }

  /** (a + b v)(c + d v) = a c + b d u + ((a + b)(c + d) - a c - b d) v. */
  static void mul(int[] r, int ro, int[] x, int xo, int[] y, int yo) {
    int[] t = new int[4 * H];
    Fp2.mul(t, 0, x, xo, y, yo);
    Fp2.mul(t, H, x, xo + H, y, yo + H);
    Fp2.add(t, 2 * H, x, xo, x, xo + H);
    Fp2.add(t, 3 * H, y, yo, y, yo + H);
    Fp2.mul(t, 2 * H, t, 2 * H, t, 3 * H);
    Fp2.sub(t, 2 * H, t, 2 * H, t, 0);
    Fp2.sub(r, ro + H, t, 2 * H, t, H);
    Fp2.mulU(t, H, t, H);
    Fp2.add(r, ro, t, 0, t, H);
  }

  /** (a + b v)^2 = (a + b)(a + b u) - a b - a b u + 2 a b v. */
  static void sqr(int[] r, int ro, int[] x, int xo) {
    int[] t = new int[3 * H];
    Fp2.mul(t, 0, x, xo, x, xo + H);
    Fp2.add(t, H, x, xo, x, xo + H);
    Fp2.mulU(t, 2 * H, x, xo + H);
    Fp2.add(t, 2 * H, t, 2 * H, x, xo);
    Fp2.mul(t, H, t, H, t, 2 * H);
    Fp2.sub(t, H, t, H, t, 0);
    Fp2.mulU(t, 2 * H, t, 0);
    Fp2.sub(r, ro, t, H, t, 2 * H);
    Fp2.dbl(r, ro + H, t, 0);
  }

  /** Multiplies by an Fq2 element k at {@code k[ko]}. */
  static void mulFp2(int[] r, int ro, int[] x, int xo, int[] k, int ko) {
    Fp2.mul(r, ro, x, xo, k, ko);
    Fp2.mul(r, ro + H, x, xo + H, k, ko);
  }

  /** (a + b v) v = b u + a v. */
  static void mulV(int[] r, int ro, int[] x, int xo) {
    int[] t = new int[H];
    Fp2.mulU(t, 0, x, xo + H);
    Fp2.copy(r, ro + H, x, xo);
    Fp2.copy(r, ro, t, 0);
  }

  /** 1 / (a + b v) = (a - b v) / (a^2 - b^2 u); 0 maps to 0. */
  static void inv(int[] r, int ro, int[] x, int xo) {
    int[] t = new int[2 * H];
    Fp2.sqr(t, 0, x, xo);
    Fp2.sqr(t, H, x, xo + H);
    Fp2.mulU(t, H, t, H);
    Fp2.sub(t, 0, t, 0, t, H);
    Fp2.inv(t, 0, t, 0);
    Fp2.mul(t, H, x, xo + H, t, 0);
    Fp2.mul(r, ro, x, xo, t, 0);
    Fp2.neg(r, ro + H, t, H);
  }

  static void cmov(int[] r, int ro, int[] a, int ao, int mask) {
    Fp2.cmov(r, ro, a, ao, mask);
    Fp2.cmov(r, ro + H, a, ao + H, mask);
  }
}
