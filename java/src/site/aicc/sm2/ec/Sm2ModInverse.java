package site.aicc.sm2.ec;

/**
 * Constant-time modular inversion for the two SM2 moduli (the field prime and the group order).
 *
 * <p>This is the safegcd algorithm of Bernstein and Yang, in the batched "divsteps" form used by
 * libsecp256k1's {@code modinv32}: numbers are 9 signed 30-bit limbs and 600 divsteps (above the
 * proven bound of 590 for 256-bit moduli) always run, so the operation count does not depend on the
 * input. It runs several times faster than a Fermat exponentiation, and it fits {@code long}
 * arithmetic without a wide multiply.
 */
final class Sm2ModInverse {
  private static final int M30 = 0x3FFFFFFF;
  private static final int BATCHES = 20;

  private final int[] modulus;
  private final int modulusInv30;

  /** Creates an inverter for an odd modulus given as little-endian 32-bit limbs. */
  Sm2ModInverse(int[] modulusLimbs) {
    this.modulus = toSigned30(modulusLimbs);
    // Newton iteration for modulus^-1 mod 2^30.
    int inv = modulus[0];
    for (int i = 0; i < 4; i++) {
      inv *= 2 - modulus[0] * inv;
    }
    this.modulusInv30 = inv & M30;
  }

  /** Sets {@code r = a^-1 mod modulus}, or 0 when {@code a == 0}. a must be below the modulus. */
  void invert(int[] r, int[] a) {
    int[] d = new int[9];
    int[] e = new int[9];
    int[] f = modulus.clone();
    int[] g = toSigned30(a);
    e[0] = 1;
    int zeta = -1;
    for (int batch = 0; batch < BATCHES; batch++) {
      // Inlined divsteps; the transition matrix is (u v / q r) scaled by 2^30.
      int u = 1;
      int v = 0;
      int q = 0;
      int s = 1;
      int f0 = f[0];
      int g0 = g[0];
      for (int i = 0; i < 30; i++) {
        int c1 = zeta >> 31;
        int c2 = -(g0 & 1);
        int x = (f0 ^ c1) - c1;
        int y = (u ^ c1) - c1;
        int z = (v ^ c1) - c1;
        g0 += x & c2;
        q += y & c2;
        s += z & c2;
        c1 &= c2;
        zeta = (zeta ^ c1) - 1;
        f0 += g0 & c1;
        u += q & c1;
        v += s & c1;
        g0 >>= 1;
        u <<= 1;
        v <<= 1;
      }
      updateDe(d, e, u, v, q, s);
      updateFg(f, g, u, v, q, s);
    }
    normalize(r, d, f[8]);
  }

  private void updateDe(int[] d, int[] e, long u, long v, long q, long s) {
    int sd = d[8] >> 31;
    int se = e[8] >> 31;
    int md = ((int) u & sd) + ((int) v & se);
    int me = ((int) q & sd) + ((int) s & se);
    long cd = u * d[0] + v * e[0];
    long ce = q * d[0] + s * e[0];
    md -= (modulusInv30 * (int) cd + md) & M30;
    me -= (modulusInv30 * (int) ce + me) & M30;
    long m0 = modulus[0];
    cd += m0 * md;
    ce += m0 * me;
    cd >>= 30;
    ce >>= 30;
    for (int i = 1; i < 9; i++) {
      long di = d[i];
      long ei = e[i];
      long mi = modulus[i];
      cd += u * di + v * ei + mi * md;
      ce += q * di + s * ei + mi * me;
      d[i - 1] = (int) cd & M30;
      e[i - 1] = (int) ce & M30;
      cd >>= 30;
      ce >>= 30;
    }
    d[8] = (int) cd;
    e[8] = (int) ce;
  }

  private static void updateFg(int[] f, int[] g, long u, long v, long q, long s) {
    long cf = u * f[0] + v * g[0];
    long cg = q * f[0] + s * g[0];
    cf >>= 30;
    cg >>= 30;
    for (int i = 1; i < 9; i++) {
      long fi = f[i];
      long gi = g[i];
      cf += u * fi + v * gi;
      cg += q * fi + s * gi;
      f[i - 1] = (int) cf & M30;
      g[i - 1] = (int) cg & M30;
      cf >>= 30;
      cg >>= 30;
    }
    f[8] = (int) cf;
    g[8] = (int) cg;
  }

  /** Brings d from (-2*modulus, modulus) to [0, modulus), negating it when f ended at -1. */
  private void normalize(int[] r, int[] d, int sign) {
    int condAdd = d[8] >> 31;
    int condNegate = sign >> 31;
    int[] t = new int[9];
    for (int i = 0; i < 9; i++) {
      int v = d[i] + (modulus[i] & condAdd);
      t[i] = (v ^ condNegate) - condNegate;
    }
    propagate(t);
    condAdd = t[8] >> 31;
    for (int i = 0; i < 9; i++) {
      t[i] += modulus[i] & condAdd;
    }
    propagate(t);
    fromSigned30(r, t);
  }

  private static void propagate(int[] t) {
    for (int i = 0; i < 8; i++) {
      t[i + 1] += t[i] >> 30;
      t[i] &= M30;
    }
  }

  private static int[] toSigned30(int[] a) {
    int[] r = new int[9];
    long acc = 0;
    int bits = 0;
    int j = 0;
    for (int i = 0; i < 8; i++) {
      acc |= (a[i] & 0xFFFFFFFFL) << bits;
      bits += 32;
      while (bits >= 30) {
        r[j++] = (int) acc & M30;
        acc >>>= 30;
        bits -= 30;
      }
    }
    r[j] = (int) acc;
    return r;
  }

  private static void fromSigned30(int[] r, int[] t) {
    long acc = 0;
    int bits = 0;
    int j = 0;
    for (int i = 0; i < 9 && j < 8; i++) {
      acc |= (t[i] & 0xFFFFFFFFL) << bits;
      bits += 30;
      if (bits >= 32) {
        r[j++] = (int) acc;
        acc >>>= 32;
        bits -= 32;
      }
    }
  }
}
