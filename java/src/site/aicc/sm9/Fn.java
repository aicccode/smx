package site.aicc.sm9;

import java.math.BigInteger;
import java.security.SecureRandom;
import site.aicc.sm2.util.SystemRandom;

/**
 * Constant-time arithmetic modulo the SM9 group order N on little-endian {@code int[8]} values in
 * [0, N). Used for the secret scalars: master keys, t1 = H1 + ks, t2 = ks / t1 and l = r - h. Only
 * a few products are needed per operation, so this is a compact Montgomery loop.
 */
final class Fn {
  static final BigInteger N_BIG =
      new BigInteger("B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25", 16);

  private static final int L = 8;
  private static final long M = 0xFFFFFFFFL;
  static final int[] N = Fp.words(N_BIG);
  private static final int[] R2 = Fp.words(BigInteger.ONE.shiftLeft(512).mod(N_BIG));
  private static final int[] RAW_ONE = {1, 0, 0, 0, 0, 0, 0, 0};
  private static final BigInteger N_MINUS_2 = N_BIG.subtract(BigInteger.valueOf(2));

  /** -N^-1 mod 2^32. */
  private static final long NP;

  static {
    int inv = N[0];
    for (int i = 0; i < 5; i++) {
      inv *= 2 - N[0] * inv;
    }
    NP = (-inv) & M;
  }

  private Fn() {}

  /** Reads 32 big-endian bytes as words, without any range check. */
  static int[] fromBytes(byte[] in, int off) {
    int[] r = new int[L];
    for (int i = 0; i < L; i++) {
      int p = off + 28 - 4 * i;
      r[i] =
          (in[p] & 0xFF) << 24
              | (in[p + 1] & 0xFF) << 16
              | (in[p + 2] & 0xFF) << 8
              | (in[p + 3] & 0xFF);
    }
    return r;
  }

  /** Writes words as 32 big-endian bytes. */
  static byte[] toBytes(int[] a) {
    byte[] out = new byte[32];
    for (int i = 0; i < L; i++) {
      int p = 28 - 4 * i;
      out[p] = (byte) (a[i] >>> 24);
      out[p + 1] = (byte) (a[i] >>> 16);
      out[p + 2] = (byte) (a[i] >>> 8);
      out[p + 3] = (byte) a[i];
    }
    return out;
  }

  /** Returns all ones when 1 <= a <= N - 1, else 0, with no early exit. */
  static int isValidScalar(int[] a) {
    long d = 0;
    int x = 0;
    for (int i = 0; i < L; i++) {
      d += (a[i] & M) - (N[i] & M);
      d >>= 32;
      x |= a[i];
    }
    int nonZero = (x | -x) >> 31;
    return (int) d & nonZero;
  }

  /** Returns all ones when a is zero, else 0. */
  static int isZero(int[] a) {
    int x = 0;
    for (int i = 0; i < L; i++) {
      x |= a[i];
    }
    return ~((x | -x) >> 31);
  }

  /** Returns (a + b) mod N for a, b in [0, N). */
  static int[] add(int[] a, int[] b) {
    int[] s = new int[L];
    long c = 0;
    for (int i = 0; i < L; i++) {
      c += (a[i] & M) + (b[i] & M);
      s[i] = (int) c;
      c >>>= 32;
    }
    return subtractNIfNeeded(s, c);
  }

  /** Returns (a - b) mod N for a, b in [0, N). */
  static int[] sub(int[] a, int[] b) {
    int[] t = new int[L];
    long d = 0;
    for (int i = 0; i < L; i++) {
      d += (a[i] & M) - (b[i] & M);
      t[i] = (int) d;
      d >>= 32;
    }
    long mask = d & M;
    long c = 0;
    for (int i = 0; i < L; i++) {
      c += (t[i] & M) + (N[i] & mask);
      t[i] = (int) c;
      c >>>= 32;
    }
    return t;
  }

  /** Reduces a public value given as a BigInteger in [0, N) to words. */
  static int[] fromBigInteger(BigInteger v) {
    return Fp.words(v.mod(N_BIG));
  }

  /** Returns a * b mod N for a, b in [0, N). */
  static int[] mul(int[] a, int[] b) {
    return mont(mont(a, b), R2);
  }

  /** Returns a^-1 mod N (0 for 0) by Fermat; the exponent is public, so the flow is fixed. */
  static int[] inv(int[] a) {
    int[] base = mont(a, R2);
    int[] acc = mont(RAW_ONE, R2);
    for (int i = N_MINUS_2.bitLength() - 1; i >= 0; i--) {
      acc = mont(acc, acc);
      if (N_MINUS_2.testBit(i)) {
        acc = mont(acc, base);
      }
    }
    return mont(acc, RAW_ONE);
  }

  /** Returns a * b / 2^256 mod N (CIOS). */
  private static int[] mont(int[] a, int[] b) {
    long[] t = new long[L + 2];
    for (int i = 0; i < L; i++) {
      long bi = b[i] & M;
      long c = 0;
      for (int j = 0; j < L; j++) {
        c += t[j] + (a[j] & M) * bi;
        t[j] = c & M;
        c >>>= 32;
      }
      c += t[L];
      t[L] = c & M;
      t[L + 1] = c >>> 32;
      long m = (t[0] * NP) & M;
      c = (t[0] + m * (N[0] & M)) >>> 32;
      for (int j = 1; j < L; j++) {
        c += t[j] + m * (N[j] & M);
        t[j - 1] = c & M;
        c >>>= 32;
      }
      c += t[L];
      t[L - 1] = c & M;
      t[L] = t[L + 1] + (c >>> 32);
    }
    int[] s = new int[L];
    for (int i = 0; i < L; i++) {
      s[i] = (int) t[i];
    }
    return subtractNIfNeeded(s, t[L]);
  }

  private static int[] subtractNIfNeeded(int[] s, long carry) {
    int[] t = new int[L];
    long d = 0;
    for (int i = 0; i < L; i++) {
      d += (s[i] & M) - (N[i] & M);
      t[i] = (int) d;
      d >>= 32;
    }
    int keep = (int) (d & (carry - 1));
    for (int i = 0; i < L; i++) {
      t[i] = (s[i] & keep) | (t[i] & ~keep);
    }
    return t;
  }

  /**
   * Draws a scalar uniform in [1, N - 1] by rejection sampling: no modulo bias.
   *
   * @throws IllegalStateException when the random source fails
   */
  static int[] random(SecureRandom rng) {
    byte[] buf = new byte[32];
    for (int attempt = 0; attempt < 256; attempt++) {
      SystemRandom.fill(rng, buf);
      int[] k = fromBytes(buf, 0);
      java.util.Arrays.fill(buf, (byte) 0);
      if (isValidScalar(k) != 0) {
        return k;
      }
    }
    throw new IllegalStateException("Secure random source failed");
  }
}
