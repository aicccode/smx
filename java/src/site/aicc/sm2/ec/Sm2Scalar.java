package site.aicc.sm2.ec;

import java.math.BigInteger;

/**
 * Constant-time arithmetic modulo the SM2 group order n, on little-endian {@code int[8]} values in
 * [0, n). Used for the secret computations of signing and key exchange. Only a few multiplications
 * are needed per operation, so this favors a compact Montgomery loop over unrolled code.
 */
final class Sm2Scalar {
  static final BigInteger N_BIG =
      new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
  private static final int[] N = Sm2Field.fromBigInteger(N_BIG);
  private static final long M = 0xFFFFFFFFL;

  /** -n^-1 mod 2^32. */
  private static final int N_PRIME;

  /** R^2 mod n with R = 2^256; converts into Montgomery form. */
  private static final int[] R2 = Sm2Field.fromBigInteger(BigInteger.ONE.shiftLeft(512).mod(N_BIG));

  private static final Sm2ModInverse INVERSE = new Sm2ModInverse(N);

  static {
    int inv = N[0];
    for (int i = 0; i < 4; i++) {
      inv *= 2 - N[0] * inv;
    }
    N_PRIME = -inv;
  }

  private Sm2Scalar() {}

  /** Returns true when the public-range check {@code 0 <= v < n} holds. */
  static boolean inRange(BigInteger v) {
    return v.signum() >= 0 && v.compareTo(N_BIG) < 0;
  }

  /** Returns all ones when {@code a < n}, else 0, with no early exit. */
  static int isBelowN(int[] a) {
    long c = 0;
    for (int i = 0; i < 8; i++) {
      c += (a[i] & M) - (N[i] & M);
      c >>= 32;
    }
    return (int) c;
  }

  /** Sets r = a + b modulo 2^256, leaving all ones in r when the sum overflows 256 bits. */
  static void addUnreduced(int[] r, int[] a, int[] b) {
    long c = 0;
    for (int i = 0; i < 8; i++) {
      c += (a[i] & M) + (b[i] & M);
      r[i] = (int) c;
      c >>>= 32;
    }
    int overflow = -(int) c;
    for (int i = 0; i < 8; i++) {
      r[i] |= overflow;
    }
  }

  /** Sets {@code r = a * b / 2^256 mod n}; r may alias a or b. */
  private static void montMul(int[] r, int[] a, int[] b) {
    long[] t = new long[10];
    for (int i = 0; i < 8; i++) {
      long bi = b[i] & M;
      long c = 0;
      for (int j = 0; j < 8; j++) {
        c += (a[j] & M) * bi + t[j];
        t[j] = c & M;
        c >>>= 32;
      }
      c += t[8];
      t[8] = c & M;
      t[9] = c >>> 32;
      long q = (t[0] * N_PRIME) & M;
      c = (q * (N[0] & M) + t[0]) >>> 32;
      for (int j = 1; j < 8; j++) {
        c += q * (N[j] & M) + t[j];
        t[j - 1] = c & M;
        c >>>= 32;
      }
      c += t[8];
      t[7] = c & M;
      t[8] = t[9] + (c >>> 32);
    }
    // The value t is below 2n: subtract n once under a mask.
    long borrow = 0;
    int[] w = new int[8];
    for (int i = 0; i < 8; i++) {
      borrow += t[i] - (N[i] & M);
      w[i] = (int) borrow;
      borrow >>= 32;
    }
    int keep = (int) (t[8] + borrow) >> 31;
    for (int i = 0; i < 8; i++) {
      r[i] = ((int) t[i] & keep) | (w[i] & ~keep);
    }
  }

  /** Sets {@code r = a * b mod n}. */
  static void mul(int[] r, int[] a, int[] b) {
    int[] t = new int[8];
    montMul(t, a, b);
    montMul(r, t, R2);
  }

  /** Sets {@code r = a + b mod n}; r may alias a or b. */
  static void add(int[] r, int[] a, int[] b) {
    long c = 0;
    int[] v = new int[8];
    for (int i = 0; i < 8; i++) {
      c += (a[i] & M) + (b[i] & M);
      v[i] = (int) c;
      c >>>= 32;
    }
    subIfAtLeastN(r, v, (int) c);
  }

  /** Sets {@code r = a - b mod n}; r may alias a or b. */
  static void sub(int[] r, int[] a, int[] b) {
    long c = 0;
    int[] v = new int[8];
    for (int i = 0; i < 8; i++) {
      c += (a[i] & M) - (b[i] & M);
      v[i] = (int) c;
      c >>= 32;
    }
    long mask = c & M;
    long carry = 0;
    for (int i = 0; i < 8; i++) {
      carry += (v[i] & M) + ((N[i] & M) & mask);
      r[i] = (int) carry;
      carry >>>= 32;
    }
  }

  /** Reduces {@code carry * 2^256 + v}, known to be below 2n, into r. */
  private static void subIfAtLeastN(int[] r, int[] v, int carry) {
    long c = 0;
    int[] w = new int[8];
    for (int i = 0; i < 8; i++) {
      c += (v[i] & M) - (N[i] & M);
      w[i] = (int) c;
      c >>= 32;
    }
    int keep = (int) (carry + c) >> 31;
    for (int i = 0; i < 8; i++) {
      r[i] = (v[i] & keep) | (w[i] & ~keep);
    }
  }

  /** Reduces any value below 2^256 (necessarily below 2n) into [0, n). */
  static void reduceOnce(int[] r, int[] a) {
    subIfAtLeastN(r, a, 0);
  }

  /** Sets {@code r = a^-1 mod n}, or 0 when a is 0. */
  static void invert(int[] r, int[] a) {
    INVERSE.invert(r, a);
  }
}
