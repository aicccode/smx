package site.aicc.sm9;

import java.math.BigInteger;

/**
 * Arithmetic in the SM9 base field Fq, q a 256-bit prime of no special form, in Montgomery form
 * with R = 2^256.
 *
 * <p>An element is 8 little-endian 32-bit limbs at an offset of an {@code int[]}, always fully
 * reduced to [0, q). Every operation runs in time independent of the values: carries are handled
 * arithmetically and results are chosen with masks. Java 8 has no 64x64-bit wide multiply, so limbs
 * are 32 bits and products are formed in {@code long}; {@link #mul} is fully unrolled with every
 * limb in a local, which removes bounds checks and loop overhead from the hottest code of SM9.
 */
final class Fp {
  static final BigInteger Q_BIG =
      new BigInteger("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D", 16);

  /** Limbs per element. */
  static final int L = 8;

  private static final long M = 0xFFFFFFFFL;
  private static final long Q0 = 0xE351457DL;
  private static final long Q1 = 0xE56F9B27L;
  private static final long Q2 = 0x1A7AEEDBL;
  private static final long Q3 = 0x21F2934BL;
  private static final long Q4 = 0xF58EC745L;
  private static final long Q5 = 0xD603AB4FL;
  private static final long Q6 = 0x02A3A6F1L;
  private static final long Q7 = 0xB6400000L;

  /** -q^-1 mod 2^32. */
  private static final long NP = 0x2F2EE42BL;

  static final int[] Q = words(Q_BIG);
  private static final int[] R2 = words(BigInteger.ONE.shiftLeft(512).mod(Q_BIG));
  private static final int[] RAW_ONE = {1, 0, 0, 0, 0, 0, 0, 0};

  /** 1 in Montgomery form. */
  static final int[] ONE = words(BigInteger.ONE.shiftLeft(256).mod(Q_BIG));

  private static final BigInteger Q_MINUS_2 = Q_BIG.subtract(BigInteger.valueOf(2));

  private Fp() {}

  /** Little-endian 32-bit words of a value below 2^256 (no Montgomery conversion). */
  static int[] words(BigInteger v) {
    int[] r = new int[L];
    for (int i = 0; i < L; i++) {
      r[i] = v.shiftRight(32 * i).intValue();
    }
    return r;
  }

  /** The Montgomery form of a public value in [0, q). */
  static int[] fromBigInteger(BigInteger v) {
    int[] r = words(v.mod(Q_BIG));
    mul(r, 0, r, 0, R2, 0);
    return r;
  }

  /** The value of a Montgomery-form element, for tests and constants only. */
  static BigInteger toBigInteger(int[] a, int ao) {
    byte[] b = new byte[32];
    encode(a, ao, b, 0);
    return new BigInteger(1, b);
  }

  /** Sets {@code r = a * b / 2^256 mod q}; r may alias a or b. Inputs must be below q. */
  static void mul(int[] r, int ro, int[] a, int ao, int[] b, int bo) {
    long a0 = a[ao + 0] & M;
    long a1 = a[ao + 1] & M;
    long a2 = a[ao + 2] & M;
    long a3 = a[ao + 3] & M;
    long a4 = a[ao + 4] & M;
    long a5 = a[ao + 5] & M;
    long a6 = a[ao + 6] & M;
    long a7 = a[ao + 7] & M;
    long b0 = b[bo + 0] & M;
    long b1 = b[bo + 1] & M;
    long b2 = b[bo + 2] & M;
    long b3 = b[bo + 3] & M;
    long b4 = b[bo + 4] & M;
    long b5 = b[bo + 5] & M;
    long b6 = b[bo + 6] & M;
    long b7 = b[bo + 7] & M;
    long c;
    c = a0 * b0;
    long z0 = c & M;
    c = (c >>> 32) + a1 * b0;
    long z1 = c & M;
    c = (c >>> 32) + a2 * b0;
    long z2 = c & M;
    c = (c >>> 32) + a3 * b0;
    long z3 = c & M;
    c = (c >>> 32) + a4 * b0;
    long z4 = c & M;
    c = (c >>> 32) + a5 * b0;
    long z5 = c & M;
    c = (c >>> 32) + a6 * b0;
    long z6 = c & M;
    c = (c >>> 32) + a7 * b0;
    long z7 = c & M;
    long z8 = c >>> 32;
    c = a0 * b1 + z1;
    z1 = c & M;
    c = (c >>> 32) + a1 * b1 + z2;
    z2 = c & M;
    c = (c >>> 32) + a2 * b1 + z3;
    z3 = c & M;
    c = (c >>> 32) + a3 * b1 + z4;
    z4 = c & M;
    c = (c >>> 32) + a4 * b1 + z5;
    z5 = c & M;
    c = (c >>> 32) + a5 * b1 + z6;
    z6 = c & M;
    c = (c >>> 32) + a6 * b1 + z7;
    z7 = c & M;
    c = (c >>> 32) + a7 * b1 + z8;
    z8 = c & M;
    long z9 = c >>> 32;
    c = a0 * b2 + z2;
    z2 = c & M;
    c = (c >>> 32) + a1 * b2 + z3;
    z3 = c & M;
    c = (c >>> 32) + a2 * b2 + z4;
    z4 = c & M;
    c = (c >>> 32) + a3 * b2 + z5;
    z5 = c & M;
    c = (c >>> 32) + a4 * b2 + z6;
    z6 = c & M;
    c = (c >>> 32) + a5 * b2 + z7;
    z7 = c & M;
    c = (c >>> 32) + a6 * b2 + z8;
    z8 = c & M;
    c = (c >>> 32) + a7 * b2 + z9;
    z9 = c & M;
    long z10 = c >>> 32;
    c = a0 * b3 + z3;
    z3 = c & M;
    c = (c >>> 32) + a1 * b3 + z4;
    z4 = c & M;
    c = (c >>> 32) + a2 * b3 + z5;
    z5 = c & M;
    c = (c >>> 32) + a3 * b3 + z6;
    z6 = c & M;
    c = (c >>> 32) + a4 * b3 + z7;
    z7 = c & M;
    c = (c >>> 32) + a5 * b3 + z8;
    z8 = c & M;
    c = (c >>> 32) + a6 * b3 + z9;
    z9 = c & M;
    c = (c >>> 32) + a7 * b3 + z10;
    z10 = c & M;
    long z11 = c >>> 32;
    c = a0 * b4 + z4;
    z4 = c & M;
    c = (c >>> 32) + a1 * b4 + z5;
    z5 = c & M;
    c = (c >>> 32) + a2 * b4 + z6;
    z6 = c & M;
    c = (c >>> 32) + a3 * b4 + z7;
    z7 = c & M;
    c = (c >>> 32) + a4 * b4 + z8;
    z8 = c & M;
    c = (c >>> 32) + a5 * b4 + z9;
    z9 = c & M;
    c = (c >>> 32) + a6 * b4 + z10;
    z10 = c & M;
    c = (c >>> 32) + a7 * b4 + z11;
    z11 = c & M;
    long z12 = c >>> 32;
    c = a0 * b5 + z5;
    z5 = c & M;
    c = (c >>> 32) + a1 * b5 + z6;
    z6 = c & M;
    c = (c >>> 32) + a2 * b5 + z7;
    z7 = c & M;
    c = (c >>> 32) + a3 * b5 + z8;
    z8 = c & M;
    c = (c >>> 32) + a4 * b5 + z9;
    z9 = c & M;
    c = (c >>> 32) + a5 * b5 + z10;
    z10 = c & M;
    c = (c >>> 32) + a6 * b5 + z11;
    z11 = c & M;
    c = (c >>> 32) + a7 * b5 + z12;
    z12 = c & M;
    long z13 = c >>> 32;
    c = a0 * b6 + z6;
    z6 = c & M;
    c = (c >>> 32) + a1 * b6 + z7;
    z7 = c & M;
    c = (c >>> 32) + a2 * b6 + z8;
    z8 = c & M;
    c = (c >>> 32) + a3 * b6 + z9;
    z9 = c & M;
    c = (c >>> 32) + a4 * b6 + z10;
    z10 = c & M;
    c = (c >>> 32) + a5 * b6 + z11;
    z11 = c & M;
    c = (c >>> 32) + a6 * b6 + z12;
    z12 = c & M;
    c = (c >>> 32) + a7 * b6 + z13;
    z13 = c & M;
    long z14 = c >>> 32;
    c = a0 * b7 + z7;
    z7 = c & M;
    c = (c >>> 32) + a1 * b7 + z8;
    z8 = c & M;
    c = (c >>> 32) + a2 * b7 + z9;
    z9 = c & M;
    c = (c >>> 32) + a3 * b7 + z10;
    z10 = c & M;
    c = (c >>> 32) + a4 * b7 + z11;
    z11 = c & M;
    c = (c >>> 32) + a5 * b7 + z12;
    z12 = c & M;
    c = (c >>> 32) + a6 * b7 + z13;
    z13 = c & M;
    c = (c >>> 32) + a7 * b7 + z14;
    z14 = c & M;
    long z15 = c >>> 32;
    reduce(r, ro, z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15);
  }

  /** Montgomery reduction of a 512-bit value given as 16 32-bit words, then one masked subtract. */
  private static void reduce(
      int[] r,
      int ro,
      long z0,
      long z1,
      long z2,
      long z3,
      long z4,
      long z5,
      long z6,
      long z7,
      long z8,
      long z9,
      long z10,
      long z11,
      long z12,
      long z13,
      long z14,
      long z15) {
    long c;
    long m;
    long carry = 0;
    m = (z0 * NP) & M;
    c = (z0 + m * Q0) >>> 32;
    c += z1 + m * Q1;
    z1 = c & M;
    c >>>= 32;
    c += z2 + m * Q2;
    z2 = c & M;
    c >>>= 32;
    c += z3 + m * Q3;
    z3 = c & M;
    c >>>= 32;
    c += z4 + m * Q4;
    z4 = c & M;
    c >>>= 32;
    c += z5 + m * Q5;
    z5 = c & M;
    c >>>= 32;
    c += z6 + m * Q6;
    z6 = c & M;
    c >>>= 32;
    c += z7 + m * Q7;
    z7 = c & M;
    c >>>= 32;
    c += z8 + carry;
    z8 = c & M;
    carry = c >>> 32;
    m = (z1 * NP) & M;
    c = (z1 + m * Q0) >>> 32;
    c += z2 + m * Q1;
    z2 = c & M;
    c >>>= 32;
    c += z3 + m * Q2;
    z3 = c & M;
    c >>>= 32;
    c += z4 + m * Q3;
    z4 = c & M;
    c >>>= 32;
    c += z5 + m * Q4;
    z5 = c & M;
    c >>>= 32;
    c += z6 + m * Q5;
    z6 = c & M;
    c >>>= 32;
    c += z7 + m * Q6;
    z7 = c & M;
    c >>>= 32;
    c += z8 + m * Q7;
    z8 = c & M;
    c >>>= 32;
    c += z9 + carry;
    z9 = c & M;
    carry = c >>> 32;
    m = (z2 * NP) & M;
    c = (z2 + m * Q0) >>> 32;
    c += z3 + m * Q1;
    z3 = c & M;
    c >>>= 32;
    c += z4 + m * Q2;
    z4 = c & M;
    c >>>= 32;
    c += z5 + m * Q3;
    z5 = c & M;
    c >>>= 32;
    c += z6 + m * Q4;
    z6 = c & M;
    c >>>= 32;
    c += z7 + m * Q5;
    z7 = c & M;
    c >>>= 32;
    c += z8 + m * Q6;
    z8 = c & M;
    c >>>= 32;
    c += z9 + m * Q7;
    z9 = c & M;
    c >>>= 32;
    c += z10 + carry;
    z10 = c & M;
    carry = c >>> 32;
    m = (z3 * NP) & M;
    c = (z3 + m * Q0) >>> 32;
    c += z4 + m * Q1;
    z4 = c & M;
    c >>>= 32;
    c += z5 + m * Q2;
    z5 = c & M;
    c >>>= 32;
    c += z6 + m * Q3;
    z6 = c & M;
    c >>>= 32;
    c += z7 + m * Q4;
    z7 = c & M;
    c >>>= 32;
    c += z8 + m * Q5;
    z8 = c & M;
    c >>>= 32;
    c += z9 + m * Q6;
    z9 = c & M;
    c >>>= 32;
    c += z10 + m * Q7;
    z10 = c & M;
    c >>>= 32;
    c += z11 + carry;
    z11 = c & M;
    carry = c >>> 32;
    m = (z4 * NP) & M;
    c = (z4 + m * Q0) >>> 32;
    c += z5 + m * Q1;
    z5 = c & M;
    c >>>= 32;
    c += z6 + m * Q2;
    z6 = c & M;
    c >>>= 32;
    c += z7 + m * Q3;
    z7 = c & M;
    c >>>= 32;
    c += z8 + m * Q4;
    z8 = c & M;
    c >>>= 32;
    c += z9 + m * Q5;
    z9 = c & M;
    c >>>= 32;
    c += z10 + m * Q6;
    z10 = c & M;
    c >>>= 32;
    c += z11 + m * Q7;
    z11 = c & M;
    c >>>= 32;
    c += z12 + carry;
    z12 = c & M;
    carry = c >>> 32;
    m = (z5 * NP) & M;
    c = (z5 + m * Q0) >>> 32;
    c += z6 + m * Q1;
    z6 = c & M;
    c >>>= 32;
    c += z7 + m * Q2;
    z7 = c & M;
    c >>>= 32;
    c += z8 + m * Q3;
    z8 = c & M;
    c >>>= 32;
    c += z9 + m * Q4;
    z9 = c & M;
    c >>>= 32;
    c += z10 + m * Q5;
    z10 = c & M;
    c >>>= 32;
    c += z11 + m * Q6;
    z11 = c & M;
    c >>>= 32;
    c += z12 + m * Q7;
    z12 = c & M;
    c >>>= 32;
    c += z13 + carry;
    z13 = c & M;
    carry = c >>> 32;
    m = (z6 * NP) & M;
    c = (z6 + m * Q0) >>> 32;
    c += z7 + m * Q1;
    z7 = c & M;
    c >>>= 32;
    c += z8 + m * Q2;
    z8 = c & M;
    c >>>= 32;
    c += z9 + m * Q3;
    z9 = c & M;
    c >>>= 32;
    c += z10 + m * Q4;
    z10 = c & M;
    c >>>= 32;
    c += z11 + m * Q5;
    z11 = c & M;
    c >>>= 32;
    c += z12 + m * Q6;
    z12 = c & M;
    c >>>= 32;
    c += z13 + m * Q7;
    z13 = c & M;
    c >>>= 32;
    c += z14 + carry;
    z14 = c & M;
    carry = c >>> 32;
    m = (z7 * NP) & M;
    c = (z7 + m * Q0) >>> 32;
    c += z8 + m * Q1;
    z8 = c & M;
    c >>>= 32;
    c += z9 + m * Q2;
    z9 = c & M;
    c >>>= 32;
    c += z10 + m * Q3;
    z10 = c & M;
    c >>>= 32;
    c += z11 + m * Q4;
    z11 = c & M;
    c >>>= 32;
    c += z12 + m * Q5;
    z12 = c & M;
    c >>>= 32;
    c += z13 + m * Q6;
    z13 = c & M;
    c >>>= 32;
    c += z14 + m * Q7;
    z14 = c & M;
    c >>>= 32;
    c += z15 + carry;
    z15 = c & M;
    carry = c >>> 32;
    long d = z8 - Q0;
    long d0 = d & M;
    d = (d >> 32) + z9 - Q1;
    long d1 = d & M;
    d = (d >> 32) + z10 - Q2;
    long d2 = d & M;
    d = (d >> 32) + z11 - Q3;
    long d3 = d & M;
    d = (d >> 32) + z12 - Q4;
    long d4 = d & M;
    d = (d >> 32) + z13 - Q5;
    long d5 = d & M;
    d = (d >> 32) + z14 - Q6;
    long d6 = d & M;
    d = (d >> 32) + z15 - Q7;
    long d7 = d & M;
    long keep = (d >> 32) & (carry - 1);
    r[ro + 0] = (int) ((z8 & keep) | (d0 & ~keep));
    r[ro + 1] = (int) ((z9 & keep) | (d1 & ~keep));
    r[ro + 2] = (int) ((z10 & keep) | (d2 & ~keep));
    r[ro + 3] = (int) ((z11 & keep) | (d3 & ~keep));
    r[ro + 4] = (int) ((z12 & keep) | (d4 & ~keep));
    r[ro + 5] = (int) ((z13 & keep) | (d5 & ~keep));
    r[ro + 6] = (int) ((z14 & keep) | (d6 & ~keep));
    r[ro + 7] = (int) ((z15 & keep) | (d7 & ~keep));
  }

  /** Sets {@code r = a^2}. */
  static void sqr(int[] r, int ro, int[] a, int ao) {
    mul(r, ro, a, ao, a, ao);
  }

  /** Sets {@code r = a + b mod q}. */
  static void add(int[] r, int ro, int[] a, int ao, int[] b, int bo) {
    long c = (a[ao] & M) + (b[bo] & M);
    long s0 = c & M;
    c = (c >>> 32) + (a[ao + 1] & M) + (b[bo + 1] & M);
    long s1 = c & M;
    c = (c >>> 32) + (a[ao + 2] & M) + (b[bo + 2] & M);
    long s2 = c & M;
    c = (c >>> 32) + (a[ao + 3] & M) + (b[bo + 3] & M);
    long s3 = c & M;
    c = (c >>> 32) + (a[ao + 4] & M) + (b[bo + 4] & M);
    long s4 = c & M;
    c = (c >>> 32) + (a[ao + 5] & M) + (b[bo + 5] & M);
    long s5 = c & M;
    c = (c >>> 32) + (a[ao + 6] & M) + (b[bo + 6] & M);
    long s6 = c & M;
    c = (c >>> 32) + (a[ao + 7] & M) + (b[bo + 7] & M);
    long s7 = c & M;
    long carry = c >>> 32;
    long d = s0 - Q0;
    long t0 = d & M;
    d = (d >> 32) + s1 - Q1;
    long t1 = d & M;
    d = (d >> 32) + s2 - Q2;
    long t2 = d & M;
    d = (d >> 32) + s3 - Q3;
    long t3 = d & M;
    d = (d >> 32) + s4 - Q4;
    long t4 = d & M;
    d = (d >> 32) + s5 - Q5;
    long t5 = d & M;
    d = (d >> 32) + s6 - Q6;
    long t6 = d & M;
    d = (d >> 32) + s7 - Q7;
    long t7 = d & M;
    long keep = (d >> 32) & (carry - 1);
    r[ro + 0] = (int) ((s0 & keep) | (t0 & ~keep));
    r[ro + 1] = (int) ((s1 & keep) | (t1 & ~keep));
    r[ro + 2] = (int) ((s2 & keep) | (t2 & ~keep));
    r[ro + 3] = (int) ((s3 & keep) | (t3 & ~keep));
    r[ro + 4] = (int) ((s4 & keep) | (t4 & ~keep));
    r[ro + 5] = (int) ((s5 & keep) | (t5 & ~keep));
    r[ro + 6] = (int) ((s6 & keep) | (t6 & ~keep));
    r[ro + 7] = (int) ((s7 & keep) | (t7 & ~keep));
  }

  /** Sets {@code r = a - b mod q}. */
  static void sub(int[] r, int ro, int[] a, int ao, int[] b, int bo) {
    long d = (a[ao] & M) - (b[bo] & M);
    long t0 = d & M;
    d = (d >> 32) + (a[ao + 1] & M) - (b[bo + 1] & M);
    long t1 = d & M;
    d = (d >> 32) + (a[ao + 2] & M) - (b[bo + 2] & M);
    long t2 = d & M;
    d = (d >> 32) + (a[ao + 3] & M) - (b[bo + 3] & M);
    long t3 = d & M;
    d = (d >> 32) + (a[ao + 4] & M) - (b[bo + 4] & M);
    long t4 = d & M;
    d = (d >> 32) + (a[ao + 5] & M) - (b[bo + 5] & M);
    long t5 = d & M;
    d = (d >> 32) + (a[ao + 6] & M) - (b[bo + 6] & M);
    long t6 = d & M;
    d = (d >> 32) + (a[ao + 7] & M) - (b[bo + 7] & M);
    long t7 = d & M;
    long mask = (d >> 32) & M;
    long c = t0 + (Q0 & mask);
    r[ro] = (int) c;
    c = (c >>> 32) + t1 + (Q1 & mask);
    r[ro + 1] = (int) c;
    c = (c >>> 32) + t2 + (Q2 & mask);
    r[ro + 2] = (int) c;
    c = (c >>> 32) + t3 + (Q3 & mask);
    r[ro + 3] = (int) c;
    c = (c >>> 32) + t4 + (Q4 & mask);
    r[ro + 4] = (int) c;
    c = (c >>> 32) + t5 + (Q5 & mask);
    r[ro + 5] = (int) c;
    c = (c >>> 32) + t6 + (Q6 & mask);
    r[ro + 6] = (int) c;
    c = (c >>> 32) + t7 + (Q7 & mask);
    r[ro + 7] = (int) c;
  }

  /** Sets {@code r = -a mod q}. */
  static void neg(int[] r, int ro, int[] a, int ao) {
    long d = -(a[ao] & M);
    long t0 = d & M;
    d = (d >> 32) - (a[ao + 1] & M);
    long t1 = d & M;
    d = (d >> 32) - (a[ao + 2] & M);
    long t2 = d & M;
    d = (d >> 32) - (a[ao + 3] & M);
    long t3 = d & M;
    d = (d >> 32) - (a[ao + 4] & M);
    long t4 = d & M;
    d = (d >> 32) - (a[ao + 5] & M);
    long t5 = d & M;
    d = (d >> 32) - (a[ao + 6] & M);
    long t6 = d & M;
    d = (d >> 32) - (a[ao + 7] & M);
    long t7 = d & M;
    long mask = (d >> 32) & M;
    long c = t0 + (Q0 & mask);
    r[ro] = (int) c;
    c = (c >>> 32) + t1 + (Q1 & mask);
    r[ro + 1] = (int) c;
    c = (c >>> 32) + t2 + (Q2 & mask);
    r[ro + 2] = (int) c;
    c = (c >>> 32) + t3 + (Q3 & mask);
    r[ro + 3] = (int) c;
    c = (c >>> 32) + t4 + (Q4 & mask);
    r[ro + 4] = (int) c;
    c = (c >>> 32) + t5 + (Q5 & mask);
    r[ro + 5] = (int) c;
    c = (c >>> 32) + t6 + (Q6 & mask);
    r[ro + 6] = (int) c;
    c = (c >>> 32) + t7 + (Q7 & mask);
    r[ro + 7] = (int) c;
  }

  /** Sets {@code r = 2a mod q}. */
  static void dbl(int[] r, int ro, int[] a, int ao) {
    add(r, ro, a, ao, a, ao);
  }

  /** Sets {@code r = a / 2 mod q}: adds q when a is odd, then shifts, with no branch. */
  static void half(int[] r, int ro, int[] a, int ao) {
    int odd = -(a[ao] & 1);
    long c = 0;
    int[] t = new int[L + 1];
    for (int i = 0; i < L; i++) {
      c += (a[ao + i] & M) + (Q[i] & odd & M);
      t[i] = (int) c;
      c >>>= 32;
    }
    t[L] = (int) c;
    for (int i = 0; i < L; i++) {
      r[ro + i] = (t[i] >>> 1) | (t[i + 1] << 31);
    }
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
    System.arraycopy(ONE, 0, r, ro, L);
  }

  /** Returns all ones when a is zero, else 0. */
  static int isZero(int[] a, int ao) {
    int x = 0;
    for (int i = 0; i < L; i++) {
      x |= a[ao + i];
    }
    return ~((x | -x) >> 31);
  }

  /** Returns all ones when a equals b, else 0. */
  static int equal(int[] a, int ao, int[] b, int bo) {
    int x = 0;
    for (int i = 0; i < L; i++) {
      x |= a[ao + i] ^ b[bo + i];
    }
    return ~((x | -x) >> 31);
  }

  /** Sets r to a where mask is all ones; keeps r where it is 0. */
  static void cmov(int[] r, int ro, int[] a, int ao, int mask) {
    for (int i = 0; i < L; i++) {
      r[ro + i] ^= (r[ro + i] ^ a[ao + i]) & mask;
    }
  }

  /** Sets {@code r = a^-1} (0 for 0) by Fermat; the exponent is public, so the flow is fixed. */
  static void inv(int[] r, int ro, int[] a, int ao) {
    int[] base = new int[L];
    copy(base, 0, a, ao);
    int[] acc = ONE.clone();
    for (int i = Q_MINUS_2.bitLength() - 1; i >= 0; i--) {
      sqr(acc, 0, acc, 0);
      if (Q_MINUS_2.testBit(i)) {
        mul(acc, 0, acc, 0, base, 0);
      }
    }
    copy(r, ro, acc, 0);
  }

  /**
   * Reads 32 big-endian bytes into Montgomery form. Returns false, leaving r unspecified, when the
   * value is not below q; the comparison has no early exit.
   */
  static boolean decode(byte[] in, int off, int[] r, int ro) {
    int[] t = new int[L];
    for (int i = 0; i < L; i++) {
      int p = off + 28 - 4 * i;
      t[i] =
          (in[p] & 0xFF) << 24
              | (in[p + 1] & 0xFF) << 16
              | (in[p + 2] & 0xFF) << 8
              | (in[p + 3] & 0xFF);
    }
    long d = 0;
    for (int i = 0; i < L; i++) {
      d += (t[i] & M) - (Q[i] & M);
      d >>= 32;
    }
    mul(r, ro, t, 0, R2, 0);
    return d != 0;
  }

  /** Writes the value of a as 32 big-endian bytes. */
  static void encode(int[] a, int ao, byte[] out, int off) {
    int[] t = new int[L];
    mul(t, 0, a, ao, RAW_ONE, 0);
    for (int i = 0; i < L; i++) {
      int v = t[i];
      int p = off + 28 - 4 * i;
      out[p] = (byte) (v >>> 24);
      out[p + 1] = (byte) (v >>> 16);
      out[p + 2] = (byte) (v >>> 8);
      out[p + 3] = (byte) v;
    }
  }
}
