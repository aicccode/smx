package site.aicc.sm9;

import java.math.BigInteger;

/**
 * Arithmetic in Fq2 = Fq[u] / (u^2 + 2). An element a0 + a1 u is 16 ints at an offset: a0 then a1,
 * each an {@link Fp} element. Every operation reads all inputs before writing, so the result may
 * alias an input, and has a fixed sequence of field operations.
 */
final class Fp2 {
  /** Ints per element. */
  static final int L = 2 * Fp.L;

  private static final int H = Fp.L;

  private Fp2() {}

  static void add(int[] r, int ro, int[] a, int ao, int[] b, int bo) {
    Fp.add(r, ro, a, ao, b, bo);
    Fp.add(r, ro + H, a, ao + H, b, bo + H);
  }

  static void sub(int[] r, int ro, int[] a, int ao, int[] b, int bo) {
    Fp.sub(r, ro, a, ao, b, bo);
    Fp.sub(r, ro + H, a, ao + H, b, bo + H);
  }

  static void neg(int[] r, int ro, int[] a, int ao) {
    Fp.neg(r, ro, a, ao);
    Fp.neg(r, ro + H, a, ao + H);
  }

  static void dbl(int[] r, int ro, int[] a, int ao) {
    Fp.dbl(r, ro, a, ao);
    Fp.dbl(r, ro + H, a, ao + H);
  }

  static void half(int[] r, int ro, int[] a, int ao) {
    Fp.half(r, ro, a, ao);
    Fp.half(r, ro + H, a, ao + H);
  }

  /** Sets r = (a0 - a1 u), the q-power Frobenius of Fq2. */
  static void conj(int[] r, int ro, int[] a, int ao) {
    Fp.copy(r, ro, a, ao);
    Fp.neg(r, ro + H, a, ao + H);
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

  /** (a0 + a1 u)(b0 + b1 u) = a0 b0 - 2 a1 b1 + (a0 b1 + a1 b0) u, with three products. */
  static void mul(int[] r, int ro, int[] a, int ao, int[] b, int bo) {
    int[] t = new int[4 * H];
    Fp.mul(t, 0, a, ao, b, bo);
    Fp.mul(t, H, a, ao + H, b, bo + H);
    Fp.add(t, 2 * H, a, ao, a, ao + H);
    Fp.add(t, 3 * H, b, bo, b, bo + H);
    Fp.mul(t, 2 * H, t, 2 * H, t, 3 * H);
    Fp.sub(t, 2 * H, t, 2 * H, t, 0);
    Fp.sub(r, ro + H, t, 2 * H, t, H);
    Fp.sub(t, 0, t, 0, t, H);
    Fp.sub(r, ro, t, 0, t, H);
  }

  /** (a0 + a1 u)^2 = (a0 + a1)(a0 - 2 a1) + a0 a1 + 2 a0 a1 u, with two products. */
  static void sqr(int[] r, int ro, int[] a, int ao) {
    int[] t = new int[3 * H];
    Fp.mul(t, 0, a, ao, a, ao + H);
    Fp.add(t, H, a, ao, a, ao + H);
    Fp.sub(t, 2 * H, a, ao, a, ao + H);
    Fp.sub(t, 2 * H, t, 2 * H, a, ao + H);
    Fp.mul(t, H, t, H, t, 2 * H);
    Fp.add(r, ro, t, H, t, 0);
    Fp.dbl(r, ro + H, t, 0);
  }

  /** Multiplies by an Fq element k at {@code k[ko]}. */
  static void mulFp(int[] r, int ro, int[] a, int ao, int[] k, int ko) {
    Fp.mul(r, ro, a, ao, k, ko);
    Fp.mul(r, ro + H, a, ao + H, k, ko);
  }

  /** (a0 + a1 u) u = -2 a1 + a0 u. */
  static void mulU(int[] r, int ro, int[] a, int ao) {
    int[] t = new int[H];
    Fp.dbl(t, 0, a, ao + H);
    Fp.copy(r, ro + H, a, ao);
    Fp.neg(r, ro, t, 0);
  }

  /** 1 / (a0 + a1 u) = (a0 - a1 u) / (a0^2 + 2 a1^2); 0 maps to 0. */
  static void inv(int[] r, int ro, int[] a, int ao) {
    int[] t = new int[2 * H];
    Fp.sqr(t, 0, a, ao);
    Fp.sqr(t, H, a, ao + H);
    Fp.dbl(t, H, t, H);
    Fp.add(t, 0, t, 0, t, H);
    Fp.inv(t, 0, t, 0);
    Fp.mul(t, H, a, ao + H, t, 0);
    Fp.mul(r, ro, a, ao, t, 0);
    Fp.neg(r, ro + H, t, H);
  }

  /** Returns all ones when a is zero, else 0. */
  static int isZero(int[] a, int ao) {
    return Fp.isZero(a, ao) & Fp.isZero(a, ao + H);
  }

  /** Returns all ones when a equals b, else 0. */
  static int equal(int[] a, int ao, int[] b, int bo) {
    return Fp.equal(a, ao, b, bo) & Fp.equal(a, ao + H, b, bo + H);
  }

  static void cmov(int[] r, int ro, int[] a, int ao, int mask) {
    Fp.cmov(r, ro, a, ao, mask);
    Fp.cmov(r, ro + H, a, ao + H, mask);
  }

  /** Public-exponent power, for constants only. */
  static int[] pow(int[] a, BigInteger e) {
    int[] acc = new int[L];
    setOne(acc, 0);
    for (int i = e.bitLength() - 1; i >= 0; i--) {
      sqr(acc, 0, acc, 0);
      if (e.testBit(i)) {
        mul(acc, 0, acc, 0, a, 0);
      }
    }
    return acc;
  }

  /** An element from its two components as public values. */
  static int[] of(BigInteger a0, BigInteger a1) {
    int[] r = new int[L];
    Fp.copy(r, 0, Fp.fromBigInteger(a0), 0);
    Fp.copy(r, H, Fp.fromBigInteger(a1), 0);
    return r;
  }

  /** Reads a1 || a0 (64 bytes); false when a component is not below q. */
  static boolean decode(byte[] in, int off, int[] r, int ro) {
    boolean hi = Fp.decode(in, off, r, ro + H);
    boolean lo = Fp.decode(in, off + 32, r, ro);
    return hi & lo;
  }

  /** Writes a1 || a0 (64 bytes). */
  static void encode(int[] a, int ao, byte[] out, int off) {
    Fp.encode(a, ao + H, out, off);
    Fp.encode(a, ao, out, off + 32);
  }
}
