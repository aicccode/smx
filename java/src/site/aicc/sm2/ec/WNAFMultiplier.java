package site.aicc.sm2.ec;

import java.math.BigInteger;

/** w-ary non-adjacent form (wNAF) point multiplication method. */
public class WNAFMultiplier extends AbstractECMultiplier {
  private static final int[] WINDOW_SIZE_CUTOFFS = {13, 41, 121, 337, 897, 2305};

  private static int getBitLen(int size) {
    if (size == 0) return 0;
    if (size == 2) return 2;
    int order = 0;
    do {
      size >>= 1;
      order++;
    } while (size > 0);
    return order;
  }

  @Override
  protected AbstractECPoint multiplyPositive(AbstractECPoint p, BigInteger k) {
    requireOperands(p, k);
    AbstractECPoint fast = Sm2Engine.tryMultiply(p, k);
    if (fast != null) {
      return fast;
    }
    int width = Math.max(2, Math.min(16, getWindowSize(k.bitLength())));
    WNAFPreCalcInfo wnafPreCompInfo = preCalc(p, width);
    AbstractECPoint[] preComp = wnafPreCompInfo.getPreComp();
    AbstractECPoint[] preCompNeg = wnafPreCompInfo.getPreCompNeg();
    int[] wnaf = generateCompactWindow(width, k);
    AbstractECPoint q = p.getCurve().getInfinity();
    int i = wnaf.length;
    if (i > 1) {
      int wi = wnaf[--i];
      int digit = wi >> 16;
      int zeroes = wi & 0xFFFF;
      int n = Math.abs(digit);
      AbstractECPoint[] table = digit < 0 ? preCompNeg : preComp;
      if ((n << 2) < (1 << width)) {
        int highest = getBitLen(n);
        int scale = width - highest;
        int lowBits = n ^ (1 << (highest - 1));
        int i1 = ((1 << (width - 1)) - 1);
        int i2 = (lowBits << scale) + 1;
        q = table[i1 >>> 1].add(table[i2 >>> 1]);
        zeroes -= scale;
      } else {
        q = table[n >>> 1];
      }

      q = q.timesPow2(zeroes);
    }
    while (i > 0) {
      int wi = wnaf[--i];
      int digit = wi >> 16;
      int zeroes = wi & 0xFFFF;
      int n = Math.abs(digit);
      AbstractECPoint[] table = digit < 0 ? preCompNeg : preComp;
      AbstractECPoint r = table[n >>> 1];
      q = q.twicePlus(r);
      q = q.timesPow2(zeroes);
    }

    return q;
  }

  /**
   * Returns tables of at least the required size. A larger table is built as a new object and only
   * then published, so threads sharing the point never see a half-filled one.
   */
  private static WNAFPreCalcInfo preCalc(AbstractECPoint p, int width) {
    int required = 1 << Math.max(0, width - 2);
    AbstractECPreCalcInfo cached = p.getPreCalcInfo();
    if (cached instanceof WNAFPreCalcInfo && cached.getPreComp().length >= required) {
      return (WNAFPreCalcInfo) cached;
    }
    AbstractECPoint[] preComp = new AbstractECPoint[required];
    preComp[0] = p;
    if (required == 2) {
      preComp[1] = p.threeTimes();
    } else if (required > 2) {
      AbstractECPoint twice = p.twice();
      for (int i = 1; i < required; i++) {
        preComp[i] = preComp[i - 1].add(twice);
      }
    }
    AbstractECPoint[] preCompNeg = new AbstractECPoint[required];
    for (int i = 0; i < required; i++) {
      preCompNeg[i] = preComp[i].negate();
    }
    WNAFPreCalcInfo info = new WNAFPreCalcInfo();
    info.setPreComp(preComp);
    info.setPreCompNeg(preCompNeg);
    p.setPreCalcInfo(info);
    return info;
  }

  private static int[] generateCompactWindow(int width, BigInteger scalar) {
    if (width == 2) {
      return generateCompact(scalar);
    }
    if (width < 2 || width > 16) {
      throw new IllegalArgumentException("'width' must be in [2, 16]");
    }
    if ((scalar.bitLength() >>> 16) != 0) {
      throw new IllegalArgumentException("'k' bit length must be less than 2^16");
    }
    if (scalar.signum() == 0) {
      return new int[0];
    }
    BigInteger k = scalar;
    int[] wnaf = new int[k.bitLength() / width + 1];
    int pow2 = 1 << width;
    int mask = pow2 - 1;
    int sign = pow2 >>> 1;
    boolean carry = false;
    int length = 0, pos = 0;
    while (pos <= k.bitLength()) {
      if (k.testBit(pos) == carry) {
        ++pos;
        continue;
      }
      k = k.shiftRight(pos);
      int digit = k.intValue() & mask;
      if (carry) {
        ++digit;
      }
      carry = (digit & sign) != 0;
      if (carry) {
        digit -= pow2;
      }
      int zeroes = length > 0 ? pos - 1 : pos;
      wnaf[length++] = (digit << 16) | zeroes;
      pos = width;
    }
    if (wnaf.length > length) {
      wnaf = trim(wnaf, length);
    }
    return wnaf;
  }

  private static int[] generateCompact(BigInteger k) {
    if ((k.bitLength() >>> 16) != 0) {
      throw new IllegalArgumentException("'k' bit length must be less than 2^16");
    }
    if (k.signum() == 0) {
      return new int[0];
    }
    BigInteger triple = k.shiftLeft(1).add(k);
    int bits = triple.bitLength();
    int[] naf = new int[bits >> 1];
    BigInteger diff = triple.xor(k);
    int highBit = bits - 1, length = 0, zeroes = 0;
    for (int i = 1; i < highBit; ++i) {
      if (!diff.testBit(i)) {
        ++zeroes;
        continue;
      }
      int digit = k.testBit(i) ? -1 : 1;
      naf[length++] = (digit << 16) | zeroes;
      zeroes = 1;
      ++i;
    }
    naf[length++] = (1 << 16) | zeroes;
    if (naf.length > length) {
      naf = trim(naf, length);
    }
    return naf;
  }

  private static int[] trim(int[] a, int length) {
    int[] result = new int[length];
    System.arraycopy(a, 0, result, 0, result.length);
    return result;
  }

  private static int getWindowSize(int bits) {
    int w = 0;
    while (w < WINDOW_SIZE_CUTOFFS.length && bits >= WINDOW_SIZE_CUTOFFS[w]) {
      ++w;
    }
    return w + 2;
  }
}
