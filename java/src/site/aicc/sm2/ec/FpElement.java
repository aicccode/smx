package site.aicc.sm2.ec;

import java.math.BigInteger;
import java.util.Arrays;
import site.aicc.sm2.util.ConvertUtil;

/**
 * Prime field element Fp. Elements of the SM2 prime field are held as limbs and use {@link
 * Sm2Field}; the BigInteger value is then produced only on demand. Other fields use BigInteger.
 */
public class FpElement extends AbstractECElement {

  private static final long UNSIGNED_MASK = 0xFFFFFFFFL;

  private final BigInteger q;
  private final BigInteger r;

  /** Set when q is the SM2 prime; never modified after construction. */
  private final int[] limbs;

  /** Lazily computed for SM2 elements; benign race, BigInteger is immutable. */
  private BigInteger v;

  /** True only for coordinates of a secret point created by {@link Sm2Engine}. */
  private boolean erasable;

  static BigInteger calculateResidue(BigInteger p) {
    int bitLength = p.bitLength();
    if (bitLength >= 96) {
      BigInteger firstWord = p.shiftRight(bitLength - 64);
      if (firstWord.longValue() == -1L) {
        return BigInteger.valueOf(1).shiftLeft(bitLength).subtract(p);
      }
    }
    return null;
  }

  FpElement(BigInteger q, BigInteger r, BigInteger v) {
    if (v == null || v.signum() < 0 || v.compareTo(q) >= 0) {
      throw new IllegalArgumentException("v is not in Fp");
    }
    this.q = q;
    this.r = r;
    this.v = v;
    this.limbs = q.equals(Sm2Field.P_BIG) ? Sm2Field.fromBigInteger(v) : null;
  }

  /** Wraps canonical limbs of the SM2 field; takes ownership of the array. */
  FpElement(int[] limbs) {
    this(limbs, false);
  }

  /** As {@link #FpElement(int[])}, marking a coordinate of a secret point as erasable. */
  FpElement(int[] limbs, boolean erasable) {
    this.q = Sm2Field.P_BIG;
    this.r = null;
    this.limbs = limbs;
    this.erasable = erasable;
  }

  /** Clears a secret coordinate after its last use; does nothing to any other element. */
  void eraseIfSecret() {
    if (erasable) {
      Arrays.fill(limbs, 0);
      v = null;
    }
  }

  /** The limbs of an SM2 field element, or null; callers must not modify the array. */
  int[] limbs() {
    return limbs;
  }

  /**
   * The other element's limbs when both are SM2 limb elements, else null. Rejects a null operand
   * and one from a different field, whose arithmetic would be meaningless.
   */
  private int[] otherLimbs(AbstractECElement b) {
    if (b == null) {
      throw new IllegalArgumentException("Field element is null");
    }
    if (!(b instanceof FpElement)) {
      return null;
    }
    FpElement other = (FpElement) b;
    if (limbs != null && other.limbs != null) {
      return other.limbs;
    }
    if (!q.equals(other.q)) {
      throw new IllegalArgumentException("Field elements are from different fields");
    }
    return null;
  }

  @Override
  public BigInteger toBigInteger() {
    BigInteger value = v;
    if (value == null) {
      value = Sm2Field.toBigInteger(limbs);
      v = value;
    }
    return value;
  }

  @Override
  public int getFieldSize() {
    return q.bitLength();
  }

  @Override
  public AbstractECElement add(AbstractECElement b) {
    int[] other = otherLimbs(b);
    if (other != null) {
      int[] out = new int[8];
      Sm2Field.add(out, limbs, other);
      return new FpElement(out);
    }
    return new FpElement(q, r, modAdd(toBigInteger(), b.toBigInteger()));
  }

  @Override
  public AbstractECElement subtract(AbstractECElement b) {
    int[] other = otherLimbs(b);
    if (other != null) {
      int[] out = new int[8];
      Sm2Field.sub(out, limbs, other);
      return new FpElement(out);
    }
    return new FpElement(q, r, modSubtract(toBigInteger(), b.toBigInteger()));
  }

  @Override
  public AbstractECElement multiply(AbstractECElement b) {
    int[] other = otherLimbs(b);
    if (other != null) {
      int[] out = new int[8];
      Sm2Field.mul(out, limbs, other);
      return new FpElement(out);
    }
    return new FpElement(q, r, modMult(toBigInteger(), b.toBigInteger()));
  }

  @Override
  public AbstractECElement divide(AbstractECElement b) {
    int[] other = otherLimbs(b);
    if (other != null) {
      int[] out = new int[8];
      invertLimbs(out, other);
      Sm2Field.mul(out, limbs, out);
      return new FpElement(out);
    }
    return new FpElement(q, r, modMult(toBigInteger(), modInverse(b.toBigInteger())));
  }

  @Override
  public AbstractECElement negate() {
    if (limbs != null) {
      if (Sm2Field.isZero(limbs) != 0) {
        return this;
      }
      int[] out = new int[8];
      Sm2Field.neg(out, limbs);
      return new FpElement(out);
    }
    return v.signum() == 0 ? this : new FpElement(q, r, q.subtract(v));
  }

  @Override
  public AbstractECElement square() {
    if (limbs != null) {
      int[] out = new int[8];
      Sm2Field.sqr(out, limbs);
      return new FpElement(out);
    }
    return new FpElement(q, r, modMult(v, v));
  }

  @Override
  public AbstractECElement invert() {
    if (limbs != null) {
      int[] out = new int[8];
      invertLimbs(out, limbs);
      return new FpElement(out);
    }
    return new FpElement(q, r, modInverse(v));
  }

  private static void invertLimbs(int[] out, int[] value) {
    if (Sm2Field.isZero(value) != 0) {
      throw new IllegalArgumentException("'x' cannot be zero");
    }
    Sm2Group.invert(out, value);
  }

  @Override
  public boolean isZero() {
    return limbs != null ? Sm2Field.isZero(limbs) != 0 : super.isZero();
  }

  @Override
  public byte[] getEncoded() {
    if (limbs != null) {
      byte[] out = new byte[32];
      Sm2Field.toBytes(limbs, out, 0);
      return out;
    }
    return super.getEncoded();
  }

  private BigInteger modAdd(BigInteger x1, BigInteger x2) {
    BigInteger x3 = x1.add(x2);
    if (x3.compareTo(q) >= 0) {
      x3 = x3.subtract(q);
    }
    return x3;
  }

  private BigInteger modInverse(BigInteger x) {
    int bits = getFieldSize();
    int len = (bits + 31) >> 5;
    int[] p = ConvertUtil.fromBigInteger(bits, q);
    int[] n = ConvertUtil.fromBigInteger(bits, x);
    int[] z = new int[len];
    invertMod(p, n, z);
    return ConvertUtil.toBigInteger(len, z);
  }

  private BigInteger modMult(BigInteger x1, BigInteger x2) {
    return modReduce(x1.multiply(x2));
  }

  private BigInteger modReduce(BigInteger value) {
    if (r == null) {
      return value.mod(q);
    }
    BigInteger x = value;
    boolean negative = x.signum() < 0;
    if (negative) {
      x = x.abs();
    }
    int qLen = q.bitLength();
    boolean residueIsOne = r.equals(BigInteger.ONE);
    while (x.bitLength() > (qLen + 1)) {
      BigInteger high = x.shiftRight(qLen);
      BigInteger low = x.subtract(high.shiftLeft(qLen));
      if (!residueIsOne) {
        high = high.multiply(r);
      }
      x = high.add(low);
    }
    while (x.compareTo(q) >= 0) {
      x = x.subtract(q);
    }
    if (negative && x.signum() != 0) {
      x = q.subtract(x);
    }
    return x;
  }

  private BigInteger modSubtract(BigInteger x1, BigInteger x2) {
    BigInteger x3 = x1.subtract(x2);
    if (x3.signum() < 0) {
      x3 = x3.add(q);
    }
    return x3;
  }

  @Override
  public boolean equals(Object other) {
    if (other == this) {
      return true;
    }
    if (!(other instanceof FpElement)) {
      return false;
    }
    FpElement o = (FpElement) other;
    if (limbs != null && o.limbs != null) {
      return Arrays.equals(limbs, o.limbs);
    }
    return q.equals(o.q) && toBigInteger().equals(o.toBigInteger());
  }

  @Override
  public int hashCode() {
    return q.hashCode() ^ toBigInteger().hashCode();
  }

  private static void invertMod(int[] p, int[] x, int[] z) {
    int len = p.length;
    if (isZero(len, x)) {
      throw new IllegalArgumentException("'x' cannot be zero");
    }
    if (isOne(len, x)) {
      System.arraycopy(x, 0, z, 0, len);
      return;
    }
    int[] u = x.clone();
    int[] a = new int[len];
    a[0] = 1;
    int carryA = 0;
    if ((u[0] & 1) == 0) {
      carryA = inversionStep(p, u, len, a, carryA);
    }
    if (isOne(len, u)) {
      inversionResult(p, carryA, a, z);
      return;
    }
    int[] v = p.clone();
    int[] b = new int[len];
    int carryB = 0;
    int uvLen = len;
    for (; ; ) {
      while (u[uvLen - 1] == 0 && v[uvLen - 1] == 0) {
        --uvLen;
      }
      if (gte(uvLen, u, v)) {
        subFrom(uvLen, v, u);
        carryA += subFrom(len, b, a) - carryB;
        carryA = inversionStep(p, u, uvLen, a, carryA);
        if (isOne(uvLen, u)) {
          inversionResult(p, carryA, a, z);
          return;
        }
      } else {
        subFrom(uvLen, u, v);
        carryB += subFrom(len, a, b) - carryA;
        carryB = inversionStep(p, v, uvLen, b, carryB);
        if (isOne(uvLen, v)) {
          inversionResult(p, carryB, b, z);
          return;
        }
      }
    }
  }

  private static void inversionResult(int[] p, int ac, int[] a, int[] z) {
    if (ac < 0) {
      add(p.length, a, p, z);
    } else {
      System.arraycopy(a, 0, z, 0, p.length);
    }
  }

  private static int inversionStep(int[] p, int[] u, int uLen, int[] x, int carry) {
    int len = p.length;
    int count = 0;
    while (u[0] == 0) {
      shiftDownWord(uLen, u);
      count += 32;
    }
    int zeroes = Integer.numberOfTrailingZeros(u[0]);
    if (zeroes > 0) {
      shiftDownBits(uLen, u, zeroes);
      count += zeroes;
    }
    int xc = carry;
    for (int i = 0; i < count; ++i) {
      if ((x[0] & 1) != 0) {
        if (xc < 0) {
          xc += addTo(len, p, x);
        } else {
          xc += subFrom(len, p, x);
        }
      }
      shiftDownBit(len, x, xc);
    }
    return xc;
  }

  private static void add(int len, int[] x, int[] y, int[] z) {
    long c = 0;
    for (int i = 0; i < len; ++i) {
      c += (x[i] & UNSIGNED_MASK) + (y[i] & UNSIGNED_MASK);
      z[i] = (int) c;
      c >>>= 32;
    }
  }

  private static int addTo(int len, int[] x, int[] z) {
    long c = 0;
    for (int i = 0; i < len; ++i) {
      c += (x[i] & UNSIGNED_MASK) + (z[i] & UNSIGNED_MASK);
      z[i] = (int) c;
      c >>>= 32;
    }
    return (int) c;
  }

  private static boolean gte(int len, int[] x, int[] y) {
    for (int i = len - 1; i >= 0; --i) {
      int xUnsigned = x[i] ^ Integer.MIN_VALUE;
      int yUnsigned = y[i] ^ Integer.MIN_VALUE;
      if (xUnsigned < yUnsigned) {
        return false;
      }
      if (xUnsigned > yUnsigned) {
        return true;
      }
    }
    return true;
  }

  private static boolean isOne(int len, int[] x) {
    if (x[0] != 1) {
      return false;
    }
    for (int i = 1; i < len; ++i) {
      if (x[i] != 0) {
        return false;
      }
    }
    return true;
  }

  private static boolean isZero(int len, int[] x) {
    for (int i = 0; i < len; ++i) {
      if (x[i] != 0) {
        return false;
      }
    }
    return true;
  }

  private static void shiftDownBit(int len, int[] z, int carry) {
    int c = carry;
    for (int i = len - 1; i >= 0; --i) {
      int next = z[i];
      z[i] = (next >>> 1) | (c << 31);
      c = next;
    }
  }

  private static void shiftDownBits(int len, int[] z, int bits) {
    int c = 0;
    for (int i = len - 1; i >= 0; --i) {
      int next = z[i];
      z[i] = (next >>> bits) | (c << -bits);
      c = next;
    }
  }

  private static void shiftDownWord(int len, int[] z) {
    int c = 0;
    for (int i = len - 1; i >= 0; --i) {
      int next = z[i];
      z[i] = c;
      c = next;
    }
  }

  private static int subFrom(int len, int[] x, int[] z) {
    long c = 0;
    for (int i = 0; i < len; ++i) {
      c += (z[i] & UNSIGNED_MASK) - (x[i] & UNSIGNED_MASK);
      z[i] = (int) c;
      c >>= 32;
    }
    return (int) c;
  }
}
