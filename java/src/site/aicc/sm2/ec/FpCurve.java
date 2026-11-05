package site.aicc.sm2.ec;

import java.math.BigInteger;

/** Prime field elliptic curve Fp. */
public class FpCurve extends AbstractECCurve {

  private static final int MAX_FIELD_BITS = 1024;
  private static final int PRIME_CERTAINTY = 64;

  private final BigInteger q;
  private final BigInteger r;
  private final AbstractECMultiplier multiplier;
  private final FpPoint infinity;
  private final boolean sm2;

  public FpCurve(AbstractECMultiplier multiplier, BigInteger q, BigInteger a, BigInteger b) {
    this(multiplier, q, a, b, null, null);
  }

  public FpCurve(
      AbstractECMultiplier multiplier,
      BigInteger q,
      BigInteger a,
      BigInteger b,
      BigInteger order,
      BigInteger cofactor) {
    if (multiplier == null || a == null || b == null) {
      throw new IllegalArgumentException("Curve parameter is null");
    }
    checkField(q);
    if (order != null && order.signum() <= 0) {
      throw new IllegalArgumentException("Curve order must be positive");
    }
    if (cofactor != null && (cofactor.signum() <= 0 || cofactor.bitLength() > q.bitLength())) {
      throw new IllegalArgumentException("Invalid curve cofactor");
    }
    this.multiplier = multiplier;
    this.q = q;
    this.r = FpElement.calculateResidue(q);
    this.infinity = new FpPoint(this, null, null);
    this.a = fromBigInteger(a);
    this.b = fromBigInteger(b);
    this.order = order;
    this.cofactor = cofactor;
    if (isSingular(q, a, b)) {
      throw new IllegalArgumentException("Curve is singular");
    }
    this.sm2 = Sm2Engine.isSm2Curve(q, a, b);
  }

  /**
   * A zero discriminant 4a^3 + 27b^2 makes this no elliptic curve: logarithms map to the field or
   * its additive group, where they are easy.
   */
  private static boolean isSingular(BigInteger q, BigInteger a, BigInteger b) {
    BigInteger cube = a.multiply(a).multiply(a).shiftLeft(2);
    BigInteger square = b.multiply(b).multiply(BigInteger.valueOf(27));
    return cube.add(square).mod(q).signum() == 0;
  }

  /** The field inversion only terminates for an odd prime modulus, so nothing else is accepted. */
  private static void checkField(BigInteger q) {
    if (q == null || q.signum() <= 0 || q.bitLength() > MAX_FIELD_BITS) {
      throw new IllegalArgumentException("Invalid field prime");
    }
    if (!q.equals(Sm2Field.P_BIG) && (!q.testBit(0) || !q.isProbablePrime(PRIME_CERTAINTY))) {
      throw new IllegalArgumentException("Invalid field prime");
    }
  }

  /** True when p, a and b are exactly the SM2 parameters. */
  boolean isSm2() {
    return sm2;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof FpCurve)) {
      return false;
    }
    FpCurve other = (FpCurve) obj;
    return q.equals(other.q) && a.equals(other.a) && b.equals(other.b);
  }

  @Override
  public int hashCode() {
    return super.hashCode();
  }

  @Override
  public int getFieldSize() {
    return q.bitLength();
  }

  @Override
  public AbstractECElement fromBigInteger(BigInteger x) {
    return new FpElement(this.q, this.r, x);
  }

  @Override
  protected AbstractECPoint createRawPoint(AbstractECElement x, AbstractECElement y) {
    return new FpPoint(this, x, y);
  }

  @Override
  public AbstractECPoint getInfinity() {
    return infinity;
  }

  @Override
  public AbstractECMultiplier getMultiplier() {
    return this.multiplier;
  }
}
