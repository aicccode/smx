package site.aicc.sm2.ec;

import java.math.BigInteger;

/** Prime field elliptic curve Fp. */
public class FpCurve extends AbstractECCurve {

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
    this.multiplier = multiplier;
    this.q = q;
    this.r = FpElement.calculateResidue(q);
    this.infinity = new FpPoint(this, null, null);
    this.a = fromBigInteger(a);
    this.b = fromBigInteger(b);
    this.order = order;
    this.cofactor = cofactor;
    this.sm2 = Sm2Engine.isSm2Curve(q, a, b);
  }

  /** True when p, a and b are exactly the SM2 parameters. */
  boolean isSm2() {
    return sm2;
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
