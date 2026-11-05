package site.aicc.sm2.ec;

import java.math.BigInteger;

/** Point on an elliptic curve. */
public abstract class AbstractECPoint {
  /** The largest count a multiplier needs: its scalars are limited to 2^16 bits. */
  private static final int MAX_DOUBLINGS = 1 << 16;

  protected AbstractECCurve curve;
  protected AbstractECElement x;
  protected AbstractECElement y;
  protected AbstractECElement[] zs;

  /** Published complete and never changed afterwards, so concurrent multiplies can share it. */
  protected volatile AbstractECPreCalcInfo preCalcInfo = null;

  protected AbstractECPoint(AbstractECCurve curve, AbstractECElement x, AbstractECElement y) {
    this(curve, x, y, new AbstractECElement[0]);
  }

  protected AbstractECPoint(
      AbstractECCurve curve, AbstractECElement x, AbstractECElement y, AbstractECElement[] zs) {
    if (curve == null || zs == null) {
      throw new IllegalArgumentException("Curve is null");
    }
    this.curve = curve;
    this.x = x;
    this.y = y;
    this.zs = zs;
  }

  AbstractECPreCalcInfo getPreCalcInfo() {
    return this.preCalcInfo;
  }

  void setPreCalcInfo(AbstractECPreCalcInfo preCalcInfo) {
    this.preCalcInfo = preCalcInfo;
  }

  private static AbstractECPoint referenceMultiply(AbstractECPoint point, BigInteger k) {
    BigInteger x = k.abs();
    AbstractECPoint p = point;
    AbstractECPoint q = p.getCurve().getInfinity();
    int t = x.bitLength();
    if (t > 0) {
      if (x.testBit(0)) {
        q = p;
      }
      for (int i = 1; i < t; i++) {
        p = p.twice();
        if (x.testBit(i)) {
          q = q.add(p);
        }
      }
    }
    return k.signum() < 0 ? q.negate() : q;
  }

  protected boolean satisfiesCofactor() {
    BigInteger h = curve.getCofactor();
    return h == null || h.equals(BigInteger.valueOf(1)) || !referenceMultiply(this, h).isInfinity();
  }

  protected abstract boolean satisfiesCurveEquation();

  public AbstractECCurve getCurve() {
    return curve;
  }

  public AbstractECElement getXCoord() {
    return x;
  }

  public AbstractECElement getYCoord() {
    return y;
  }

  public boolean isInfinity() {
    return x == null || y == null || (zs.length > 0 && zs[0].isZero());
  }

  public boolean isValid() {
    if (isInfinity()) {
      return true;
    }
    return getCurve() == null || (satisfiesCurveEquation() && satisfiesCofactor());
  }

  public byte[] getEncoded() {
    if (this.isInfinity()) {
      return new byte[1];
    }
    byte[] xBytes = this.getXCoord().getEncoded();
    byte[] yBytes = this.getYCoord().getEncoded();
    byte[] encoded = new byte[xBytes.length + yBytes.length + 1];
    encoded[0] = 0x04;
    System.arraycopy(xBytes, 0, encoded, 1, xBytes.length);
    System.arraycopy(yBytes, 0, encoded, xBytes.length + 1, yBytes.length);
    return encoded;
  }

  public abstract AbstractECPoint add(AbstractECPoint b);

  protected abstract AbstractECPoint negate();

  public abstract AbstractECPoint subtract(AbstractECPoint b);

  public AbstractECPoint timesPow2(int e) {
    checkDoublingCount(e);

    AbstractECPoint p = this;
    for (int i = 0; i < e; i++) {
      p = p.twice();
    }
    return p;
  }

  /** Bounds {@link #timesPow2} so that no argument can make it run for hours. */
  protected static void checkDoublingCount(int e) {
    if (e < 0) {
      throw new IllegalArgumentException("'e' cannot be negative");
    }
    if (e > MAX_DOUBLINGS) {
      throw new IllegalArgumentException("'e' is too large");
    }
  }

  public abstract AbstractECPoint twice();

  public AbstractECPoint twicePlus(AbstractECPoint b) {
    return twice().add(b);
  }

  public AbstractECPoint threeTimes() {
    return twicePlus(this);
  }

  public AbstractECPoint multiply(BigInteger k) {
    return this.getCurve().getMultiplier().multiply(this, k);
  }
}
