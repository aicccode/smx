package site.aicc.sm2.ec;

import java.math.BigInteger;

/** Point on a prime field elliptic curve. */
public class FpPoint extends AbstractECPoint {

  public FpPoint(AbstractECCurve curve, AbstractECElement x, AbstractECElement y) {
    super(curve, x, y);
    if ((x == null) != (y == null)) {
      throw new IllegalArgumentException("Field element is null");
    }
  }

  FpPoint(AbstractECCurve curve, AbstractECElement x, AbstractECElement y, AbstractECElement[] zs) {
    super(curve, x, y, zs);
  }

  @Override
  protected boolean satisfiesCurveEquation() {
    if (this.isInfinity()) {
      return true;
    }
    AbstractECElement lhs = this.y.square();
    AbstractECElement rhs = this.x.square().add(curve.getA()).multiply(this.x).add(curve.getB());
    return lhs.equals(rhs);
  }

  @Override
  public AbstractECPoint subtract(AbstractECPoint b) {
    requirePoint(b);
    if (b.isInfinity()) {
      return this;
    }
    return this.add(b.negate());
  }

  @Override
  public AbstractECPoint add(AbstractECPoint b) {
    requirePoint(b);
    if (this.isInfinity()) {
      return b;
    }
    if (b.isInfinity()) {
      return this;
    }
    if (this == b) {
      return twice();
    }
    AbstractECElement x1 = this.x;
    AbstractECElement y1 = this.y;
    AbstractECElement x2 = b.x;
    AbstractECElement y2 = b.y;
    AbstractECElement dx = x2.subtract(x1);
    AbstractECElement dy = y2.subtract(y1);
    if (dx.isZero()) {
      if (dy.isZero()) {
        return twice();
      }
      return this.getCurve().getInfinity();
    }
    AbstractECElement gamma = dy.divide(dx);
    AbstractECElement x3 = gamma.square().subtract(x1).subtract(x2);
    AbstractECElement y3 = gamma.multiply(x1.subtract(x3)).subtract(y1);
    return new FpPoint(this.getCurve(), x3, y3);
  }

  @Override
  public AbstractECPoint twice() {
    if (this.isInfinity()) {
      return this;
    }
    AbstractECElement y1 = this.y;
    if (y1.isZero()) {
      return this.getCurve().getInfinity();
    }
    AbstractECElement x1 = this.x;
    AbstractECElement gamma = three(x1.square()).add(this.getCurve().getA()).divide(two(y1));
    AbstractECElement x3 = gamma.square().subtract(two(x1));
    AbstractECElement y3 = gamma.multiply(x1.subtract(x3)).subtract(y1);
    return new FpPoint(this.getCurve(), x3, y3);
  }

  @Override
  public AbstractECPoint twicePlus(AbstractECPoint b) {
    requirePoint(b);
    if (this == b) {
      return threeTimes();
    }
    if (this.isInfinity()) {
      return b;
    }
    if (b.isInfinity()) {
      return twice();
    }
    AbstractECElement y1 = this.y;
    if (y1.isZero()) {
      return b;
    }
    AbstractECElement x1 = this.x;
    AbstractECElement x2 = b.x;
    AbstractECElement y2 = b.y;
    AbstractECElement dx = x2.subtract(x1);
    AbstractECElement dy = y2.subtract(y1);
    if (dx.isZero()) {
      if (dy.isZero()) {
        return threeTimes();
      }
      return this;
    }
    // 2P + Q with a single inversion, skipping the y coordinate of 2P.
    AbstractECElement dxSquared = dx.square();
    AbstractECElement dySquared = dy.square();
    AbstractECElement d = dxSquared.multiply(two(x1).add(x2)).subtract(dySquared);
    if (d.isZero()) {
      return this.getCurve().getInfinity();
    }
    AbstractECElement inverse = d.multiply(dx).invert();
    AbstractECElement lambda1 = d.multiply(inverse).multiply(dy);
    AbstractECElement lambda2 =
        two(y1).multiply(dxSquared).multiply(dx).multiply(inverse).subtract(lambda1);
    AbstractECElement x4 = lambda2.subtract(lambda1).multiply(lambda1.add(lambda2)).add(x2);
    AbstractECElement y4 = x1.subtract(x4).multiply(lambda2).subtract(y1);
    return new FpPoint(this.getCurve(), x4, y4);
  }

  @Override
  public AbstractECPoint threeTimes() {
    if (this.isInfinity()) {
      return this;
    }
    AbstractECElement y1 = this.y;
    if (y1.isZero()) {
      return this;
    }
    AbstractECElement x1 = this.x;
    AbstractECElement twoY1 = two(y1);
    AbstractECElement twoY1Squared = twoY1.square();
    AbstractECElement slope = three(x1.square()).add(this.getCurve().getA());
    AbstractECElement d = three(x1).multiply(twoY1Squared).subtract(slope.square());
    if (d.isZero()) {
      return this.getCurve().getInfinity();
    }
    AbstractECElement inverse = d.multiply(twoY1).invert();
    AbstractECElement lambda1 = d.multiply(inverse).multiply(slope);
    AbstractECElement lambda2 = twoY1Squared.square().multiply(inverse).subtract(lambda1);
    AbstractECElement x4 = lambda2.subtract(lambda1).multiply(lambda1.add(lambda2)).add(x1);
    AbstractECElement y4 = x1.subtract(x4).multiply(lambda2).subtract(y1);
    return new FpPoint(this.getCurve(), x4, y4);
  }

  @Override
  public AbstractECPoint timesPow2(int e) {
    checkDoublingCount(e);
    if (e == 0 || this.isInfinity()) {
      return this;
    }
    if (e == 1) {
      return twice();
    }
    AbstractECCurve curve = this.getCurve();
    AbstractECElement y1 = this.y;
    if (y1.isZero()) {
      return curve.getInfinity();
    }
    AbstractECElement w1 = curve.getA();
    AbstractECElement x1 = this.x;
    AbstractECElement z1 =
        this.zs.length < 1 ? curve.fromBigInteger(BigInteger.valueOf(1)) : this.zs[0];
    for (int i = 0; i < e; ++i) {
      if (y1.isZero()) {
        return curve.getInfinity();
      }
      AbstractECElement m = three(x1.square());
      AbstractECElement twoY1 = two(y1);
      AbstractECElement twoY1Squared = twoY1.multiply(y1);
      AbstractECElement s = two(x1.multiply(twoY1Squared));
      AbstractECElement fourT = twoY1Squared.square();
      AbstractECElement eightT = two(fourT);
      if (!w1.isZero()) {
        m = m.add(w1);
        w1 = two(eightT.multiply(w1));
      }
      x1 = m.square().subtract(two(s));
      y1 = m.multiply(s.subtract(x1)).subtract(eightT);
      z1 = z1.isOne() ? twoY1 : twoY1.multiply(z1);
    }
    AbstractECElement zInv = z1.invert();
    AbstractECElement zInv2 = zInv.square();
    AbstractECElement zInv3 = zInv2.multiply(zInv);
    return new FpPoint(curve, x1.multiply(zInv2), y1.multiply(zInv3));
  }

  private static void requirePoint(AbstractECPoint b) {
    if (b == null) {
      throw new IllegalArgumentException("Point is null");
    }
  }

  protected AbstractECElement two(AbstractECElement x) {
    if (x == null) {
      throw new IllegalArgumentException("Field element is null");
    }
    return x.add(x);
  }

  protected AbstractECElement three(AbstractECElement x) {
    return two(x).add(x);
  }

  @Override
  protected AbstractECPoint negate() {
    if (this.isInfinity()) {
      return this;
    }
    return new FpPoint(this.getCurve(), this.x, this.y.negate());
  }
}
