package site.aicc.sm2.ec;

import java.math.BigInteger;

/** Abstract base class for EC point multiplication algorithms. */
public abstract class AbstractECMultiplier {

  /**
   * Returns k * p. An off-curve p is rejected before any secret scalar is applied to it, since
   * multiplying on the wrong curve is how invalid-curve attacks extract a key. Scalars are secret
   * here: on the SM2 curve the built-in multipliers take constant-flow paths. On other curves this
   * is {@link BigInteger} arithmetic and not side-channel protected.
   *
   * @throws IllegalArgumentException for a null argument, an invalid point or an unusable scalar
   */
  public AbstractECPoint multiply(AbstractECPoint p, BigInteger k) {
    if (p == null || k == null) {
      throw new IllegalArgumentException("Point and scalar are required");
    }
    if (!p.isValid()) {
      throw new IllegalArgumentException("Invalid EC point");
    }
    int sign = k.signum();
    if (sign == 0 || p.isInfinity()) {
      return p.getCurve().getInfinity();
    }
    AbstractECPoint positive = multiplyPositive(p, k.abs());
    AbstractECPoint result = sign > 0 ? positive : positive.negate();
    return validatePoint(result);
  }

  /** Rejects what {@link #multiplyPositive} cannot use, for direct calls from subclasses. */
  protected static void requireOperands(AbstractECPoint p, BigInteger k) {
    if (p == null || k == null || k.signum() <= 0 || !p.isValid() || p.isInfinity()) {
      throw new IllegalArgumentException("Invalid point or scalar");
    }
  }

  private static AbstractECPoint validatePoint(AbstractECPoint p) {
    if (!p.isValid()) {
      throw new IllegalArgumentException("Invalid EC point");
    }
    return p;
  }

  protected abstract AbstractECPoint multiplyPositive(AbstractECPoint p, BigInteger k);
}
