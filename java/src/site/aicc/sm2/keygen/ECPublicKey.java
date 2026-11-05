package site.aicc.sm2.keygen;

import site.aicc.sm2.ec.AbstractECPoint;

/** SM2 public key. */
public class ECPublicKey extends ECKey {

  private final AbstractECPoint q;

  public ECPublicKey(AbstractECPoint q) {
    super(false);
    this.q = validate(q);
  }

  private static AbstractECPoint validate(AbstractECPoint q) {
    if (q == null) {
      throw new IllegalArgumentException("Point is null");
    }
    if (q.isInfinity()) {
      throw new IllegalArgumentException("Point is at infinity");
    }
    if (!q.isValid()) {
      throw new IllegalArgumentException("Point is not on the curve");
    }
    return q;
  }

  public AbstractECPoint getQ() {
    return q;
  }
}
