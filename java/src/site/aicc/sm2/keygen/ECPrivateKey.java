package site.aicc.sm2.keygen;

import java.math.BigInteger;

/** SM2 private key. */
public class ECPrivateKey extends ECKey {

  private BigInteger d;

  public ECPrivateKey(BigInteger d) {
    super(true);
    if (d == null || d.signum() <= 0) {
      throw new IllegalArgumentException("Invalid private key");
    }
    this.d = d;
  }

  public BigInteger getD() {
    return d;
  }
}
