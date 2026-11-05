package site.aicc.sm2.keygen;

import java.math.BigInteger;
import java.security.SecureRandom;
import site.aicc.sm2.ec.AbstractECCurve;
import site.aicc.sm2.ec.AbstractECMultiplier;
import site.aicc.sm2.ec.AbstractECPoint;

/** SM2 key pair generator. */
public class ECKeyPairGenerator {

  /** Generates a key pair with a uniformly drawn scalar. */
  public ECKeyPair getECKeyPair(
      AbstractECMultiplier multiplier,
      AbstractECCurve curve,
      AbstractECPoint g,
      BigInteger n,
      SecureRandom random) {
    return getECKeyPair(multiplier, curve, g, n, random, -1);
  }

  /**
   * Generates a key pair whose scalar also encodes to {@code scalarBytes} bytes in {@link
   * BigInteger#toByteArray()}, or any length when negative. Rejecting a scalar here avoids the
   * point multiplication that would only be thrown away by a caller filtering on the same
   * condition.
   */
  public ECKeyPair getECKeyPair(
      AbstractECMultiplier multiplier,
      AbstractECCurve curve,
      AbstractECPoint g,
      BigInteger n,
      SecureRandom random,
      int scalarBytes) {
    SecureRandom source = random == null ? new SecureRandom() : random;
    int minWidth = n.bitLength() >>> 2;
    BigInteger d;
    do {
      d = new BigInteger(n.bitLength(), source);
    } while (d.compareTo(BigInteger.valueOf(2)) < 0
        || d.compareTo(n) >= 0
        || getWidth(d) < minWidth
        || (scalarBytes >= 0 && d.toByteArray().length != scalarBytes));
    AbstractECPoint q = multiplier.multiply(g, d);
    return new ECKeyPair(new ECPublicKey(q), new ECPrivateKey(d));
  }

  private static int getWidth(BigInteger k) {
    return k.signum() == 0 ? 0 : k.shiftLeft(1).add(k).xor(k).bitCount();
  }
}
