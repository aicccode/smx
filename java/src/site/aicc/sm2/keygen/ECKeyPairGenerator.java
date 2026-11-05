package site.aicc.sm2.keygen;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import site.aicc.sm2.ec.AbstractECCurve;
import site.aicc.sm2.ec.AbstractECMultiplier;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.SystemRandom;

/** SM2 key pair generator. */
public class ECKeyPairGenerator {
  /**
   * At least half of all candidates are in range, so this many draws failing means a broken RNG.
   */
  private static final int MAX_DRAWS = 128;

  /** Smallest group order for which [1, n - 2] is not trivially small. */
  private static final int MIN_ORDER_BITS = 8;

  /**
   * Generates a key pair with the private key uniform in [1, n - 2], by rejection sampling on the
   * full byte width with no modulo reduction. Candidates are compared without an early exit.
   *
   * @param random the generator, or null for the operating system's CSPRNG
   * @throws IllegalArgumentException for invalid parameters
   * @throws IllegalStateException when the random source fails or never yields a value in range
   */
  public ECKeyPair getECKeyPair(
      AbstractECMultiplier multiplier,
      AbstractECCurve curve,
      AbstractECPoint g,
      BigInteger n,
      SecureRandom random) {
    if (multiplier == null || curve == null || g == null || n == null) {
      throw new IllegalArgumentException("Key generation parameter is null");
    }
    if (n.signum() <= 0
        || n.bitLength() < MIN_ORDER_BITS
        || n.bitLength() > curve.getFieldSize() + 1) {
      throw new IllegalArgumentException("Invalid group order");
    }
    BigInteger d = drawScalar(n, random == null ? SystemRandom.get() : random);
    AbstractECPoint q = multiplier.multiply(g, d);
    return new ECKeyPair(new ECPublicKey(q), new ECPrivateKey(d));
  }

  private static BigInteger drawScalar(BigInteger n, SecureRandom source) {
    int width = (n.bitLength() + 7) / 8;
    int topMask = 0xFF >>> (width * 8 - n.bitLength());
    byte[] max = toFixedBytes(n.subtract(BigInteger.valueOf(2)), width);
    byte[] candidate = new byte[width];
    try {
      for (int i = 0; i < MAX_DRAWS; i++) {
        SystemRandom.fill(source, candidate);
        candidate[0] &= (byte) topMask;
        if (isInRange(candidate, max)) {
          return new BigInteger(1, candidate);
        }
      }
    } finally {
      Arrays.fill(candidate, (byte) 0);
    }
    throw new IllegalStateException("Secure random source failed");
  }

  /** True when 1 <= value <= max, for big-endian arrays of equal length; no early exit. */
  private static boolean isInRange(byte[] value, byte[] max) {
    int borrow = 0;
    int any = 0;
    for (int i = value.length - 1; i >= 0; i--) {
      int v = value[i] & 0xFF;
      borrow = ((max[i] & 0xFF) - v + borrow) >> 8;
      any |= v;
    }
    return (borrow == 0) & (any != 0);
  }

  private static byte[] toFixedBytes(BigInteger v, int width) {
    byte[] raw = v.toByteArray();
    byte[] out = new byte[width];
    int count = Math.min(raw.length, width);
    System.arraycopy(raw, raw.length - count, out, width - count, count);
    return out;
  }
}
