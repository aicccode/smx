package site.aicc.sm2;

import java.math.BigInteger;
import site.aicc.sm2.ec.AbstractECCurve;
import site.aicc.sm2.ec.AbstractECMultiplier;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.FpCurve;
import site.aicc.sm2.ec.Sm2Engine;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECKeyPairGenerator;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm2.util.SystemRandom;
import site.aicc.sm3.SM3;

/** SM2 initializer: sets up the elliptic curve and key pair generator from parameters. */
public class SM2Initializer {
  private static final int PARAM_COUNT = 6;
  private static final int FIELD_BITS = 256;
  private static final int PRIME_CERTAINTY = 64;
  private static final int MAX_USER_ID_BYTES = 8191;

  private final BigInteger p;
  private final BigInteger a;
  private final BigInteger b;
  private final BigInteger n;
  private final int w;
  private final BigInteger gx;
  private final BigInteger gy;
  private final AbstractECCurve curve;
  private final AbstractECPoint g;

  private final AbstractECMultiplier multiplier;

  /** a || b || Gx || Gy, the constant middle of every Z value. */
  private final byte[] domainBytes;

  /** True when the parameters are the standard SM2 ones, so limb arithmetic applies. */
  private final boolean standardDomain;

  public BigInteger getN() {
    return n;
  }

  public AbstractECPoint getG() {
    return g;
  }

  public int getW() {
    return w;
  }

  private final ECKeyPairGenerator keyPairGenerator;

  /**
   * Builds the domain from six hex values: p, a, b, n, Gx, Gy.
   *
   * @throws IllegalArgumentException unless p and n are 256-bit primes and G is a curve point of
   *     order n
   */
  public SM2Initializer(String[] params, AbstractECMultiplier multiplier) {
    if (params == null || params.length != PARAM_COUNT || multiplier == null) {
      throw new IllegalArgumentException("Invalid SM2 domain parameters");
    }
    this.multiplier = multiplier;
    this.p = parseParam(params[0]);
    this.a = parseParam(params[1]);
    this.b = parseParam(params[2]);
    this.n = parseParam(params[3]);
    this.w = (this.n.bitLength() + 1) / 2 - 1;
    this.gx = parseParam(params[4]);
    this.gy = parseParam(params[5]);
    if (this.p.bitLength() != FIELD_BITS || this.n.bitLength() != FIELD_BITS) {
      throw new IllegalArgumentException("Invalid SM2 domain parameters");
    }
    this.curve = new FpCurve(this.multiplier, this.p, this.a, this.b);
    this.g = this.curve.validatePoint(this.gx, this.gy);
    this.keyPairGenerator = new ECKeyPairGenerator();
    this.domainBytes = new byte[128];
    BigInteger[] domain = {this.a, this.b, this.gx, this.gy};
    for (int i = 0; i < domain.length; i++) {
      System.arraycopy(ConvertUtil.bigIntegerTo32Bytes(domain[i]), 0, domainBytes, i * 32, 32);
    }
    this.standardDomain = Sm2Engine.isStandardDomain(this.curve, this.g, this.n);
    if (!this.standardDomain
        && (!this.n.isProbablePrime(PRIME_CERTAINTY)
            || !hasCofactorOne()
            || !this.g.multiply(this.n).isInfinity())) {
      throw new IllegalArgumentException("Invalid SM2 domain parameters");
    }
  }

  /**
   * By Hasse's bound the curve has at most p + 1 + 2 * sqrt(p) points; when 2n exceeds that, n is
   * the whole group, so every on-curve point is in the prime-order group and there are no small
   * subgroups for a malicious peer point to fall into.
   */
  private boolean hasCofactorOne() {
    BigInteger hasseBound =
        this.p.add(BigInteger.ONE).add(BigInteger.ONE.shiftLeft(FIELD_BITS / 2 + 1));
    return this.n.shiftLeft(1).compareTo(hasseBound) > 0;
  }

  private static BigInteger parseParam(String hex) {
    if (hex == null || hex.isEmpty() || hex.length() > 2 * FIELD_BITS / 8) {
      throw new IllegalArgumentException("Invalid SM2 domain parameters");
    }
    char first = hex.charAt(0);
    if (first == '+' || first == '-') {
      throw new IllegalArgumentException("Invalid SM2 domain parameters");
    }
    return new BigInteger(hex, 16);
  }

  public ECKeyPair genKeyPair() {
    return this.keyPairGenerator.getECKeyPair(
        this.multiplier, this.curve, this.g, this.n, SystemRandom.get());
  }

  boolean isStandardDomain() {
    return standardDomain;
  }

  AbstractECCurve getCurve() {
    return curve;
  }

  public AbstractECPoint decodePoint(byte[] point) {
    return this.curve.decodePoint(point);
  }

  /**
   * Computes d * G.
   *
   * @throws IllegalArgumentException unless 1 <= d <= n - 2
   */
  public AbstractECPoint getPublicKey(BigInteger privateKey) {
    if (standardDomain) {
      return Sm2Engine.publicPoint(this.curve, privateKey);
    }
    if (!isPrivateKeyInRange(privateKey)) {
      throw new IllegalArgumentException("Invalid private key");
    }
    return this.g.multiply(privateKey);
  }

  /** Range check of a private key; on the standard domain it runs without an early exit. */
  boolean isPrivateKeyInRange(BigInteger d) {
    if (standardDomain) {
      return Sm2Engine.isValidPrivateKey(d);
    }
    return d != null && d.signum() > 0 && d.compareTo(this.n.subtract(BigInteger.ONE)) < 0;
  }

  /** Checks that a point is finite, on this curve, with coordinates below p. */
  public void validatePoint(BigInteger x, BigInteger y) {
    this.curve.validatePoint(x, y);
  }

  /** True when p is a finite point on this domain's curve. */
  boolean isUsablePoint(AbstractECPoint point) {
    return point != null
        && !point.isInfinity()
        && this.curve.equals(point.getCurve())
        && point.isValid();
  }

  /**
   * Computes the user hash Z of GB/T 32918.
   *
   * @throws IllegalArgumentException for an ID of 8192 bytes or more, whose bit length does not fit
   *     the 16-bit field, or for a point that is not a finite point on this curve
   */
  public byte[] userSM3Z(byte[] userId, AbstractECPoint pA) {
    if (userId == null || userId.length > MAX_USER_ID_BYTES) {
      throw new IllegalArgumentException("Invalid user ID");
    }
    if (!isUsablePoint(pA)) {
      throw new IllegalArgumentException("Invalid EC point");
    }
    SM3 sm3 = new SM3();
    int len = userId.length * 8;
    sm3.update((byte) (len >> 8 & 0xFF));
    sm3.update((byte) (len & 0xFF));
    sm3.update(userId, 0, userId.length);
    sm3.update(domainBytes, 0, domainBytes.length);
    byte[] xBytes = ConvertUtil.bigIntegerTo32Bytes(pA.getXCoord().toBigInteger());
    sm3.update(xBytes, 0, xBytes.length);
    byte[] yBytes = ConvertUtil.bigIntegerTo32Bytes(pA.getYCoord().toBigInteger());
    sm3.update(yBytes, 0, yBytes.length);
    sm3.finish();
    return sm3.getHashBytes();
  }
}
