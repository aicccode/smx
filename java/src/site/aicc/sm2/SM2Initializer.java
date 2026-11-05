package site.aicc.sm2;

import java.math.BigInteger;
import java.security.SecureRandom;
import site.aicc.sm2.ec.AbstractECCurve;
import site.aicc.sm2.ec.AbstractECMultiplier;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.ec.FpCurve;
import site.aicc.sm2.ec.Sm2Engine;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECKeyPairGenerator;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

/** SM2 initializer: sets up the elliptic curve and key pair generator from parameters. */
public class SM2Initializer {
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

  public SM2Initializer(String[] params, AbstractECMultiplier multiplier) {
    this.multiplier = multiplier;
    this.p = new BigInteger(params[0], 16);
    this.a = new BigInteger(params[1], 16);
    this.b = new BigInteger(params[2], 16);
    this.n = new BigInteger(params[3], 16);
    this.w = (this.n.bitLength() + 1) / 2 - 1;
    this.gx = new BigInteger(params[4], 16);
    this.gy = new BigInteger(params[5], 16);
    this.curve = new FpCurve(this.multiplier, this.p, this.a, this.b);
    this.g = this.curve.createPoint(this.gx, this.gy);
    this.keyPairGenerator = new ECKeyPairGenerator();
    this.domainBytes = new byte[128];
    BigInteger[] domain = {this.a, this.b, this.gx, this.gy};
    for (int i = 0; i < domain.length; i++) {
      System.arraycopy(ConvertUtil.bigIntegerTo32Bytes(domain[i]), 0, domainBytes, i * 32, 32);
    }
    this.standardDomain = Sm2Engine.isStandardDomain(this.curve, this.g, this.n);
  }

  public ECKeyPair genKeyPair() {
    return this.keyPairGenerator.getECKeyPair(
        this.multiplier, this.curve, this.g, this.n, new SecureRandom());
  }

  /** Like {@link #genKeyPair()} with a scalar whose signed encoding is exactly 32 bytes. */
  ECKeyPair genKeyPairWith32ByteScalar() {
    return this.keyPairGenerator.getECKeyPair(
        this.multiplier, this.curve, this.g, this.n, new SecureRandom(), 32);
  }

  boolean isStandardDomain() {
    return standardDomain;
  }

  public AbstractECPoint decodePoint(byte[] point) {
    return this.curve.decodePoint(point);
  }

  public AbstractECPoint getPublicKey(BigInteger privateKey) {
    return this.g.multiply(privateKey);
  }

  public void validatePoint(BigInteger x, BigInteger y) {
    this.curve.validatePoint(x, y);
  }

  public byte[] userSM3Z(byte[] userId, AbstractECPoint pA) {
    SM3 sm3 = new SM3();
    int len = userId.length * 8;
    sm3.update((byte) (len >> 8 & 0xFF));
    sm3.update((byte) (len & 0xFF));
    sm3.update(userId, 0, userId.length);
    sm3.update(domainBytes, 0, domainBytes.length);
    byte[] p;
    p = ConvertUtil.bigIntegerTo32Bytes(pA.getXCoord().toBigInteger());
    sm3.update(p, 0, p.length);
    p = ConvertUtil.bigIntegerTo32Bytes(pA.getYCoord().toBigInteger());
    sm3.update(p, 0, p.length);
    sm3.finish();
    return sm3.getHashBytes();
  }
}
