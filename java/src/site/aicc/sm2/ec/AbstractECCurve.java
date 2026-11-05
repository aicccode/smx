package site.aicc.sm2.ec;

import java.math.BigInteger;
import site.aicc.sm2.util.ConvertUtil;

/** Abstract elliptic curve. */
public abstract class AbstractECCurve {
  private static final byte UNCOMPRESSED_PREFIX = 0x04;

  protected AbstractECElement a;
  protected AbstractECElement b;
  protected BigInteger order;
  protected BigInteger cofactor;

  public abstract int getFieldSize();

  public abstract AbstractECElement fromBigInteger(BigInteger x);

  /** Creates a point after checking 0 <= x, y < p and the curve equation. */
  public AbstractECPoint validatePoint(BigInteger x, BigInteger y) {
    AbstractECPoint p = createPoint(x, y);
    if (!p.isValid()) {
      throw new IllegalArgumentException("Point is not on the curve");
    }
    return p;
  }

  /** Creates a point without checking the curve equation; use {@link #validatePoint} for input. */
  public AbstractECPoint createPoint(BigInteger x, BigInteger y) {
    if (x == null || y == null) {
      throw new IllegalArgumentException("Coordinate is null");
    }
    return createRawPoint(fromBigInteger(x), fromBigInteger(y));
  }

  protected abstract AbstractECPoint createRawPoint(AbstractECElement x, AbstractECElement y);

  public abstract AbstractECPoint getInfinity();

  public AbstractECElement getA() {
    return a;
  }

  public AbstractECElement getB() {
    return b;
  }

  public BigInteger getOrder() {
    return order;
  }

  public BigInteger getCofactor() {
    return cofactor;
  }

  public abstract AbstractECMultiplier getMultiplier();

  /**
   * Decodes an uncompressed point: exactly 0x04 || x || y, with x and y below p and on the curve.
   *
   * @throws IllegalArgumentException for anything else
   */
  public AbstractECPoint decodePoint(byte[] encoded) {
    int expectedLength = (getFieldSize() + 7) / 8;
    if (encoded == null || encoded.length != (2 * expectedLength + 1)) {
      throw new IllegalArgumentException("Invalid point encoding length");
    }
    if (encoded[0] != UNCOMPRESSED_PREFIX) {
      throw new IllegalArgumentException("Invalid point encoding prefix");
    }
    BigInteger x = ConvertUtil.fromUnsignedByteArray(encoded, 1, expectedLength);
    BigInteger y = ConvertUtil.fromUnsignedByteArray(encoded, 1 + expectedLength, expectedLength);
    AbstractECPoint p = validatePoint(x, y);
    if (p.isInfinity()) {
      throw new IllegalArgumentException("Point is at infinity");
    }
    return p;
  }

  protected void checkPoints(AbstractECPoint[] points, int off, int len) {
    if (points == null) {
      throw new IllegalArgumentException("Points cannot be null");
    }
    if (off < 0 || len < 0 || (off > (points.length - len))) {
      throw new IllegalArgumentException("Points out of range");
    }
    for (int i = 0; i < len; ++i) {
      AbstractECPoint point = points[off + i];
      if (null != point && this != point.getCurve()) {
        throw new IllegalArgumentException("Point is not on this curve");
      }
    }
  }

  /** Curves are equal only to themselves, unless a subclass can compare its parameters. */
  @Override
  public boolean equals(Object obj) {
    return this == obj;
  }

  @Override
  public int hashCode() {
    return getFieldSize();
  }
}
