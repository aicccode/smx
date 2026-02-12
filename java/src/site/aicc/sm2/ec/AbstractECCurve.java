package site.aicc.sm2.ec;

import java.math.BigInteger;

import site.aicc.sm2.util.ConvertUtil;

/** Abstract elliptic curve. */
public abstract class AbstractECCurve {
    protected AbstractECElement a, b;
    protected BigInteger order, cofactor;

    public abstract int getFieldSize();

    public abstract AbstractECElement fromBigInteger(BigInteger x);

    public AbstractECPoint validatePoint(BigInteger x, BigInteger y) {
        AbstractECPoint p = createPoint(x, y);
        if (!p.isValid()) {
            throw new IllegalArgumentException("Point is not on the curve");
        }
        return p;
    }

    public AbstractECPoint createPoint(BigInteger x, BigInteger y) {
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

    public AbstractECPoint decodePoint(byte[] encoded) {
        AbstractECPoint p = null;
        int expectedLength = (getFieldSize() + 7) / 8;
        if (encoded.length != (2 * expectedLength + 1)) {
            throw new IllegalArgumentException("Invalid point encoding length");
        }
        BigInteger X = ConvertUtil.fromUnsignedByteArray(encoded, 1, expectedLength);
        BigInteger Y = ConvertUtil.fromUnsignedByteArray(encoded, 1 + expectedLength, expectedLength);
        p = validatePoint(X, Y);
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

    @Override
    public boolean equals(Object obj) {
        return this == obj || (obj instanceof AbstractECCurve && equals((AbstractECCurve) obj));
    }

    @Override
    public int hashCode() {
        return getFieldSize();
    }

}
