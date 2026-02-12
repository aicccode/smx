package site.aicc.sm2.ec;

import java.math.BigInteger;

import site.aicc.sm2.util.ConvertUtil;

/** Field element for elliptic curve operations. */
public abstract class AbstractECElement {

    public abstract BigInteger toBigInteger();

    public abstract int getFieldSize();

    public abstract AbstractECElement add(AbstractECElement b);

    public abstract AbstractECElement subtract(AbstractECElement b);

    public abstract AbstractECElement multiply(AbstractECElement b);

    public abstract AbstractECElement divide(AbstractECElement b);

    public abstract AbstractECElement negate();

    public abstract AbstractECElement square();

    public abstract AbstractECElement invert();

    public int bitLength() {
        return toBigInteger().bitLength();
    }

    public boolean isOne() {
        return bitLength() == 1;
    }

    public boolean isZero() {
        return 0 == toBigInteger().signum();
    }

    public byte[] getEncoded() {
        return ConvertUtil.asUnsignedByteArray((getFieldSize() + 7) / 8, toBigInteger());
    }

}
