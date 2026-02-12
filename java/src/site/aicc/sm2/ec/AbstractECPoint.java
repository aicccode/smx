package site.aicc.sm2.ec;

import java.math.BigInteger;

/** Point on an elliptic curve. */
public abstract class AbstractECPoint {

    protected AbstractECCurve curve;
    protected AbstractECElement x;
    protected AbstractECElement y;
    protected AbstractECElement[] zs;
    protected AbstractECPreCalcInfo preCalcInfo = null;

    protected AbstractECPoint(AbstractECCurve curve, AbstractECElement x, AbstractECElement y) {
        this(curve, x, y, new AbstractECElement[0]);
    }

    protected AbstractECPoint(AbstractECCurve curve, AbstractECElement x, AbstractECElement y, AbstractECElement[] zs) {
        this.curve = curve;
        this.x = x;
        this.y = y;
        this.zs = zs;
    }

    AbstractECPreCalcInfo getPreCalcInfo() {
            return this.preCalcInfo;
    }

    void setPreCalcInfo(AbstractECPreCalcInfo preCalcInfo) {
        this.preCalcInfo = preCalcInfo;
    }

    private static AbstractECPoint referenceMultiply(AbstractECPoint p, BigInteger k) {
        BigInteger x = k.abs();
        AbstractECPoint q = p.getCurve().getInfinity();
        int t = x.bitLength();
        if (t > 0) {
            if (x.testBit(0)) {
                q = p;
            }
            for (int i = 1; i < t; i++) {
                p = p.twice();
                if (x.testBit(i)) {
                    q = q.add(p);
                }
            }
        }
        return k.signum() < 0 ? q.negate() : q;
    }

    protected boolean satisfiesCofactor() {
        BigInteger h = curve.getCofactor();
        return h == null || h.equals(BigInteger.valueOf(1)) || !referenceMultiply(this, h).isInfinity();
    }

    protected abstract boolean satisfiesCurveEquation();

    public AbstractECCurve getCurve() {
        return curve;
    }

    public AbstractECElement getXCoord() {
        return x;
    }

    public AbstractECElement getYCoord() {
        return y;
    }

    public boolean isInfinity() {
        return x == null || y == null || (zs.length > 0 && zs[0].isZero());
    }

    public boolean isValid() {
        if (isInfinity()) {
            return true;
        }
        AbstractECCurve curve = getCurve();
        if (curve != null) {
            if (!satisfiesCurveEquation()) {
                return false;
            }

            if (!satisfiesCofactor()) {
                return false;
            }
        }

        return true;
    }

    public byte[] getEncoded() {
        if (this.isInfinity()) {
            return new byte[1];
        }
        byte[] X = this.getXCoord().getEncoded();
        byte[] Y = this.getYCoord().getEncoded();
        byte[] PO = new byte[X.length + Y.length + 1];
        PO[0] = 0x04;
        System.arraycopy(X, 0, PO, 1, X.length);
        System.arraycopy(Y, 0, PO, X.length + 1, Y.length);
        return PO;
    }

    public abstract AbstractECPoint add(AbstractECPoint b);

    protected abstract AbstractECPoint negate();

    public abstract AbstractECPoint subtract(AbstractECPoint b);

    public AbstractECPoint timesPow2(int e) {
        if (e < 0) {
            throw new IllegalArgumentException("'e' cannot be negative");
        }

        AbstractECPoint p = this;
        while (--e >= 0) {
            p = p.twice();
        }
        return p;
    }

    public abstract AbstractECPoint twice();

    public AbstractECPoint twicePlus(AbstractECPoint b) {
        return twice().add(b);
    }

    public AbstractECPoint threeTimes() {
        return twicePlus(this);
    }

    public AbstractECPoint multiply(BigInteger k) {
        return this.getCurve().getMultiplier().multiply(this, k);
    }
}
