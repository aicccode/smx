package site.aicc.sm2.ec;

import java.math.BigInteger;

/** Abstract base class for EC point multiplication algorithms. */
public abstract class AbstractECMultiplier {

    public AbstractECPoint multiply(AbstractECPoint p, BigInteger k) {
        int sign = k.signum();
        if (sign == 0 || p.isInfinity()) {
            return p.getCurve().getInfinity();
        }
        AbstractECPoint positive = multiplyPositive(p, k.abs());
        AbstractECPoint result = sign > 0 ? positive : positive.negate();
        return validatePoint(result);
    }

    private static AbstractECPoint validatePoint(AbstractECPoint p) {
        if (!p.isValid()) {
            throw new IllegalArgumentException("Invalid EC point");
        }
        return p;
    }

    protected abstract AbstractECPoint multiplyPositive(AbstractECPoint p, BigInteger k);
}
