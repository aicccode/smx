package site.aicc.sm2.ec;

import java.math.BigInteger;

//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : </p>
*     </li>
*     <li>
*       <h4> 使用示例(Example)：素数域椭圆曲线点</h4>
*       <p></p>
*       <p></p>
*     </li>
*     <li>
*       <h3>版本历史</h3>
*       <ul>
*           <li>Version : 1.00</li>
*           <li>Date : 2020-09-27 | 下午10:54:58</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class FpPoint extends AbstractECPoint {

    public FpPoint(AbstractECCurve curve, AbstractECElement x, AbstractECElement y) {
        super(curve, x, y);
        if ((x == null) != (y == null)) {
            throw new IllegalArgumentException("域元素是null");
        }
    }

    FpPoint(AbstractECCurve curve, AbstractECElement x, AbstractECElement y, AbstractECElement[] zs) {
        super(curve, x, y, zs);
    }

    protected boolean satisfiesCurveEquation() {
        AbstractECElement X = this.x, Y = this.y, A = curve.getA(), B = curve.getB();
        AbstractECElement lhs = Y.square();
        AbstractECElement rhs = X.square().add(A).multiply(X).add(B);
        return lhs.equals(rhs);
    }

    public AbstractECPoint subtract(AbstractECPoint b) {
        if (b.isInfinity()) {
            return this;
        }
        return this.add(b.negate());
    }

    public AbstractECPoint add(AbstractECPoint b) {
        if (this.isInfinity()) {
            return b;
        }
        if (b.isInfinity()) {
            return this;
        }
        if (this == b) {
            return twice();
        }
        AbstractECCurve curve = this.getCurve();
        AbstractECElement X1 = this.x, Y1 = this.y;
        AbstractECElement X2 = b.x, Y2 = b.y;
        AbstractECElement dx = X2.subtract(X1), dy = Y2.subtract(Y1);
        if (dx.isZero()) {
            if (dy.isZero()) {
                return twice();
            }
            return curve.getInfinity();
        }
        AbstractECElement gamma = dy.divide(dx);
        AbstractECElement X3 = gamma.square().subtract(X1).subtract(X2);
        AbstractECElement Y3 = gamma.multiply(X1.subtract(X3)).subtract(Y1);
        return new FpPoint(curve, X3, Y3);

    }

    public AbstractECPoint twice() {
        if (this.isInfinity()) {
            return this;
        }
        AbstractECCurve curve = this.getCurve();
        AbstractECElement Y1 = this.y;
        if (Y1.isZero()) {
            return curve.getInfinity();
        }
        AbstractECElement X1 = this.x;
        AbstractECElement X1Squared = X1.square();
        AbstractECElement gamma = three(X1Squared).add(this.getCurve().getA()).divide(two(Y1));
        AbstractECElement X3 = gamma.square().subtract(two(X1));
        AbstractECElement Y3 = gamma.multiply(X1.subtract(X3)).subtract(Y1);
        return new FpPoint(curve, X3, Y3);
    }

    public AbstractECPoint twicePlus(AbstractECPoint b) {
        if (this == b) {
            return threeTimes();
        }
        if (this.isInfinity()) {
            return b;
        }
        if (b.isInfinity()) {
            return twice();
        }

        AbstractECElement Y1 = this.y;
        if (Y1.isZero()) {
            return b;
        }
        AbstractECCurve curve = this.getCurve();
        AbstractECElement X1 = this.x;
        AbstractECElement X2 = b.x, Y2 = b.y;

        AbstractECElement dx = X2.subtract(X1), dy = Y2.subtract(Y1);

        if (dx.isZero()) {
            if (dy.isZero()) {
                return threeTimes();
            }

            return this;
        }

        AbstractECElement X = dx.square(), Y = dy.square();
        AbstractECElement d = X.multiply(two(X1).add(X2)).subtract(Y);
        if (d.isZero()) {
            return curve.getInfinity();
        }

        AbstractECElement D = d.multiply(dx);
        AbstractECElement I = D.invert();
        AbstractECElement L1 = d.multiply(I).multiply(dy);
        AbstractECElement L2 = two(Y1).multiply(X).multiply(dx).multiply(I).subtract(L1);
        AbstractECElement X4 = (L2.subtract(L1)).multiply(L1.add(L2)).add(X2);
        AbstractECElement Y4 = (X1.subtract(X4)).multiply(L2).subtract(Y1);

        return new FpPoint(curve, X4, Y4);
    }

    public AbstractECPoint threeTimes() {
        if (this.isInfinity()) {
            return this;
        }
        AbstractECElement Y1 = this.y;
        if (Y1.isZero()) {
            return this;
        }
        AbstractECCurve curve = this.getCurve();
        AbstractECElement X1 = this.x;
        AbstractECElement _2Y1 = two(Y1);
        AbstractECElement X = _2Y1.square();
        AbstractECElement Z = three(X1.square()).add(this.getCurve().getA());
        AbstractECElement Y = Z.square();
        AbstractECElement d = three(X1).multiply(X).subtract(Y);
        if (d.isZero()) {
            return this.getCurve().getInfinity();
        }
        AbstractECElement D = d.multiply(_2Y1);
        AbstractECElement I = D.invert();
        AbstractECElement L1 = d.multiply(I).multiply(Z);
        AbstractECElement L2 = X.square().multiply(I).subtract(L1);
        AbstractECElement X4 = (L2.subtract(L1)).multiply(L1.add(L2)).add(X1);
        AbstractECElement Y4 = (X1.subtract(X4)).multiply(L2).subtract(Y1);
        return new FpPoint(curve, X4, Y4);
    }

    public AbstractECPoint timesPow2(int e) {
        if (e < 0) {
            throw new IllegalArgumentException("'e' 不能为负数");
        }
        if (e == 0 || this.isInfinity()) {
            return this;
        }
        if (e == 1) {
            return twice();
        }
        AbstractECCurve curve = this.getCurve();
        AbstractECElement Y1 = this.y;
        if (Y1.isZero()) {
            return curve.getInfinity();
        }
        AbstractECElement W1 = curve.getA();
        AbstractECElement X1 = this.x;
        AbstractECElement Z1 = this.zs.length < 1 ? curve.fromBigInteger(BigInteger.valueOf(1)) : this.zs[0];
        for (int i = 0; i < e; ++i) {
            if (Y1.isZero()) {
                return curve.getInfinity();
            }
            AbstractECElement X1Squared = X1.square();
            AbstractECElement M = three(X1Squared);
            AbstractECElement _2Y1 = two(Y1);
            AbstractECElement _2Y1Squared = _2Y1.multiply(Y1);
            AbstractECElement S = two(X1.multiply(_2Y1Squared));
            AbstractECElement _4T = _2Y1Squared.square();
            AbstractECElement _8T = two(_4T);
            if (!W1.isZero()) {
                M = M.add(W1);
                W1 = two(_8T.multiply(W1));
            }
            X1 = M.square().subtract(two(S));
            Y1 = M.multiply(S.subtract(X1)).subtract(_8T);
            Z1 = Z1.isOne() ? _2Y1 : _2Y1.multiply(Z1);
        }
        AbstractECElement zInv = Z1.invert(), zInv2 = zInv.square(), zInv3 = zInv2.multiply(zInv);
        return new FpPoint(curve, X1.multiply(zInv2), Y1.multiply(zInv3));
    }
    // 2P
    protected AbstractECElement two(AbstractECElement x) {
        return x.add(x);
    }
    // 3P
    protected AbstractECElement three(AbstractECElement x) {
        return two(x).add(x);
    }
    // -P
    protected AbstractECPoint negate() {
        if (this.isInfinity()) {
            return this;
        }
        AbstractECCurve curve = this.getCurve();
        return new FpPoint(curve, this.x, this.y.negate());
    }
}
