package site.aicc.sm2.ec;

import java.math.BigInteger;

//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : 素数域椭圆曲线</p>
*     </li>
*     <li>
*       <h4> 使用示例(Example)：</h4>
*       <p></p>
*       <p></p>
*     </li>
*     <li>
*       <h3>版本历史</h3>
*       <ul>
*           <li>Version : 1.00</li>
*           <li>Date : 2020-09-27 | 下午10:46:17</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class FpCurve extends AbstractECCurve {

    BigInteger q, r;
    AbstractECMultiplier multiplier;
    FpPoint infinity;

    public FpCurve(AbstractECMultiplier multiplier, BigInteger q, BigInteger a, BigInteger b) {
        this(multiplier, q, a, b, null, null);
    }

    public FpCurve(AbstractECMultiplier multiplier, BigInteger q, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor) {
        this.multiplier = multiplier;
        this.q = q;
        this.r = FpElement.calculateResidue(q);
        this.infinity = new FpPoint(this, null, null);
        this.a = fromBigInteger(a);
        this.b = fromBigInteger(b);
        this.order = order;
        this.cofactor = cofactor;
    }

    public int getFieldSize() {
        return q.bitLength();
    }

    public AbstractECElement fromBigInteger(BigInteger x) {
        return new FpElement(this.q, this.r, x);
    }

    protected AbstractECPoint createRawPoint(AbstractECElement x, AbstractECElement y) {
        return new FpPoint(this, x, y);
    }

    public AbstractECPoint getInfinity() {
        return infinity;
    }

    public AbstractECMultiplier getMultiplier() {
        return this.multiplier;
    }

}
