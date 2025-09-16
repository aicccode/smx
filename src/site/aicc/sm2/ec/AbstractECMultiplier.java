package site.aicc.sm2.ec;

import java.math.BigInteger;
//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : 倍点运算器</p>
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
*           <li>Date : 2020-09-26 | 下午10:35:11</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
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
            throw new IllegalArgumentException("该点是无效的点!");
        }
        return p;
    }

    protected abstract AbstractECPoint multiplyPositive(AbstractECPoint p, BigInteger k);
}
