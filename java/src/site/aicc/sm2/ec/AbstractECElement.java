package site.aicc.sm2.ec;

import java.math.BigInteger;

import site.aicc.sm2.util.ConvertUtil;
//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : 域元素</p>
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
*           <li>Date : 2020-09-26 | 下午09:25:16</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
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
